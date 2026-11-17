//! Committee rotation wire types, nomination-binding checks, union resolution,
//! and chain verification for HuMoCo Sync Locks (`SPEC.md` §6.10, Concept §5.4–§5.6).

use crate::causal::LockEntry;
use crate::crypto::{
    derive_bucket, verify_ed25519_strict, CREATOR_HEARTBEAT_DOMAIN, FREEZE_SNAPSHOT_DOMAIN,
    FREEZE_STATE_DOMAIN, IMPORT_ACK_DOMAIN, IMPORT_UNION_STATE_DOMAIN, MAX_MIGRATION_CHAIN_LEN,
    MIGRATION_CERT_DOMAIN, MIGRATION_PROPOSAL_DOMAIN, MIGRATION_VETO_DOMAIN,
};
use crate::manifest::{AnchorAuthority, AnchorManifest, NominatedBy, ServerEntry};
use crate::types::{
    decode_hex_fixed, serde_hex_32, serde_hex_64, serde_hex_opt_32, serde_hex_opt_64,
    LockCommittee, LockPubKey, QuorumCertificate,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Party initiating a committee rotation proposal (`Concept` §5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposalInitiator {
    /// Voucher creator signed with `creator_mig_sk`.
    Creator,
    /// Guarantor at `guarantor_index` in `AnchorAuthority::guarantor_mig_pubs` after 30d creator inactivity.
    Guarantor {
        /// Index into `AnchorAuthority::guarantor_mig_pubs`.
        guarantor_index: u8,
    },
    /// Any voucher holder promoting pre-declared `successors` matching the failed slot's `NominatedBy`.
    HolderStandby,
}

impl ProposalInitiator {
    fn write_canonical(&self, out: &mut Vec<u8>) {
        match *self {
            Self::Creator => out.push(0x00),
            Self::Guarantor { guarantor_index } => {
                out.push(0x01);
                out.push(guarantor_index);
            }
            Self::HolderStandby => out.push(0x02),
        }
    }
}

/// Optional co-signature by a guarantor approving changes to its nominated seat(s).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuarantorCosig {
    /// Index into `AnchorAuthority::guarantor_mig_pubs`.
    pub guarantor_index: u8,
    /// Ed25519 signature over [`MigrationProposal::core_digest`].
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

/// Result of checking [`verify_nomination_binding`] on a rotation proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NominationCheckOutcome {
    /// `true` if any `Guarantor(i)` slot had to be shrunk without co-signature / standby replacement.
    pub guarantor_protection_reduced: bool,
}

/// Proposal transitioning an anchor set from `from_rev` to `to_rev = from_rev + 1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationProposal {
    /// Immutable Genesis revision-1 `anchor_id`.
    #[serde(with = "serde_hex_32")]
    pub anchor_id: [u8; 32],
    /// Current revision being rotated away from.
    pub from_rev: u64,
    /// Target revision (`must equal from_rev + 1`).
    pub to_rev: u64,
    /// Target quorum threshold (`1 <= new_threshold <= new_servers.len()`, `2 * threshold > len`).
    pub new_threshold: u8,
    /// Ordered target committee members (`1 <= N <= 5`).
    pub new_servers: Vec<ServerEntry>,
    /// Remaining standby successor servers per nominator.
    pub new_successors: Vec<ServerEntry>,
    /// Immutable bucket retention quarter (`must equal prev_manifest.retain_until_quarter`).
    pub retain_until_quarter: u16,
    /// Proposal creation timestamp in UTC Unix seconds (starts the 72h timelock).
    pub proposed_at: u64,
    /// Role initiating the rotation (`Creator`, `Guarantor`, or `HolderStandby`).
    pub initiator: ProposalInitiator,
    /// Proposer Ed25519 signature over [`Self::core_digest`]; `None` iff `HolderStandby`.
    #[serde(with = "serde_hex_opt_64")]
    pub proposer_sig: Option<[u8; 64]>,
    /// Optional guarantor co-signatures over [`Self::core_digest`].
    pub guarantor_cosigs: Vec<GuarantorCosig>,
}

impl MigrationProposal {
    /// Validates `new_threshold` and `new_servers` as a strict `LockCommittee`.
    pub fn new_committee(&self) -> Result<LockCommittee, &'static str> {
        let committee = LockCommittee {
            members: self.new_servers.iter().map(|s| s.lock_pub).collect(),
            threshold: self.new_threshold,
        };
        committee.validate()?;
        Ok(committee)
    }

    /// Computes the canonical `HUMOCO_MIGRATION_PROP_V1` SHA-256 digest covering all
    /// proposal parameters and `initiator`, signed by `proposer_sig` and `guarantor_cosigs`.
    pub fn core_digest(&self) -> Result<[u8; 32], &'static str> {
        if self.proposed_at == 0 {
            return Err("proposal timestamp must be positive");
        }
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(MIGRATION_PROPOSAL_DOMAIN);
        buf.extend_from_slice(&self.anchor_id);
        buf.extend_from_slice(&self.from_rev.to_le_bytes());
        buf.extend_from_slice(&self.to_rev.to_le_bytes());
        buf.push(self.new_threshold);
        let server_count =
            u8::try_from(self.new_servers.len()).map_err(|_| "new_servers count overflow")?;
        buf.push(server_count);
        for s in &self.new_servers {
            s.write_canonical(&mut buf)?;
        }
        let succ_count = u16::try_from(self.new_successors.len())
            .map_err(|_| "new_successors count overflow")?;
        buf.extend_from_slice(&succ_count.to_le_bytes());
        for s in &self.new_successors {
            s.write_canonical(&mut buf)?;
        }
        buf.extend_from_slice(&self.retain_until_quarter.to_le_bytes());
        buf.extend_from_slice(&self.proposed_at.to_le_bytes());
        self.initiator.write_canonical(&mut buf);
        Ok(Sha256::digest(&buf).into())
    }

    /// Verifies structural validity, authority signatures, retention invariance, and
    /// nomination-binding rules against `prev_manifest` for `expected_anchor_id`.
    pub fn verify_against_manifest(
        &self,
        expected_anchor_id: &[u8; 32],
        prev_manifest: &AnchorManifest,
    ) -> Result<NominationCheckOutcome, &'static str> {
        prev_manifest.validate_local()?;
        if self.anchor_id != *expected_anchor_id {
            return Err("proposal anchor_id mismatch");
        }
        if self.from_rev != prev_manifest.revision {
            return Err("proposal from_rev does not match current manifest revision");
        }
        if self.to_rev != self.from_rev.checked_add(1).ok_or("revision overflow")? {
            return Err("proposal to_rev must equal from_rev + 1");
        }
        if self.retain_until_quarter != prev_manifest.retain_until_quarter {
            return Err("proposal must preserve retain_until_quarter");
        }
        let committee = self.new_committee()?;
        let guarantor_count = prev_manifest.authority.guarantor_mig_pubs.len();
        for server in &self.new_servers {
            server.validate(guarantor_count)?;
        }
        for (i, succ) in self.new_successors.iter().enumerate() {
            succ.validate(guarantor_count)?;
            if committee.contains(&succ.lock_pub) {
                return Err("proposal successor lock_pub already in active new_servers");
            }
            if self.new_successors[..i]
                .iter()
                .any(|p| p.lock_pub == succ.lock_pub)
            {
                return Err("duplicate proposal successor lock_pub");
            }
        }

        let digest = self.core_digest()?;
        match self.initiator {
            ProposalInitiator::Creator => {
                let sig = self
                    .proposer_sig
                    .ok_or("creator proposal requires proposer_sig")?;
                if !verify_ed25519_strict(&prev_manifest.authority.creator_mig_pub, &digest, &sig) {
                    return Err("invalid creator proposer_sig");
                }
            }
            ProposalInitiator::Guarantor { guarantor_index } => {
                let sig = self
                    .proposer_sig
                    .ok_or("guarantor proposal requires proposer_sig")?;
                let g_pub = prev_manifest
                    .authority
                    .guarantor_mig_pubs
                    .get(usize::from(guarantor_index))
                    .ok_or("guarantor_index out of range")?;
                if !verify_ed25519_strict(g_pub, &digest, &sig) {
                    return Err("invalid guarantor proposer_sig");
                }
            }
            ProposalInitiator::HolderStandby => {
                if self.proposer_sig.is_some() || !self.guarantor_cosigs.is_empty() {
                    return Err("holder standby proposal must not carry authority signatures");
                }
            }
        }

        let mut seen_cosig_idx = HashSet::new();
        for cosig in &self.guarantor_cosigs {
            if !seen_cosig_idx.insert(cosig.guarantor_index) {
                return Err("duplicate guarantor cosig");
            }
            let g_pub = prev_manifest
                .authority
                .guarantor_mig_pubs
                .get(usize::from(cosig.guarantor_index))
                .ok_or("guarantor cosig index out of range")?;
            if !verify_ed25519_strict(g_pub, &digest, &cosig.sig) {
                return Err("invalid guarantor cosig");
            }
        }

        verify_nomination_binding(prev_manifest, self)
    }
}

/// Pure verifier enforcing Concept §5.4 nomination-binding across revisions:
///
/// - A `HolderStandby` proposal may only swap active slots with the next declared standby
///   successor of the same `NominatedBy` origin while leaving threshold and committee size intact.
/// - A `Guarantor(i)` seat cannot be reassigned to an unendorsed server or replaced by a creator
///   server unless guarantor `i` co-signed or a declared `Guarantor(i)` successor is promoted
///   in declaration order; if no successors remain, the seat may only shrink (flagging
///   `guarantor_protection_reduced`) without increasing creator-seat count.
pub fn verify_nomination_binding(
    prev_manifest: &AnchorManifest,
    proposal: &MigrationProposal,
) -> Result<NominationCheckOutcome, &'static str> {
    if proposal.initiator == ProposalInitiator::HolderStandby {
        if proposal.new_threshold != prev_manifest.threshold
            || proposal.new_servers.len() != prev_manifest.servers.len()
        {
            return Err("holder standby rotation cannot alter committee size or threshold");
        }
        if proposal.new_servers == prev_manifest.servers {
            return Err("holder standby rotation must replace at least one server");
        }
        let mut standby_pool = prev_manifest.successors.clone();
        for (old_s, new_s) in prev_manifest.servers.iter().zip(&proposal.new_servers) {
            if new_s == old_s {
                continue;
            }
            let next_pos = standby_pool
                .iter()
                .position(|cand| cand.nominated_by == old_s.nominated_by)
                .ok_or("no declared standby successor available for slot origin")?;
            let expected_succ = standby_pool.remove(next_pos);
            if *new_s != expected_succ {
                return Err("holder standby rotation must promote the next declared successor");
            }
        }
        if proposal.new_successors != standby_pool {
            return Err("holder standby rotation must remove exactly the promoted successors");
        }
        return Ok(NominationCheckOutcome {
            guarantor_protection_reduced: false,
        });
    }

    let mut signed_guarantors = HashSet::new();
    if let ProposalInitiator::Guarantor { guarantor_index } = proposal.initiator {
        signed_guarantors.insert(guarantor_index);
    }
    for cosig in &proposal.guarantor_cosigs {
        signed_guarantors.insert(cosig.guarantor_index);
    }

    let creator_signed = matches!(proposal.initiator, ProposalInitiator::Creator);
    let mut reduced = false;
    let mut all_guarantors_signed = true;

    for idx_usize in 0..prev_manifest.authority.guarantor_mig_pubs.len() {
        let g_idx = u8::try_from(idx_usize).map_err(|_| "guarantor count overflow")?;
        let role = NominatedBy::Guarantor(g_idx);
        let role_signed = signed_guarantors.contains(&g_idx);
        if !role_signed {
            all_guarantors_signed = false;
        }
        if role_signed {
            continue;
        }
        check_unsigned_role_servers_and_successors(role, prev_manifest, proposal, &mut reduced)?;
    }

    if !creator_signed {
        let mut unused_creator_reduce = false;
        check_unsigned_role_servers_and_successors(
            NominatedBy::Creator,
            prev_manifest,
            proposal,
            &mut unused_creator_reduce,
        )?;
    }

    let prev_creator_cnt = prev_manifest
        .servers
        .iter()
        .filter(|s| s.nominated_by == NominatedBy::Creator)
        .count();
    let new_creator_cnt = proposal
        .new_servers
        .iter()
        .filter(|s| s.nominated_by == NominatedBy::Creator)
        .count();

    if !all_guarantors_signed
        && !prev_manifest.authority.guarantor_mig_pubs.is_empty()
        && new_creator_cnt > prev_creator_cnt
    {
        return Err("cannot expand creator-nominated seats without all guarantors co-signing");
    }

    Ok(NominationCheckOutcome {
        guarantor_protection_reduced: reduced,
    })
}

fn check_unsigned_role_servers_and_successors(
    role: NominatedBy,
    prev_manifest: &AnchorManifest,
    proposal: &MigrationProposal,
    reduced_flag: &mut bool,
) -> Result<(), &'static str> {
    let prev_active: Vec<&ServerEntry> = prev_manifest
        .servers
        .iter()
        .filter(|s| s.nominated_by == role)
        .collect();
    let new_active: Vec<&ServerEntry> = proposal
        .new_servers
        .iter()
        .filter(|s| s.nominated_by == role)
        .collect();

    if new_active.len() > prev_active.len() {
        return Err("cannot expand seats for an un-signed nominator");
    }

    let prev_succ: Vec<&ServerEntry> = prev_manifest
        .successors
        .iter()
        .filter(|s| s.nominated_by == role)
        .collect();
    let new_succ: Vec<&ServerEntry> = proposal
        .new_successors
        .iter()
        .filter(|s| s.nominated_by == role)
        .collect();

    let prev_active_set: HashSet<[u8; 32]> = prev_active.iter().map(|s| s.lock_pub).collect();
    let added: Vec<&ServerEntry> = new_active
        .iter()
        .copied()
        .filter(|s| !prev_active_set.contains(&s.lock_pub))
        .collect();

    if added.len() > prev_succ.len() {
        return Err("replacement server is not in declared standby successors");
    }
    for (idx, added_srv) in added.iter().enumerate() {
        if *added_srv != prev_succ[idx] {
            return Err("standby successors must be promoted in declared FIFO order");
        }
    }
    let remaining_succ = &prev_succ[added.len()..];
    if new_succ.len() != remaining_succ.len()
        || new_succ.iter().zip(remaining_succ).any(|(a, b)| a != b)
    {
        return Err("unpromoted successors must remain unchanged for un-signed nominator");
    }

    if new_active.len() < prev_active.len() {
        if !remaining_succ.is_empty() {
            return Err("cannot shrink nominator seat while unused standby successors remain");
        }
        if matches!(role, NominatedBy::Guarantor(_)) {
            *reduced_flag = true;
        }
    }
    Ok(())
}

/// Authority veto cancelling an active `MigrationProposal` during its 72h timelock (`Concept` §5.4–5.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationVeto {
    /// Target `anchor_id`.
    #[serde(with = "serde_hex_32")]
    pub anchor_id: [u8; 32],
    /// Revision that was targeted by the vetoed proposal.
    pub from_rev: u64,
    /// `proposal.core_digest()` being vetoed.
    #[serde(with = "serde_hex_32")]
    pub proposal_hash: [u8; 32],
    /// Public key (`creator_mig_pub` or `guarantor_mig_pubs[i]`) signing the veto.
    #[serde(with = "serde_hex_32")]
    pub vetoer_pub: [u8; 32],
    /// Timestamp of veto creation in UTC Unix seconds.
    pub vetoed_at: u64,
    /// Ed25519 signature over `HUMOCO_MIGRATION_VETO_V1`.
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl MigrationVeto {
    /// Computes the canonical `HUMOCO_MIGRATION_VETO_V1` SHA-256 digest.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(MIGRATION_VETO_DOMAIN);
        hasher.update(self.anchor_id);
        hasher.update(self.from_rev.to_le_bytes());
        hasher.update(self.proposal_hash);
        hasher.update(self.vetoer_pub);
        hasher.update(self.vetoed_at.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verifies that `vetoer_pub` is a legitimate authority distinct from the proposer and that
    /// `sig` validates cleanly over `self.digest()`.
    pub fn verify(
        &self,
        authority: &AnchorAuthority,
        proposer_initiator: &ProposalInitiator,
    ) -> Result<(), &'static str> {
        if self.vetoed_at == 0 {
            return Err("veto timestamp must be positive");
        }
        let is_creator = self.vetoer_pub == authority.creator_mig_pub;
        let guarantor_idx = authority
            .guarantor_mig_pubs
            .iter()
            .position(|g| *g == self.vetoer_pub)
            .map(|i| i as u8);
        if !is_creator && guarantor_idx.is_none() {
            return Err("vetoer_pub is not an authority in manifest");
        }
        match *proposer_initiator {
            ProposalInitiator::Creator if is_creator => {
                return Err("creator cannot veto creator's own proposal");
            }
            ProposalInitiator::Guarantor { guarantor_index }
                if guarantor_idx == Some(guarantor_index) =>
            {
                return Err("guarantor cannot veto guarantor's own proposal");
            }
            _ => {}
        }
        let digest = self.digest();
        if !verify_ed25519_strict(&self.vetoer_pub, &digest, &self.sig) {
            return Err("invalid veto signature");
        }
        Ok(())
    }
}

/// Signed creator liveness proof resetting the 30-day guarantor takeover timer (`SPEC.md` §6.10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatorHeartbeat {
    /// Anchor set ID.
    #[serde(with = "serde_hex_32")]
    pub anchor_id: [u8; 32],
    /// Liveness timestamp in UTC Unix seconds.
    pub timestamp_secs: u64,
    /// Creator migration signature (`creator_mig_sk`) over `HUMOCO_CREATOR_HB_V1`.
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl CreatorHeartbeat {
    /// Computes the canonical `HUMOCO_CREATOR_HB_V1` SHA-256 digest.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CREATOR_HEARTBEAT_DOMAIN);
        hasher.update(self.anchor_id);
        hasher.update(self.timestamp_secs.to_le_bytes());
        hasher.finalize().into()
    }

    /// Strictly verifies `sig` against `creator_mig_pub`.
    pub fn verify(&self, creator_mig_pub: &[u8; 32]) -> bool {
        if self.timestamp_secs == 0 {
            return false;
        }
        let digest = self.digest();
        verify_ed25519_strict(creator_mig_pub, &digest, &self.sig)
    }
}

/// Deterministic commitment over a server's locked entries and unresolved conflict pairs
/// exported during Phase 1 (`?lock_freeze`).
pub fn compute_freeze_state_hash(
    anchor_id: &[u8; 32],
    from_rev: u64,
    entries: &[LockEntry],
    conflicts: &[Vec<LockEntry>],
) -> Result<[u8; 32], &'static str> {
    let mut single_items: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(entries.len());
    for entry in entries {
        single_items.push((entry.slot, entry.entry_hash()?));
    }
    single_items.sort_unstable();

    let mut conflict_items: Vec<([u8; 32], Vec<[u8; 32]>)> = Vec::with_capacity(conflicts.len());
    for group in conflicts {
        if group.is_empty() {
            return Err("conflict group must not be empty");
        }
        let slot = group[0].slot;
        let mut hashes = Vec::with_capacity(group.len());
        for entry in group {
            if entry.slot != slot {
                return Err("conflict group entries must share identical slot");
            }
            hashes.push(entry.entry_hash()?);
        }
        hashes.sort_unstable();
        hashes.dedup();
        conflict_items.push((slot, hashes));
    }
    conflict_items.sort_unstable();

    let mut hasher = Sha256::new();
    hasher.update(FREEZE_STATE_DOMAIN);
    hasher.update(anchor_id);
    hasher.update(from_rev.to_le_bytes());
    hasher.update(
        u64::try_from(single_items.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (slot, eh) in single_items {
        hasher.update(slot);
        hasher.update(eh);
    }
    hasher.update(
        u64::try_from(conflict_items.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (slot, hashes) in conflict_items {
        hasher.update(slot);
        hasher.update(
            u64::try_from(hashes.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        for eh in hashes {
            hasher.update(eh);
        }
    }
    Ok(hasher.finalize().into())
}

/// Signed Phase-1 snapshot attesting a server's frozen bucket contents (`SPEC.md` §6.10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeSnapshot {
    /// Immutable Genesis `anchor_id`.
    #[serde(with = "serde_hex_32")]
    pub anchor_id: [u8; 32],
    /// Server-blinded bucket `derive_bucket(anchor_id, lock_pub)`.
    #[serde(with = "serde_hex_32")]
    pub bucket: [u8; 32],
    /// Current revision whose bucket state was frozen.
    pub from_rev: u64,
    /// Immutable bucket retention quarter.
    pub retain_until_quarter: u16,
    /// Bucket write counter at snapshot time.
    pub write_seq: u64,
    /// Bucket hash-chain tip at snapshot time.
    #[serde(with = "serde_hex_32")]
    pub bucket_head: [u8; 32],
    /// Commitment over all entries and conflicts via [`compute_freeze_state_hash`].
    #[serde(with = "serde_hex_32")]
    pub state_hash: [u8; 32],
    /// `true` once locked permanently to a valid `proposal_hash`, `false` for temporary pre-proposal freeze.
    pub permanent: bool,
    /// Core digest of the bound [`MigrationProposal`], `Some` iff `permanent == true`.
    #[serde(with = "serde_hex_opt_32")]
    pub proposal_hash: Option<[u8; 32]>,
    /// Freeze timestamp in UTC Unix seconds.
    pub frozen_at: u64,
    /// Pre-proposal freeze expiration timestamp; `None` when `permanent == true`.
    pub expires_at: Option<u64>,
    /// Signing server's `LockPubKey`.
    #[serde(with = "serde_hex_32")]
    pub lock_pub: LockPubKey,
    /// Ed25519 signature by `S.lock_sk` over `FreezeSnapshot::digest()`.
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl FreezeSnapshot {
    /// Computes the canonical `HUMOCO_FREEZE_SNAP_V1` digest signed in `sig`.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(FREEZE_SNAPSHOT_DOMAIN);
        hasher.update(self.anchor_id);
        hasher.update(self.bucket);
        hasher.update(self.from_rev.to_le_bytes());
        hasher.update(self.retain_until_quarter.to_le_bytes());
        hasher.update(self.write_seq.to_le_bytes());
        hasher.update(self.bucket_head);
        hasher.update(self.state_hash);
        hasher.update([if self.permanent { 1 } else { 0 }]);
        match self.proposal_hash {
            Some(ph) => {
                hasher.update([1]);
                hasher.update(ph);
            }
            None => hasher.update([0]),
        }
        hasher.update(self.frozen_at.to_le_bytes());
        hasher.update(self.expires_at.unwrap_or(0).to_le_bytes());
        hasher.update(self.lock_pub);
        hasher.finalize().into()
    }

    /// Verifies syntactic invariants, bucket derivation, and `sig`.
    pub fn verify(&self) -> bool {
        if self.frozen_at == 0 || self.from_rev == 0 {
            return false;
        }
        if self.permanent && (self.proposal_hash.is_none() || self.expires_at.is_some()) {
            return false;
        }
        if !self.permanent && (self.proposal_hash.is_some() || self.expires_at.is_none()) {
            return false;
        }
        if self.bucket != derive_bucket(&self.anchor_id, &self.lock_pub) {
            return false;
        }
        let digest = self.digest();
        verify_ed25519_strict(&self.lock_pub, &digest, &self.sig)
    }

    /// Verifies signature and checks that `state_hash` commits to `entries` and `conflicts`.
    pub fn verify_with_entries(
        &self,
        entries: &[LockEntry],
        conflicts: &[Vec<LockEntry>],
    ) -> Result<(), &'static str> {
        if !self.verify() {
            return Err("invalid FreezeSnapshot signature or metadata");
        }
        let expected =
            compute_freeze_state_hash(&self.anchor_id, self.from_rev, entries, conflicts)?;
        if expected != self.state_hash {
            return Err("FreezeSnapshot state_hash does not match entries");
        }
        Ok(())
    }
}

/// Exported frozen state supplied by one old server to Phase 2 (`?lock_import`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotExport {
    /// Server-signed Phase 1 freeze snapshot attestation.
    pub snapshot: FreezeSnapshot,
    /// Single-entry slots encoded as canonical 1210-char wire hex.
    pub entries: Vec<String>,
    /// Preserved unresolved `CONFLICT([A, B, ...])` slot entry lists encoded as 1210-char wire hex.
    pub conflicts: Vec<Vec<String>>,
}

/// Deterministic outcome per slot after QC-aware union across surviving old snapshots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedSlot {
    /// Uncontested entry or conflict resolved cleanly by a verified `QuorumCertificate`.
    Single(Box<LockEntry>),
    /// Multiple distinct spends on `slot` lacking any valid `QuorumCertificate`; preserves SST V4.
    Conflict(Vec<LockEntry>),
}

/// Verified union output passed from [`resolve_import_union`] to target servers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedImportUnion {
    /// Per-slot resolved entries sorted by canonical `slot`.
    pub slots: BTreeMap<[u8; 32], ResolvedSlot>,
    /// Unambiguous `(parent_slot, output_branch) -> slot` claims across single & conflict parents.
    pub output_claims: BTreeMap<([u8; 32], u8), [u8; 32]>,
    /// Deterministic SHA-256 commitment (`HUMOCO_IMPORT_STATE_V1`) signed inside [`ImportAck`].
    pub imported_state_hash: [u8; 32],
}

/// Verifies `>= Q_old` permanent snapshots and computes the lossless union with QC conflict
/// resolution (`Concept` §5.4 Nr. 3).
pub fn resolve_import_union(
    anchor_id: &[u8; 32],
    active_manifest: &AnchorManifest,
    proposal: &MigrationProposal,
    exports: &[SnapshotExport],
    quorum_certificates: &[QuorumCertificate],
    pow_base_bits: u32,
) -> Result<ResolvedImportUnion, &'static str> {
    proposal.verify_against_manifest(anchor_id, active_manifest)?;
    let active_committee = active_manifest.committee()?;
    let historical_committees = active_manifest.verified_committees()?;
    let proposal_hash = proposal.core_digest()?;

    if exports.len() < usize::from(active_committee.threshold) {
        return Err("fewer than Q_old freeze snapshots supplied for import");
    }

    let mut seen_servers = HashSet::new();
    let mut candidate_entries: BTreeMap<[u8; 32], BTreeMap<[u8; 32], LockEntry>> = BTreeMap::new();

    for export in exports {
        let snap = &export.snapshot;
        if snap.anchor_id != *anchor_id || snap.from_rev != active_manifest.revision {
            return Err("snapshot anchor_id or from_rev mismatch");
        }
        if snap.retain_until_quarter != active_manifest.retain_until_quarter {
            return Err("snapshot retain_until_quarter mismatch");
        }
        if !snap.permanent || snap.proposal_hash != Some(proposal_hash) {
            return Err("snapshot is not permanently bound to this proposal");
        }
        if !active_committee.contains(&snap.lock_pub) {
            return Err("snapshot signer is not in active committee");
        }
        if !seen_servers.insert(snap.lock_pub) {
            return Err("duplicate freeze snapshot from same server");
        }

        let mut decoded_entries = Vec::with_capacity(export.entries.len());
        for hex_s in &export.entries {
            decoded_entries.push(LockEntry::from_wire_hex(hex_s)?);
        }
        let mut decoded_conflicts = Vec::with_capacity(export.conflicts.len());
        for group in &export.conflicts {
            let mut decoded_group = Vec::with_capacity(group.len());
            for hex_s in group {
                decoded_group.push(LockEntry::from_wire_hex(hex_s)?);
            }
            decoded_conflicts.push(decoded_group);
        }
        snap.verify_with_entries(&decoded_entries, &decoded_conflicts)?;

        for entry in decoded_entries
            .into_iter()
            .chain(decoded_conflicts.into_iter().flatten())
        {
            let eh = entry.entry_hash()?;
            candidate_entries
                .entry(entry.slot)
                .or_default()
                .insert(eh, entry);
        }
    }

    // Verify causal lineage depth-by-depth so no unauthenticated entry enters the new committee.
    let mut ordered: Vec<(u32, [u8; 32], Vec<LockEntry>)> = candidate_entries
        .iter()
        .map(|(slot, map)| {
            let mut list: Vec<LockEntry> = map.values().cloned().collect();
            list.sort_by_key(|e| e.depth);
            let min_depth = list.first().map(|e| e.depth).unwrap_or(0);
            (min_depth, *slot, list)
        })
        .collect();
    ordered.sort_by_key(|(d, s, _)| (*d, *s));

    let mut verified_slots: BTreeMap<[u8; 32], Vec<LockEntry>> = BTreeMap::new();
    for (_d, slot, entries) in ordered {
        let mut valid_list = Vec::with_capacity(entries.len());
        for entry in entries {
            if entry.depth == 0 {
                entry.verify_entry(
                    anchor_id,
                    &active_manifest.authority.creator_mig_pub,
                    pow_base_bits,
                    None,
                )?;
            } else {
                let parents = verified_slots
                    .get(&entry.parent_slot)
                    .ok_or("imported entry missing verified parent slot")?;
                let matched_parent = parents
                    .iter()
                    .find(|p| {
                        entry
                            .verify_entry(
                                anchor_id,
                                &active_manifest.authority.creator_mig_pub,
                                pow_base_bits,
                                Some(p),
                            )
                            .is_ok()
                    })
                    .ok_or(
                        "imported entry fails causal verification against all candidate parents",
                    )?;
                let _ = matched_parent;
            }
            valid_list.push(entry);
        }
        valid_list.sort_by_key(|e| e.entry_hash().unwrap_or([0; 32]));
        verified_slots.insert(slot, valid_list);
    }

    // Resolve conflicts per slot using verified QuorumCertificates across historical committees.
    let mut slots: BTreeMap<[u8; 32], ResolvedSlot> = BTreeMap::new();
    let mut output_claims: BTreeMap<([u8; 32], u8), [u8; 32]> = BTreeMap::new();

    for (slot, entries) in verified_slots {
        if entries.len() == 1 {
            let e = entries.into_iter().next().ok_or("empty slot list")?;
            record_output_claim(&mut output_claims, &e)?;
            slots.insert(slot, ResolvedSlot::Single(Box::new(e)));
            continue;
        }

        let qc_winner = entries.iter().find(|entry| {
            let Ok(eh) = entry.entry_hash() else {
                return false;
            };
            quorum_certificates.iter().any(|qc| {
                qc.slot == slot
                    && qc.child_lock == entry.child_lock
                    && qc.receipts.iter().all(|r| r.entry_hash == eh)
                    && historical_committees.iter().any(|comm| {
                        qc.verify_with_anchor(comm, anchor_id, active_manifest.retain_until_quarter)
                            .is_ok()
                    })
            })
        });

        if let Some(winner) = qc_winner.cloned() {
            record_output_claim(&mut output_claims, &winner)?;
            slots.insert(slot, ResolvedSlot::Single(Box::new(winner)));
        } else {
            for e in &entries {
                record_output_claim(&mut output_claims, e)?;
            }
            slots.insert(slot, ResolvedSlot::Conflict(entries));
        }
    }

    let imported_state_hash = compute_import_union_state_hash(anchor_id, proposal.to_rev, &slots)?;
    Ok(ResolvedImportUnion {
        slots,
        output_claims,
        imported_state_hash,
    })
}

fn record_output_claim(
    claims: &mut BTreeMap<([u8; 32], u8), [u8; 32]>,
    entry: &LockEntry,
) -> Result<(), &'static str> {
    if entry.depth == 0 {
        return Ok(());
    }
    match claims.get(&(entry.parent_slot, entry.output_branch)) {
        Some(existing) if *existing != entry.slot => {
            Err("ambiguous child slot claim for (parent_slot, output_branch)")
        }
        Some(_) => Ok(()),
        None => {
            claims.insert((entry.parent_slot, entry.output_branch), entry.slot);
            Ok(())
        }
    }
}

/// Computes the deterministic SHA-256 commitment over a [`ResolvedSlot`] map (`HUMOCO_IMPORT_STATE_V1`).
pub fn compute_import_union_state_hash(
    anchor_id: &[u8; 32],
    to_rev: u64,
    slots: &BTreeMap<[u8; 32], ResolvedSlot>,
) -> Result<[u8; 32], &'static str> {
    let mut hasher = Sha256::new();
    hasher.update(IMPORT_UNION_STATE_DOMAIN);
    hasher.update(anchor_id);
    hasher.update(to_rev.to_le_bytes());
    hasher.update(u64::try_from(slots.len()).unwrap_or(u64::MAX).to_le_bytes());
    for (slot, resolved) in slots {
        hasher.update(slot);
        match resolved {
            ResolvedSlot::Single(e) => {
                hasher.update([0x01]);
                hasher.update(e.entry_hash()?);
            }
            ResolvedSlot::Conflict(list) => {
                hasher.update([0x02]);
                hasher.update(u64::try_from(list.len()).unwrap_or(u64::MAX).to_le_bytes());
                for e in list {
                    hasher.update(e.entry_hash()?);
                }
            }
        }
    }
    Ok(hasher.finalize().into())
}

/// Target server Phase-2 acknowledgment confirming union import (`SPEC.md` §6.10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportAck {
    /// Immutable Genesis `anchor_id`.
    #[serde(with = "serde_hex_32")]
    pub anchor_id: [u8; 32],
    /// Core digest of the bound [`MigrationProposal`].
    #[serde(with = "serde_hex_32")]
    pub proposal_hash: [u8; 32],
    /// Target revision (`proposal.to_rev`).
    pub to_rev: u64,
    /// Deterministic commitment computed over the imported union via [`compute_import_union_state_hash`].
    #[serde(with = "serde_hex_32")]
    pub imported_state_hash: [u8; 32],
    /// Verified immutable retention quarter.
    pub retain_until_quarter: u16,
    /// Target server's `LockPubKey`.
    #[serde(with = "serde_hex_32")]
    pub lock_pub: LockPubKey,
    /// Target server acceptance timestamp in UTC Unix seconds.
    pub acked_at: u64,
    /// Ed25519 signature by `target.lock_sk` over `ImportAck::digest()`.
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl ImportAck {
    /// Computes the canonical `HUMOCO_IMPORT_ACK_V1` digest signed in `sig`.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(IMPORT_ACK_DOMAIN);
        hasher.update(self.anchor_id);
        hasher.update(self.proposal_hash);
        hasher.update(self.to_rev.to_le_bytes());
        hasher.update(self.imported_state_hash);
        hasher.update(self.retain_until_quarter.to_le_bytes());
        hasher.update(self.lock_pub);
        hasher.update(self.acked_at.to_le_bytes());
        hasher.finalize().into()
    }

    /// Strictly verifies `sig` against `lock_pub`.
    pub fn verify(&self) -> bool {
        if self.acked_at == 0 || self.to_rev <= 1 {
            return false;
        }
        let digest = self.digest();
        verify_ed25519_strict(&self.lock_pub, &digest, &self.sig)
    }
}

/// Old-committee server counter-signature committing a completed Phase-3 migration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeSignature {
    /// Signing old-committee server `LockPubKey`.
    #[serde(with = "serde_hex_32")]
    pub lock_pub: LockPubKey,
    /// Commit timestamp in UTC Unix seconds.
    pub committed_at: u64,
    /// Ed25519 signature by `S.lock_sk` over [`MigrationCert::commit_digest`].
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

/// Self-verifiable revision transition certificate linking `from_rev` to `to_rev` (`Concept` §5.4, §5.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationCert {
    /// Immutable Genesis `anchor_id`.
    #[serde(with = "serde_hex_32")]
    pub anchor_id: [u8; 32],
    /// Full Genesis Revision-1 manifest; required strictly on step `1 -> 2`, `None` for all later steps.
    pub genesis_manifest: Option<Box<AnchorManifest>>,
    /// Verified proposal authorizing the new committee & successors.
    pub proposal: MigrationProposal,
    /// Union state commitment acknowledged by every target server.
    #[serde(with = "serde_hex_32")]
    pub imported_state_hash: [u8; 32],
    /// Complete set of `ImportAck`s from every member of `proposal.new_servers`.
    pub import_acks: Vec<ImportAck>,
    /// Counter-signatures from at least `Q_old` members of the previous committee.
    pub commit_sigs: Vec<CommitteeSignature>,
}

impl MigrationCert {
    /// Computes the canonical `HUMOCO_MIGRATION_CERT_V1` message digest signed inside `commit_sigs`.
    pub fn commit_digest(
        anchor_id: &[u8; 32],
        proposal_hash: &[u8; 32],
        to_rev: u64,
        imported_state_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(MIGRATION_CERT_DOMAIN);
        hasher.update(anchor_id);
        hasher.update(proposal_hash);
        hasher.update(to_rev.to_le_bytes());
        hasher.update(imported_state_hash);
        hasher.finalize().into()
    }

    /// Computes this certificate's own `commit_digest` using `self.proposal.core_digest()`.
    pub fn digest(&self) -> Result<[u8; 32], &'static str> {
        let prop_hash = self.proposal.core_digest()?;
        Ok(Self::commit_digest(
            &self.anchor_id,
            &prop_hash,
            self.proposal.to_rev,
            &self.imported_state_hash,
        ))
    }

    /// Verifies one migration step `prev_manifest -> next_manifest`, checking proposal authority,
    /// nomination binding, all target `ImportAck`s, and `>= Q_old` old-committee `commit_sigs`.
    pub fn verify_step(
        &self,
        expected_anchor_id: &[u8; 32],
        prev_manifest: &AnchorManifest,
    ) -> Result<(AnchorManifest, bool), &'static str> {
        if self.anchor_id != *expected_anchor_id {
            return Err("migration cert anchor_id mismatch");
        }
        if prev_manifest.revision == 1 {
            let genesis = self
                .genesis_manifest
                .as_deref()
                .ok_or("rev 1->2 migration cert must carry genesis_manifest")?;
            if genesis.revision != 1 || !genesis.migration_chain.is_empty() {
                return Err("embedded genesis_manifest must be revision 1");
            }
            if genesis != prev_manifest {
                return Err("embedded genesis_manifest mismatch");
            }
        } else if self.genesis_manifest.is_some() {
            return Err("non-genesis migration step must not carry genesis_manifest");
        }

        let binding = self
            .proposal
            .verify_against_manifest(expected_anchor_id, prev_manifest)?;
        let proposal_hash = self.proposal.core_digest()?;

        // Every target server in proposal.new_servers must have acknowledged import with identical state.
        let new_committee = self.proposal.new_committee()?;
        if self.import_acks.len() != new_committee.members.len() {
            return Err("import_acks must cover every target server");
        }
        let mut acked_targets = HashSet::with_capacity(self.import_acks.len());
        for ack in &self.import_acks {
            if ack.anchor_id != *expected_anchor_id
                || ack.proposal_hash != proposal_hash
                || ack.to_rev != self.proposal.to_rev
                || ack.imported_state_hash != self.imported_state_hash
                || ack.retain_until_quarter != self.proposal.retain_until_quarter
                || !new_committee.contains(&ack.lock_pub)
                || !ack.verify()
                || !acked_targets.insert(ack.lock_pub)
            {
                return Err("invalid or duplicate ImportAck in migration cert");
            }
        }

        // At least Q_old distinct previous-committee servers must have signed the commit digest.
        let prev_committee = prev_manifest.committee()?;
        let commit_digest = Self::commit_digest(
            expected_anchor_id,
            &proposal_hash,
            self.proposal.to_rev,
            &self.imported_state_hash,
        );
        let mut committers = HashSet::new();
        for cs in &self.commit_sigs {
            if cs.committed_at == 0 || !prev_committee.contains(&cs.lock_pub) {
                return Err("commit_sig signer not in previous committee");
            }
            if !committers.insert(cs.lock_pub) {
                return Err("duplicate commit_sig signer");
            }
            if !verify_ed25519_strict(&cs.lock_pub, &commit_digest, &cs.sig) {
                return Err("invalid commit_sig signature");
            }
        }
        if committers.len() < usize::from(prev_committee.threshold) {
            return Err("insufficient commit_sigs for Q_old quorum");
        }

        let mut next_chain = prev_manifest.migration_chain.clone();
        next_chain.push(self.clone());
        let next_manifest = AnchorManifest {
            revision: self.proposal.to_rev,
            threshold: self.proposal.new_threshold,
            servers: self.proposal.new_servers.clone(),
            successors: self.proposal.new_successors.clone(),
            authority: prev_manifest.authority.clone(),
            migration_chain: next_chain,
            issued_at_ms: self.proposal.proposed_at.saturating_mul(1_000),
            retain_until_quarter: prev_manifest.retain_until_quarter,
        };
        Ok((next_manifest, binding.guarantor_protection_reduced))
    }
}

/// Summary produced when verifying an [`AnchorManifest`] from Genesis revision 1 (`verify_anchor_id`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainVerificationReport {
    /// Verified immutable Genesis revision-1 `anchor_id`.
    pub anchor_id: [u8; 32],
    /// `true` if any rotation shrunk a guarantor slot without co-signature / replacement.
    pub guarantor_protection_reduced: bool,
    /// Ordered valid `LockCommittee` snapshots across revisions `1..=manifest.revision`.
    pub historical_committees: Vec<LockCommittee>,
}

/// Verifies a full `AnchorManifest` (revision 1 or multi-revision chain `<= MAX_MIGRATION_CHAIN_LEN`)
/// against `expected_anchor_id` (`Concept` §5.4, §5.6).
pub fn verify_anchor_manifest_chain(
    manifest: &AnchorManifest,
    expected_anchor_id: &[u8; 32],
) -> Result<ChainVerificationReport, &'static str> {
    manifest.validate_local()?;
    if manifest.migration_chain.len() > MAX_MIGRATION_CHAIN_LEN {
        return Err("migration_chain exceeds maximum allowed length");
    }

    if manifest.revision == 1 {
        let rev1 = manifest.rev1_anchor_id()?;
        if rev1 != *expected_anchor_id {
            return Err("revision 1 manifest rev1_anchor_id mismatches expected anchor_id");
        }
        return Ok(ChainVerificationReport {
            anchor_id: rev1,
            guarantor_protection_reduced: false,
            historical_committees: vec![manifest.committee()?],
        });
    }

    let genesis = manifest
        .migration_chain
        .first()
        .and_then(|c| c.genesis_manifest.as_deref())
        .ok_or("multi-revision manifest missing genesis_manifest in migration_chain[0]")?;
    genesis.validate_local()?;
    if genesis.revision != 1 || !genesis.migration_chain.is_empty() {
        return Err("migration_chain[0].genesis_manifest must be revision 1");
    }
    let anchor_id = genesis.rev1_anchor_id()?;
    if anchor_id != *expected_anchor_id {
        return Err("genesis_manifest anchor_id mismatches expected anchor_id");
    }

    let mut historical_committees = Vec::with_capacity(manifest.migration_chain.len() + 1);
    historical_committees.push(genesis.committee()?);

    let mut current = genesis.clone();
    let mut reduced_any = false;
    for cert in &manifest.migration_chain {
        let (next, step_reduced) = cert.verify_step(expected_anchor_id, &current)?;
        reduced_any |= step_reduced;
        historical_committees.push(next.committee()?);
        current = next;
    }

    if current.revision != manifest.revision
        || current.threshold != manifest.threshold
        || current.servers != manifest.servers
        || current.successors != manifest.successors
        || current.authority != manifest.authority
        || current.retain_until_quarter != manifest.retain_until_quarter
    {
        return Err("manifest header fields do not match end of verified migration_chain");
    }

    Ok(ChainVerificationReport {
        anchor_id,
        guarantor_protection_reduced: reduced_any,
        historical_committees,
    })
}

/// Optional replacement server target advertised inside a planned-move [`SyncRevocationNotice`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationReplacementTarget {
    /// New server write endpoint URL (`POST ?lock` / `?lock_*`).
    pub write_url: String,
    /// New server static read endpoint URL (`/locks/...`).
    pub read_url: String,
    /// Hex-encoded server admin public key of the destination host.
    pub drop_pub: String,
}

/// Admin-signed server revocation notice (`HUMOCO-DROP-REVOKE-V1`, `Concept` §5.4 Fall A).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRevocationNotice {
    /// Hex-encoded admin public key of the retiring server (`S.admin_pub`).
    pub drop_pub: String,
    /// Notice creation timestamp in UTC Unix seconds.
    pub issued_at: u64,
    /// Effective timestamp in UTC Unix seconds.
    pub effective_at: u64,
    /// Optional human-readable reason (bounded, newline-free).
    pub reason: Option<String>,
    /// Optional replacement endpoint coordinates for planned migrations.
    pub replacement: Option<RevocationReplacementTarget>,
    /// Hex-encoded Ed25519 signature created by `S.admin_sk`.
    pub signature: String,
}

impl SyncRevocationNotice {
    /// Builds the canonical `HUMOCO-DROP-REVOKE-V1` plaintext signed in `signature`.
    pub fn canonical_message(&self) -> String {
        let (rep_w, rep_r, rep_p) = match &self.replacement {
            Some(r) => (
                r.write_url.as_str(),
                r.read_url.as_str(),
                r.drop_pub.to_ascii_lowercase(),
            ),
            None => ("", "", String::new()),
        };
        format!(
            "HUMOCO-DROP-REVOKE-V1\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.drop_pub.to_ascii_lowercase(),
            self.issued_at,
            self.effective_at,
            rep_w,
            rep_r,
            rep_p,
            self.reason.as_deref().unwrap_or("")
        )
    }

    /// Strictly verifies `signature` against `expected_admin_pub` and checks field invariants.
    pub fn verify(&self, expected_admin_pub: &[u8; 32]) -> Result<(), &'static str> {
        let drop_pub_bytes = decode_hex_fixed::<32>(&self.drop_pub.to_ascii_lowercase())?;
        if drop_pub_bytes != *expected_admin_pub {
            return Err("revocation notice drop_pub mismatches server admin_pub");
        }
        if self.issued_at == 0 || self.effective_at == 0 {
            return Err("revocation timestamps must be positive");
        }
        if let Some(ref reason) = self.reason {
            if reason.len() > 200
                || reason.contains('\n')
                || reason.contains('\r')
                || reason.contains('\0')
            {
                return Err("invalid revocation reason");
            }
        }
        if let Some(ref rep) = self.replacement {
            let rep_pk = decode_hex_fixed::<32>(&rep.drop_pub.to_ascii_lowercase())?;
            if VerifyingKey::from_bytes(&rep_pk).is_err() {
                return Err("invalid replacement drop_pub");
            }
            if (!rep.write_url.starts_with("http://") && !rep.write_url.starts_with("https://"))
                || (!rep.read_url.starts_with("http://") && !rep.read_url.starts_with("https://"))
            {
                return Err("invalid replacement URL scheme");
            }
        }
        let sig_bytes = decode_hex_fixed::<64>(&self.signature.to_ascii_lowercase())?;
        let msg = self.canonical_message();
        if !verify_ed25519_strict(expected_admin_pub, msg.as_bytes(), &sig_bytes) {
            return Err("invalid revocation signature");
        }
        Ok(())
    }
}

/// Checks if `signer_pub` belongs to `authority` as either creator or guarantor migration key.
pub fn is_migration_authority_key(authority: &AnchorAuthority, signer_pub: &[u8; 32]) -> bool {
    *signer_pub == authority.creator_mig_pub || authority.guarantor_mig_pubs.contains(signer_pub)
}

/// Deduplicates and validates canonical server entries by `lock_pub`.
pub fn unique_server_keys(servers: &[ServerEntry]) -> BTreeSet<LockPubKey> {
    servers.iter().map(|s| s.lock_pub).collect()
}

/// Utility helper returning whether any slot inside `ResolvedImportUnion` remained in `Conflict`.
pub fn union_has_unresolved_conflicts(union: &ResolvedImportUnion) -> bool {
    union
        .slots
        .values()
        .any(|s| matches!(s, ResolvedSlot::Conflict(_)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::causal::CausalOutputProof;
    use crate::crypto::{
        compute_root_mig_auth_digest, derive_slot, hash_pubkey_sha3, solve_lock_pow,
        DEFAULT_LOCK_POW_BASE_BITS,
    };
    use crate::retention::encode_quarter;
    use crate::types::{LockReceipt, LockReceiptKind};
    use ed25519_dalek::{Signer, SigningKey};

    fn make_server(seed: u8, role: NominatedBy) -> (ServerEntry, SigningKey, SigningKey) {
        let admin_sk = SigningKey::from_bytes(&[seed; 32]);
        let lock_sk = SigningKey::from_bytes(&[seed.wrapping_add(100); 32]);
        let entry = ServerEntry {
            write_url: format!("https://s{seed}.example/sync.php"),
            read_url: format!("https://s{seed}.example/locks"),
            admin_pub: admin_sk.verifying_key().to_bytes(),
            lock_pub: lock_sk.verifying_key().to_bytes(),
            nominated_by: role,
        };
        (entry, lock_sk, admin_sk)
    }

    fn make_root_entry(
        anchor_id: [u8; 32],
        creator_mig_sk: &SigningKey,
        seed: u8,
        recv_seed: u8,
    ) -> LockEntry {
        let ds_tag = [seed; 32];
        let slot = derive_slot(&anchor_id, &ds_tag);
        let child_lock = [seed.wrapping_add(50); 32];
        let g_sk = SigningKey::from_bytes(&[seed.wrapping_add(10); 32]);
        let g_pub = g_sk.verifying_key().to_bytes();
        let recv_sk = SigningKey::from_bytes(&[recv_seed; 32]);
        let recv_hash = hash_pubkey_sha3(&recv_sk.verifying_key().to_bytes());
        let mut cp = CausalOutputProof {
            anchor_id,
            slot,
            parent_slot: [0; 32],
            output_branch: 0,
            depth: 0,
            child_lock,
            sender_pubkey: g_pub,
            receiver_pubkey_hash: recv_hash,
            change_pubkey_hash: None,
            causal_sig: [0; 64],
        };
        cp.causal_sig = g_sk.sign(&cp.digest().unwrap()).to_bytes();
        let rms = creator_mig_sk
            .sign(&compute_root_mig_auth_digest(&anchor_id, &slot, &g_pub))
            .to_bytes();
        let pow_nonce = solve_lock_pow(
            &slot,
            &child_lock,
            0,
            DEFAULT_LOCK_POW_BASE_BITS,
            0,
            500_000,
        )
        .unwrap();
        LockEntry {
            slot,
            parent_slot: [0; 32],
            output_branch: 0,
            depth: 0,
            child_lock,
            sender_pubkey: g_pub,
            receiver_pubkey_hash: recv_hash,
            change_pubkey_hash: None,
            causal_sig: cp.causal_sig,
            root_mig_sig: Some(rms),
            encrypted_payload: [0x22; crate::HOP_ENCRYPTED_PAYLOAD_LEN],
            pow_nonce,
        }
    }

    fn build_cert(
        anchor_id: [u8; 32],
        prev_manifest: &AnchorManifest,
        old_lock_sks: &[&SigningKey],
        new_lock_sks: &[&SigningKey],
        proposal: MigrationProposal,
        imported_state_hash: [u8; 32],
    ) -> MigrationCert {
        let prop_hash = proposal.core_digest().unwrap();
        let import_acks: Vec<ImportAck> = new_lock_sks
            .iter()
            .map(|sk| {
                let mut ack = ImportAck {
                    anchor_id,
                    proposal_hash: prop_hash,
                    to_rev: proposal.to_rev,
                    imported_state_hash,
                    retain_until_quarter: proposal.retain_until_quarter,
                    lock_pub: sk.verifying_key().to_bytes(),
                    acked_at: proposal.proposed_at + 260_000,
                    sig: [0; 64],
                };
                ack.sig = sk.sign(&ack.digest()).to_bytes();
                ack
            })
            .collect();
        let commit_digest = MigrationCert::commit_digest(
            &anchor_id,
            &prop_hash,
            proposal.to_rev,
            &imported_state_hash,
        );
        let commit_sigs: Vec<CommitteeSignature> = old_lock_sks
            .iter()
            .take(usize::from(prev_manifest.threshold))
            .map(|sk| CommitteeSignature {
                lock_pub: sk.verifying_key().to_bytes(),
                committed_at: proposal.proposed_at + 260_100,
                sig: sk.sign(&commit_digest).to_bytes(),
            })
            .collect();
        MigrationCert {
            anchor_id,
            genesis_manifest: if prev_manifest.revision == 1 {
                Some(Box::new(prev_manifest.clone()))
            } else {
                None
            },
            proposal,
            imported_state_hash,
            import_acks,
            commit_sigs,
        }
    }

    #[test]
    fn test_three_revision_chain_nomination_binding_and_veto() {
        let creator_mig_sk = SigningKey::from_bytes(&[201; 32]);
        let g0_mig_sk = SigningKey::from_bytes(&[202; 32]);
        let (s1, sk1, _) = make_server(1, NominatedBy::Creator);
        let (s2, sk2, _) = make_server(2, NominatedBy::Guarantor(0));
        let (s3, _sk3, _) = make_server(3, NominatedBy::Guarantor(0));
        let (s4, _sk4, _) = make_server(4, NominatedBy::Creator);
        let (s5, sk5, _) = make_server(5, NominatedBy::Guarantor(0));
        let (s6_creator, sk6, _) = make_server(6, NominatedBy::Creator);

        let q = encode_quarter(2035, 4).unwrap();
        let rev1 = AnchorManifest {
            revision: 1,
            threshold: 2,
            servers: vec![s1.clone(), s2.clone(), s3.clone()],
            successors: vec![s4.clone(), s5.clone()],
            authority: AnchorAuthority {
                creator_mig_pub: creator_mig_sk.verifying_key().to_bytes(),
                guarantor_mig_pubs: vec![g0_mig_sk.verifying_key().to_bytes()],
            },
            migration_chain: Vec::new(),
            issued_at_ms: 1_760_000_000_000,
            retain_until_quarter: q,
        };
        let anchor_id = rev1.rev1_anchor_id().unwrap();

        // Malicious Creator attempt to replace Guarantor(0) slot s3 with s6_creator -> REJECTED!
        let mut evil_prop = MigrationProposal {
            anchor_id,
            from_rev: 1,
            to_rev: 2,
            new_threshold: 2,
            new_servers: vec![s1.clone(), s2.clone(), s6_creator.clone()],
            new_successors: vec![s4.clone(), s5.clone()],
            retain_until_quarter: q,
            proposed_at: 1_760_100_000,
            initiator: ProposalInitiator::Creator,
            proposer_sig: None,
            guarantor_cosigs: Vec::new(),
        };
        evil_prop.proposer_sig = Some(
            creator_mig_sk
                .sign(&evil_prop.core_digest().unwrap())
                .to_bytes(),
        );
        assert!(evil_prop
            .verify_against_manifest(&anchor_id, &rev1)
            .is_err());

        // Compromised creator proposal can be vetoed by Guarantor(0), while Creator cannot veto own proposal
        let veto_by_creator = MigrationVeto {
            anchor_id,
            from_rev: 1,
            proposal_hash: evil_prop.core_digest().unwrap(),
            vetoer_pub: rev1.authority.creator_mig_pub,
            vetoed_at: 1_760_100_100,
            sig: [0; 64],
        };
        let mut veto_creator_signed = veto_by_creator;
        veto_creator_signed.sig = creator_mig_sk
            .sign(&veto_creator_signed.digest())
            .to_bytes();
        assert!(veto_creator_signed
            .verify(&rev1.authority, &evil_prop.initiator)
            .is_err());

        let mut veto_by_g0 = MigrationVeto {
            anchor_id,
            from_rev: 1,
            proposal_hash: evil_prop.core_digest().unwrap(),
            vetoer_pub: rev1.authority.guarantor_mig_pubs[0],
            vetoed_at: 1_760_100_200,
            sig: [0; 64],
        };
        veto_by_g0.sig = g0_mig_sk.sign(&veto_by_g0.digest()).to_bytes();
        assert!(veto_by_g0
            .verify(&rev1.authority, &evil_prop.initiator)
            .is_ok());

        // Step 1 -> 2: Any holder promotes Guarantor(0) standby s5 to replace s3
        let prop_rev2 = MigrationProposal {
            anchor_id,
            from_rev: 1,
            to_rev: 2,
            new_threshold: 2,
            new_servers: vec![s1.clone(), s2.clone(), s5.clone()],
            new_successors: vec![s4.clone()],
            retain_until_quarter: q,
            proposed_at: 1_760_200_000,
            initiator: ProposalInitiator::HolderStandby,
            proposer_sig: None,
            guarantor_cosigs: Vec::new(),
        };
        let cert12 = build_cert(
            anchor_id,
            &rev1,
            &[&sk1, &sk2],
            &[&sk1, &sk2, &sk5],
            prop_rev2,
            [0x12; 32],
        );
        let (rev2, reduced12) = cert12.verify_step(&anchor_id, &rev1).unwrap();
        assert!(!reduced12);

        // Step 2 -> 3: Creator drops lost Guarantor(0) slot s5 (no G0 successor remains)
        // Must preserve threshold invariant, forbid Creator expansion, and flag guarantor_protection_reduced
        let mut prop_rev3 = MigrationProposal {
            anchor_id,
            from_rev: 2,
            to_rev: 3,
            new_threshold: 2,
            new_servers: vec![s1.clone(), s2.clone()],
            new_successors: vec![s4.clone()],
            retain_until_quarter: q,
            proposed_at: 1_760_600_000,
            initiator: ProposalInitiator::Creator,
            proposer_sig: None,
            guarantor_cosigs: Vec::new(),
        };
        prop_rev3.proposer_sig = Some(
            creator_mig_sk
                .sign(&prop_rev3.core_digest().unwrap())
                .to_bytes(),
        );
        let cert23 = build_cert(
            anchor_id,
            &rev2,
            &[&sk1, &sk5],
            &[&sk1, &sk2],
            prop_rev3,
            [0x23; 32],
        );
        let (rev3, reduced23) = cert23.verify_step(&anchor_id, &rev2).unwrap();
        assert!(reduced23);

        // Step 3 -> 4: Creator swaps own server s1 -> s6_creator (G0 slot s2 intact!)
        let mut prop_rev4 = MigrationProposal {
            anchor_id,
            from_rev: 3,
            to_rev: 4,
            new_threshold: 2,
            new_servers: vec![s6_creator, s2.clone()],
            new_successors: vec![s4],
            retain_until_quarter: q,
            proposed_at: 1_761_000_000,
            initiator: ProposalInitiator::Creator,
            proposer_sig: None,
            guarantor_cosigs: Vec::new(),
        };
        prop_rev4.proposer_sig = Some(
            creator_mig_sk
                .sign(&prop_rev4.core_digest().unwrap())
                .to_bytes(),
        );
        let cert34 = build_cert(
            anchor_id,
            &rev3,
            &[&sk1, &sk2],
            &[&sk6, &sk2],
            prop_rev4,
            [0x34; 32],
        );
        let (rev4, _) = cert34.verify_step(&anchor_id, &rev3).unwrap();

        let report = rev4.verify_anchor_id(&anchor_id).unwrap();
        assert_eq!(report.anchor_id, anchor_id);
        assert!(report.guarantor_protection_reduced);
        assert_eq!(report.historical_committees.len(), 4);
        assert!(rev4.effective_anchor_id().unwrap() == anchor_id);
    }

    #[test]
    fn test_resolve_import_union_qc_winner_and_conflict_preservation() {
        let creator_mig_sk = SigningKey::from_bytes(&[201; 32]);
        let (s1, sk1, _) = make_server(1, NominatedBy::Creator);
        let (s2, sk2, _) = make_server(2, NominatedBy::Creator);
        let (s3, sk3, _) = make_server(3, NominatedBy::Creator);
        let (s4, _, _) = make_server(4, NominatedBy::Creator);

        let q = encode_quarter(2035, 4).unwrap();
        let rev1 = AnchorManifest {
            revision: 1,
            threshold: 2,
            servers: vec![s1, s2, s3.clone()],
            successors: vec![s4.clone()],
            authority: AnchorAuthority {
                creator_mig_pub: creator_mig_sk.verifying_key().to_bytes(),
                guarantor_mig_pubs: Vec::new(),
            },
            migration_chain: Vec::new(),
            issued_at_ms: 1_760_000_000_000,
            retain_until_quarter: q,
        };
        let anchor_id = rev1.rev1_anchor_id().unwrap();

        let prop = MigrationProposal {
            anchor_id,
            from_rev: 1,
            to_rev: 2,
            new_threshold: 2,
            new_servers: vec![rev1.servers[0].clone(), rev1.servers[1].clone(), s4],
            new_successors: Vec::new(),
            retain_until_quarter: q,
            proposed_at: 1_760_100_000,
            initiator: ProposalInitiator::HolderStandby,
            proposer_sig: None,
            guarantor_cosigs: Vec::new(),
        };
        let prop_hash = prop.core_digest().unwrap();

        // Slot 1 has a QC on e1_win (s1 & s2 hold e1_win, s3 holds conflicting e1_lose)
        let e1_win = make_root_entry(anchor_id, &creator_mig_sk, 1, 11);
        let e1_lose = make_root_entry(anchor_id, &creator_mig_sk, 1, 12);
        // Slot 2 has NO QC (s1 holds e2_a, s2 holds e2_b) -> must remain Conflict([e2_a, e2_b])!
        let e2_a = make_root_entry(anchor_id, &creator_mig_sk, 2, 21);
        let e2_b = make_root_entry(anchor_id, &creator_mig_sk, 2, 22);

        let make_snap = |sk: &SigningKey, entries: Vec<LockEntry>| {
            let state_hash = compute_freeze_state_hash(&anchor_id, 1, &entries, &[]).unwrap();
            let mut snap = FreezeSnapshot {
                anchor_id,
                bucket: derive_bucket(&anchor_id, &sk.verifying_key().to_bytes()),
                from_rev: 1,
                retain_until_quarter: q,
                write_seq: entries.len() as u64,
                bucket_head: [0x55; 32],
                state_hash,
                permanent: true,
                proposal_hash: Some(prop_hash),
                frozen_at: 1_760_100_010,
                expires_at: None,
                lock_pub: sk.verifying_key().to_bytes(),
                sig: [0; 64],
            };
            snap.sig = sk.sign(&snap.digest()).to_bytes();
            SnapshotExport {
                snapshot: snap,
                entries: entries
                    .into_iter()
                    .map(|e| e.to_wire_hex().unwrap())
                    .collect(),
                conflicts: Vec::new(),
            }
        };

        let exp1 = make_snap(&sk1, vec![e1_win.clone(), e2_a.clone()]);
        let exp2 = make_snap(&sk2, vec![e1_win.clone(), e2_b.clone()]);
        let exp3 = make_snap(&sk3, vec![e1_lose]);

        // Build QC on e1_win from s1 + s2
        let e1_eh = e1_win.entry_hash().unwrap();
        let qc_receipts = [&sk1, &sk2]
            .iter()
            .map(|sk| {
                let lp = sk.verifying_key().to_bytes();
                let mut r = LockReceipt {
                    kind: LockReceiptKind::FirstWrite,
                    lock_pub: lp,
                    bucket: derive_bucket(&anchor_id, &lp),
                    slot: e1_win.slot,
                    child_lock: e1_win.child_lock,
                    entry_hash: e1_eh,
                    retain_until_quarter: q,
                    write_seq: 1,
                    bucket_head: [0x66; 32],
                    recipient_nonce: [0x77; 32],
                    sig: [0; 64],
                };
                r.sig = sk.sign(&r.digest()).to_bytes();
                r
            })
            .collect();
        let qc1 = QuorumCertificate {
            slot: e1_win.slot,
            child_lock: e1_win.child_lock,
            receipts: qc_receipts,
        };

        let resolved = resolve_import_union(
            &anchor_id,
            &rev1,
            &prop,
            &[exp1, exp2, exp3],
            &[qc1],
            DEFAULT_LOCK_POW_BASE_BITS,
        )
        .unwrap();
        assert_eq!(
            resolved.slots.get(&e1_win.slot),
            Some(&ResolvedSlot::Single(Box::new(e1_win)))
        );
        assert!(matches!(
            resolved.slots.get(&e2_a.slot),
            Some(ResolvedSlot::Conflict(v)) if v.len() == 2
        ));
        assert!(union_has_unresolved_conflicts(&resolved));
    }

    #[test]
    fn test_sync_revocation_notice_verification() {
        let admin_sk = SigningKey::from_bytes(&[77; 32]);
        let admin_pub = admin_sk.verifying_key().to_bytes();
        let new_admin_sk = SigningKey::from_bytes(&[88; 32]);
        let mut notice = SyncRevocationNotice {
            drop_pub: hex::encode(admin_pub),
            issued_at: 1_760_000_000,
            effective_at: 1_760_000_000,
            reason: Some("Planned host migration".into()),
            replacement: Some(RevocationReplacementTarget {
                write_url: "https://new.example/sync.php".into(),
                read_url: "https://new.example/locks".into(),
                drop_pub: hex::encode(new_admin_sk.verifying_key().to_bytes()),
            }),
            signature: String::new(),
        };
        notice.signature = hex::encode(
            admin_sk
                .sign(notice.canonical_message().as_bytes())
                .to_bytes(),
        );
        assert!(notice.verify(&admin_pub).is_ok());

        let mut tampered = notice.clone();
        tampered.effective_at += 1;
        assert!(tampered.verify(&admin_pub).is_err());
    }
}
