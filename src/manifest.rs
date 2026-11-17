//! Anchor manifest, server committee entries, and offline genesis tickets (`SPEC.md` §6.3, §6.5).

use crate::crypto::{
    verify_ed25519_strict, ANCHOR_MANIFEST_DOMAIN, GENESIS_TICKET_DOMAIN, MAX_MIGRATION_CHAIN_LEN,
};
use crate::retention::decode_quarter;
use crate::rotation::{verify_anchor_manifest_chain, ChainVerificationReport, MigrationCert};
use crate::types::{serde_hex_32, serde_hex_64, serde_hex_vec_32, LockCommittee, LockPubKey};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum UTF-8 byte length permitted for a server URL in `ServerEntry`.
pub const MAX_SERVER_URL_LEN: usize = 2048;

/// Maximum number of guarantors supported per voucher anchor manifest.
pub const MAX_GUARANTORS: usize = 32;

/// Role responsible for nominating a committee or successor server (`SPEC.md` §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NominatedBy {
    /// Server slot nominated by the voucher creator.
    Creator,
    /// Server slot nominated by guarantor `index` in `AnchorAuthority::guarantor_mig_pubs`.
    Guarantor(u8),
}

impl NominatedBy {
    /// Encodes `NominatedBy` into its canonical binary byte representation (`0x00` or `0x01 || idx`).
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        match *self {
            Self::Creator => out.push(0x00),
            Self::Guarantor(idx) => {
                out.push(0x01);
                out.push(idx);
            }
        }
    }
}

/// Public identity and endpoint coordinates of a single Sync Lock server (`SPEC.md` §6.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEntry {
    /// Authenticated write endpoint base URL (e.g., `https://host/sync.php`).
    pub write_url: String,
    /// Unauthenticated public read endpoint base URL for lock files.
    pub read_url: String,
    /// Server administrative Ed25519 public key (reported in `?info`).
    #[serde(with = "serde_hex_32")]
    pub admin_pub: [u8; 32],
    /// Dedicated per-server Lock Channel Ed25519 public key (`S.lock_pub`).
    #[serde(with = "serde_hex_32")]
    pub lock_pub: LockPubKey,
    /// Authority role that nominated this slot.
    pub nominated_by: NominatedBy,
}

impl ServerEntry {
    /// Validates URL sizes, key encodings, and guarantor index bounds.
    pub fn validate(&self, guarantor_count: usize) -> Result<(), &'static str> {
        if self.write_url.is_empty()
            || self.write_url.len() > MAX_SERVER_URL_LEN
            || self.read_url.is_empty()
            || self.read_url.len() > MAX_SERVER_URL_LEN
        {
            return Err("server URL empty or exceeds length limit");
        }
        if VerifyingKey::from_bytes(&self.admin_pub).is_err() {
            return Err("invalid server admin_pub Ed25519 key");
        }
        if VerifyingKey::from_bytes(&self.lock_pub).is_err() {
            return Err("invalid server lock_pub Ed25519 key");
        }
        if let NominatedBy::Guarantor(idx) = self.nominated_by {
            if usize::from(idx) >= guarantor_count {
                return Err("guarantor nomination index out of range");
            }
        }
        Ok(())
    }

    /// Appends the canonical byte encoding used inside `HUMOCO_ANCHOR_MANIFEST_V1` (`SPEC.md` §6.3).
    pub fn write_canonical(&self, out: &mut Vec<u8>) -> Result<(), &'static str> {
        let write_len = u16::try_from(self.write_url.len()).map_err(|_| "write_url too long")?;
        let read_len = u16::try_from(self.read_url.len()).map_err(|_| "read_url too long")?;
        out.extend_from_slice(&write_len.to_le_bytes());
        out.extend_from_slice(self.write_url.as_bytes());
        out.extend_from_slice(&read_len.to_le_bytes());
        out.extend_from_slice(self.read_url.as_bytes());
        out.extend_from_slice(&self.admin_pub);
        out.extend_from_slice(&self.lock_pub);
        self.nominated_by.write_canonical(out);
        Ok(())
    }
}

/// Unlinkable per-anchor migration public keys for the creator and optional guarantors (`SPEC.md` §6.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorAuthority {
    /// Creator unlinkable migration key (`creator_mig_pub`).
    #[serde(with = "serde_hex_32")]
    pub creator_mig_pub: [u8; 32],
    /// Per-guarantor unlinkable migration keys, indexed identically to `NominatedBy::Guarantor(idx)`.
    #[serde(with = "serde_hex_vec_32")]
    pub guarantor_mig_pubs: Vec<[u8; 32]>,
}

impl AnchorAuthority {
    /// Validates Ed25519 public key encodings and guarantor count limits.
    pub fn validate(&self) -> Result<(), &'static str> {
        if VerifyingKey::from_bytes(&self.creator_mig_pub).is_err() {
            return Err("invalid creator_mig_pub Ed25519 key");
        }
        if self.guarantor_mig_pubs.len() > MAX_GUARANTORS {
            return Err("too many guarantors");
        }
        for (i, g) in self.guarantor_mig_pubs.iter().enumerate() {
            if VerifyingKey::from_bytes(g).is_err() {
                return Err("invalid guarantor_mig_pub Ed25519 key");
            }
            if *g == self.creator_mig_pub || self.guarantor_mig_pubs[..i].contains(g) {
                return Err("duplicate migration authority key");
            }
        }
        Ok(())
    }
}

/// Voucher-pinned Sync Lock committee manifest (`SPEC.md` §6.3, Concept §4.1–4.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorManifest {
    /// Manifest revision (`1` at Genesis; incremented monotonically on rotation).
    pub revision: u64,
    /// Quorum threshold `Q` (`1 <= Q <= N`, `2 * Q > N`).
    pub threshold: u8,
    /// Active Sync Lock committee servers (`1 <= N <= 5`).
    pub servers: Vec<ServerEntry>,
    /// Pre-declared standby successor servers ordered per nominator.
    pub successors: Vec<ServerEntry>,
    /// Creator and guarantor migration authorization public keys.
    pub authority: AnchorAuthority,
    /// Ordered migration certificates linking Genesis Revision 1 to `revision` (empty when `revision == 1`).
    pub migration_chain: Vec<MigrationCert>,
    /// Manifest creation timestamp in UTC Unix milliseconds.
    pub issued_at_ms: u64,
    /// Immutable bucket lock retention quarter (`YYYY-QN` encoded as `year * 4 + (q - 1)`).
    pub retain_until_quarter: u16,
}

impl AnchorManifest {
    /// Validates structural fields, committee bounds, authority keys, URLs, and chain length
    /// without recursing into embedded `migration_chain` certificates.
    pub fn validate_local(&self) -> Result<(), &'static str> {
        if self.revision == 0 {
            return Err("manifest revision must be >= 1");
        }
        if self.migration_chain.len() > MAX_MIGRATION_CHAIN_LEN {
            return Err("migration_chain exceeds maximum length");
        }
        if self.revision == 1 && !self.migration_chain.is_empty() {
            return Err("revision 1 manifest must have empty migration_chain");
        }
        if self.revision > 1 && self.migration_chain.len() != (self.revision - 1) as usize {
            return Err("migration_chain length does not match revision");
        }
        if self.issued_at_ms == 0 {
            return Err("manifest issued_at_ms must be positive");
        }
        decode_quarter(self.retain_until_quarter)?;
        self.authority.validate()?;

        let committee = self.committee()?;
        committee.validate()?;

        let guarantor_count = self.authority.guarantor_mig_pubs.len();
        for server in &self.servers {
            server.validate(guarantor_count)?;
        }
        for (i, succ) in self.successors.iter().enumerate() {
            succ.validate(guarantor_count)?;
            if committee.contains(&succ.lock_pub) {
                return Err("successor lock_pub already active in committee");
            }
            if self.successors[..i]
                .iter()
                .any(|prev| prev.lock_pub == succ.lock_pub)
            {
                return Err("duplicate successor lock_pub");
            }
        }
        Ok(())
    }

    /// Validates all committee, authority, retention, and full cryptographic `migration_chain` invariants.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.verify_chain_report().map(|_| ())
    }

    /// Verifies the manifest structurally and cryptographically from Genesis Rev 1, returning the
    /// full [`ChainVerificationReport`].
    pub fn verify_chain_report(&self) -> Result<ChainVerificationReport, &'static str> {
        self.validate_local()?;
        if self.revision == 1 {
            let anchor_id = self.rev1_anchor_id()?;
            return Ok(ChainVerificationReport {
                anchor_id,
                guarantor_protection_reduced: false,
                historical_committees: vec![self.committee()?],
            });
        }
        let genesis = self
            .migration_chain
            .first()
            .and_then(|cert| cert.genesis_manifest.as_deref())
            .ok_or("multi-revision manifest missing genesis_manifest in migration_chain[0]")?;
        genesis.validate_local()?;
        if genesis.revision != 1 {
            return Err("embedded genesis_manifest must be revision 1");
        }
        let expected_anchor = genesis.rev1_anchor_id()?;
        verify_anchor_manifest_chain(self, &expected_anchor)
    }

    /// Extracts and verifies the immutable Genesis revision-1 `anchor_id` for both
    /// `revision == 1` manifests and multi-revision rotated manifests.
    pub fn effective_anchor_id(&self) -> Result<[u8; 32], &'static str> {
        self.verify_chain_report().map(|r| r.anchor_id)
    }

    /// Verifies that this manifest cryptographically links back to `expected_anchor_id` at Genesis Rev 1.
    pub fn verify_anchor_id(
        &self,
        expected_anchor_id: &[u8; 32],
    ) -> Result<ChainVerificationReport, &'static str> {
        verify_anchor_manifest_chain(self, expected_anchor_id)
    }

    /// Returns all cryptographically verified `LockCommittee` snapshots across `Rev 1..=self.revision`.
    pub fn verified_committees(&self) -> Result<Vec<LockCommittee>, &'static str> {
        self.verify_chain_report().map(|r| r.historical_committees)
    }

    /// Returns `true` if any migration along the verified chain reduced guarantor protection.
    pub fn has_reduced_guarantor_protection(&self) -> Result<bool, &'static str> {
        self.verify_chain_report()
            .map(|r| r.guarantor_protection_reduced)
    }

    /// Extracts the `LockCommittee` view (`members`, `threshold`) from `self.servers`.
    pub fn committee(&self) -> Result<LockCommittee, &'static str> {
        let committee = LockCommittee {
            members: self.servers.iter().map(|s| s.lock_pub).collect(),
            threshold: self.threshold,
        };
        committee.validate()?;
        Ok(committee)
    }

    /// Computes the canonical 32-byte `anchor_id` (`HUMOCO_ANCHOR_MANIFEST_V1`) matching
    /// Layer 1 `voucher.layer2_anchor` (`SPEC.md` §6.3).
    pub fn rev1_anchor_id(&self) -> Result<[u8; 32], &'static str> {
        if self.revision != 1 {
            return Err("rev1_anchor_id must be computed on revision 1 manifest");
        }
        self.validate_local()?;

        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(ANCHOR_MANIFEST_DOMAIN);
        buf.extend_from_slice(&1u64.to_le_bytes());
        buf.push(self.threshold);
        let server_count = u8::try_from(self.servers.len()).map_err(|_| "server count overflow")?;
        buf.push(server_count);
        for server in &self.servers {
            server.write_canonical(&mut buf)?;
        }
        let succ_count =
            u16::try_from(self.successors.len()).map_err(|_| "successor count overflow")?;
        buf.extend_from_slice(&succ_count.to_le_bytes());
        for succ in &self.successors {
            succ.write_canonical(&mut buf)?;
        }
        buf.extend_from_slice(&self.authority.creator_mig_pub);
        let g_count = u8::try_from(self.authority.guarantor_mig_pubs.len())
            .map_err(|_| "guarantor count overflow")?;
        buf.push(g_count);
        for g in &self.authority.guarantor_mig_pubs {
            buf.extend_from_slice(g);
        }
        buf.extend_from_slice(&self.issued_at_ms.to_le_bytes());
        buf.extend_from_slice(&self.retain_until_quarter.to_le_bytes());

        Ok(Sha256::digest(&buf).into())
    }
}

/// Server-signed offline genesis ticket authorizing initial bucket creation for an anchor set (`SPEC.md` §6.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisTicket {
    /// Canonical 32-byte `anchor_id` authorized by this ticket.
    #[serde(with = "serde_hex_32")]
    pub anchor_id: [u8; 32],
    /// Immutable bucket retention quarter authorized by the server.
    pub retain_until_quarter: u16,
    /// Server issuance timestamp in UTC Unix seconds.
    pub issued_at: u64,
    /// Issuing server's Lock Channel public key (`S.lock_pub`).
    #[serde(with = "serde_hex_32")]
    pub lock_pub: LockPubKey,
    /// Server Ed25519 signature (`S.lock_sk`) over `GenesisTicket::digest()`.
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl GenesisTicket {
    /// Computes the canonical `HUMOCO_GENESIS_TICKET_V1` digest signed in `sig` (`SPEC.md` §6.3).
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(GENESIS_TICKET_DOMAIN);
        hasher.update(self.anchor_id);
        hasher.update(self.retain_until_quarter.to_le_bytes());
        hasher.update(self.issued_at.to_le_bytes());
        hasher.update(self.lock_pub);
        hasher.finalize().into()
    }

    /// Strictly verifies the server signature and retention quarter validity.
    pub fn verify(&self) -> bool {
        if self.issued_at == 0 || decode_quarter(self.retain_until_quarter).is_err() {
            return false;
        }
        let digest = self.digest();
        verify_ed25519_strict(&self.lock_pub, &digest, &self.sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention::encode_quarter;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_server(seed: u8, role: NominatedBy) -> ServerEntry {
        let admin = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let lock = SigningKey::from_bytes(&[seed.wrapping_add(100); 32])
            .verifying_key()
            .to_bytes();
        ServerEntry {
            write_url: format!("https://s{seed}.example/sync.php"),
            read_url: format!("https://s{seed}.example/locks"),
            admin_pub: admin,
            lock_pub: lock,
            nominated_by: role,
        }
    }

    fn sample_manifest() -> AnchorManifest {
        let creator_mig_pub = SigningKey::from_bytes(&[201; 32])
            .verifying_key()
            .to_bytes();
        let g0_mig_pub = SigningKey::from_bytes(&[202; 32])
            .verifying_key()
            .to_bytes();
        AnchorManifest {
            revision: 1,
            threshold: 2,
            servers: vec![
                sample_server(1, NominatedBy::Creator),
                sample_server(2, NominatedBy::Guarantor(0)),
                sample_server(3, NominatedBy::Guarantor(0)),
            ],
            successors: vec![sample_server(4, NominatedBy::Guarantor(0))],
            authority: AnchorAuthority {
                creator_mig_pub,
                guarantor_mig_pubs: vec![g0_mig_pub],
            },
            migration_chain: Vec::new(),
            issued_at_ms: 1_794_916_800_000,
            retain_until_quarter: encode_quarter(2031, 2).unwrap(),
        }
    }

    #[test]
    fn test_manifest_anchor_id_is_deterministic_and_sensitive() {
        let m1 = sample_manifest();
        let id1 = m1.rev1_anchor_id().unwrap();
        assert_eq!(id1, m1.rev1_anchor_id().unwrap());

        let mut m2 = m1.clone();
        m2.retain_until_quarter += 1;
        assert_ne!(id1, m2.rev1_anchor_id().unwrap());

        let mut m3 = m1.clone();
        m3.servers[1].nominated_by = NominatedBy::Creator;
        assert_ne!(id1, m3.rev1_anchor_id().unwrap());

        // Invalid threshold / guarantor bounds rejected
        let mut bad_q = m1.clone();
        bad_q.threshold = 1; // 2*1 <= 3
        assert!(bad_q.validate().is_err());

        let mut bad_g = m1.clone();
        bad_g.servers[1].nominated_by = NominatedBy::Guarantor(1);
        assert!(bad_g.validate().is_err());

        // JSON roundtrip preserves exact anchor_id
        let json = serde_json::to_string(&m1).unwrap();
        let decoded: AnchorManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.rev1_anchor_id().unwrap(), id1);
    }

    #[test]
    fn test_genesis_ticket_sign_and_verify() {
        let lock_sk = SigningKey::from_bytes(&[77; 32]);
        let lock_pub = lock_sk.verifying_key().to_bytes();
        let mut ticket = GenesisTicket {
            anchor_id: [0x42; 32],
            retain_until_quarter: encode_quarter(2031, 2).unwrap(),
            issued_at: 1_794_916_800,
            lock_pub,
            sig: [0; 64],
        };
        ticket.sig = lock_sk.sign(&ticket.digest()).to_bytes();
        assert!(ticket.verify());

        let mut forged = ticket.clone();
        forged.retain_until_quarter += 1;
        assert!(!forged.verify());

        let json = serde_json::to_string(&ticket).unwrap();
        let decoded: GenesisTicket = serde_json::from_str(&json).unwrap();
        assert!(decoded.verify());
    }
}
