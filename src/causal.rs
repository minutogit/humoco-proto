//! Per-hop causal output proofs and canonical 605-byte `LockEntry` wire layout (`SPEC.md` §6.3–6.4).

use crate::crypto::{
    hash_pubkey_sha3, required_lock_pow_bits, verify_ed25519_strict, verify_lock_pow,
    verify_root_mig_auth, CAUSAL_OUTPUT_DOMAIN, LOCK_ENTRY_DOMAIN,
};
use crate::types::{
    decode_hex_fixed, serde_hex_32, serde_hex_64, serde_hex_opt_32, serde_hex_opt_64,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 4-byte ASCII wire magic header for serialized `LockEntry` records (`SPEC.md` §6.4).
pub const LOCK_ENTRY_MAGIC: [u8; 4] = *b"HMLK";

/// Current canonical `LockEntry` binary format version (`SPEC.md` §6.4).
pub const LOCK_ENTRY_VERSION: u8 = 1;

/// Fixed plaintext byte size of the per-hop AEAD payload before encryption (`SPEC.md` §6.4).
pub const HOP_PLAINTEXT_LEN: usize = 225;

/// Fixed encrypted payload byte size (`24B nonce || 225B ciphertext || 16B Poly1305 tag`).
pub const HOP_ENCRYPTED_PAYLOAD_LEN: usize = 265;

/// Byte length of the `LockEntry` identity prefix excluding the trailing 8-byte `pow_nonce`.
pub const LOCK_ENTRY_IDENTITY_LEN: usize = 597;

/// Total fixed wire length of a canonical `LockEntry` record in bytes.
pub const LOCK_ENTRY_WIRE_LEN: usize = 605;

mod serde_hex_265 {
    use super::{decode_hex_fixed, HOP_ENCRYPTED_PAYLOAD_LEN};
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        bytes: &[u8; HOP_ENCRYPTED_PAYLOAD_LEN],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; HOP_ENCRYPTED_PAYLOAD_LEN], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            decode_hex_fixed::<HOP_ENCRYPTED_PAYLOAD_LEN>(&s).map_err(D::Error::custom)
        } else {
            struct Bytes265Visitor;
            impl<'de> serde::de::Visitor<'de> for Bytes265Visitor {
                type Value = [u8; HOP_ENCRYPTED_PAYLOAD_LEN];

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("265 bytes")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: Error,
                {
                    if v.len() == HOP_ENCRYPTED_PAYLOAD_LEN {
                        let mut out = [0u8; HOP_ENCRYPTED_PAYLOAD_LEN];
                        out.copy_from_slice(v);
                        Ok(out)
                    } else {
                        Err(E::custom(format!("expected 265 bytes, got {}", v.len())))
                    }
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let mut out = [0u8; HOP_ENCRYPTED_PAYLOAD_LEN];
                    for slot in &mut out {
                        *slot = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("expected 265 bytes"))?;
                    }
                    Ok(out)
                }
            }
            deserializer.deserialize_bytes(Bytes265Visitor)
        }
    }
}

/// Author-signed causal commitment binding an L1 transaction hop to its parent output
/// and next ephemeral owner hashes (`SPEC.md` §6.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalOutputProof {
    /// Voucher-pinned committee anchor identifier (`anchor_id`).
    #[serde(with = "serde_hex_32")]
    pub anchor_id: [u8; 32],
    /// Canonical set-wide slot identifier for this hop.
    #[serde(with = "serde_hex_32")]
    pub slot: [u8; 32],
    /// Parent slot identifier (`[0u8; 32]` iff `depth == 0`).
    #[serde(with = "serde_hex_32")]
    pub parent_slot: [u8; 32],
    /// Spent parent output branch (`0` = receiver output, `1` = split change output).
    pub output_branch: u8,
    /// Hop depth (`0` for L1 `init`, `parent.depth + 1` for spends).
    pub depth: u32,
    /// Child lock (`tx.t_id`) committed at `slot`.
    #[serde(with = "serde_hex_32")]
    pub child_lock: [u8; 32],
    /// Ephemeral sender Ed25519 public key (`tx.sender_ephemeral_pub`).
    #[serde(with = "serde_hex_32")]
    pub sender_pubkey: [u8; 32],
    /// `SHA3-256` hash of the receiver's ephemeral public key.
    #[serde(with = "serde_hex_32")]
    pub receiver_pubkey_hash: [u8; 32],
    /// Optional `SHA3-256` hash of the split change ephemeral public key.
    #[serde(with = "serde_hex_opt_32")]
    pub change_pubkey_hash: Option<[u8; 32]>,
    /// Ed25519 signature by `sender_pubkey` over `CausalOutputProof::digest()`.
    #[serde(with = "serde_hex_64")]
    pub causal_sig: [u8; 64],
}

impl CausalOutputProof {
    /// Validates structural bounds and computes the canonical 253-byte SHA-256 digest (`SPEC.md` §6.3).
    pub fn digest(&self) -> Result<[u8; 32], &'static str> {
        if self.output_branch > 1 {
            return Err("output_branch must be 0 or 1");
        }
        if self.depth == 0 {
            if self.parent_slot != [0u8; 32] || self.output_branch != 0 {
                return Err("depth 0 root must use zero parent_slot and output_branch 0");
            }
        } else if self.parent_slot == [0u8; 32] {
            return Err("non-root entry must reference a non-zero parent_slot");
        }

        let mut buf = [0u8; 253];
        buf[0..23].copy_from_slice(CAUSAL_OUTPUT_DOMAIN);
        buf[23..55].copy_from_slice(&self.anchor_id);
        buf[55..87].copy_from_slice(&self.slot);
        buf[87..119].copy_from_slice(&self.parent_slot);
        buf[119] = self.output_branch;
        buf[120..124].copy_from_slice(&self.depth.to_le_bytes());
        buf[124..156].copy_from_slice(&self.child_lock);
        buf[156..188].copy_from_slice(&self.sender_pubkey);
        buf[188..220].copy_from_slice(&self.receiver_pubkey_hash);
        match self.change_pubkey_hash {
            Some(change) => {
                buf[220] = 1;
                buf[221..253].copy_from_slice(&change);
            }
            None => {
                buf[220] = 0;
            }
        }
        Ok(Sha256::digest(buf).into())
    }

    /// Strictly verifies `self.causal_sig` against `self.sender_pubkey`.
    pub fn verify(&self) -> bool {
        let Ok(digest) = self.digest() else {
            return false;
        };
        verify_ed25519_strict(&self.sender_pubkey, &digest, &self.causal_sig)
    }
}

/// Canonical 605-byte Sync Lock entry stored on disk and transmitted in `POST ?lock` batches (`SPEC.md` §6.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockEntry {
    /// Canonical set-wide slot identifier.
    #[serde(with = "serde_hex_32")]
    pub slot: [u8; 32],
    /// Parent slot identifier (`[0u8; 32]` iff `depth == 0`).
    #[serde(with = "serde_hex_32")]
    pub parent_slot: [u8; 32],
    /// Output branch claimed on parent (`0` = receiver, `1` = change; `0` at `depth == 0`).
    pub output_branch: u8,
    /// Hop depth (`0` for L1 `init`, `parent.depth + 1` for spends).
    pub depth: u32,
    /// Child lock (`tx.t_id`).
    #[serde(with = "serde_hex_32")]
    pub child_lock: [u8; 32],
    /// Sender ephemeral Ed25519 public key (`tx.sender_ephemeral_pub`).
    #[serde(with = "serde_hex_32")]
    pub sender_pubkey: [u8; 32],
    /// `SHA3-256` hash of next receiver ephemeral public key.
    #[serde(with = "serde_hex_32")]
    pub receiver_pubkey_hash: [u8; 32],
    /// Optional `SHA3-256` hash of split change ephemeral public key.
    #[serde(with = "serde_hex_opt_32")]
    pub change_pubkey_hash: Option<[u8; 32]>,
    /// Ed25519 signature by `sender_pubkey` over `CausalOutputProof`.
    #[serde(with = "serde_hex_64")]
    pub causal_sig: [u8; 64],
    /// Optional offline creator migration signature (`Some` iff `depth == 0`, over `HUMOCO_ROOT_MIG_AUTH_V1`).
    #[serde(with = "serde_hex_opt_64")]
    pub root_mig_sig: Option<[u8; 64]>,
    /// Fixed 265-byte per-hop AEAD blob (`24B nonce || ciphertext || Poly1305 tag`).
    #[serde(with = "serde_hex_265")]
    pub encrypted_payload: [u8; HOP_ENCRYPTED_PAYLOAD_LEN],
    /// Proof-of-work nonce satisfying `HUMOCO_LOCK_POW_V1`.
    pub pow_nonce: u64,
}

impl LockEntry {
    /// Encodes the 597-byte canonical identity prefix (`wire_bytes[0..597]`) excluding `pow_nonce`.
    pub fn identity_bytes(&self) -> Result<[u8; LOCK_ENTRY_IDENTITY_LEN], &'static str> {
        if self.output_branch > 1 {
            return Err("invalid output_branch");
        }
        if self.depth == 0 && (self.parent_slot != [0u8; 32] || self.output_branch != 0) {
            return Err("invalid root entry header");
        }
        if self.depth > 0 && self.parent_slot == [0u8; 32] {
            return Err("non-root entry requires non-zero parent_slot");
        }
        if self.depth == 0 && self.root_mig_sig.is_none() {
            return Err("depth 0 entry requires root_mig_sig");
        }
        if self.depth > 0 && self.root_mig_sig.is_some() {
            return Err("non-root entry must not carry root_mig_sig");
        }

        let mut buf = [0u8; LOCK_ENTRY_IDENTITY_LEN];
        buf[0..4].copy_from_slice(&LOCK_ENTRY_MAGIC);
        buf[4] = LOCK_ENTRY_VERSION;
        buf[5..37].copy_from_slice(&self.slot);
        buf[37..69].copy_from_slice(&self.parent_slot);
        buf[69] = self.output_branch;
        buf[70..74].copy_from_slice(&self.depth.to_le_bytes());
        buf[74..106].copy_from_slice(&self.child_lock);
        buf[106..138].copy_from_slice(&self.sender_pubkey);
        buf[138..170].copy_from_slice(&self.receiver_pubkey_hash);
        if let Some(ch) = self.change_pubkey_hash {
            buf[170] = 1;
            buf[171..203].copy_from_slice(&ch);
        } else {
            buf[170] = 0;
        }
        buf[203..267].copy_from_slice(&self.causal_sig);
        if let Some(root_sig) = self.root_mig_sig {
            buf[267] = 1;
            buf[268..332].copy_from_slice(&root_sig);
        } else {
            buf[267] = 0;
        }
        buf[332..597].copy_from_slice(&self.encrypted_payload);
        Ok(buf)
    }

    /// Serializes this entry into the fixed canonical 605-byte binary wire format (`SPEC.md` §6.4).
    pub fn to_wire_bytes(&self) -> Result<[u8; LOCK_ENTRY_WIRE_LEN], &'static str> {
        let identity = self.identity_bytes()?;
        let mut out = [0u8; LOCK_ENTRY_WIRE_LEN];
        out[..LOCK_ENTRY_IDENTITY_LEN].copy_from_slice(&identity);
        out[LOCK_ENTRY_IDENTITY_LEN..LOCK_ENTRY_WIRE_LEN]
            .copy_from_slice(&self.pow_nonce.to_le_bytes());
        Ok(out)
    }

    /// Strictly parses a 605-byte binary `LockEntry` and rejects non-canonical flags/padding.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != LOCK_ENTRY_WIRE_LEN {
            return Err("LockEntry wire length must be 605 bytes");
        }
        if bytes[0..4] != LOCK_ENTRY_MAGIC {
            return Err("invalid LockEntry magic");
        }
        if bytes[4] != LOCK_ENTRY_VERSION {
            return Err("unsupported LockEntry version");
        }
        let mut slot = [0u8; 32];
        slot.copy_from_slice(&bytes[5..37]);
        let mut parent_slot = [0u8; 32];
        parent_slot.copy_from_slice(&bytes[37..69]);
        let output_branch = bytes[69];
        if output_branch > 1 {
            return Err("invalid output_branch");
        }
        let depth = u32::from_le_bytes(bytes[70..74].try_into().map_err(|_| "depth slice")?);
        let mut child_lock = [0u8; 32];
        child_lock.copy_from_slice(&bytes[74..106]);
        let mut sender_pubkey = [0u8; 32];
        sender_pubkey.copy_from_slice(&bytes[106..138]);
        let mut receiver_pubkey_hash = [0u8; 32];
        receiver_pubkey_hash.copy_from_slice(&bytes[138..170]);

        let change_pubkey_hash = match bytes[170] {
            0 => {
                if bytes[171..203] != [0u8; 32] {
                    return Err("non-zero change_pubkey_hash when has_change == 0");
                }
                None
            }
            1 => {
                let mut ch = [0u8; 32];
                ch.copy_from_slice(&bytes[171..203]);
                Some(ch)
            }
            _ => return Err("invalid has_change flag"),
        };

        let mut causal_sig = [0u8; 64];
        causal_sig.copy_from_slice(&bytes[203..267]);

        let root_mig_sig = match bytes[267] {
            0 => {
                if bytes[268..332] != [0u8; 64] {
                    return Err("non-zero root_mig_sig when has_root_mig_sig == 0");
                }
                if depth == 0 {
                    return Err("depth 0 requires has_root_mig_sig == 1");
                }
                None
            }
            1 => {
                if depth != 0 {
                    return Err("has_root_mig_sig == 1 only permitted at depth 0");
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&bytes[268..332]);
                Some(sig)
            }
            _ => return Err("invalid has_root_mig_sig flag"),
        };

        if depth == 0 && (parent_slot != [0u8; 32] || output_branch != 0) {
            return Err("depth 0 requires zero parent_slot and output_branch 0");
        }
        if depth > 0 && parent_slot == [0u8; 32] {
            return Err("non-root entry requires non-zero parent_slot");
        }

        let mut encrypted_payload = [0u8; HOP_ENCRYPTED_PAYLOAD_LEN];
        encrypted_payload.copy_from_slice(&bytes[332..597]);

        let pow_nonce =
            u64::from_le_bytes(bytes[597..605].try_into().map_err(|_| "pow_nonce slice")?);

        Ok(Self {
            slot,
            parent_slot,
            output_branch,
            depth,
            child_lock,
            sender_pubkey,
            receiver_pubkey_hash,
            change_pubkey_hash,
            causal_sig,
            root_mig_sig,
            encrypted_payload,
            pow_nonce,
        })
    }

    /// Parses a lowercase 1210-character hex string into a canonical `LockEntry`.
    pub fn from_wire_hex(hex_str: &str) -> Result<Self, &'static str> {
        let bytes = decode_hex_fixed::<LOCK_ENTRY_WIRE_LEN>(hex_str)?;
        Self::from_wire_bytes(&bytes)
    }

    /// Serializes this entry as a canonical 1210-character lowercase hex string.
    pub fn to_wire_hex(&self) -> Result<String, &'static str> {
        Ok(hex::encode(self.to_wire_bytes()?))
    }

    /// Computes the canonical `entry_hash` (`SHA-256("HUMOCO_LOCK_ENTRY_V1" || wire_bytes[0..597])`).
    pub fn entry_hash(&self) -> Result<[u8; 32], &'static str> {
        let identity = self.identity_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(LOCK_ENTRY_DOMAIN);
        hasher.update(identity);
        Ok(hasher.finalize().into())
    }

    /// Extracts the `CausalOutputProof` view for this entry under `anchor_id`.
    pub fn causal_proof(&self, anchor_id: [u8; 32]) -> CausalOutputProof {
        CausalOutputProof {
            anchor_id,
            slot: self.slot,
            parent_slot: self.parent_slot,
            output_branch: self.output_branch,
            depth: self.depth,
            child_lock: self.child_lock,
            sender_pubkey: self.sender_pubkey,
            receiver_pubkey_hash: self.receiver_pubkey_hash,
            change_pubkey_hash: self.change_pubkey_hash,
            causal_sig: self.causal_sig,
        }
    }

    /// Verifies PoW difficulty, `CausalOutputProof`, and either `depth == 0` creator migration
    /// authorization or `depth >= 1` linkage against `parent` (`SPEC.md` §6.6.4).
    pub fn verify_entry(
        &self,
        anchor_id: &[u8; 32],
        creator_mig_pub: &[u8; 32],
        pow_base_bits: u32,
        parent: Option<&LockEntry>,
    ) -> Result<(), &'static str> {
        let req_bits = required_lock_pow_bits(pow_base_bits, self.depth);
        if !verify_lock_pow(
            &self.slot,
            &self.child_lock,
            self.depth,
            self.pow_nonce,
            req_bits,
        ) {
            return Err("insufficient lock proof-of-work");
        }

        if !self.causal_proof(*anchor_id).verify() {
            return Err("invalid causal_sig");
        }

        if self.depth == 0 {
            if parent.is_some() {
                return Err("depth 0 entry must not supply parent");
            }
            let root_sig = self.root_mig_sig.ok_or("missing depth 0 root_mig_sig")?;
            if !verify_root_mig_auth(
                anchor_id,
                &self.slot,
                &self.sender_pubkey,
                creator_mig_pub,
                &root_sig,
            ) {
                return Err("invalid root_mig_sig");
            }
            return Ok(());
        }

        if self.root_mig_sig.is_some() {
            return Err("non-root entry must not carry root_mig_sig");
        }
        let p = parent.ok_or("missing parent entry")?;
        if p.slot != self.parent_slot {
            return Err("parent slot mismatch");
        }
        let expected_depth = p.depth.checked_add(1).ok_or("depth overflow")?;
        if self.depth != expected_depth {
            return Err("child depth must equal parent.depth + 1");
        }

        let sender_hash = hash_pubkey_sha3(&self.sender_pubkey);
        let expected_owner_hash = match self.output_branch {
            0 => Some(p.receiver_pubkey_hash),
            1 => p.change_pubkey_hash,
            _ => return Err("invalid output_branch"),
        };
        match expected_owner_hash {
            Some(expected) if expected == sender_hash => Ok(()),
            Some(_) => Err("sender_pubkey SHA3-256 does not match parent output owner"),
            None => Err("parent entry has no change output"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        compute_root_mig_auth_digest, derive_slot, hash_pubkey_sha3, solve_lock_pow,
    };
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_lock_entry_wire_roundtrip_and_causal_parent_chain() {
        let anchor_id = [0xAA; 32];
        let creator_mig_sk = SigningKey::from_bytes(&[10; 32]);
        let creator_mig_pub = creator_mig_sk.verifying_key().to_bytes();

        let genesis_sk = SigningKey::from_bytes(&[11; 32]);
        let genesis_pub = genesis_sk.verifying_key().to_bytes();
        let recv1_sk = SigningKey::from_bytes(&[12; 32]);
        let recv1_pub = recv1_sk.verifying_key().to_bytes();
        let recv1_hash = hash_pubkey_sha3(&recv1_pub);
        let change1_sk = SigningKey::from_bytes(&[13; 32]);
        let change1_pub = change1_sk.verifying_key().to_bytes();
        let change1_hash = hash_pubkey_sha3(&change1_pub);

        let slot0 = derive_slot(&anchor_id, &[0x01; 32]);
        let child_lock0 = [0x01; 32];
        let mut proof0 = CausalOutputProof {
            anchor_id,
            slot: slot0,
            parent_slot: [0u8; 32],
            output_branch: 0,
            depth: 0,
            child_lock: child_lock0,
            sender_pubkey: genesis_pub,
            receiver_pubkey_hash: recv1_hash,
            change_pubkey_hash: Some(change1_hash),
            causal_sig: [0; 64],
        };
        proof0.causal_sig = genesis_sk.sign(&proof0.digest().unwrap()).to_bytes();

        let root_digest = compute_root_mig_auth_digest(&anchor_id, &slot0, &genesis_pub);
        let root_sig = creator_mig_sk.sign(&root_digest).to_bytes();
        let pow0 = solve_lock_pow(&slot0, &child_lock0, 0, 8, 0, 100_000).unwrap();

        let root_entry = LockEntry {
            slot: slot0,
            parent_slot: [0u8; 32],
            output_branch: 0,
            depth: 0,
            child_lock: child_lock0,
            sender_pubkey: genesis_pub,
            receiver_pubkey_hash: recv1_hash,
            change_pubkey_hash: Some(change1_hash),
            causal_sig: proof0.causal_sig,
            root_mig_sig: Some(root_sig),
            encrypted_payload: [0x5A; HOP_ENCRYPTED_PAYLOAD_LEN],
            pow_nonce: pow0,
        };

        let wire = root_entry.to_wire_bytes().unwrap();
        assert_eq!(wire.len(), LOCK_ENTRY_WIRE_LEN);
        let parsed = LockEntry::from_wire_bytes(&wire).unwrap();
        assert_eq!(parsed, root_entry);
        assert_eq!(
            parsed.entry_hash().unwrap(),
            root_entry.entry_hash().unwrap()
        );
        parsed
            .verify_entry(&anchor_id, &creator_mig_pub, 8, None)
            .unwrap();

        // Spend receiver branch (output_branch = 0) and change branch (output_branch = 1)
        let recv2_hash = [0x77; 32];
        let slot1_recv = derive_slot(&anchor_id, &[0x02; 32]);
        let child_lock1_recv = [0x02; 32];
        let mut proof1 = CausalOutputProof {
            anchor_id,
            slot: slot1_recv,
            parent_slot: slot0,
            output_branch: 0,
            depth: 1,
            child_lock: child_lock1_recv,
            sender_pubkey: recv1_pub,
            receiver_pubkey_hash: recv2_hash,
            change_pubkey_hash: None,
            causal_sig: [0; 64],
        };
        proof1.causal_sig = recv1_sk.sign(&proof1.digest().unwrap()).to_bytes();
        let pow1 = solve_lock_pow(&slot1_recv, &child_lock1_recv, 1, 8, 0, 100_000).unwrap();
        let spend_recv = LockEntry {
            slot: slot1_recv,
            parent_slot: slot0,
            output_branch: 0,
            depth: 1,
            child_lock: child_lock1_recv,
            sender_pubkey: recv1_pub,
            receiver_pubkey_hash: recv2_hash,
            change_pubkey_hash: None,
            causal_sig: proof1.causal_sig,
            root_mig_sig: None,
            encrypted_payload: [0x6B; HOP_ENCRYPTED_PAYLOAD_LEN],
            pow_nonce: pow1,
        };
        spend_recv
            .verify_entry(&anchor_id, &creator_mig_pub, 8, Some(&root_entry))
            .unwrap();

        // Change key spending receiver branch 0 MUST fail!
        let mut bad_branch = spend_recv.clone();
        bad_branch.output_branch = 1; // recv1_pub != change1_pub!
        assert!(bad_branch
            .verify_entry(&anchor_id, &creator_mig_pub, 8, Some(&root_entry))
            .is_err());

        // Non-canonical wire padding rejected
        let mut bad_wire = spend_recv.to_wire_bytes().unwrap();
        bad_wire[175] = 0xFF; // nonzero change_pubkey_hash when has_change == 0
        assert!(LockEntry::from_wire_bytes(&bad_wire).is_err());
    }
}
