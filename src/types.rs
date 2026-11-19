//! Canonical wire protocol types and data transfer objects for HuMoCo Sync Locks (`SPEC.md` §6).

use crate::crypto::{verify_ed25519_strict, LOCK_RECEIPT_DOMAIN};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum number of lock servers permitted in a voucher's `LockCommittee` (`SPEC.md` §6.3).
pub const MAX_COMMITTEE_SIZE: usize = 5;

/// 32-byte Ed25519 public key identifying a Sync Lock server (`lock_pub`).
pub type LockPubKey = [u8; 32];

/// Decodes a strict lowercase hex string into a fixed-size byte array `[u8; N]`.
pub fn decode_hex_fixed<const N: usize>(hex_str: &str) -> Result<[u8; N], &'static str> {
    if hex_str.len() != N * 2 {
        return Err("invalid hex length");
    }
    if hex_str.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err("hex must be lowercase");
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(hex_str, &mut out).map_err(|_| "invalid hex characters")?;
    Ok(out)
}

/// Custom serializer/deserializer for 32-byte arrays: lowercase hex in JSON, raw bytes in binary.
pub mod serde_hex_32 {
    use super::decode_hex_fixed;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    /// Serializes a 32-byte array as lowercase 64-hex for human-readable formats, or `[u8; 32]` in binary.
    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serde::Serialize::serialize(bytes, serializer)
        }
    }

    /// Deserializes a 32-byte array from 64-hex (human-readable) or `[u8; 32]` (binary).
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            decode_hex_fixed::<32>(&s).map_err(D::Error::custom)
        } else {
            <[u8; 32]>::deserialize(deserializer)
        }
    }
}

/// Custom serializer/deserializer for 64-byte arrays: lowercase hex in JSON, raw bytes in binary.
pub mod serde_hex_64 {
    use super::decode_hex_fixed;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    /// Serializes a 64-byte array as lowercase 128-hex for human-readable formats, or raw bytes in binary.
    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    /// Deserializes a 64-byte array from 128-hex (human-readable) or raw bytes/sequence (binary).
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            decode_hex_fixed::<64>(&s).map_err(D::Error::custom)
        } else {
            struct Bytes64Visitor;
            impl<'de> serde::de::Visitor<'de> for Bytes64Visitor {
                type Value = [u8; 64];

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("64 bytes")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: Error,
                {
                    if v.len() == 64 {
                        let mut out = [0u8; 64];
                        out.copy_from_slice(v);
                        Ok(out)
                    } else {
                        Err(E::custom(format!("expected 64 bytes, got {}", v.len())))
                    }
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let mut out = [0u8; 64];
                    for slot in &mut out {
                        *slot = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom("expected 64 bytes"))?;
                    }
                    Ok(out)
                }
            }
            deserializer.deserialize_bytes(Bytes64Visitor)
        }
    }
}

/// Custom serializer/deserializer for `Vec<[u8; 32]>`: hex strings in JSON, `[u8; 32]` sequence in binary.
pub mod serde_hex_vec_32 {
    use super::decode_hex_fixed;
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes a `Vec<[u8; 32]>` as lowercase hex strings in JSON or `[u8; 32]` entries in binary.
    pub fn serialize<S>(items: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let hexes: Vec<String> = items.iter().map(hex::encode).collect();
            hexes.serialize(serializer)
        } else {
            items.serialize(serializer)
        }
    }

    /// Deserializes a `Vec<[u8; 32]>` from lowercase hex strings in JSON or `[u8; 32]` entries in binary.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let hexes = Vec::<String>::deserialize(deserializer)?;
            hexes
                .iter()
                .map(|s| decode_hex_fixed::<32>(s).map_err(D::Error::custom))
                .collect()
        } else {
            Vec::<[u8; 32]>::deserialize(deserializer)
        }
    }
}

/// Custom serializer/deserializer for `Option<[u8; 32]>` using `serde_hex_32` on `Some`.
pub mod serde_hex_opt_32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    struct Hex32(#[serde(with = "crate::types::serde_hex_32")] [u8; 32]);

    /// Serializes `Option<[u8; 32]>` as optional 64-hex in JSON or optional `[u8; 32]` in binary.
    pub fn serialize<S>(val: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        val.map(Hex32).serialize(serializer)
    }

    /// Deserializes `Option<[u8; 32]>` via `serde_hex_32`.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Hex32>::deserialize(deserializer).map(|opt| opt.map(|w| w.0))
    }
}

/// Custom serializer/deserializer for `Option<[u8; 64]>` using `serde_hex_64` on `Some`.
pub mod serde_hex_opt_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    struct Hex64(#[serde(with = "crate::types::serde_hex_64")] [u8; 64]);

    /// Serializes `Option<[u8; 64]>` as optional 128-hex in JSON or optional 64 bytes in binary.
    pub fn serialize<S>(val: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        val.map(Hex64).serialize(serializer)
    }

    /// Deserializes `Option<[u8; 64]>` via `serde_hex_64`.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Hex64>::deserialize(deserializer).map(|opt| opt.map(|w| w.0))
    }
}

/// Voucher-pinned Sync Lock committee replacing legacy global node shard counts (`SPEC.md` §6.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockCommittee {
    /// Ordered list of distinct committee server `lock_pub` Ed25519 keys (`1 <= N <= 5`).
    #[serde(with = "serde_hex_vec_32")]
    pub members: Vec<LockPubKey>,
    /// Required quorum size `Q` (`1 <= Q <= N` and `2 * Q > N`).
    pub threshold: u8,
}

impl LockCommittee {
    /// Validates committee bounds, strict majority quorum invariant (`2 * Q > N`),
    /// key distinctness, and valid Ed25519 encoding of every member key.
    pub fn validate(&self) -> Result<(), &'static str> {
        let n = self.members.len();
        if n == 0 || n > MAX_COMMITTEE_SIZE {
            return Err("committee size must be between 1 and 5");
        }
        let q = usize::from(self.threshold);
        if q == 0 || q > n {
            return Err("committee threshold out of bounds");
        }
        if 2 * q <= n {
            return Err("committee threshold must satisfy 2 * threshold > members.len()");
        }
        for (i, pk) in self.members.iter().enumerate() {
            if VerifyingKey::from_bytes(pk).is_err() {
                return Err("committee member has invalid Ed25519 key");
            }
            if self.members[..i].contains(pk) {
                return Err("duplicate committee member");
            }
        }
        Ok(())
    }

    /// Returns `true` iff `lock_pub` is a member of this committee.
    pub fn contains(&self, lock_pub: &LockPubKey) -> bool {
        self.members.contains(lock_pub)
    }

    /// Minimum number of trusted server `FirstWrite` receipts required for a `Green` verdict
    /// (`N - Q + 1`, Concept §5.3).
    pub fn needed_trusted(&self) -> usize {
        self.members
            .len()
            .saturating_sub(usize::from(self.threshold))
            .saturating_add(1)
    }

    /// Maximum number of Byzantine committee servers tolerated without quorum split (`2Q - N - 1`).
    pub fn byzantine_tolerance(&self) -> usize {
        (2 * usize::from(self.threshold)).saturating_sub(self.members.len() + 1)
    }

    /// Maximum number of offline/crashed committee servers while retaining quorum availability (`N - Q`).
    pub fn crash_tolerance(&self) -> usize {
        self.members
            .len()
            .saturating_sub(usize::from(self.threshold))
    }
}

/// Receipt outcome tag signed by a Sync Lock server (`SPEC.md` §6.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockReceiptKind {
    /// Slot was freshly written or matched identically (`wire_bytes[0..597]`).
    FirstWrite,
    /// Slot already held a different `wire_bytes[0..597]` spend.
    ConflictSeen,
}

impl LockReceiptKind {
    /// Canonical single-byte domain tag value used inside `HUMOCO_LOCK_RECEIPT_V1`.
    pub fn as_byte(self) -> u8 {
        match self {
            Self::FirstWrite => 0,
            Self::ConflictSeen => 1,
        }
    }
}

/// Server-signed lock write/conflict receipt (`SPEC.md` §6.6.2).
///
/// **Architectural Invariant (ADR-001):** Transport-agnostic lock attestation primitive shared
/// across Sync-Locks and intended for reuse by any future HMNN backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockReceipt {
    /// Outcome (`first_write` or `conflict_seen`).
    pub kind: LockReceiptKind,
    /// Server Ed25519 lock public key (`S.lock_pub`).
    #[serde(with = "serde_hex_32")]
    pub lock_pub: LockPubKey,
    /// Per-server blinded bucket identifier (`B_S`).
    #[serde(with = "serde_hex_32")]
    pub bucket: [u8; 32],
    /// Canonical set-wide slot identifier.
    #[serde(with = "serde_hex_32")]
    pub slot: [u8; 32],
    /// Committed (`FirstWrite`) or conflicting stored (`ConflictSeen`) 32-byte `child_lock` (`t_id`).
    #[serde(with = "serde_hex_32")]
    pub child_lock: [u8; 32],
    /// Canonical `entry_hash` (`SHA-256("HUMOCO_LOCK_ENTRY_V1" || wire_bytes[0..597])`).
    #[serde(with = "serde_hex_32")]
    pub entry_hash: [u8; 32],
    /// Encoded bucket retention quarter bound at bucket creation (`YYYY-QN`).
    pub retain_until_quarter: u16,
    /// Server bucket sequence counter (`>= 1` after first committed slot).
    pub write_seq: u64,
    /// Bucket hash-chain tip at the time this receipt was issued.
    #[serde(with = "serde_hex_32")]
    pub bucket_head: [u8; 32],
    /// Fresh client nonce echoed from the `POST ?lock` request to bind timeliness.
    #[serde(with = "serde_hex_32")]
    pub recipient_nonce: [u8; 32],
    /// Ed25519 signature by `S.lock_sk` over `LockReceipt::digest()`.
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl LockReceipt {
    /// Computes the canonical 257-byte preimage SHA-256 digest signed in `sig` (`SPEC.md` §6.6.2).
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(LOCK_RECEIPT_DOMAIN);
        hasher.update([self.kind.as_byte()]);
        hasher.update(self.lock_pub);
        hasher.update(self.bucket);
        hasher.update(self.slot);
        hasher.update(self.child_lock);
        hasher.update(self.entry_hash);
        hasher.update(self.retain_until_quarter.to_le_bytes());
        hasher.update(self.write_seq.to_le_bytes());
        hasher.update(self.bucket_head);
        hasher.update(self.recipient_nonce);
        hasher.finalize().into()
    }

    /// Strictly verifies `self.sig` against `self.lock_pub` over `self.digest()`.
    pub fn verify_signature(&self) -> bool {
        let digest = self.digest();
        verify_ed25519_strict(&self.lock_pub, &digest, &self.sig)
    }
}

/// Set of `Q` matching `FirstWrite` receipts proving an offline-portable hop lock (`SPEC.md` / Concept §4.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// Canonical set-wide slot covered by this certificate.
    #[serde(with = "serde_hex_32")]
    pub slot: [u8; 32],
    /// Locked transaction ID (`tx.t_id`) committed at `slot`.
    #[serde(with = "serde_hex_32")]
    pub child_lock: [u8; 32],
    /// Distinct committee `FirstWrite` receipts binding `(slot, child_lock)`.
    pub receipts: Vec<LockReceipt>,
}

/// Irrefutable proof that a single server issued conflicting `FirstWrite` receipts on the same slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationProof {
    /// First signed `FirstWrite` receipt from the equivocating server.
    pub receipt_a: LockReceipt,
    /// Conflicting signed `FirstWrite` receipt from the same `lock_pub` and `slot`.
    pub receipt_b: LockReceipt,
}

/// Deterministic checkout decision computed solely from `evaluate_checkout` (Concept §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutVerdict {
    /// Quorum reached AND at least `N - Q + 1` receipts come from merchant-trusted servers.
    Green,
    /// Insufficient trusted quorum or missing availability/retention guarantee; manual trust decision only.
    Yellow,
    /// Double-spend conflict (`ConflictSeen` / equivocation) or failed retention policy (`init.deletable_at`).
    Red,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct OptHexWrap {
        #[serde(with = "serde_hex_opt_32")]
        anchor: Option<[u8; 32]>,
    }

    #[test]
    fn test_decode_hex_fixed_rejects_uppercase() {
        let lower = "aa".repeat(32);
        assert_eq!(decode_hex_fixed::<32>(&lower), Ok([0xaa; 32]));
        let upper = "AA".repeat(32);
        assert_eq!(decode_hex_fixed::<32>(&upper), Err("hex must be lowercase"));
    }

    #[test]
    fn test_serde_hex_opt_32_json_and_bincode() {
        let none_w = OptHexWrap { anchor: None };
        assert_eq!(
            serde_json::to_string(&none_w).unwrap(),
            r#"{"anchor":null}"#
        );
        let some_w = OptHexWrap {
            anchor: Some([0xAB; 32]),
        };
        let json = serde_json::to_string(&some_w).unwrap();
        assert_eq!(json, format!(r#"{{"anchor":"{}"}}"#, "ab".repeat(32)));
        assert_eq!(serde_json::from_str::<OptHexWrap>(&json).unwrap(), some_w);

        // Uppercase rejected on deserialize too
        let upper_json = format!(r#"{{"anchor":"{}"}}"#, "AB".repeat(32));
        assert!(serde_json::from_str::<OptHexWrap>(&upper_json).is_err());

        // Bincode roundtrip
        let bin = bincode::serialize(&some_w).unwrap();
        assert_eq!(bincode::deserialize::<OptHexWrap>(&bin).unwrap(), some_w);
    }
}
