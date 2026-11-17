//! Cryptographic hashing primitives, domain separators, and proof-of-work
//! helpers for HuMoCo Layer 1 / Layer 2 Sync Locks (`SPEC.md` §6).

use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

/// Domain separator tag for SST V4 Layer-1 and Layer-2 transaction authorization signatures.
pub const HMC_TX_AUTH_V4_DOMAIN: &[u8] = b"HMC_TX_AUTH_V4";

/// Sentinel placeholder string denoting the absence of a Shared-Signature Trap.
pub const TRAP_NONE_PLACEHOLDER: &str = "none";

/// Domain tag for HMAC-SHA256 derivation of an unlinkable per-anchor migration seed (`SPEC.md` §6.3).
pub const ANCHOR_MIG_SEED_DOMAIN: &[u8] = b"HUMOCO_ANCHOR_MIG_SEED_V1:";

/// Domain tag (26 bytes with trailing NUL) for canonical `anchor_id` computation (`SPEC.md` §6.3).
pub const ANCHOR_MANIFEST_DOMAIN: &[u8] = b"HUMOCO_ANCHOR_MANIFEST_V1\0";

/// Domain tag for canonical set-wide slot derivation (`SPEC.md` §6.3).
pub const SYNC_SLOT_DOMAIN: &[u8] = b"HUMOCO_SYNC_SLOT_V1";

/// Domain tag for per-server blinded bucket derivation (`SPEC.md` §6.3).
pub const SYNC_BUCKET_DOMAIN: &[u8] = b"HUMOCO_SYNC_BUCKET_V1";

/// Domain tag for per-server blinded lock file path derivation (`SPEC.md` §6.3).
pub const SYNC_FILE_DOMAIN: &[u8] = b"HUMOCO_SYNC_FILE_V1";

/// Domain tag for server-signed offline `GenesisTicket` digests (`SPEC.md` §6.3).
pub const GENESIS_TICKET_DOMAIN: &[u8] = b"HUMOCO_GENESIS_TICKET_V1";

/// Domain tag for `depth == 0` offline creator migration authorization (`SPEC.md` §6.3).
pub const ROOT_MIG_AUTH_DOMAIN: &[u8] = b"HUMOCO_ROOT_MIG_AUTH_V1";

/// Domain tag for per-hop `CausalOutputProof` signatures (`SPEC.md` §6.3).
pub const CAUSAL_OUTPUT_DOMAIN: &[u8] = b"HUMOCO_CAUSAL_OUTPUT_V1";

/// Domain tag for depth-progressive lock submission proof-of-work (`SPEC.md` §6.3).
pub const LOCK_POW_DOMAIN: &[u8] = b"HUMOCO_LOCK_POW_V1";

/// Domain tag for optional unauthenticated `GenesisTicket` proof-of-work (`SPEC.md` §6.5).
pub const LOCK_TICKET_POW_DOMAIN: &[u8] = b"HUMOCO_LOCK_TICKET_POW_V1";

/// Domain tag for per-hop XChaCha20-Poly1305 AEAD key derivation (`SPEC.md` §6.4).
pub const HOP_AEAD_KEY_DOMAIN: &[u8] = b"HUMOCO_HOP_AEAD_KEY_V1";

/// Domain tag for deterministic per-hop XChaCha20-Poly1305 AEAD nonce derivation (`SPEC.md` §6.4).
pub const HOP_AEAD_NONCE_DOMAIN: &[u8] = b"HUMOCO_HOP_AEAD_NONCE_V1";

/// Domain tag for canonical `LockEntry` identity hash over `wire_bytes[0..597]` (`SPEC.md` §6.4).
pub const LOCK_ENTRY_DOMAIN: &[u8] = b"HUMOCO_LOCK_ENTRY_V1";

/// Domain tag for bucket hash-chain initialization at `write_seq = 0` (`SPEC.md` §6.6).
pub const BUCKET_INIT_DOMAIN: &[u8] = b"HUMOCO_BUCKET_INIT_V1";

/// Domain tag for bucket hash-chain progression on newly committed slots (`SPEC.md` §6.6).
pub const BUCKET_STEP_DOMAIN: &[u8] = b"HUMOCO_BUCKET_STEP_V1";

/// Domain tag for server-signed `LockReceipt` digests (`SPEC.md` §6.6).
pub const LOCK_RECEIPT_DOMAIN: &[u8] = b"HUMOCO_LOCK_RECEIPT_V1";

/// Default baseline proof-of-work difficulty in leading zero bits for `POST ?lock`.
pub const DEFAULT_LOCK_POW_BASE_BITS: u32 = 8;

/// Hard upper bound on depth-progressive lock proof-of-work difficulty in leading zero bits.
pub const MAX_LOCK_POW_BITS: u32 = 24;

type HmacSha256 = Hmac<Sha256>;

/// Derives an unlinkable 32-byte migration key seed for a specific anchor set (`SPEC.md` §6.3).
///
/// Computed as `HMAC-SHA256(key = master_seed, msg = b"HUMOCO_ANCHOR_MIG_SEED_V1:" || anchor_nonce)`.
pub fn derive_anchor_mig_seed(
    master_seed: &[u8],
    anchor_nonce: &[u8],
) -> Result<[u8; 32], &'static str> {
    if master_seed.is_empty() || anchor_nonce.is_empty() {
        return Err("master_seed and anchor_nonce must not be empty");
    }
    let mut mac = HmacSha256::new_from_slice(master_seed).map_err(|_| "invalid HMAC key length")?;
    mac.update(ANCHOR_MIG_SEED_DOMAIN);
    mac.update(anchor_nonce);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Computes the canonical set-wide slot identifier (`SPEC.md` §6.3).
///
/// `SHA-256(b"HUMOCO_SYNC_SLOT_V1" || anchor_id || ds_tag)`
pub fn derive_slot(anchor_id: &[u8; 32], ds_tag: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SYNC_SLOT_DOMAIN);
    hasher.update(anchor_id);
    hasher.update(ds_tag);
    hasher.finalize().into()
}

/// Computes the per-server blinded bucket identifier (`SPEC.md` §6.3).
///
/// `SHA-256(b"HUMOCO_SYNC_BUCKET_V1" || anchor_id || lock_pub)`
pub fn derive_bucket(anchor_id: &[u8; 32], lock_pub: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SYNC_BUCKET_DOMAIN);
    hasher.update(anchor_id);
    hasher.update(lock_pub);
    hasher.finalize().into()
}

/// Computes the per-server blinded disk/read filename stem (`SPEC.md` §6.3).
///
/// `SHA-256(b"HUMOCO_SYNC_FILE_V1" || slot || lock_pub)`
pub fn derive_slot_file_id(slot: &[u8; 32], lock_pub: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SYNC_FILE_DOMAIN);
    hasher.update(slot);
    hasher.update(lock_pub);
    hasher.finalize().into()
}

/// Derives the 32-byte XChaCha20-Poly1305 AEAD key for a per-hop encrypted payload (`SPEC.md` §6.4).
///
/// `SHA-256(b"HUMOCO_HOP_AEAD_KEY_V1" || anchor_id || ds_tag || sender_pubkey)`
pub fn derive_hop_aead_key(
    anchor_id: &[u8; 32],
    ds_tag: &[u8; 32],
    sender_pubkey: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HOP_AEAD_KEY_DOMAIN);
    hasher.update(anchor_id);
    hasher.update(ds_tag);
    hasher.update(sender_pubkey);
    hasher.finalize().into()
}

/// Derives the deterministic 24-byte XChaCha20-Poly1305 AEAD nonce for a hop (`SPEC.md` §6.4).
///
/// First 24 bytes of `SHA-256(b"HUMOCO_HOP_AEAD_NONCE_V1" || anchor_id || ds_tag || child_lock || layer2_signature)`.
pub fn derive_hop_aead_nonce(
    anchor_id: &[u8; 32],
    ds_tag: &[u8; 32],
    child_lock: &[u8; 32],
    layer2_signature: &[u8; 64],
) -> [u8; 24] {
    let mut hasher = Sha256::new();
    hasher.update(HOP_AEAD_NONCE_DOMAIN);
    hasher.update(anchor_id);
    hasher.update(ds_tag);
    hasher.update(child_lock);
    hasher.update(layer2_signature);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&digest[..24]);
    nonce
}

/// Constructs the canonical 96-byte AAD for per-hop AEAD encryption (`SPEC.md` §6.4).
///
/// Layout: `slot (32B) || child_lock (32B) || sender_pubkey (32B)`.
pub fn derive_hop_aead_aad(
    slot: &[u8; 32],
    child_lock: &[u8; 32],
    sender_pubkey: &[u8; 32],
) -> [u8; 96] {
    let mut aad = [0u8; 96];
    aad[..32].copy_from_slice(slot);
    aad[32..64].copy_from_slice(child_lock);
    aad[64..96].copy_from_slice(sender_pubkey);
    aad
}

/// Computes the required leading zero bits for a lock entry at `depth` (`SPEC.md` §6.3).
///
/// Formula: `min(24, base_bits + (depth / 16) * 2)`.
pub fn required_lock_pow_bits(base_bits: u32, depth: u32) -> u32 {
    base_bits
        .saturating_add((depth / 16).saturating_mul(2))
        .min(MAX_LOCK_POW_BITS)
}

/// Computes the 32-byte SHA-256 work digest for a `LockEntry` proof-of-work candidate (`SPEC.md` §6.3).
///
/// `SHA-256(b"HUMOCO_LOCK_POW_V1" || slot || child_lock || depth.to_le_bytes() || pow_nonce.to_le_bytes())`
pub fn compute_lock_pow_hash(
    slot: &[u8; 32],
    child_lock: &[u8; 32],
    depth: u32,
    pow_nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LOCK_POW_DOMAIN);
    hasher.update(slot);
    hasher.update(child_lock);
    hasher.update(depth.to_le_bytes());
    hasher.update(pow_nonce.to_le_bytes());
    hasher.finalize().into()
}

/// Counts the number of leading zero bits in a 32-byte digest.
pub fn count_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut zeros = 0;
    for &byte in hash {
        let lz = byte.leading_zeros();
        zeros += lz;
        if lz < 8 {
            break;
        }
    }
    zeros
}

/// Verifies whether `hash` has at least `difficulty` leading zero bits.
pub fn check_pow_difficulty(hash: &[u8; 32], difficulty: u32) -> bool {
    count_leading_zero_bits(hash) >= difficulty
}

/// Verifies a `LockEntry` proof-of-work nonce against `required_bits`.
pub fn verify_lock_pow(
    slot: &[u8; 32],
    child_lock: &[u8; 32],
    depth: u32,
    pow_nonce: u64,
    required_bits: u32,
) -> bool {
    let hash = compute_lock_pow_hash(slot, child_lock, depth, pow_nonce);
    check_pow_difficulty(&hash, required_bits)
}

/// Searches for a valid proof-of-work nonce satisfying `required_bits` for a `LockEntry`.
pub fn solve_lock_pow(
    slot: &[u8; 32],
    child_lock: &[u8; 32],
    depth: u32,
    required_bits: u32,
    start_nonce: u64,
    max_iterations: u64,
) -> Option<u64> {
    for i in 0..max_iterations {
        let nonce = start_nonce.wrapping_add(i);
        if verify_lock_pow(slot, child_lock, depth, nonce, required_bits) {
            return Some(nonce);
        }
    }
    None
}

/// Computes the SHA-256 digest for optional unauthenticated `GenesisTicket` PoW (`SPEC.md` §6.5).
///
/// `SHA-256(b"HUMOCO_LOCK_TICKET_POW_V1" || anchor_id || retain_until_quarter.to_le_bytes() || pow_timestamp.to_le_bytes() || pow_nonce.to_le_bytes())`
pub fn compute_ticket_pow_hash(
    anchor_id: &[u8; 32],
    retain_until_quarter: u16,
    pow_timestamp: u64,
    pow_nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LOCK_TICKET_POW_DOMAIN);
    hasher.update(anchor_id);
    hasher.update(retain_until_quarter.to_le_bytes());
    hasher.update(pow_timestamp.to_le_bytes());
    hasher.update(pow_nonce.to_le_bytes());
    hasher.finalize().into()
}

/// Verifies an optional `GenesisTicket` PoW tuple against `required_bits`.
pub fn verify_ticket_pow(
    anchor_id: &[u8; 32],
    retain_until_quarter: u16,
    pow_timestamp: u64,
    pow_nonce: u64,
    required_bits: u32,
) -> bool {
    let hash = compute_ticket_pow_hash(anchor_id, retain_until_quarter, pow_timestamp, pow_nonce);
    check_pow_difficulty(&hash, required_bits)
}

/// Searches for a valid `GenesisTicket` PoW nonce satisfying `required_bits`.
pub fn solve_ticket_pow(
    anchor_id: &[u8; 32],
    retain_until_quarter: u16,
    pow_timestamp: u64,
    required_bits: u32,
    start_nonce: u64,
    max_iterations: u64,
) -> Option<u64> {
    for i in 0..max_iterations {
        let nonce = start_nonce.wrapping_add(i);
        if verify_ticket_pow(
            anchor_id,
            retain_until_quarter,
            pow_timestamp,
            nonce,
            required_bits,
        ) {
            return Some(nonce);
        }
    }
    None
}

/// Computes the initial `bucket_head` at `write_seq = 0` (`SPEC.md` §6.6).
///
/// `SHA-256(b"HUMOCO_BUCKET_INIT_V1" || bucket || retain_until_quarter.to_le_bytes())`
pub fn compute_bucket_init_head(bucket: &[u8; 32], retain_until_quarter: u16) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BUCKET_INIT_DOMAIN);
    hasher.update(bucket);
    hasher.update(retain_until_quarter.to_le_bytes());
    hasher.finalize().into()
}

/// Advances the bucket hash chain on a newly committed slot (`SPEC.md` §6.6).
///
/// `SHA-256(b"HUMOCO_BUCKET_STEP_V1" || prev_head || write_seq.to_le_bytes() || slot || entry_hash)`
pub fn compute_bucket_step_head(
    prev_head: &[u8; 32],
    write_seq: u64,
    slot: &[u8; 32],
    entry_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BUCKET_STEP_DOMAIN);
    hasher.update(prev_head);
    hasher.update(write_seq.to_le_bytes());
    hasher.update(slot);
    hasher.update(entry_hash);
    hasher.finalize().into()
}

/// Computes the SHA-256 digest signed by `creator_mig_sk` to authorize a `depth == 0` root entry (`SPEC.md` §6.3).
///
/// `SHA-256(b"HUMOCO_ROOT_MIG_AUTH_V1" || anchor_id || root_slot || genesis_pubkey)`
pub fn compute_root_mig_auth_digest(
    anchor_id: &[u8; 32],
    root_slot: &[u8; 32],
    genesis_pubkey: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROOT_MIG_AUTH_DOMAIN);
    hasher.update(anchor_id);
    hasher.update(root_slot);
    hasher.update(genesis_pubkey);
    hasher.finalize().into()
}

/// Strictly verifies a `depth == 0` creator migration authorization signature against `creator_mig_pub`.
pub fn verify_root_mig_auth(
    anchor_id: &[u8; 32],
    root_slot: &[u8; 32],
    genesis_pubkey: &[u8; 32],
    creator_mig_pub: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(creator_mig_pub) else {
        return false;
    };
    let digest = compute_root_mig_auth_digest(anchor_id, root_slot, genesis_pubkey);
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(&digest, &signature).is_ok()
}

/// Computes the 32-byte raw `SHA3-256` hash of a public key, matching Layer-1 `ephemeral_pub_hash`
/// before Base58 encoding.
pub fn hash_pubkey_sha3(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(pubkey);
    hasher.finalize().into()
}

/// Verifies a strict Ed25519 signature over an arbitrary byte message with `verify_strict`.
pub fn verify_ed25519_strict(pubkey: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_l1_constants_preserved_and_domain_tags() {
        assert_eq!(HMC_TX_AUTH_V4_DOMAIN, b"HMC_TX_AUTH_V4");
        assert_eq!(TRAP_NONE_PLACEHOLDER, "none");
        assert_eq!(ANCHOR_MANIFEST_DOMAIN.len(), 26);
        assert_eq!(CAUSAL_OUTPUT_DOMAIN.len(), 23);
        assert_eq!(LOCK_RECEIPT_DOMAIN.len(), 22);
    }

    #[test]
    fn test_mig_seed_and_slot_bucket_file_separation() {
        let seed_a = derive_anchor_mig_seed(b"master-secret", b"nonce-1").unwrap();
        let seed_b = derive_anchor_mig_seed(b"master-secret", b"nonce-2").unwrap();
        assert_ne!(seed_a, seed_b);
        assert!(derive_anchor_mig_seed(b"", b"nonce-1").is_err());

        let anchor = [0x11; 32];
        let ds_tag = [0x22; 32];
        let lock_pub_1 = [0x33; 32];
        let lock_pub_2 = [0x44; 32];

        let slot = derive_slot(&anchor, &ds_tag);
        assert_eq!(slot, derive_slot(&anchor, &ds_tag));
        assert_ne!(slot, derive_slot(&[0x12; 32], &ds_tag));

        let b1 = derive_bucket(&anchor, &lock_pub_1);
        let b2 = derive_bucket(&anchor, &lock_pub_2);
        assert_ne!(b1, b2);

        let f1 = derive_slot_file_id(&slot, &lock_pub_1);
        let f2 = derive_slot_file_id(&slot, &lock_pub_2);
        assert_ne!(f1, f2);
        assert_ne!(f1, slot);
    }

    #[test]
    fn test_progressive_lock_pow_and_ticket_pow() {
        assert_eq!(required_lock_pow_bits(8, 0), 8);
        assert_eq!(required_lock_pow_bits(8, 15), 8);
        assert_eq!(required_lock_pow_bits(8, 16), 10);
        assert_eq!(required_lock_pow_bits(8, 32), 12);
        assert_eq!(required_lock_pow_bits(8, 10_000), 24);

        let slot = [0xAA; 32];
        let child = [0xBB; 32];
        let nonce = solve_lock_pow(&slot, &child, 0, 8, 0, 100_000).expect("PoW 8 bits solves");
        assert!(verify_lock_pow(&slot, &child, 0, nonce, 8));
        assert!(!verify_lock_pow(&slot, &[0xBC; 32], 0, nonce, 8));

        let ticket_nonce =
            solve_ticket_pow(&[0x55; 32], 8125, 1_794_916_800, 8, 0, 100_000).expect("ticket PoW");
        assert!(verify_ticket_pow(
            &[0x55; 32],
            8125,
            1_794_916_800,
            ticket_nonce,
            8
        ));
    }

    #[test]
    fn test_root_mig_auth_and_bucket_head_chain() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let anchor_id = [0x10; 32];
        let root_slot = derive_slot(&anchor_id, &[0x20; 32]);
        let genesis_pub = [0x30; 32];
        let digest = compute_root_mig_auth_digest(&anchor_id, &root_slot, &genesis_pub);
        let sig = sk.sign(&digest).to_bytes();

        assert!(verify_root_mig_auth(
            &anchor_id,
            &root_slot,
            &genesis_pub,
            &pk,
            &sig
        ));
        assert!(!verify_root_mig_auth(
            &anchor_id,
            &root_slot,
            &[0x31; 32],
            &pk,
            &sig
        ));

        let bucket = derive_bucket(&anchor_id, &pk);
        let h0 = compute_bucket_init_head(&bucket, 8125);
        let h1 = compute_bucket_step_head(&h0, 1, &root_slot, &[0x99; 32]);
        let h1_diff = compute_bucket_step_head(&h0, 2, &root_slot, &[0x99; 32]);
        assert_ne!(h0, h1);
        assert_ne!(h1, h1_diff);
    }

    #[test]
    fn test_hop_aead_nonce_and_aad_layout() {
        let anchor = [1u8; 32];
        let ds_tag = [2u8; 32];
        let sender = [3u8; 32];
        let child = [4u8; 32];
        let l2_sig = [5u8; 64];
        let slot = derive_slot(&anchor, &ds_tag);

        let k1 = derive_hop_aead_key(&anchor, &ds_tag, &sender);
        let n1 = derive_hop_aead_nonce(&anchor, &ds_tag, &child, &l2_sig);
        let aad = derive_hop_aead_aad(&slot, &child, &sender);

        assert_eq!(k1, derive_hop_aead_key(&anchor, &ds_tag, &sender));
        assert_eq!(n1, derive_hop_aead_nonce(&anchor, &ds_tag, &child, &l2_sig));
        assert_ne!(
            n1,
            derive_hop_aead_nonce(&anchor, &ds_tag, &[9u8; 32], &l2_sig)
        );
        assert_eq!(&aad[..32], &slot);
        assert_eq!(&aad[32..64], &child);
        assert_eq!(&aad[64..96], &sender);
    }
}
