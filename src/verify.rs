//! Zero-trust receipt verifiers for HuMoCo Layer 2 quorum proofs.

use crate::types::{NodePubKey, QuorumProof};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashSet;

/// Verifies a Layer 2 quorum proof against an expected digest, committee, and quorum threshold.
///
/// # Validation Steps:
/// 1. Verifies that `proof.votes.len() >= required_quorum`.
/// 2. Verifies that every voting signer is a member of `eligible_committee`.
/// 3. Verifies that there are no duplicate votes from the same signer.
/// 4. Cryptographically verifies each Ed25519 signature over `expected_digest`.
///
/// # Returns:
/// - `Ok(())` if the proof is valid.
/// - `Err(&'static str)` describing the reason for rejection:
///   - `"insufficient votes"`: Vote count is below `required_quorum`.
///   - `"signer not in eligible committee"`: A vote was signed by a non-committee key.
///   - `"duplicate signer"`: Multiple votes were signed by the same public key.
///   - `"invalid signature"`: An Ed25519 signature failed cryptographic verification or the public key was malformed.
pub fn verify_quorum_proof(
    proof: &QuorumProof,
    expected_digest: &[u8; 32],
    eligible_committee: &[NodePubKey],
    required_quorum: usize,
) -> Result<(), &'static str> {
    if proof.votes.len() < required_quorum {
        return Err("insufficient votes");
    }

    let mut seen = HashSet::with_capacity(proof.votes.len());

    for vote in &proof.votes {
        if !eligible_committee.contains(&vote.signer_pubkey) {
            return Err("signer not in eligible committee");
        }

        if !seen.insert(vote.signer_pubkey) {
            return Err("duplicate signer");
        }

        let Ok(vk) = VerifyingKey::from_bytes(&vote.signer_pubkey) else {
            return Err("invalid signature");
        };

        let sig = Signature::from_bytes(&vote.signature);
        if vk.verify_strict(expected_digest, &sig).is_err() {
            return Err("invalid signature");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AttestationVote;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;

    fn make_test_signer(seed: u8) -> (SigningKey, NodePubKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn test_valid_quorum_proof() {
        let digest = [0x5au8; 32];
        let (sk1, pk1) = make_test_signer(1);
        let (sk2, pk2) = make_test_signer(2);
        let (sk3, pk3) = make_test_signer(3);
        let (_, pk4) = make_test_signer(4);

        let committee = vec![pk1, pk2, pk3, pk4];

        let proof = QuorumProof {
            shard_id: 1,
            votes: vec![
                AttestationVote {
                    signer_pubkey: pk1,
                    signature: sk1.sign(&digest).to_bytes(),
                },
                AttestationVote {
                    signer_pubkey: pk2,
                    signature: sk2.sign(&digest).to_bytes(),
                },
                AttestationVote {
                    signer_pubkey: pk3,
                    signature: sk3.sign(&digest).to_bytes(),
                },
            ],
        };

        let result = verify_quorum_proof(&proof, &digest, &committee, 3);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_insufficient_votes() {
        let digest = [0x5au8; 32];
        let (sk1, pk1) = make_test_signer(1);
        let (_, pk2) = make_test_signer(2);
        let committee = vec![pk1, pk2];

        let proof = QuorumProof {
            shard_id: 1,
            votes: vec![AttestationVote {
                signer_pubkey: pk1,
                signature: sk1.sign(&digest).to_bytes(),
            }],
        };

        let result = verify_quorum_proof(&proof, &digest, &committee, 2);
        assert_eq!(result, Err("insufficient votes"));
    }

    #[test]
    fn test_non_committee_signer() {
        let digest = [0x5au8; 32];
        let (sk1, pk1) = make_test_signer(1);
        let (sk_rogue, pk_rogue) = make_test_signer(99);
        let committee = vec![pk1];

        let proof = QuorumProof {
            shard_id: 1,
            votes: vec![
                AttestationVote {
                    signer_pubkey: pk1,
                    signature: sk1.sign(&digest).to_bytes(),
                },
                AttestationVote {
                    signer_pubkey: pk_rogue,
                    signature: sk_rogue.sign(&digest).to_bytes(),
                },
            ],
        };

        let result = verify_quorum_proof(&proof, &digest, &committee, 1);
        assert_eq!(result, Err("signer not in eligible committee"));
    }

    #[test]
    fn test_duplicate_signer() {
        let digest = [0x5au8; 32];
        let (sk1, pk1) = make_test_signer(1);
        let committee = vec![pk1];

        let proof = QuorumProof {
            shard_id: 1,
            votes: vec![
                AttestationVote {
                    signer_pubkey: pk1,
                    signature: sk1.sign(&digest).to_bytes(),
                },
                AttestationVote {
                    signer_pubkey: pk1,
                    signature: sk1.sign(&digest).to_bytes(),
                },
            ],
        };

        let result = verify_quorum_proof(&proof, &digest, &committee, 2);
        assert_eq!(result, Err("duplicate signer"));
    }

    #[test]
    fn test_bad_signature() {
        let digest = [0x5au8; 32];
        let (_, pk1) = make_test_signer(1);
        let (sk2, _) = make_test_signer(2);
        let committee = vec![pk1];

        // Signed by sk2 but claimed to be from pk1
        let proof = QuorumProof {
            shard_id: 1,
            votes: vec![AttestationVote {
                signer_pubkey: pk1,
                signature: sk2.sign(&digest).to_bytes(),
            }],
        };

        let result = verify_quorum_proof(&proof, &digest, &committee, 1);
        assert_eq!(result, Err("invalid signature"));
    }

    #[test]
    fn test_wrong_digest() {
        let digest = [0x5au8; 32];
        let wrong_digest = [0x99u8; 32];
        let (sk1, pk1) = make_test_signer(1);
        let committee = vec![pk1];

        // Signed over wrong_digest
        let proof = QuorumProof {
            shard_id: 1,
            votes: vec![AttestationVote {
                signer_pubkey: pk1,
                signature: sk1.sign(&wrong_digest).to_bytes(),
            }],
        };

        let result = verify_quorum_proof(&proof, &digest, &committee, 1);
        assert_eq!(result, Err("invalid signature"));
    }
}
