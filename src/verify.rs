//! Zero-trust receipt, quorum certificate, equivocation, and checkout verdict
//! verifiers for HuMoCo Sync Locks (`SPEC.md` §6, Concept §5.3).

use crate::crypto::derive_bucket;
use crate::retention::{decode_quarter, retention_covers};
use crate::types::{
    CheckoutVerdict, EquivocationProof, LockCommittee, LockPubKey, LockReceipt, LockReceiptKind,
    QuorumCertificate,
};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy)]
struct CheckoutPolicy<'a> {
    anchor_id: &'a [u8; 32],
    init_deletable_at_ms: u64,
    manifest_retain_until_quarter: u16,
}

impl QuorumCertificate {
    /// Verifies that this `QuorumCertificate` contains at least `committee.threshold` distinct,
    /// validly signed `FirstWrite` receipts from `committee` members for `(self.slot, self.child_lock)`.
    ///
    /// If `expected_retain_until_quarter` is `Some(q)`, all receipts must also match `q`.
    pub fn verify(
        &self,
        committee: &LockCommittee,
        expected_retain_until_quarter: Option<u16>,
    ) -> Result<(), &'static str> {
        self.verify_inner(committee, None, expected_retain_until_quarter)
    }

    /// Verifies this `QuorumCertificate` with strict `anchor_id`-derived bucket binding and exact
    /// retention quarter verification.
    pub fn verify_with_anchor(
        &self,
        committee: &LockCommittee,
        anchor_id: &[u8; 32],
        expected_retain_until_quarter: u16,
    ) -> Result<(), &'static str> {
        self.verify_inner(
            committee,
            Some(anchor_id),
            Some(expected_retain_until_quarter),
        )
    }

    fn verify_inner(
        &self,
        committee: &LockCommittee,
        expected_anchor_id: Option<&[u8; 32]>,
        expected_retain_until_quarter: Option<u16>,
    ) -> Result<(), &'static str> {
        committee.validate()?;

        if self.receipts.len() > committee.members.len() {
            return Err("too many receipts for committee size");
        }
        if self.receipts.len() < usize::from(committee.threshold) {
            return Err("insufficient receipts for quorum threshold");
        }

        let mut seen_signers = HashSet::with_capacity(self.receipts.len());
        let mut expected_entry_hash: Option<[u8; 32]> = None;

        for receipt in &self.receipts {
            if receipt.kind != LockReceiptKind::FirstWrite {
                return Err("quorum certificate requires FirstWrite receipts");
            }
            if receipt.slot != self.slot {
                return Err("receipt slot mismatch");
            }
            if receipt.child_lock != self.child_lock {
                return Err("receipt child_lock mismatch");
            }
            if receipt.recipient_nonce == [0u8; 32] {
                return Err("receipt recipient_nonce must be non-zero");
            }
            if receipt.write_seq == 0 {
                return Err("receipt write_seq must be positive");
            }
            decode_quarter(receipt.retain_until_quarter)?;
            if let Some(expected_q) = expected_retain_until_quarter {
                if receipt.retain_until_quarter != expected_q {
                    return Err("receipt retain_until_quarter mismatch");
                }
            }
            if let Some(anchor_id) = expected_anchor_id {
                if receipt.bucket != derive_bucket(anchor_id, &receipt.lock_pub) {
                    return Err("receipt bucket does not match anchor_id and lock_pub");
                }
            }
            if !committee.contains(&receipt.lock_pub) {
                return Err("receipt signer not in committee");
            }
            if !seen_signers.insert(receipt.lock_pub) {
                return Err("duplicate receipt signer in quorum certificate");
            }
            match expected_entry_hash {
                None => expected_entry_hash = Some(receipt.entry_hash),
                Some(eh) if eh != receipt.entry_hash => {
                    return Err("inconsistent entry_hash across quorum receipts");
                }
                _ => {}
            }
            if !receipt.verify_signature() {
                return Err("invalid receipt signature");
            }
        }

        Ok(())
    }
}

impl EquivocationProof {
    /// Verifies that both receipts are validly signed `FirstWrite` claims from the exact same
    /// server `lock_pub` on the same `slot`, but committing conflicting `child_lock` or `entry_hash`.
    ///
    /// On success, returns the offending server's `LockPubKey`.
    pub fn verify(&self) -> Result<LockPubKey, &'static str> {
        if self.receipt_a.kind != LockReceiptKind::FirstWrite
            || self.receipt_b.kind != LockReceiptKind::FirstWrite
        {
            return Err("equivocation requires two FirstWrite receipts");
        }
        if self.receipt_a.lock_pub != self.receipt_b.lock_pub {
            return Err("equivocation receipts must share the same lock_pub");
        }
        if self.receipt_a.slot != self.receipt_b.slot {
            return Err("equivocation receipts must reference the same slot");
        }
        if self.receipt_a.child_lock == self.receipt_b.child_lock
            && self.receipt_a.entry_hash == self.receipt_b.entry_hash
        {
            return Err("receipts do not conflict");
        }
        if !self.receipt_a.verify_signature() || !self.receipt_b.verify_signature() {
            return Err("invalid equivocation receipt signature");
        }
        Ok(self.receipt_a.lock_pub)
    }
}

/// Evaluates merchant PoS checkout receipts exclusively via the Green-Rule (Concept §5.3):
///
/// - Any validly signed `ConflictSeen` or conflicting `FirstWrite` from a committee member on
///   `expected_slot` immediately yields [`CheckoutVerdict::Red`].
/// - Otherwise, [`CheckoutVerdict::Green`] iff distinct valid `FirstWrite` receipts reach `Q` AND
///   at least `N - Q + 1` of them are from `trusted_servers`.
/// - All other cases yield [`CheckoutVerdict::Yellow`].
pub fn evaluate_checkout(
    committee: &LockCommittee,
    expected_slot: &[u8; 32],
    expected_child_lock: &[u8; 32],
    receipts: &[LockReceipt],
    trusted_servers: &[LockPubKey],
) -> CheckoutVerdict {
    evaluate_checkout_inner(
        committee,
        expected_slot,
        expected_child_lock,
        receipts,
        trusted_servers,
        None,
    )
}

/// Evaluates merchant PoS checkout receipts together with `anchor_id` bucket binding and
/// `init.deletable_at` vs. `retain_until_quarter` retention enforcement (Concept §4.3, §5.3, §6.6).
#[allow(clippy::too_many_arguments)]
pub fn evaluate_checkout_with_policy(
    committee: &LockCommittee,
    anchor_id: &[u8; 32],
    expected_slot: &[u8; 32],
    expected_child_lock: &[u8; 32],
    init_deletable_at_ms: u64,
    manifest_retain_until_quarter: u16,
    receipts: &[LockReceipt],
    trusted_servers: &[LockPubKey],
) -> CheckoutVerdict {
    evaluate_checkout_inner(
        committee,
        expected_slot,
        expected_child_lock,
        receipts,
        trusted_servers,
        Some(CheckoutPolicy {
            anchor_id,
            init_deletable_at_ms,
            manifest_retain_until_quarter,
        }),
    )
}

fn evaluate_checkout_inner(
    committee: &LockCommittee,
    expected_slot: &[u8; 32],
    expected_child_lock: &[u8; 32],
    receipts: &[LockReceipt],
    trusted_servers: &[LockPubKey],
    policy: Option<CheckoutPolicy<'_>>,
) -> CheckoutVerdict {
    if committee.validate().is_err() {
        return CheckoutVerdict::Red;
    }

    if let Some(p) = policy {
        if !retention_covers(p.init_deletable_at_ms, p.manifest_retain_until_quarter) {
            return CheckoutVerdict::Red;
        }
    }

    let mut seen_first_write: HashMap<LockPubKey, [u8; 32]> =
        HashMap::with_capacity(committee.members.len());

    for receipt in receipts {
        if !committee.contains(&receipt.lock_pub)
            || receipt.slot != *expected_slot
            || receipt.recipient_nonce == [0u8; 32]
            || receipt.write_seq == 0
            || decode_quarter(receipt.retain_until_quarter).is_err()
        {
            continue;
        }

        if let Some(p) = policy {
            if receipt.bucket != derive_bucket(p.anchor_id, &receipt.lock_pub) {
                continue;
            }
        }

        if !receipt.verify_signature() {
            continue;
        }

        if receipt.kind == LockReceiptKind::ConflictSeen {
            return CheckoutVerdict::Red;
        }

        if let Some(p) = policy {
            if receipt.retain_until_quarter != p.manifest_retain_until_quarter
                || !retention_covers(p.init_deletable_at_ms, receipt.retain_until_quarter)
            {
                return CheckoutVerdict::Red;
            }
        }

        if receipt.child_lock != *expected_child_lock {
            return CheckoutVerdict::Red;
        }

        if let Some(prev_hash) = seen_first_write.insert(receipt.lock_pub, receipt.entry_hash) {
            if prev_hash != receipt.entry_hash {
                return CheckoutVerdict::Red;
            }
        }
    }

    let ok_count = seen_first_write.len();
    let trusted_count = seen_first_write
        .keys()
        .filter(|pk| trusted_servers.contains(*pk))
        .count();

    if ok_count >= usize::from(committee.threshold) && trusted_count >= committee.needed_trusted() {
        CheckoutVerdict::Green
    } else {
        CheckoutVerdict::Yellow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention::encode_quarter;
    use ed25519_dalek::{Signer, SigningKey};

    #[allow(clippy::too_many_arguments)]
    fn make_signed_receipt(
        sk: &SigningKey,
        kind: LockReceiptKind,
        anchor_id: &[u8; 32],
        slot: [u8; 32],
        child_lock: [u8; 32],
        entry_hash: [u8; 32],
        write_seq: u64,
        retain_until_quarter: u16,
    ) -> LockReceipt {
        let lock_pub = sk.verifying_key().to_bytes();
        let mut r = LockReceipt {
            kind,
            lock_pub,
            bucket: derive_bucket(anchor_id, &lock_pub),
            slot,
            child_lock,
            entry_hash,
            retain_until_quarter,
            write_seq,
            bucket_head: [0x55; 32],
            recipient_nonce: [0x99; 32],
            sig: [0; 64],
        };
        r.sig = sk.sign(&r.digest()).to_bytes();
        r
    }

    #[test]
    fn test_exhaustive_green_rule_878_cases() {
        let keys: Vec<SigningKey> = (1u8..=5u8)
            .map(|i| SigningKey::from_bytes(&[i; 32]))
            .collect();
        let pubs: Vec<LockPubKey> = keys
            .iter()
            .map(|sk| sk.verifying_key().to_bytes())
            .collect();

        let anchor_id = [0x11; 32];
        let slot = [0x22; 32];
        let child_a = [0x33; 32];
        let entry_hash_a = [0x44; 32];
        let retain_q = encode_quarter(2031, 2).unwrap();

        let base_receipts: Vec<LockReceipt> = keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                make_signed_receipt(
                    sk,
                    LockReceiptKind::FirstWrite,
                    &anchor_id,
                    slot,
                    child_a,
                    entry_hash_a,
                    (i + 1) as u64,
                    retain_q,
                )
            })
            .collect();

        let mut total_states = 0usize;
        let mut quorum_states = 0usize;
        let mut green_states = 0usize;
        let mut violations = 0usize;

        for n in 1usize..=5usize {
            let committee_members = pubs[..n].to_vec();
            let valid_thresholds: Vec<u8> = (1u8..=(n as u8))
                .filter(|&q| 2 * usize::from(q) > n)
                .collect();

            for threshold in valid_thresholds {
                let committee = LockCommittee {
                    members: committee_members.clone(),
                    threshold,
                };
                committee.validate().unwrap();
                let q = usize::from(threshold);
                let needed_trusted = n - q + 1;

                for trusted_mask in 0usize..(1usize << n) {
                    let trusted: Vec<LockPubKey> = (0..n)
                        .filter(|&i| (trusted_mask & (1 << i)) != 0)
                        .map(|i| pubs[i])
                        .collect();

                    for response_mask in 0usize..(1usize << n) {
                        total_states += 1;
                        let resp_count = response_mask.count_ones() as usize;
                        if resp_count >= q {
                            quorum_states += 1;
                        }

                        let receipts: Vec<LockReceipt> = (0..n)
                            .filter(|&i| (response_mask & (1 << i)) != 0)
                            .map(|i| base_receipts[i].clone())
                            .collect();

                        let verdict =
                            evaluate_checkout(&committee, &slot, &child_a, &receipts, &trusted);

                        // Trusted honest locks held in R cannot participate in a competing spend C.
                        let honest_locked_count =
                            (response_mask & trusted_mask).count_ones() as usize;
                        let max_competing_committee = n - honest_locked_count;
                        let competing_quorum_possible = max_competing_committee >= q;

                        if resp_count >= q && honest_locked_count >= needed_trusted {
                            assert_eq!(verdict, CheckoutVerdict::Green);
                            green_states += 1;
                            if competing_quorum_possible {
                                violations += 1;
                            }
                            // Exhaustively verify every competing mask C of size >= Q hits at least one
                            // server in (response_mask & trusted_mask).
                            for competing_mask in 0usize..(1usize << n) {
                                if (competing_mask.count_ones() as usize) >= q
                                    && (competing_mask & response_mask & trusted_mask) == 0
                                {
                                    violations += 1;
                                }
                            }
                        } else {
                            assert_eq!(verdict, CheckoutVerdict::Yellow);
                            if resp_count >= q {
                                // Strict tightness: when quorum is reached but verdict is Yellow,
                                // a competing subset of size >= Q strictly exists.
                                assert!(competing_quorum_possible);
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(total_states, 3732);
        assert_eq!(quorum_states, 878);
        assert_eq!(violations, 0);
        assert!(green_states > 0);
    }

    #[test]
    fn test_conflict_forged_sig_and_retention_checkout_policy() {
        let keys: Vec<SigningKey> = (10u8..13u8)
            .map(|i| SigningKey::from_bytes(&[i; 32]))
            .collect();
        let pubs: Vec<LockPubKey> = keys
            .iter()
            .map(|sk| sk.verifying_key().to_bytes())
            .collect();
        let committee = LockCommittee {
            members: pubs.clone(),
            threshold: 2,
        };
        let anchor_id = [0xAA; 32];
        let slot = [0xBB; 32];
        let child_a = [0xCC; 32];
        let child_b = [0xDD; 32];
        let q_2031_q2 = encode_quarter(2031, 2).unwrap();
        let q_2031_q1 = encode_quarter(2031, 1).unwrap();

        let r0 = make_signed_receipt(
            &keys[0],
            LockReceiptKind::FirstWrite,
            &anchor_id,
            slot,
            child_a,
            [0x01; 32],
            1,
            q_2031_q2,
        );
        let r1 = make_signed_receipt(
            &keys[1],
            LockReceiptKind::FirstWrite,
            &anchor_id,
            slot,
            child_a,
            [0x01; 32],
            1,
            q_2031_q2,
        );
        // Valid 2/3 with 2 trusted -> Green
        assert_eq!(
            evaluate_checkout(
                &committee,
                &slot,
                &child_a,
                &[r0.clone(), r1.clone()],
                &pubs
            ),
            CheckoutVerdict::Green
        );

        // One ConflictSeen from third member flips straight to Red
        let conflict = make_signed_receipt(
            &keys[2],
            LockReceiptKind::ConflictSeen,
            &anchor_id,
            slot,
            child_b,
            [0x02; 32],
            1,
            q_2031_q2,
        );
        assert_eq!(
            evaluate_checkout(
                &committee,
                &slot,
                &child_a,
                &[r0.clone(), r1.clone(), conflict.clone()],
                &pubs
            ),
            CheckoutVerdict::Red
        );

        // Forged ConflictSeen MUST be ignored (attacker cannot force bogus Red)
        let mut forged_conflict = conflict;
        forged_conflict.sig[0] ^= 0xFF;
        assert_eq!(
            evaluate_checkout(
                &committee,
                &slot,
                &child_a,
                &[r0.clone(), r1.clone(), forged_conflict],
                &pubs
            ),
            CheckoutVerdict::Green
        );

        // Uncovered deletable_at fails retention -> Red
        let uncaught_deletable_at_ms = 2_000_000_000_000; // year 2033
        assert_eq!(
            evaluate_checkout_with_policy(
                &committee,
                &anchor_id,
                &slot,
                &child_a,
                uncaught_deletable_at_ms,
                q_2031_q2,
                &[r0.clone(), r1.clone()],
                &pubs
            ),
            CheckoutVerdict::Red
        );

        // Receipt claiming shorter quarter than manifest fails retention -> Red
        let short_r1 = make_signed_receipt(
            &keys[1],
            LockReceiptKind::FirstWrite,
            &anchor_id,
            slot,
            child_a,
            [0x01; 32],
            1,
            q_2031_q1,
        );
        let covered_ms = 1_893_456_000_000; // 2030-01-01
        assert_eq!(
            evaluate_checkout_with_policy(
                &committee,
                &anchor_id,
                &slot,
                &child_a,
                covered_ms,
                q_2031_q2,
                &[r0.clone(), short_r1],
                &pubs
            ),
            CheckoutVerdict::Red
        );

        // Matching covered retention -> Green
        assert_eq!(
            evaluate_checkout_with_policy(
                &committee,
                &anchor_id,
                &slot,
                &child_a,
                covered_ms,
                q_2031_q2,
                &[r0, r1],
                &pubs
            ),
            CheckoutVerdict::Green
        );
    }

    #[test]
    fn test_quorum_certificate_and_equivocation_proof() {
        let sk0 = SigningKey::from_bytes(&[20; 32]);
        let sk1 = SigningKey::from_bytes(&[21; 32]);
        let pk0 = sk0.verifying_key().to_bytes();
        let pk1 = sk1.verifying_key().to_bytes();
        let committee = LockCommittee {
            members: vec![pk0, pk1],
            threshold: 2,
        };
        let anchor_id = [0x31; 32];
        let slot = [0x32; 32];
        let child_a = [0x33; 32];
        let child_b = [0x34; 32];
        let q = encode_quarter(2031, 2).unwrap();

        let r0 = make_signed_receipt(
            &sk0,
            LockReceiptKind::FirstWrite,
            &anchor_id,
            slot,
            child_a,
            [0x77; 32],
            1,
            q,
        );
        let r1 = make_signed_receipt(
            &sk1,
            LockReceiptKind::FirstWrite,
            &anchor_id,
            slot,
            child_a,
            [0x77; 32],
            1,
            q,
        );

        let qc = QuorumCertificate {
            slot,
            child_lock: child_a,
            receipts: vec![r0.clone(), r1.clone()],
        };
        qc.verify(&committee, Some(q)).unwrap();
        qc.verify_with_anchor(&committee, &anchor_id, q).unwrap();

        // JSON & bincode roundtrips preserve exact signature validity
        let qc_json = serde_json::to_string(&qc).unwrap();
        let qc_from_json: QuorumCertificate = serde_json::from_str(&qc_json).unwrap();
        qc_from_json
            .verify_with_anchor(&committee, &anchor_id, q)
            .unwrap();
        let qc_bin = bincode::serialize(&qc).unwrap();
        let qc_from_bin: QuorumCertificate = bincode::deserialize(&qc_bin).unwrap();
        qc_from_bin
            .verify_with_anchor(&committee, &anchor_id, q)
            .unwrap();

        // Duplicate signer rejected
        let dup_qc = QuorumCertificate {
            slot,
            child_lock: child_a,
            receipts: vec![r0.clone(), r0.clone()],
        };
        assert!(dup_qc.verify(&committee, Some(q)).is_err());

        // Equivocation proof convicts sk0
        let r0_b = make_signed_receipt(
            &sk0,
            LockReceiptKind::FirstWrite,
            &anchor_id,
            slot,
            child_b,
            [0x88; 32],
            2,
            q,
        );
        let eq = EquivocationProof {
            receipt_a: r0,
            receipt_b: r0_b,
        };
        assert_eq!(eq.verify().unwrap(), pk0);

        // Non-conflicting pair rejected as equivocation
        let non_eq = EquivocationProof {
            receipt_a: r1.clone(),
            receipt_b: r1,
        };
        assert!(non_eq.verify().is_err());
    }
}
