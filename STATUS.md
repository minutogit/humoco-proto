# Project Status: `humoco-proto`

**Version:** `v0.1.2`  
**Last Updated:** 2026-11-21

## Overview
Canonical wire formats, SHA-256 / BLAKE3 / SHA3-256 domain separators, quarterly retention utilities, and `#![forbid(unsafe_code)]` zero-trust Sync Lock verifiers shared across `human-money-core`, `humoco-sync`, and `human-money-app`.

## Task Progress

| ID | Task | Status | Notes |
|---|---|---|---|
| `PROTO-006` | Pure committee growth verifier (`is_pure_committee_growth`) & monotone quorum floor (`v0.1.2`) | ✅ **Done** | Added `is_pure_committee_growth` in `src/rotation.rs` (preserving `N=1 -> 2/3` auto-growth while rejecting non-additive committee replacements/shrinkage for 0s timelocks) and enforced monotone quorum floor (`threshold >= 2` cannot drop below `2` when `guarantor_mig_pubs` is empty) in `verify_nomination_binding`, with regression test `test_k4_pure_growth_and_monotone_quorum_floor`; verified `cargo fmt --all -- --check`, `cargo clippy --all-targets --offline -- -D warnings` (0 warnings), and `20/20` unit tests passing |
| `PROTO-005` | Pubkey-only `anchor_id` canonical hashing & URL-independent `ServerEntry::same_identity` | ✅ **Done** | Clean break excluding `write_url`/`read_url` from `ServerEntry::write_canonical` (`anchor_id` / `AnchorManifest`) and using key-based `ServerEntry::same_identity` in `rotation.rs` so Sync-Lock domain relocations preserve existing committee `anchor_id`s without committee rotation; verified with `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings` (0 warnings), and `19/19` tests passing |
| `PROTO-001` | Extract `humoco-proto` crate (`types`, `crypto`, `verify`, `causal`) | ✅ **Done** | Clean separation between Core L1 and shared L2 wire contracts |
| `PROTO-002` | Align `HMC_TX_AUTH_V4_DOMAIN`, stateless PoW & causal sidecars | ✅ **Done** | Superseded by `PROTO-003` Sync Lock clean break (`zero-compat`) |
| `PROTO-003` | Canonical Sync Lock committee model (`LockCommittee`, `LockReceipt`, `QuorumCertificate`, `EquivocationProof`, `AnchorManifest`, `GenesisTicket`, 605B `LockEntry`, `retention_covers`, `evaluate_checkout`) | ✅ **Done** | Removed legacy `live.rs`, `mesh.rs`, rigid `20`/`14` quorum constants, and stateless node PoW; enforced strict lowercase hex decoding for canonical JCS; verified exhaustive Green-Rule across all `3732` states (`878` quorum states, `0` safety violations, strict tightness); `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and all `15/15` tests passing |
| `PROTO-004` | Rotation wire types (`MigrationProposal`, `FreezeSnapshot`, `ImportAck`, `MigrationCert`), `AnchorManifest::verify_anchor_id` chain verifier, `verify_nomination_binding`, `resolve_import_union`, and `SyncRevocationNotice` | ✅ **Done** | Upgraded `AnchorManifest.migration_chain` (`Vec<MigrationCert>`, Zero-Compat); added `HUMOCO_MIGRATION_*` / `HUMOCO_FREEZE_*` / `HUMOCO_IMPORT_*` / `HUMOCO_CREATOR_HB_V1` / `HUMOCO_KEY_SUCCESSOR_V1` domains & `1800s`/`72h`/`30d` policy constants; pure `verify_nomination_binding` (`guarantor_protection_reduced` & `HolderStandby` checks), `resolve_import_union` (QC winner + `CONFLICT([A, B])` preservation), and `SyncRevocationNotice`; `cargo fmt --all --check`, `clippy --all-targets -- -D warnings`, and `18/18` tests passed (`#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`) |
