# Project Status: `humoco-proto`

**Version:** `v0.1.0`  
**Last Updated:** 2026-11-17

## Overview
Canonical wire formats, SHA-256 / BLAKE3 / SHA3-256 domain separators, quarterly retention utilities, and `#![forbid(unsafe_code)]` zero-trust Sync Lock verifiers shared across `human-money-core`, `humoco-sync`, and `human-money-app`.

## Task Progress

| ID | Task | Status | Notes |
|---|---|---|---|
| `PROTO-001` | Extract `humoco-proto` crate (`types`, `crypto`, `verify`, `causal`) | ✅ **Done** | Clean separation between Core L1 and shared L2 wire contracts |
| `PROTO-002` | Align `HMC_TX_AUTH_V4_DOMAIN`, stateless PoW & causal sidecars | ✅ **Done** | Superseded by `PROTO-003` Sync Lock clean break (`zero-compat`) |
| `PROTO-003` | Canonical Sync Lock committee model (`LockCommittee`, `LockReceipt`, `QuorumCertificate`, `EquivocationProof`, `AnchorManifest`, `GenesisTicket`, 605B `LockEntry`, `retention_covers`, `evaluate_checkout`) | ✅ **Done** | Removed legacy `live.rs`, `mesh.rs`, rigid `20`/`14` quorum constants, and stateless node PoW; enforced strict lowercase hex decoding for canonical JCS; verified exhaustive Green-Rule across all `3732` states (`878` quorum states, `0` safety violations, strict tightness); `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and all `15/15` tests passing |
| `PROTO-004` | Rotation wire types (`MigrationProposal`, `FreezeSnapshot`, `ImportAck`, `MigrationCert`), `AnchorManifest::verify_anchor_id` chain verifier, `verify_nomination_binding`, `resolve_import_union`, and `SyncRevocationNotice` | ✅ **Done** | Upgraded `AnchorManifest.migration_chain` (`Vec<MigrationCert>`, Zero-Compat); added `HUMOCO_MIGRATION_*` / `HUMOCO_FREEZE_*` / `HUMOCO_IMPORT_*` / `HUMOCO_CREATOR_HB_V1` / `HUMOCO_KEY_SUCCESSOR_V1` domains & `1800s`/`72h`/`30d` policy constants; pure `verify_nomination_binding` (`guarantor_protection_reduced` & `HolderStandby` checks), `resolve_import_union` (QC winner + `CONFLICT([A, B])` preservation), and `SyncRevocationNotice`; `cargo fmt --all --check`, `clippy --all-targets -- -D warnings`, and `18/18` tests passed (`#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`) |
