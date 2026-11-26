# Handoff — Agent 05 (`sbm-server`)

The server is optional. Ordinary local boot does not contact it. Shared structs come from `sbm-common` `28d38450954f0b93815e12f31da92370b13a7462` (`sbm-protocol`, `sbm-types`). This repo does not fork those structs.

Signing bytes are implemented once, in `crates/sbm-wire`, against `test-vectors/command-envelope.v1.json`. Spec 06 §16.1 names that profile and the wire field `signature_ed25519_hex`.

## Verified here

`cargo test --workspace` covers the signing profile, the enroll → report targets → queue next boot → device ack path, UEFI rejection of a `recovery_access` command without blocking a later boot selection, a bad verify key and an expired command (neither advances `last_sequence`), cross-device ack, role scope, CSRF, audit immutability, a MAC address ignored as identity, and an authenticated recovery tunnel whose first bytes are `RFB 003.008\n`. The dashboard shell is the built SvelteKit app, not the placeholder.

Those tests use `sbm-sim`. They do not boot firmware and they do not reboot the host. `cargo clippy --all-targets -- -D warnings` is clean. Release-binary startup and request timings from this machine are in `../research/validation/evidence/sbm-server-2026-11-26.md`. Those timings are not the UEFI frame targets.

## `sbm-common` gaps

- Command signing stays in `sbm-wire` so `sbm-protocol` can remain `no_std` without `serde_json` and `ed25519-dalek`. Agent 01 should add something like `command_signing_preimage()` next to `COMMAND_SIGNING_DOMAIN_V1` if the UEFI build can take the compact JSON bytes from outside the crate. Until then, UEFI and this server must both follow Spec 06 §16.1. The golden vector is the check.
- `AuthScope::is_allowed_in_uefi` returns true only for `ReadOnly` and `BootSelect`. Spec 06's table says `RecoveryAccess` is "Launch only" in UEFI. This server follows the Rust helper and does not change `sbm-common`. A recovery boot that UEFI may apply is `BootCommand::BootTarget` for a reported target such as `sbm-core:slot-a`, scope `boot_select`. `BootCommand::BootRecovery` is signed with `recovery_access` and is not included in `GET /v1/devices/{id}/boot-policy`.
- Operator session tokens and the dashboard color tokens are local. They are not protocol types.
- Enrollment still accepts a TPM attestation blob and records that it was present or absent. It does not verify the quote.
- Passkey sign-in calls `Passkey::update_credential` and then `insert_passkey(...).ok()`. A duplicate credential id is swallowed, so the signature counter may not be written back. Registration of a second passkey for a new username is rejected; an admin can add a passkey only to the signed-in admin username.

## `sbm-lab`

`sbm-sim` is the device stand-in. State files (`*.sim.json`) hold the device seed and certificate and are gitignored. `SBM_DEV_BOOTSTRAP=1` creates operator `lab` and enables `POST /v1/auth/dev-login`. See [docs/SBM_LAB.md](docs/SBM_LAB.md). Screenshots from a headless browser against that login are in `docs/screenshots/`.

## Blockers for neighbors

- Agent 02 (`sbm-core` / `wayvnc`): the recovery path is an outbound device WebSocket and a same-origin browser socket. There is no public VNC port. `sbm-sim` speaks a minimal RFB 3.8 server (160×100, raw encoding, name `sbm-sim (no hardware)`) and a text banner that says it is not a PTY. A real `wayvnc` attachment is not implemented.
- Agent 01 (`sbm-uefi`): verify commands with the profile in Spec 06 §16.1, and only accept `read_only` and `boot_select` on the boot-policy poll. Do not treat a queued command as a reboot.
- PostgreSQL: `migrations-postgres/0001_init.sql` is SQL only. The running queries are SQLite. Do not claim a Postgres deployment from this tree.
- Storage plans and OS install plans return 403 `destructive_disabled` / `os_install_disabled`. There is no configuration flag that turns them on.

## Explicitly not done

No public listener was deployed. WebRTC, WireGuard, and Iroh are not started. The server does not call `SLSSetAppearanceThemeSwitchesAutomatically` or change the Mac's boot or SIP settings. Those are outside this repo.
