# Handoff — Agent 05 (`sbm-server`)

The server is optional. Ordinary local boot does not contact it. Shared structs come from `sbm-common` `4b432228caae40479d28c8f6f48fb7cb9cc6df85` (`sbm-protocol`, `sbm-types`). This repo does not fork those structs.

Signing bytes are `sbm_protocol::command_signing_preimage`. `sbm-wire` calls that function and checks it against `sbm-common/test-vectors/command-signing.v1.json` and against `serde_json` compact output. Spec 06 §16.1 names the profile and the wire field `signature_ed25519_hex`.

There is no Agent 10 tree, prompt, or handoff. The scope discrepancy was Spec 06's table cell for `RecoveryAccess` ("Launch only") against §16 rule 5 and `AuthScope::is_allowed_in_uefi`. The table now matches the helper: UEFI accepts `read_only` and `boot_select` only. This server does not change `is_allowed_in_uefi`. A recovery target UEFI may apply is `BootCommand::BootTarget` for a reported target such as `sbm-core:slot-a`, scope `boot_select`. `BootCommand::BootRecovery` is signed with `recovery_access` and is not on `GET /v1/devices/{id}/boot-policy`.

## Verified here

`cargo test --workspace` covers the signing profile and the published vectors, the enroll → report targets → queue next boot → device ack path, UEFI rejection of a `recovery_access` command without blocking a later boot selection, a bad verify key and an expired command (neither advances `last_sequence`), a repeated terminal ack, revocation (the revoked device's pending list is only `revoke_enrollment`, another device cannot read it, a later boot command is 409, and boot-policy is empty), cross-device ack, role scope, CSRF, audit immutability, a MAC address ignored as identity, an authenticated recovery tunnel whose first bytes are `RFB 003.008\n`, an unauthenticated recovery socket rejected with 401, and another device rejected from that tunnel. `POST /v1/devices/{id}/boot-success` stores one `BootSuccessReport` per attempt, repeats the same report, and returns 409 when the details differ. It does not queue a command or reboot. The dashboard shell is the built SvelteKit app, not the placeholder.

Passkey login no longer inserts the existing credential and swallows the error. When `Passkey::update_credential` reports a change, the row is updated and a failed write does not issue a session. An unchanged counter (the usual synced passkey) does not rewrite the row. The SQL replacement is a unit test. A full WebAuthn ceremony is not in this suite.

Those tests use `sbm-sim`. They do not boot firmware and they do not reboot the host. `cargo clippy --all-targets -- -D warnings` is clean. Release-binary startup and request timings from this machine are in `../research/validation/evidence/sbm-server-2026-11-26.md`. Those timings are not the UEFI frame targets.

## Unresolved

- Enrollment records whether a TPM attestation blob was present. It does not verify the quote. Do not describe attestation as verified.
- The recovery session kind is `outbound-tunnel`. The open response says `desktop: "not-attached"` and `transport: "device-initiated-websocket"`. `sbm-core` leaves `wayvnc` disabled until an operator enables it, and then it binds `127.0.0.1` with a generated password. No artifact speaks this server's outbound WebSocket, so the framebuffer is still `sbm-sim` (160×100, raw RFB, name `sbm-sim (no hardware)`). The text channel is a banner, not a PTY. The dashboard was not rewritten.
- Storage plans and OS install plans return 403 `destructive_disabled` / `os_install_disabled`. There is no configuration flag that turns them on.
- PostgreSQL: `migrations-postgres/0001_init.sql` is SQL only. The running queries are SQLite. Do not claim a Postgres deployment from this tree.
- `docker build` was not run. No image was published. No public listener was deployed.
- A stolen `command.key.bin` can sign boot selections for known targets until the key is rotated and devices enroll again. It does not give a shell in UEFI.
- Passkey authenticator attestation is whatever `webauthn-rs` 0.6.2 checks. This tree does not add an authenticator allow-list. Registration of a second passkey for a new username is rejected; an admin can add a passkey only to the signed-in admin username.
- WebRTC, WireGuard, and Iroh are not started.

## `sbm-agent`

`POST /v1/devices/{id}/boot-success` accepts a schema 1.0 `BootSuccessReport` from the enrolled device's mTLS certificate. `attempt_id` is cleaned text, `target_id` must be a boot target id, and `confirmed_at_unix` must be positive. The same `(device_id, attempt_id)` with the same details is idempotent. Different details are 409. Another device's certificate is 404. The response says the report was stored and that no reboot was requested. The agent is not implemented in this repo, and local boot does not require it.

## `sbm-lab`

`sbm-sim` is the device stand-in. State files (`*.sim.json`) hold the device seed and certificate and are gitignored. `SBM_DEV_BOOTSTRAP=1` creates operator `lab` and enables `POST /v1/auth/dev-login`. See [docs/SBM_LAB.md](docs/SBM_LAB.md). Screenshots from a headless browser against that login are in `docs/screenshots/`.

## Blockers for neighbors

- Agent 02 (`sbm-core` / `wayvnc`): when a recovery image can open an outbound WebSocket to `GET /v1/devices/{id}/recovery/tunnel` with the device certificate, this server will relay those bytes. Until that artifact exists, the session stays `not-attached` and the simulator paints the framebuffer. Do not publish a VNC port.
- Agent 01 (`sbm-uefi`): verify commands with `sbm_protocol::command_signing_preimage` (Spec 06 §16.1). Accept only `read_only` and `boot_select` on the boot-policy poll. Do not treat a queued command as a reboot.
- Agent 08 (`sbm-agent`): the boot-success route above is the server side of an optional confirmation. It must not be required to boot, and it must not partition or install.

## Explicitly not done

The server does not call `SLSSetAppearanceThemeSwitchesAutomatically` or change the Mac's boot or SIP settings. Those are outside this repo.
