# `sbm-server` implementation plan (SBM 0.1)

The plan below is what this tree implements. Behavior that is actually checked is listed in [LIMITATIONS.md](LIMITATIONS.md) and [../HANDOFF.md](../HANDOFF.md). The server is optional. Local boot does not call it. Shared types come from `sbm-protocol` / `sbm-types`. Command bytes follow Spec 06 §16.1 (Command Signing Profile v1). No second copy of those structs lives in this repo.

## Runtime

- One Rust binary (`axum` 0.8.9, `tokio` 1.54.1, `sqlx` 0.9.1, `rustls` 0.23.46).
- Default store: one SQLite file, WAL, foreign keys, data directory mode `0700`, key files mode `0600`.
- PostgreSQL migrations ship beside the SQLite migrations. The 0.1 query path is SQLite. PostgreSQL is not claimed as a verified runtime until those queries are executed against it.
- Listen address defaults to `127.0.0.1:8443`. TLS certificate and CA are generated on first start and reused.
- The SvelteKit 3.4.0 app is built with `adapter-static` and embedded. No external UI host.

## Identity

- Operators: WebAuthn passkeys (`webauthn-rs` 0.6.2). The first successful registration becomes the admin. After that, only an admin can register another passkey.
- `SBM_DEV_BOOTSTRAP=1` plus a long `SBM_BOOTSTRAP_SECRET` enables `POST /v1/auth/dev-login` for `sbm-lab`. It is off unless set. It is rate-limited and audited. It is not a second production authenticator.
- Devices: one-time enrollment token (hashed at rest, ≤ 15 minutes, single use, bound to the CA fingerprint). The device generates an Ed25519 key. The server issues an mTLS certificate whose subject public key is that key and whose SAN URI is `urn:sbm:device:{uuid}`. A MAC address is not read and is not an identity.
- Rotation retires the previous certificate. Revocation rejects the certificate on the next request. A revoked device may still fetch a single signed `RevokeEnrollment` command.
- The server command key is a separate Ed25519 key from the TLS CA. Devices pin the verify key from `EnrollmentResponse`.

## Commands

Operator APIs accept a `BootCommand`, not a shell string and not a pre-signed envelope. The server chooses the scope:

- boot target, reboot, shutdown, firmware setup → `boot_select`
- boot recovery → `recovery_access`
- storage plans and OS install plans → refused in this release (`storage_destructive` and `os_install` stay off)

States are `requested`, `delivered`, `accepted`, `executed`, `failed`, `rejected`, and `expired`. Creating a row does not mark it executed. The UEFI poll (`GET /v1/devices/{id}/boot-policy`) returns only `read_only` / `boot_select` boot envelopes. Unsigned policy JSON is advisory.

`sbm-sim` is a labeled simulator. It enrolls, reports targets, verifies the signing profile, refuses replays, expiry, cross-device envelopes, bad signatures, and non-UEFI scopes, then reports the real ack state.

## Remote desktop

Recovery sessions are authorized records plus an outbound device WebSocket. The browser noVNC client attaches to that session through the server. The process does not open a public VNC port. WebRTC, WireGuard, and Iroh are out of this release.

## Tests that must pass before the branch is done

Unauthorized device, expired command, replayed command, cross-device command, tampered signature, destructive plan refused, cookie mutation without CSRF, and a full enroll → report targets → next boot → accept → execute flow whose history matches those states.
