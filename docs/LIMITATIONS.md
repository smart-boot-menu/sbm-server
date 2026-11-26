# Limitations

These are the boundaries of the 0.1 tree. They are not bugs that the tests hide.

## Verified

The automated tests run against the real server and `sbm-sim`. They check enrollment, signed next-boot, the published command-signing vectors, rejection of a bad signature, replay, expiry, a repeated terminal ack, revocation and cross-device command isolation, UEFI scope, destructive and OS-install refusal, CSRF, audit immutability, the recovery tunnel banner, an unauthenticated recovery socket, and `POST /v1/devices/{id}/boot-success`. The passkey row update is a SQL unit test. The dashboard is the SvelteKit build embedded in the binary. Screenshots in `docs/screenshots/` were taken from that UI against a local process. Measurements in the research repo, when present, are from a release binary on this machine and say so.

## Not verified

- No run inside `sbm-uefi` or `sbm-core`. The simulator is a user-space client with a QEMU-like inventory and three sample targets. It does not touch firmware.
- `wayvnc` is not connected. A recovery session is stored as `outbound-tunnel` with `desktop: "not-attached"`. The framebuffer is still drawn by `sbm-sim` (160×100, raw RFB). The text channel is a banner, not a PTY. `sbm-core` does not yet dial this server.
- TPM quotes are recorded as present or absent. They are not validated.
- Passkey login persists a changed credential. The suite does not drive a software authenticator through the WebAuthn ceremony.
- PostgreSQL migrations are not applied to a Postgres server.
- Passkey authenticator attestation is whatever `webauthn-rs` 0.6.2 checks. This tree does not add an authenticator allow-list.
- WebRTC, WireGuard, and Iroh are not implemented.
- The content security policy allows the embedded bootstrap script by hash. It does not allow `unsafe-eval`. noVNC 1.7.0 is bundled for the recovery page. A future codec that needs `wasm-unsafe-eval` is not enabled.
- Startup and request timings are whatever the archived measurement says. The engineering targets in `docs/testing/benchmarks.md` are targets, not results from this server.
- `docker build` was not run. The Dockerfile and Compose file describe the image. No image was published.

## Product limits that are intentional

- The server is not required to boot.
- Queued is not executed. The UI says: "The command is queued. The device has not applied it, and no reboot has happened."
- An executed simulator result says: "The simulator recorded the selection. No machine rebooted."
- Remote destructive storage and OS install cannot be turned on.
- A compromised server must not gain arbitrary code execution in UEFI. The command set is the `BootCommand` enum, checked against reported targets and three command-line presets.
