# Security

The server is a management plane. It is not on the boot path. A machine that cannot reach it uses the last policy the device stored locally. That unsigned policy is advisory. Only a signed command envelope changes the next boot, and only after the device checks it.

## What the process enforces

- TLS with a private CA. The CA and the server certificate are ECDSA P-256, named `localhost` and `127.0.0.1`. Device certificates stay Ed25519, matching the key the device generated. The handshake offers X25519 and P-256, not the ML-KEM hybrid, so clients that do not speak that group can still connect. Issued certificates carry an authority key identifier. Clients that enroll pin the CA fingerprint from the token bundle before they send the token.
- Device identity is the Ed25519 key the device generated. The certificate's SAN URI is `urn:sbm:device:{uuid}` and the certificate hash is the lookup key. A MAC address is not read and is not stored. JSON that contains a `mac` field is ignored.
- Optional client certificates so a browser and a device share one listener. A route that needs a device rejects a request with no certificate. A revoked certificate is rejected. A revoked device may still fetch a signed `RevokeEnrollment` and acknowledge it.
- Command envelopes use Spec 06 §16.1. The server allocates the sequence with a compare-and-swap before it signs. A bad signature, the wrong device, a replay, or an expiry does not advance `last_sequence`. A signature that verifies, then fails scope or target checks, does advance, so the device cannot be asked to retry that sequence.
- The UEFI poll returns only `boot_select` boot commands. `BootRecovery`, storage plans, and OS install plans are not on that poll. Storage and OS install endpoints always answer 403. There is no switch that enables them.
- Targets and command-line presets are checked before a sequence is reserved. Unknown targets and raw command lines are rejected. Remote command lines are limited to `quiet`, `verbose`, and `nomodeset`.
- Operators use passkeys. A login that changes the credential writes the updated passkey JSON before the session is issued. A failed write does not issue a session. An unchanged signature counter does not rewrite the row. Lab bootstrap is a separate, opt-in, rate-limited, audited path. Sessions store only the SHA-256 of a 32-byte token. Cookie mutations require `X-CSRF-Token`. Session lifetime is absolute.
- Authorization: the role is required or the answer is 403. A role without ownership or a grant is 404, so device ids are not enumerated. `admin` sees every device. `storage_destructive` is not implied by `admin` and is not granted.
- Rate limits, per client IP: authentication 20/minute, enrollment 30/minute, everything else 600/minute. Bodies are limited to 256 KiB. Requests time out at 30 seconds.
- Security headers include a content security policy without `unsafe-inline` or `unsafe-eval`. The dashboard's bootstrap script is allowed by a SHA-256 hash computed from the embedded `index.html`.
- The audit log has SQLite triggers that abort `UPDATE` and `DELETE`.
- Recovery does not open a VNC port. The device dials out. The browser attaches on the same origin with its session cookie. The session id is not placed in the query string for the browser.

## What this does not claim

- TPM attestation is not verified. Enrollment records that a blob was present or absent. Quote validation is not implemented.
- A full WebAuthn ceremony is not in the automated suite. The counter write is the SQL update plus the login path in [HANDOFF.md](../HANDOFF.md). There is no authenticator allow-list.
- A stolen `command.key.bin` lets the thief sign boot selections for known targets until you rotate the key and re-enroll. It does not give them a shell in UEFI.
- The simulator's framebuffer and text pane are not a remote desktop of a real machine.
- PostgreSQL is not a verified runtime.
- Host firewall, disk encryption, and who can read `./data` are your responsibility. The file modes are `0700` and `0600`.
