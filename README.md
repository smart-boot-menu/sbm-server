# Optional self-hosted management server (`sbm-server`)

`sbm-server` is an optional console for Smart Boot Menu computers. Local boot does not call it. A machine with no network still boots from its own policy.

This tree runs locally: the Rust server, the embedded SvelteKit dashboard, and `sbm-sim`, a labeled simulator that enrolls, checks signed commands, and reports what it did. It does not reboot the computer it runs on. Remote destructive storage and OS install are refused. Nothing here deploys a public service.

## Run it locally

Sibling checkout, pinned by the tests and the container build:

`../sbm-common` at `4b432228caae40479d28c8f6f48fb7cb9cc6df85`

```sh
cd web && npm ci && npm run build && cd ..
cargo run -p sbm-server
```

The process listens on `https://127.0.0.1:8443` and creates `./data` (mode `0700`) on first start. Trust `data/ca.cert.pem` in the browser, or use the lab bootstrap below. Open the printed URL.

`cargo build` embeds `web/build`. If that directory has no `index.html`, the binary serves a placeholder that says the dashboard was not built.

Lab bootstrap is off unless you set both of these. The secret must be at least 16 characters. It is not a production login.

```sh
export SBM_DEV_BOOTSTRAP=1
export SBM_BOOTSTRAP_SECRET='replace-with-a-long-secret'
cargo run -p sbm-server
```

The dashboard then offers "Sign in for the lab". The username is `lab`. Passkeys remain the operator login: the first registration becomes the admin.

## Simulated device

```sh
cargo run -p sbm-sim -- enroll \
  --server https://127.0.0.1:8443 \
  --token TOKEN \
  --ca-pem ./data/ca.cert.pem \
  --fingerprint sha256:FINGERPRINT \
  --hostname lab-vm \
  --state device.sim.json
cargo run -p sbm-sim -- once --state device.sim.json --mode uefi
```

The enrollment page prints that command after you create a token. The token is shown once. Queuing a next boot does not reboot anything. The simulator's executed result is "The simulator recorded the selection. No machine rebooted."

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

## Container

`docker compose up --build` publishes the server on `127.0.0.1:8443` only. Inside the container the process listens on `0.0.0.0:8443` so the published port can reach it. The image clones `sbm-common` at the revision above. Dev bootstrap stays off. See [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md).

## What this release does not do

Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) before treating a behavior as verified. PostgreSQL SQL is shipped and not executed. `wayvnc` is not connected. A recovery picture from `sbm-sim` is a painted rectangle, not a desktop. The command key and the TLS CA are different keys. A compromised server can sign a boot selection for a target the device already reported. It cannot send a shell command or an arbitrary kernel command line into UEFI.

## Docs

- [HANDOFF.md](HANDOFF.md) — interface gaps and blockers for the other agents
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
- [docs/SECURITY.md](docs/SECURITY.md)
- [docs/BACKUP.md](docs/BACKUP.md)
- [docs/SBM_LAB.md](docs/SBM_LAB.md)
- [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)
- [openapi.yaml](crates/sbm-server/openapi.yaml) — also served at `/v1/openapi.yaml`

Dashboard colors live in `web/src/lib/tokens.css`. They are not a `sbm-common` type.

Original code is [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE). The embedded noVNC client is MPL-2.0. xterm.js is MIT.
