# Lab use

`sbm-sim` is a user-space device. It enrolls with a one-time token, reports three targets (`linux:fedora`, `sbm-core:slot-a`, `windows:11`), and checks each command with the same signing profile as the server. Its inventory says it is simulated and includes no hardware serial. Heartbeats use component `sbm-sim`.

Nothing in this client reboots the host. An executed boot selection stores this result message:

`The simulator recorded the selection. No machine rebooted.`

## Bootstrap

```sh
export SBM_DEV_BOOTSTRAP=1
export SBM_BOOTSTRAP_SECRET='replace-with-a-long-secret'
cargo run -p sbm-server
```

`POST /v1/auth/dev-login` with `{ "secret": "..." }` returns a bearer token and sets the session cookies. `POST /v1/auth/dev-operators` (admin only) creates another operator and returns a bearer. Both are rate-limited and audited. With bootstrap off, dev-login answers 404.

The first real passkey registration is still the production admin path. Use that on any machine that is not a private lab.

## Simulator commands

```sh
sbm-sim enroll --server https://127.0.0.1:8443 --token TOKEN \
  --ca-pem ./data/ca.cert.pem --fingerprint sha256:... \
  --hostname lab-vm --state device.sim.json
sbm-sim once --state device.sim.json --mode uefi
sbm-sim once --state device.sim.json --mode core
sbm-sim run --state device.sim.json --mode uefi
sbm-sim identity --state device.sim.json
sbm-sim recovery --state device.sim.json --session SESSION --kind vnc
sbm-sim recovery --state device.sim.json --session SESSION --kind terminal
```

`once` reports targets, inventory, and a heartbeat, then pulls pending commands. `uefi` rejects `recovery_access` and still accepts a later `boot_select`. `core` can accept `BootRecovery`. Both modes reject storage plans and OS install plans. `run` repeats `once` every two seconds until ctrl-c. `identity` prints the client certificate and key for a tool such as curl. `recovery` dials the outbound tunnel. The RFB name is `sbm-sim (no hardware)`. The text banner says it is not a real PTY.

State files are mode `0600` and match `*.sim.json` in `.gitignore`. They contain the device private key.

## Screenshots

`tools/capture.sh` starts a debug server on `127.0.0.1:18443` and opens `https://localhost:18443`, enrolls `lab-vm`, and drives headless Chrome through the dashboard. Output goes to `docs/screenshots/`. The script trusts the generated CA by passing `--ignore-certificate-errors` to Chrome. It does not change the system trust store.

## What the lab is not

It is not `sbm-lab`'s QEMU firmware harness. It does not start OVMF, and it does not attach `wayvnc`. Those remain the other agents' machines.
