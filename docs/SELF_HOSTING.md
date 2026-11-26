# Self-hosting

Run one process on a machine you administer. The default bind is `127.0.0.1:8443`. Opening that to a network is a choice you make with `SBM_BIND` and a firewall. This repository does not ship a public deployment, an account service, or paid infrastructure.

## First start

```sh
cd web && npm ci && npm run build && cd ..
cargo build --release -p sbm-server
./target/release/sbm-server
```

The first start writes a private CA, a server certificate for `localhost` and `127.0.0.1`, and a separate Ed25519 command key under `./data`. Later starts reuse those files. Import `data/ca.cert.pem` into the browsers that will open the console, or terminate TLS at a reverse proxy you already trust and set `SBM_PUBLIC_ORIGIN` to that `https` origin.

Register a passkey from the console. The first successful registration is the admin. After that, only an admin can add a passkey, and only for that admin's username. Lab bootstrap is documented in [SBM_LAB.md](SBM_LAB.md) and should stay off on a machine other people can reach.

## Container

From this directory:

```sh
docker compose up --build
```

The image build clones `smart-boot-menu/sbm-common` at `28d38450954f0b93815e12f31da92370b13a7462` and compiles the server. The data volume holds the database and the keys. Back it up with the procedure in [BACKUP.md](BACKUP.md). The published port is localhost only. To use a hostname other than `localhost`, set `SBM_PUBLIC_ORIGIN` and `SBM_RP_ID` together and bring your own certificate if you are not using the generated one. The generated certificate names `localhost` and `127.0.0.1` only.

## What you operate

- Sessions last 12 hours by default and do not slide. Signing out deletes the server-side hash.
- Cookie mutations need the `X-CSRF-Token` header. The dashboard reads the non-HttpOnly `sbm_csrf` cookie and sends it. Bearer clients skip CSRF.
- Enrollment tokens last 10 minutes by default, are single-use, and are stored as a SHA-256 hash.
- Devices poll `GET /v1/devices/{id}/boot-policy` with their certificate. Unsigned policy JSON does not change the boot. A signed envelope does, after the device accepts it.
- Command history distinguishes requested, delivered, accepted, executed, failed, rejected, and expired. Creating a row does not mean the machine rebooted.
- Audit rows cannot be updated or deleted. The SQLite trigger aborts those statements.
- Rotate the command key only when you can re-enroll every device. They keep the previous verify key until they enroll again.

## PostgreSQL

`migrations-postgres/0001_init.sql` is the same shape as the SQLite migration. The 0.1 process does not open a Postgres connection. Do not point operators at it as a working store.
