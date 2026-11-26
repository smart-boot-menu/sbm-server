# Backup

Stop the process, or use SQLite's online backup. Copying `sbm.db` alone while the server is running can drop the WAL.

The data directory is the whole server identity:

- `sbm.db`, and if they exist `sbm.db-wal` and `sbm.db-shm`
- `ca.cert.pem`, `ca.key.pem`
- `server.cert.pem`, `server.key.pem`
- `command.key.bin`, `command.pub`, `command.previous.pub`

`ca.key.pem`, `server.key.pem`, and `command.key.bin` are the secrets. They are mode `0600`. The directory is mode `0700`. A backup that omits `command.key.bin` can still serve the old database, and every enrolled device will reject new commands until you restore that seed or re-enroll them. A backup that omits `ca.key.pem` cannot issue or rotate device certificates.

## Stopped copy

```sh
# server is not running
cp -a data data-backup-$(date +%Y%m%d)
```

## Online SQLite backup

With the `sqlite3` CLI, while the server is up:

```sh
sqlite3 data/sbm.db ".backup data-backup.db"
```

Copy the key files as well. They change only when you rotate the command key or delete the directory and start fresh. Take them in the same backup as the database so a restore boots one consistent server.

## Restore

Stop the process. Replace the data directory with the backup. Start the process. Do not mix a database from one data directory with keys from another.

There is no export of enrollment token secrets. They are stored as hashes and shown once at creation. Devices keep their own private keys; those are not in this directory. `sbm-sim` state files are separate and are not part of the server backup.
