# Optional Self-Hosted Management Server & Dashboard (`sbm-server`)

Single-binary Rust self-hosted management server (`axum 0.8.9`, `tokio 1.54.1`, `sqlx 0.9.1` SQLite WAL + PostgreSQL) with embedded `SvelteKit 3.4.0` web dashboard, Passkeys (`webauthn-rs`), mTLS, Ed25519 command signing, and `noVNC`/`xterm.js` tunneling.

> **Project Status:** Phase 0 initialized — ready for dedicated engineering agent implementation targeting **SBM 0.1**.

## Scope & Responsibilities

- Explicit opt-in device enrollment via short-lived single-use enrollment tokens + `rcgen` mTLS certificate issuance.
- Strict RBAC (`read_only`, `boot_select`, `recovery_access`, `os_install`, `storage_destructive`, `admin`) with Passkey step-up confirmation for destructive operations and immutable audit log.
- Signed, replay-protected `CommandEnvelope` API for `sbm-uefi`, `sbm-core`, and `sbm-agent`.
- Embedded SvelteKit dashboard with `@novnc/novnc` (`MPL-2.0`) and `xterm.js` proxied to `sbm-core`.

## Canonical Documentation & Contracts

- Central coordination & roadmap: [`smart-boot-menu/sbm`](https://github.com/smart-boot-menu/sbm)
- Normative specifications & ADRs: [`smart-boot-menu/docs`](https://github.com/smart-boot-menu/docs)
- Primary-source technical research: [`smart-boot-menu/research`](https://github.com/smart-boot-menu/research)
- Shared Rust types & JSON Schemas: [`smart-boot-menu/sbm-common`](https://github.com/smart-boot-menu/sbm-common)
- Agent guide: [AGENTS.md](AGENTS.md)

## License

Original code and documentation in this repository are dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), subject to third-party licensing requirements for bundled external components.
