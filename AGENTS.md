# AGENTS.md — `sbm-server`

Follow the universal Smart Boot Menu agent rules in [`smart-boot-menu/.github/AGENTS.md`](https://github.com/smart-boot-menu/.github/blob/main/AGENTS.md) (locally `../.github/AGENTS.md`).

## Assigned Repository & Role

- **Repository:** `smart-boot-menu/sbm-server`
- **Primary Dependencies & Specs:** `sbm-common`, `docs/specifications/02, 06, 07`, `ADR-007`, `docs/threat-model/README.md`

## Responsibilities (What You Own)

- Explicit opt-in device enrollment via short-lived single-use enrollment tokens + `rcgen` mTLS certificate issuance.
- Strict RBAC (`read_only`, `boot_select`, `recovery_access`, `os_install`, `storage_destructive`, `admin`) with Passkey step-up confirmation for destructive operations and immutable audit log.
- Signed, replay-protected `CommandEnvelope` API for `sbm-uefi`, `sbm-core`, and `sbm-agent`.
- Embedded SvelteKit dashboard with `@novnc/novnc` (`MPL-2.0`) and `xterm.js` proxied to `sbm-core`.

## Strict Boundaries (Do NOT Duplicate or Violate)

Do NOT make `sbm-server` mandatory for local SBM use. Do NOT link AGPL-3.0 libraries. Do NOT redefine `sbm-common` protocol types.

## Engineering & Performance Targets

Zero-config SQLite startup in < 1 s; low idle RAM (< 64 MiB); strict sub-50 ms API response for `sbm-uefi` boot-policy polling.

*(Targets are goals, not claims; follow `../docs/testing/benchmarks.md` and archive real measurements in `../research/validation/evidence/`.)*

## Security, Testing & Interface Coordination

- Enforce all invariants in `../docs/threat-model/README.md` (offline-first, no secrets committed, bounded timeouts, safe storage plans).
- Run formatting, clippy, unit tests, and integration hooks before committing.
- Never silently diverge from `sbm-common` types or `docs/specifications/`; follow the Interface Change Protocol in `../.github/agent-reference.md`.
