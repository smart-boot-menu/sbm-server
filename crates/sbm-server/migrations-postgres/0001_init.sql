-- PostgreSQL translation of the SQLite schema.
-- The 0.1 query path speaks SQLite only. This file is the migration to apply
-- when a later runtime grows a Postgres pool. It is not executed by `sbm-server` 0.1.

CREATE TABLE operators (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE operator_roles (
    operator_id TEXT NOT NULL REFERENCES operators(id),
    role TEXT NOT NULL,
    PRIMARY KEY (operator_id, role),
    CHECK (role IN ('read_only', 'boot_select', 'recovery_access', 'os_install', 'storage_destructive', 'admin'))
);

CREATE TABLE webauthn_credentials (
    credential_id TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL REFERENCES operators(id),
    passkey_json TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL REFERENCES operators(id),
    csrf_token TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL
);

CREATE TABLE enrollment_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL REFERENCES operators(id),
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    used_by_device TEXT,
    ca_fingerprint TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES operators(id),
    public_key_hex TEXT NOT NULL,
    platform_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('enrolled', 'revoked')),
    created_at BIGINT NOT NULL,
    revoked_at BIGINT,
    revoke_reason TEXT,
    cert_pem TEXT NOT NULL,
    cert_sha256 TEXT NOT NULL,
    last_seen_at BIGINT,
    last_sequence_issued BIGINT NOT NULL DEFAULT 0,
    simulated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE device_certs (
    cert_sha256 TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    public_key_hex TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT
);

CREATE TABLE device_grants (
    device_id TEXT NOT NULL REFERENCES devices(id),
    operator_id TEXT NOT NULL REFERENCES operators(id),
    role TEXT NOT NULL,
    PRIMARY KEY (device_id, operator_id, role)
);

CREATE TABLE boot_targets (
    device_id TEXT NOT NULL REFERENCES devices(id),
    target_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    reported_at BIGINT NOT NULL,
    PRIMARY KEY (device_id, target_id)
);

CREATE TABLE boot_policies (
    device_id TEXT PRIMARY KEY REFERENCES devices(id),
    policy_json TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE commands (
    command_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    sequence BIGINT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'requested', 'delivered', 'accepted', 'executed', 'failed', 'rejected', 'expired'
    )),
    required_scope TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    requested_by TEXT REFERENCES operators(id),
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    delivered_at BIGINT,
    accepted_at BIGINT,
    finished_at BIGINT,
    result_code TEXT,
    result_message TEXT,
    UNIQUE (device_id, sequence)
);

CREATE INDEX commands_device_state ON commands (device_id, state);

CREATE TABLE audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at_unix BIGINT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    device_id TEXT,
    detail_json TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION sbm_audit_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit log is immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW EXECUTE FUNCTION sbm_audit_immutable();

CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION sbm_audit_immutable();

CREATE TABLE hardware_inventory (
    device_id TEXT PRIMARY KEY REFERENCES devices(id),
    inventory_json TEXT NOT NULL,
    reported_at BIGINT NOT NULL
);

CREATE TABLE device_status (
    device_id TEXT PRIMARY KEY REFERENCES devices(id),
    component TEXT NOT NULL,
    software_version TEXT NOT NULL,
    mode TEXT NOT NULL,
    last_heartbeat_at BIGINT NOT NULL,
    detail_json TEXT NOT NULL
);

CREATE TABLE recovery_sessions (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    operator_id TEXT NOT NULL REFERENCES operators(id),
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    closed_at BIGINT
);
