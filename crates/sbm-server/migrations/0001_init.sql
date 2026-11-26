CREATE TABLE operators (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
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
    created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL REFERENCES operators(id),
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);

CREATE TABLE enrollment_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL REFERENCES operators(id),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
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
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revoke_reason TEXT,
    cert_pem TEXT NOT NULL,
    cert_sha256 TEXT NOT NULL,
    last_seen_at INTEGER,
    last_sequence_issued INTEGER NOT NULL DEFAULT 0,
    simulated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE device_certs (
    cert_sha256 TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    public_key_hex TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
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
    reported_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, target_id)
);

CREATE TABLE boot_policies (
    device_id TEXT PRIMARY KEY REFERENCES devices(id),
    policy_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE commands (
    command_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    sequence INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'requested', 'delivered', 'accepted', 'executed', 'failed', 'rejected', 'expired'
    )),
    required_scope TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    requested_by TEXT REFERENCES operators(id),
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    delivered_at INTEGER,
    accepted_at INTEGER,
    finished_at INTEGER,
    result_code TEXT,
    result_message TEXT,
    UNIQUE (device_id, sequence)
);

CREATE INDEX commands_device_state ON commands (device_id, state);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at_unix INTEGER NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    device_id TEXT,
    detail_json TEXT NOT NULL
);

CREATE INDEX audit_log_recent ON audit_log (id DESC);

CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit log is immutable');
END;

CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit log is immutable');
END;

CREATE TABLE hardware_inventory (
    device_id TEXT PRIMARY KEY REFERENCES devices(id),
    inventory_json TEXT NOT NULL,
    reported_at INTEGER NOT NULL
);

CREATE TABLE device_status (
    device_id TEXT PRIMARY KEY REFERENCES devices(id),
    component TEXT NOT NULL,
    software_version TEXT NOT NULL,
    mode TEXT NOT NULL,
    last_heartbeat_at INTEGER NOT NULL,
    detail_json TEXT NOT NULL
);

CREATE TABLE recovery_sessions (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    operator_id TEXT NOT NULL REFERENCES operators(id),
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    closed_at INTEGER
);
