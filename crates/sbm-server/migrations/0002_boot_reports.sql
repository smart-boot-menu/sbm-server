CREATE TABLE boot_reports (
    device_id TEXT NOT NULL REFERENCES devices(id),
    attempt_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    confirmed_by TEXT NOT NULL,
    confirmed_at_unix INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, attempt_id)
);
