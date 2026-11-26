# Configuration

The process reads an optional TOML file from `SBM_CONFIG`, then lets environment variables replace individual fields. See `config.example.toml`. A missing file is fine. The defaults listen on localhost and turn lab bootstrap off.

| TOML key | Environment | Default | Bounds |
|---|---|---|---|
| `bind` | `SBM_BIND` | `127.0.0.1:8443` | socket address |
| `data_dir` | `SBM_DATA_DIR` | `./data` | directory, created mode `0700` |
| `public_origin` | `SBM_PUBLIC_ORIGIN` | `https://localhost:8443` | `https://` unless insecure HTTP is on |
| `rp_id` | `SBM_RP_ID` | `localhost` | WebAuthn relying party id |
| `dev_bootstrap` | `SBM_DEV_BOOTSTRAP` | off | `1`, `true`, `TRUE`, or `yes` |
| `bootstrap_secret` | `SBM_BOOTSTRAP_SECRET` | unset | at least 16 characters when bootstrap is on |
| `enrollment_ttl_seconds` | `SBM_ENROLLMENT_TTL_SECONDS` | 600 | 30–900 |
| `boot_command_ttl_seconds` | `SBM_BOOT_COMMAND_TTL_SECONDS` | 43200 | 30–86400 |
| `recovery_command_ttl_seconds` | `SBM_RECOVERY_COMMAND_TTL_SECONDS` | 1800 | 30–86400 |
| `session_ttl_seconds` | `SBM_SESSION_TTL_SECONDS` | 43200 | 300–86400 |
| `log_format` | `SBM_LOG_FORMAT` | `text` | `json` selects JSON tracing |
| `insecure_http` | `SBM_INSECURE_HTTP` | off | plain HTTP. Device enrollment still needs HTTPS for mTLS |

The database file is `data_dir/sbm.db`. Key files in the same directory are mode `0600`: `ca.key.pem`, `server.key.pem`, `command.key.bin`. Certificates and public keys are `ca.cert.pem`, `server.cert.pem`, `command.pub`, and after a rotation `command.previous.pub`.

`SBM_DEV_BOOTSTRAP` without a long `SBM_BOOTSTRAP_SECRET` refuses to start (exit 2). The secret comparison is SHA-256, compared in constant time. Prefer the environment over the TOML file so the secret is not left in a config that gets copied.

`public_origin` is the origin embedded in enrollment bundles and the WebAuthn configuration. Browsers must open that origin. `rp_id` must be a registrable suffix of it (`localhost` for `https://localhost:8443`). `allow_any_port` is on, so a non-default port on that host still matches.

Inside Compose, `SBM_BIND` is `0.0.0.0:8443` and the published port is `127.0.0.1:8443`. That is the container's own interface, not a public bind on the host.

`SBM_INSECURE_HTTP=1` is for a private lab in front of your own TLS terminator. Cookies are then not marked `Secure`. Do not expose that mode.

Exit 2 is a configuration error. Exit 1 is a startup failure after the config parsed (bind, database, or TLS material).
