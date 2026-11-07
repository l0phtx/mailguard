# Changelog

## v1.0.0 - 2026-11-07

- SPF checks: record count, `all` qualifier, recursive include/redirect walk with the 10-lookup limit, loop and syntax detection
- DKIM checks: concurrent probing of 30+ provider selectors, RSA and Ed25519 key size, revoked keys
- DMARC checks: policy, `pct`, `sp`, `rua`, and inherited policies through a DNS tree walk
- MX and null MX detection
- A-F grading, table/JSON/CSV output and `-fail-under` for CI
- Concurrent worker pool with per-query timeouts and Ctrl+C cancellation
