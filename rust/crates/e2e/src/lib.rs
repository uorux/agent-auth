#![forbid(unsafe_code)]
//! End-to-end tests of agent-auth: the real `agent-auth-server`,
//! `agent-auth` and `agent-auth-mcp` binaries against a fresh Postgres
//! database, with GitHub and OpenRouter faked by local servers. Everything
//! is in `tests/e2e`; this library is empty.
