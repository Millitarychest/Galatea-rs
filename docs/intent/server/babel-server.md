# babel-server

## Purpose

The babel server is the central management server, built with axum and tokio. It handles agent enrollment, heartbeat and command delivery, and telemetry ingestion into SQLite. It also serves a server-side-rendered web console: fleet overview, per-agent timeline, event feed. The agents share the wire types through `babel-api-definition`.

## Architecture and data flow

- Startup (`main.rs`): the `-d/--db-path` argument is required. The optional `-p/--port` argument defaults to port 80 on `0.0.0.0`. The SQLite pool (r2d2, max 16) and the global `AppContext` live in `OnceLock` globals. A monitor task ticks every 30 s. It marks agents offline when the last heartbeat is older than 90 s. The bind uses a retry loop with exponential backoff. The code does not enable TLS.
- Routes: web pages (`/`, `/agents/{id}`, `/events`), agent API (`/api/v1/agents/register`, `.../{id}/heartbeat`, `.../{id}/telemetry`, `.../{id}/commands/{cmd_id}/ack`), and `/static` served from `<exe_dir>/web/static`.
- Database: idempotent `CREATE TABLE IF NOT EXISTS` statements for `agents`, `commands`, `telemetry_events`, and the singleton `server_config`. A command flows pending -> delivered -> completed. Telemetry inserts use `INSERT OR IGNORE` on the `event_id` primary key. The server returns accepted and rejected counts.
- The web tier renders by placeholder substitution into HTML templates embedded with `include_str!`. A shared layout wraps each page.

## Design decisions

- Auth is hand-rolled: each agent request carries `AgentAuthentication { psk }`. Each handler compares it against the hardcoded constant `galatea_secret` in `config.rs`. The path id must equal the body uuid. There is no middleware. The checks sit in each handler.
- Command delivery is poll-based: the heartbeat returns all pending commands. It marks them delivered at once. The ack endpoint then marks one command completed.
- Two secrets exist. The server enforces one: it generates a 5-word passphrase from an embedded wordlist and stores it as the "Agent Registration Secret". The web UI shows it. No route validates it. The API validates only the PSK.
- Telemetry dedup is idempotent on the event UUID primary key.
- The database stores times as RFC3339 strings. The staleness query compares `COALESCE(last_heartbeat_at, registered_at)`.

## Subtleties

- Command delivery is at-least-once. The ack is fire-and-forget: the ack handler ignores `success` and `message`. An agent that dies between heartbeat and ack leaves the command stuck in `delivered`. Nothing re-queues it.
- No code writes `AgentStatus::Stale`. The dashboard counts it. The monitor flips online -> offline only. Expect a stale count of zero.
- The offline-timeout conversion falls back to 90 s on error. The fallback equals the configured value today. The heartbeat interval, the timeout, and the fallback are coupled.
- The web tier re-parses stored `payload_json` into a `TelemetryEvent` to extract fields. A new telemetry variant needs handling there. An unhandled variant falls into the generic row path.
- `static/` is compile-time: the wordlist goes in through `include_str!` from `CARGO_MANIFEST_DIR`. `web/` is a runtime expectation next to the executable. The TLS certs in `static/` are not wired into the bind.
- `fetch_persisted_config` swallows all errors and persists a new secret. A temporary database fault then resets the enrollment secret shown in the UI.
- The ack handler's error message says "Failed to register agent". It is a copy-paste remnant.

## Key files

- `server/babel-server/src/main.rs` : router, startup order, monitor, bind and retry loop.
- `server/babel-server/src/state.rs` : `OnceLock` globals and the persisted registration secret.
- `server/babel-server/src/db/` : schema, pools, agent, command and telemetry queries.
- `server/babel-server/src/routes/api.rs` : the four agent endpoints with PSK and uuid checks.
- `server/babel-server/src/routes/` : server-rendered console pages.
- `server/babel-server/src/config.rs` : port, PSK, heartbeat and timeout constants.
