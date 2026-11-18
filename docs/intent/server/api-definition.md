# babel-api-definition

## Purpose

This crate is a pure data-definition library. It does no I/O and no async. It holds the wire contract between the endpoint agents and the babel server: registration, heartbeat, telemetry upload, and command-ack bodies, plus the `TelemetryEvent` enum. Both the server and the agent side depend on it. A change here is a shared protocol change. The crate also ships a `Secret<T>` wrapper. The wrapper keeps sensitive fields out of debug output.

## Design decisions

- `TelemetryEvent` is a tagged enum: `#[serde(tag = "kind", content = "data", rename_all = "snake_case")]`. Today it has the single variant `Process(ProcessTelemetryEvent)`. One JSON column on the server then holds any event kind.
- `Secret<T>` implements `Deserialize` but not `Serialize`. A field that serializes must opt in by name with `serialize_with = "expose_secret"`. The Debug output prints `[REDACTED: T]`.
- UUIDs are the correlation keys everywhere: event id, command id, agent uuid. The server deduplicates telemetry on the event UUID.
- Timestamps are `chrono::DateTime<Utc>`. They serialize as RFC3339. This matches the server's string database columns.
- `AgentTelemetry.schema_version` defaults to 1 when absent. The server stores it. The server checks nothing today.
- The crate builds with `#![deny(missing_docs)]`.

## Subtleties

- The `Secret` wrapper protects logs and debug output only. The PSK is plaintext in the JSON body.
- `redact_secret` writes the Debug string. Its output does not deserialize. Do not use it where a round trip must work.
- `expose_secret` exists twice: as a method on `Secret`, and as the free function in the serde attributes. A wrong `use` compiles the wrong one.
- The `Secret` `From` and `TryFrom` impls shuffle `Option` and `Result` in and out of the wrapper. They can change the serde shape without a message. Keep concrete types if you use them.
- To add a `TelemetryEvent` variant, update the three accessors (`event_id`, `occurred_at`, `event_type`). Then update every server-side match on parsed events.
- Nothing in this crate ties the uuid to the host info or the PSK. The server-side equality checks do that job.

## Key files

- `server/babel-api-definition/src/lib.rs` : request bodies, `TelemetryEvent` and friends, serde tagging.
- `server/babel-api-definition/src/secrets/mod.rs` : `Secret<T>`, `SerializableSecret`, `expose_secret`, `redact_secret`.
