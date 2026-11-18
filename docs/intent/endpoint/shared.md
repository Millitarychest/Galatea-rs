# galatea-shared

## Purpose

`galatea-shared` is a `no_std` crate. It holds all wire definitions for the endpoint components:

1. Agent to kernel sensor driver. The channel is a buffered IOCTL.
2. Agent to kernel filter driver. The channel is a minifilter communication port.
3. Agent to local GUI. The channel is a named pipe.
4. The `GA_PID` process identity. The kernel sensor and the userland hooks use the same identity.

The kernel drivers include this crate directly. For this reason, this crate controls the struct layouts across the kernel boundary.

## Design decisions

- The kernel surface uses only `core` and `sha1_smol`. The user-mode IPC layer needs `alloc` and serde. The `client_ipc` and `agent_ipc` feature gates hide the IPC layer from kernel builds. The same source then serves the agent and a lighter GUI build.
- The kernel messages use fixed-size `#repr(C)` structs (`GalateaProcEvent`, `GalateaVerdict`, `GalateaFSEvent`). The drivers copy raw buffers. They need no allocator and no serialization.
- The filter port uses one fixed-size envelope: `GalateaFilterMessage { kind, payload_len, [u8; 2048] }`. The `kind` field discriminates the message type (`Raw` = 0, `FileTelemetry` = 1). New message types do not change the kernel-side layout.
- The GUI named-pipe messages use serde JSON (`DetectionEvent`, `IpcMessage`, `IpcRequest`, `IpcResponse`). The GUI does not cross a kernel boundary. It can use version-tolerant string types.
- `GA_PID` (`id.rs`): the hash is `sha1(namespace || pid_le || image_bytes || ticks_le)[0..16]`. The hash is a correlation token, not a security hash. Windows reuses PIDs, so the identity mixes in the process creation time. `PsGetProcessCreateTimeQuadPart` gives the same value as the `GetProcessTimes` creation ticks. The source code pins the namespace constant. `GA_PID` is not a standard UUIDv5. Do not treat it as one in external systems.

## Subtleties

- The kernel structs carry no version marker. If you change `GalateaProcEvent` or `GalateaVerdict`, compile the sensor driver and the agent together. Otherwise the IOCTL decode fails.
- The `[u16; 260]` path fields hold a path prefix. There is no null terminator. Consumers must trust the fixed length. They must not assume a NUL.
- The `request_id` field in `GalateaFSEvent` is not wired. The filter driver always sends 0. Do not build request and response pairing on it.
- `FSEventType::FileModify` carries data. The `Rename` variant holds a second path buffer. This variant sets the size of the whole enum. A new large variant grows `GalateaFSEvent`. The growth eats into the 2048-byte envelope.
- `GA_PID` has no collision handling. Two processes with the same pid, image, and creation ticks share one value. The project accepts this risk.
- The identity inputs must stay byte-identical in kernel and userland: same pid, same raw UTF-16 image bytes, same creation ticks. One side out of sync breaks the correlation. The break is silent.

## Key files

- `endpoint/galatea-shared/src/lib.rs` : IOCTL codes, kernel structs, filter-port envelope, feature-gated GUI IPC types.
- `endpoint/galatea-shared/src/id.rs` : `GA_PID` type, namespace, `generate_process_id`, unit tests.
