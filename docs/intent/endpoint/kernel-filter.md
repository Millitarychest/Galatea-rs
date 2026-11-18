# galatea-kernel-filter (minifilter)

## Purpose

The filter is a filesystem minifilter driver (`no_std`, Filter Manager model, links `fltMgr.lib`). It observes file creates, writes, and rename or set-information operations. It forwards them as `GalateaFSEvent` telemetry over the minifilter communication port `\GalateaFilterPort` to the agent. The filter only observes. Every pre-operation callback returns success. No callback blocks an operation. The agent's file-context pipeline consumes this telemetry.

## Architecture and data flow

- `DriverEntry` (lib.rs) builds the operation registration table for `IRP_MJ_CREATE` (pre and post), `IRP_MJ_WRITE` (pre), and `IRP_MJ_SET_INFORMATION` (pre). It then registers with the Filter Manager, creates the port, and starts filtering. Each failure rolls back the steps that already completed.
- `io/filter_port.rs`: the port accepts one client only. On connect, the filter stores the client port and the agent PID. On disconnect, it clears both. `is_agent_process()` skips the agent's own I/O. The telemetry loop stays clean this way.
- `send_fs_telemetry` wraps a `GalateaFSEvent` in the 2048-byte `GalateaFilterMessage` envelope and sends it with `FltSendMessage`.
- `callbacks/fs_callbacks.rs`: `pre_create` asks for the post-operation callback. `post_create` emits `FileCreate` only when the disposition says created, superseded, or overwritten. `pre_write` emits `FileWrite`. `pre_set_info` matches the rename information classes (10, 56, 65, 66). It validates the rename buffer with care: length, alignment, `read_unaligned`. It emits `FileModify(Rename{...})`. It also queries the NTFS file index. The value 0 means "unavailable". Consumers then fall back to a path key.

## Design decisions

- Minifilter instead of a legacy FS filter: the Filter Manager supplies the callbacks and a first-class user-mode channel, the communication port. No custom IRP plumbing and no IOCTL device are needed.
- One fixed-size envelope with a `kind` discriminator: the kernel-side layout stays stable when new message types come in.
- Telemetry only, today: `FLT_PREOP_SUCCESS_NO_CALLBACK` everywhere. The pre-create callback asks for the post callback, because it must see the final create disposition. A block feature would later live in the pre-operation return values.
- The filter suppresses its own process (agent PID) and System activity (PID <= 4).
- File identity uses the NTFS file index next to the path. The events also carry `PsGetProcessStartKey` next to the plain PID for correlation.
- The crate notes that `ffi/flt.rs` was generated largely with AI tooling. No one has verified the FFI structs against fltKernel.h by hand.

## Subtleties

- `message_notify` ignores its input. The port is one-way today. There is no agent-to-filter command message. The `request_id` in `GalateaFSEvent` is always 0.
- One global client-port slot, no locks: the Filter Manager serializes connect, disconnect, and unload for the port (MaxConnections = 1). A second client, or a send from another thread context, needs added synchronization.
- `send_fs_telemetry` passes a zero relative timeout to `FltSendMessage`. Check the FltMgr semantics before you change this value. NULL means "wait indefinitely".
- Treat the `ffi/flt.rs` struct layouts as unchecked. Above all, check `FILE_RENAME_INFORMATION` and the `offset_of!(..., file_name)` use. A wrong offset reads attacker-controlled data.
- Events are dropped when no client is connected. There is no kernel-side queue like the sensor's.
- The filter sends the whole 2048-byte envelope, whatever `payload_len` says.

## Key files

- `endpoint/galatea-kernel-filter/src/lib.rs` : filter registration table, lifecycle with rollback.
- `endpoint/galatea-kernel-filter/src/io/filter_port.rs` : port lifecycle, single-client policy, telemetry send.
- `endpoint/galatea-kernel-filter/src/callbacks/fs_callbacks.rs` : create, write, and rename telemetry extraction.
- `endpoint/galatea-kernel-filter/src/ffi/flt.rs` : Filter Manager FFI: types, constants, functions.
