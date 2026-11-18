# galatea-kernel-sensor (driver)

## Purpose

The sensor is a WDM kernel driver. It builds `no_std` with the `wdk` crate family. It registers process and thread creation callbacks. The driver freezes each new process that is not on the static allowlist. It holds the process frozen in a kernel APC until the agent sends a verdict over IOCTL. It streams process create and exit events to the agent. The delivery uses an inverted call, also known as a pending IRP. The agent is the only IOCTL client that the driver accepts.

## Architecture and data flow

- `DriverEntry` (lib.rs) sets up the spin locks and the global state stores. It wires the IRP dispatch. It creates `\Device\Galatea` with the symlink `\DosDevices\Galatea`. It registers the callbacks. `WdmlibIoCreateDeviceSecure` applies the SDDL string `D:P(A;;GA;;;SY)(A;;GA;;;BA)`. Only SYSTEM and Administrators get access.
- `callback.rs`, process create: the driver takes a `request_id` from a monotonic atomic counter. Allowlisted images take the "fastpass" path. The fastpass path freezes nothing and scans nothing. All other processes go into `TARGET_PIDS`. The first thread that such a process creates gets the freeze APC (thread callback).
- `callback.rs`, process exit: the driver locates the image name again. The exit event then carries the same identity fields as the create event.
- `callback.rs`, event delivery: `notify_agent` builds a `GalateaProcEvent`. The event holds a `GA_PID` from `galatea_shared::id::generate_process_id`. If the agent holds a pending `IOCTL_GET_EVENT` IRP, the driver completes that IRP. Otherwise the driver buffers the event in `EVENT_QUEUE` (cap 1000, drop beyond).
- `apc.rs`: the freeze APC checks the early-verdict cache first. If there is no cached verdict, it waits on a `KEVENT` with a 5 second timeout. It applies the verdict from `PENDING_SCANS`. On a block verdict it terminates the process with `STATUS_ACCESS_DENIED`.
- `ioctl.rs`: `IOCTL_REGISTER_AGENT` is one-shot. The driver pins the agent `EPROCESS` with `ObfReferenceObject`. It compares this pointer on every later call. `IOCTL_GET_EVENT` drains the queue first. If the queue is empty, it parks the IRP in the single `PENDING_IRP` slot with a cancel routine. `IOCTL_SEND_VERDICT` reads a `GalateaVerdict` and calls `apply_verdict`.

## Design decisions

- Inverted-call delivery: one pending IRP slot plus a bounded queue. No create or exit event is lost while a GET_EVENT IRP is in flight. The next IOCTL call drains the queue first.
- Verdict cache (1024 entries, 10 s TTL): the verdict can arrive before the victim thread reaches the APC. The APC then reads and removes the cached verdict and does not wait. This design closes the early-arrival race.
- Freeze model: only the first thread of a target process gets a queued APC. Later threads of the same process pin to the live pending scan. They wait on the same event. `apply_verdict` signals every pending scan with the same `request_id`.
- Fail-closed: the pending scan stores the default verdict `STATUS_ACCESS_DENIED`.
- The driver releases every spin lock before `IofCompleteRequest`. It swaps the cancel routine lock-free through an `AtomicPtr` view. Each IRP completes exactly once.
- Unload order: unregister callbacks, wake all pending scans, wait until the APC count reaches zero, release the agent reference, delete device. An APC that runs after image unload returns into freed memory.

## Subtleties

- The 5 s timeout path does not terminate the process. The `ZwTerminateProcess` call in the APC normal routine is commented out. The code carries the TODO "Make dependent on agent status". A timed-out process currently resumes. Change this only together with the agent-side policy.
- Lifetime contract: `inject_freeze_apc` publishes a `PendingScan`. The scan holds a raw pointer into the `FreezeApcCtx` box. The publish happens before `Box::into_raw`. Every exit path must remove the matching `PendingScan` before the drop of the box. The match uses `request_id` and `event_ptr` together, because many threads share one `request_id`. A wrong order leaves a dangling pointer. Another CPU can then `KeSetEvent` through it.
- `APC_COUNT` must decrease on every exit path: insert failure, rundown, normal routine. `driver_unload` spin-waits on this counter.
- The static allowlist is a hardcoded case-insensitive System32 or SysWOW64 prefix match. The code notes it as "not very secure" (PoC grade). An image path collision bypasses it.
- If `SeLocateProcessImageName` fails on process exit, the exit event goes out with an empty image path. Its `GA_PID` then does not match the create event.
- The allowed-process exit path sends an event again. The allowlist does not suppress exit events.
- The `GA_PID` inputs (pid, image bytes, `PsGetProcessCreateTimeQuadPart`) must mirror the userland hooks crate exactly.
- One agent can register. The driver keeps the `EPROCESS` reference until unload. The registration stays valid even if the agent process dies.

## Key files

- `endpoint/galatea-kernel-sensor/src/lib.rs` : entry and unload, global state, secured device.
- `endpoint/galatea-kernel-sensor/src/callback.rs` : process and thread callbacks, event delivery.
- `endpoint/galatea-kernel-sensor/src/apc.rs` : freeze APC lifecycle, verdict cache, `apply_verdict`.
- `endpoint/galatea-kernel-sensor/src/ioctl.rs` : IOCTL dispatch, agent registration, pending IRP park and cancel.
- `endpoint/galatea-kernel-sensor/src/utils.rs` : `w!` macro, kernel time, static allowlist.
- `endpoint/galatea-kernel-sensor/src/ffi.rs` : `SeLocateProcessImageName` and `WdmlibIoCreateDeviceSecure` bindings. wdk-sys does not supply them.
