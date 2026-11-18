# galatea-agent

## Purpose

The agent is the Windows endpoint orchestrator. It registers with the kernel sensor. It reads frozen process-creation events from the kernel. It runs a static-analysis pipeline on a worker pool. It sends allow and block verdicts to the driver. It collects FS-filter telemetry and userland-hook ETW events into context caches. It broadcasts detections over named pipes to the local GUI. It posts registration and telemetry to the babel server. It injects the userland hooks DLL into allowed processes. All other endpoint components connect through the agent.

## Architecture and data flow

Startup (`main.rs`), in order:

1. Start the file logger. It writes `galatea.log` next to the executable. A Ctrl+C handler exists in debug builds only.
2. Set up the driver: install and start the `Galatea` service with `sc` shell-outs. The agent runs with `HIGH_PRIORITY_CLASS`.
3. Open the SQLite pool (`galatea_dataset.db`, r2d2). The database holds one `signatures` table.
4. Load the optional engines: packer signatures (`userdb.txt`) and the ONNX model (`model.onnx`). A missing model disables the ML stage only.
5. Connect to the filter port `\\GalateaFilterPort` (listener thread).
6. Start the ETW consumer thread for the hook DLL provider (`mimicry.galatea_hooks`), the IPC named-pipe server (event broadcast pipe, command pipe), and an `mpsc` sender for detections.
7. Open two handles to `\\.\Galatea`. One handle listens for events. The other handle registers the agent (`ks_register_agent`). A registration failure means another agent runs.
8. Post the registration to babel.
9. Run the main loop: block on `DeviceIoControl(IOCTL_GET_EVENT)`. Create events feed the `ProcessContextCache` and go to the analysis pool. Exit events invalidate the `GA_PID` in the process cache.

Analysis (`static_analyzer/mod.rs::analyze_ks_event`), per event on a 16-thread pool:

- Fast-track events (`frozen == false`) skip the scan.
- The full pipeline runs these stages: signature check (MD5 against SQLite) -> Authenticode (WinVerifyTrust) -> ML (ONNX) -> heuristics (packer, entropy, RWX section, hidden imports). The stages sit in an explicit slice of function pointers. A `Block` outcome short-circuits the rest.
- The scoring is additive into one `threat_score`. `STAT_BLOCK_THRESHOLD` (80) blocks. A score of 50 marks suspicious. All weights and thresholds live in `config.rs`.
- After the scan: write a `ScanSummary` to the `FileContextCache`, inject the hooks DLL when allowed, broadcast a `DetectionEvent` on the IPC pipe, and send `IOCTL_SEND_VERDICT` with the `request_id` to the driver.

Side channels:

- Filter-port thread: `GalateaFSEvent` telemetry sets flags in the `FileContextCache` (create success, write success, rename-to-executable, temp or startup location). `file_index == 0` falls back to a path key.
- ETW thread: hook event 0 (foreign process handle opened) and event 1 (remote allocation) set process flags on the actor `GA_PID`.
- IPC server: detection broadcast pipe plus a command pipe. The command pipe serves `GetFileContextSnapshot` with a length-prefixed response.
- Network: registration POST to babel (PoC grade).

## Design decisions

- Freeze and verdict timing contract: the kernel APC waits 5 s. `SCAN_WAIT_TIMEOUT_SECS` is 4 s. Cache waiters then fall through to a fail-closed block, or re-acquire a scan slot, before the kernel deadline. This contract drives the whole multi-level wait design.
- Fail-closed scan path: a stat failure, a zero-size file, an unreadable file, or a double cache-wait failure blocks the process.
- Scan deduplication (`cache/static_analyzer_cache.rs`): a completed-scan cache (moka) validates entries by size, mtime, and NTFS file index. The file index is an anti-timestomping check. An in-flight map of barriers (Mutex + Condvar) coalesces concurrent scans of the same file. A `ScanGuard` owner publishes the result, or aborts and wakes all waiters.
- Two-tier caches, both process and file: a large normal tier and a small high-priority tier. Benign churn cannot evict an entry from the high-priority tier. Promotion is one-way. The priority derives from the behavioural score (process) or from high-value flag combinations (file).
- File identity uses aliases, not single keys: a monotonic `FileContextId`, with the NTFS file index and the canonical path as aliases in a bidirectional index. File-index aliases win on resolution.
- The event pipe and the command pipe use different protocols on purpose: fire-and-forget JSON broadcast versus length-prefixed request and response. Do not unify them without care.
- `SendHandle` and `ScanGuard` wrap raw handles and pointers with `unsafe impl Send`. The safety contract says the cache lives in a `OnceLock` static for the process lifetime. A local `StaticResultCache` breaks the contract and causes UB.

## Subtleties

- Timing: a scan path slower than about 4 s turns verdicts into fail-closed blocks. The nested cache-wait state machine in `analyze_ks_event` (hit -> wait -> complete, failed, or timeout -> re-acquire -> second wait -> block) is deep and duplicated. It is easy to break. The injection call is copy-pasted at six sites.
- `cleanup()` returns before the commented-out driver uninstall. The comment says "As this seems to break". The driver service stays installed on exit by design. Debug builds only cancel the blocking IOCTL via Ctrl+C.
- `ScanGuard` holds a raw pointer into the `OnceLock` cache. A poisoned in-progress lock yields a guard that scans independently and never publishes. Lock poisoning then disables coalescing for that path, without a message.
- The allow boundary is off-by-one-fragile: fresh scans use strict `>` for stage blocks and `>=` for the `Malicious` summary class. Cached results recompute allow as `threat_score <= 80`. A score of exactly 80 is `Malicious` in the summary and allowed in practice.
- The scan reads the file from disk (`fs::read` + MD5). There is a TOCTOU gap between the kernel's image and the scanned file. The cache layer mitigates it with the file index. The first scan does not.
- Path handling exists twice: `main.rs` and `analyze_ks_event` each decode `image_path` and canonicalize it on their own. Both must apply the same canonicalization rules. Otherwise the process context paths and the scan cache keys diverge.
- The command pipe blocks on a 1-byte read after it writes a response. The read holds the pipe open until the client closes. If you remove it, long JSON snapshots truncate.
- Rename alias retirement removes the retired path alias only from the context it maps to now. A rename that arrives out of order with the FS cache can lose the alias, or re-create a context at the old path.
- `FileContextCache` eviction is lazy: eviction listeners enqueue IDs, and the alias rows are cleaned on the next operation. Stale alias rows can exist between operations.
- Not implemented yet: `get_command_line` in the probes is a stub that returns `None`. A `StageOutcome::Allow` is never produced (a missing emulation stage). The babel registration sends fake host info and the literal PSK `galatea_secret`.
- ETW event IDs 0 and 1 are magic numbers tied to the hooks DLL provider.

## Key files

- `endpoint/galatea-agent/src/main.rs` : startup orchestration, kernel-event loop, worker dispatch.
- `endpoint/galatea-agent/src/config.rs` : all constants: thresholds, weights, PSK, file names, ETW GUIDs.
- `endpoint/galatea-agent/src/static_analyzer/mod.rs` : the core scan state machine.
- `endpoint/galatea-agent/src/cache/static_analyzer_cache.rs` : scan result cache and in-flight barriers.
- `endpoint/galatea-agent/src/cache/file_context_cache.rs` : alias-indexed two-tier file context cache. Highest invariant load. Includes tests.
- `endpoint/galatea-agent/src/cache/process_context_cache.rs` : `GA_PID`-keyed two-tier process context cache.
- `endpoint/galatea-agent/src/communication/driver/` : kernel IOCTLs, filter-port listener, driver service management.
- `endpoint/galatea-agent/src/communication/ipc/` : named-pipe broadcast and command server.
- `endpoint/galatea-agent/src/communication/etw/etw_consumer.rs` : hook DLL telemetry consumer.
- `endpoint/galatea-agent/src/engine/` : correlation and the file and process signature flag engines.
- `endpoint/galatea-agent/src/static_analyzer/` : authenticode, heuristics, packers, ML stages.
- `endpoint/galatea-agent/src/injector.rs` : remote-thread DLL injection.
- `endpoint/galatea-agent/src/probes/` : native process and file metadata probes.
- `endpoint/galatea-agent/src/db.rs` : SQLite signature store and pool.
