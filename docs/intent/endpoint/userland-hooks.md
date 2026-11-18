# galatea-userland-hooks (DLL)

## Purpose

This crate builds a `cdylib` DLL. The agent injects it into allowed processes. On attach, the DLL hot-patches the `ntdll.dll` export stubs for `ZwOpenProcess` and `ZwAllocateVirtualMemory`. The patch installs trampolines. The trampolines redirect calls into Rust functions. These functions emit ETW telemetry when the host process opens a handle to, or allocates memory in, a foreign process. They then execute the real syscall directly. The design avoids the common userland hook-detection vectors. It tags every event with the kernel-consistent `GA_PID`.

## Design decisions

- Trampoline shape: a 32-byte NOP wipe, then `mov rax, <imm64>; jmp rax` (12 bytes). The NOP wipe erases the original `mov eax, ss; syscall` prologue. Tools that scan those regions for the syscall pattern then find them sanitized. The absolute trampoline avoids relocation math.
- Forwarding path: the stubs run `syscall` inline from Rust asm with the SSN captured earlier. The call never re-enters any `Nt*` or `Zw*` code path. Integrity checks against the rest of ntdll do not see it.
- Central invariant: the code must read the SSN map from the pristine, unpatched prologues before the patch runs. `try_init_hooks` forces `ssn::SYSCALL_NUMBER` before it patches one byte. A deferred read sees NOP bytes. The SSN guard then fails.
- Freeze then patch: `DllMain` only spawns an init thread, so there is no loader-lock risk. The init suspends all other threads of the host with a RAII guard. No thread runs across a half-written stub. The guard resumes all threads when it drops.
- Remote-only telemetry: `nt_open_process` reads the target PID from the caller's `CLIENT_ID`. `virtual_alloc_ex` compares `GetProcessId(handle)` with the current PID. Self-directed calls forward without telemetry.
- Identity: `current_ga_pid()` uses the same recipe as the kernel sensor. The input is `sha1` over namespace, pid, raw UTF-16 image bytes, and the `GetProcessTimes` creation ticks. A `OnceLock` caches the result. Userland events then correlate exactly with kernel events across PID reuse.
- Exfiltration uses ETW through a trace-logging provider. The agent consumes the events with its ETW consumer. Hook telemetry is decoupled from the agent's IPC.

## Subtleties

- `virtual_alloc_ex` declares `options(nostack)`, but it writes to stack space. It reserves that space with `sub rsp, 0x30` for the syscall's 5th and 6th arguments. A stricter future rustc can miscompile around it. Consider this before you touch the asm.
- A stub `expect()` on a missing SSN aborts the host process. The workspace profiles set `panic = "abort"`. The SSN read-before-patch order makes the fallback unreachable. Keep the stub names in `stubs.rs` in sync with the name list in `ssn.rs`.
- The SSN extraction masks the `mov eax, imm32` immediate with `0xfff`. An SSN above 4095 yields a wrong number. The failure is silent.
- The patch writes the `Zw*` export stubs, not the `Nt*` ones. On x64 both point to the same stub for user-mode callers. A process that resolved and cached an `Nt*` pointer earlier bypasses the hook.
- `GetProcessId` can return 0 for a bad handle. The code does not guard this. The stub then treats a self-allocation as remote.
- Two `println!` calls fire on every hooked call in Debug builds. They are a behavioral fingerprint in a traced binary. Do not ship them.
- `GetModuleHandleA("Ntdll.dll")` and `GetProcAddress` resolve the patch targets at attach time. A process that re-maps ntdll later keeps the patched copy hooked. A fresh mapping stays unhooked.

## Key files

- `endpoint/galatea-userland-hooks/src/lib.rs` : `DllMain`, init sequence, patch routine.
- `endpoint/galatea-userland-hooks/src/addresses.rs` : export resolution into `StubAddresses`.
- `endpoint/galatea-userland-hooks/src/ssn.rs` : SSN extraction from unpatched prologues.
- `endpoint/galatea-userland-hooks/src/stubs.rs` : hooked call stubs with inline `syscall` forwarding.
- `endpoint/galatea-userland-hooks/src/threads.rs` : thread freeze RAII guard.
- `endpoint/galatea-userland-hooks/src/identity.rs` : `GA_PID` computation for the host process.
- `endpoint/galatea-userland-hooks/src/etw.rs` : trace-logging provider and events.
