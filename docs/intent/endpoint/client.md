# galatea-client (GUI)

## Purpose

The client is the local Windows GUI, built with iced. It shows detections from the agent. It does no detection of its own. It connects to the agent's named pipes. It streams `DetectionEvent`s into a scrolling list. It pulls `FileContextSnapshot`s on demand for a "Files" tab. The client is the operator console next to the agent.

## Design decisions

- The app uses the iced Elm architecture: one state struct (`GalateaGui`), `update`/`view`/`subscription` in `app.rs`, pure view functions in `ui/`.
- The app uses two pipes by design: a read-only event stream pipe, and a read/write command pipe. Each JSON response on the command pipe has a `u64` length prefix. The event pipe has no framing.
- Detections sit in a `VecDeque` capped at 1000. The pause feature pushes new events into a second capped deque. The inspected list does not churn. On unpause, the app drains the pending deque back in arrival order. Expanding a detection auto-pauses the list.
- A tick subscription fires every 100 ms. It drains at most one message per tick.
- The Files tab refreshes on entry, then every 2 s, through `spawn_blocking` on async_std. The snapshot is capped at 500 entries.
- The theme cycle has 23 entries. Only `DefenderExplorer` is custom. It mimics the Microsoft Defender colors: near-black background, orange primary.
- All mutations stay on the iced update path. The refresh guards (`loading_file_contexts`, `last_file_refresh`) are safe only under that serialization.

## Subtleties

- One message per 100 ms sets a ceiling of about 10 messages per second. A detection burst backs up in the channel. The GUI then falls behind. Drain in a loop if event rates go up.
- The event pipe assumes each `ReadFile` returns exactly one JSON message. A split or coalesced chunk fails to parse. The command pipe frames its responses. The asymmetry is deliberate. Do not unify the protocols without care.
- `selected_detection` indexes the filtered view. The index goes stale when new detections push to the front. The expansion state keys on event ID strings instead.
- The IPC sender thread runs forever. There is no shutdown path. Each file-context request opens and closes a fresh command-pipe handle.
- `windows_subsystem = "windows"` hides the console. `eprintln!` output from the IPC layer is invisible in normal runs.
- `Task::perform` mixes async_std blocking threads into the iced runtime. It works. Do not add async work that assumes tokio.
- A busy pipe (`ERROR_PIPE_BUSY`) blocks in `WaitNamedPipeW` and then retries the connect recursively.

## Key files

- `endpoint/galatea-client/src/app.rs` : state machine, views, pause and pending logic, tick drain, refresh cadence.
- `endpoint/galatea-client/src/ipc_client.rs` : event and command pipe clients, Win32 framing, retry logic.
- `endpoint/galatea-client/src/ui/` : header, detection list, file-context list.
- `endpoint/galatea-client/src/theme.rs` : theme cycle and the custom palette.
