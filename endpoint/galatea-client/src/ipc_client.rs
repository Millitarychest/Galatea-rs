use galatea_shared::ipc::{
    COMMAND_PIPE_NAME, FileContextSnapshot, IpcMessage, IpcRequest, IpcResponse, PIPE_NAME,
};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::{CloseHandle, ERROR_PIPE_BUSY, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    ReadFile, WriteFile,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;
use windows::core::PWSTR;

#[derive(Debug, Clone)]
pub enum IpcClientMessage {
    Connected,
    Disconnected,
    Message(IpcMessage),
}

pub struct IpcClient {
    receiver: Receiver<IpcClientMessage>,
}

impl IpcClient {
    pub fn start() -> Self {
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            run_ipc_client(tx);
        });

        IpcClient { receiver: rx }
    }

    pub fn try_recv(&self) -> Option<IpcClientMessage> {
        self.receiver.try_recv().ok()
    }

    pub fn request_file_context_snapshot(limit: usize) -> Result<Vec<FileContextSnapshot>, String> {
        let pipe_handle = connect_to_command_pipe()
            .ok_or_else(|| "failed to connect to agent command pipe".to_string())?;

        let result = request_file_context_snapshot_inner(pipe_handle, limit);
        unsafe {
            let _ = CloseHandle(pipe_handle);
        }

        result
    }
}

fn run_ipc_client(sender: Sender<IpcClientMessage>) {
    loop {
        // Try to connect to the named pipe
        match connect_to_pipe() {
            Some(pipe_handle) => {
                let _ = sender.send(IpcClientMessage::Connected);

                // Read messages until disconnection
                read_messages(pipe_handle, &sender);

                unsafe {
                    let _ = CloseHandle(pipe_handle);
                }
                let _ = sender.send(IpcClientMessage::Disconnected);
            }
            None => {
                // Connection failed, retry after delay
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn connect_to_pipe() -> Option<HANDLE> {
    let pipe_name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    // Try to open the pipe
    unsafe {
        match CreateFileW(
            PWSTR(pipe_name_wide.as_ptr() as *mut _),
            FILE_GENERIC_READ.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) {
            Ok(handle) => Some(handle),
            Err(e) => {
                let error_code = win32_error_code(&e);
                if error_code == ERROR_PIPE_BUSY.0 {
                    // Pipe is busy, wait for it
                    if WaitNamedPipeW(PWSTR(pipe_name_wide.as_ptr() as *mut _), 5000).as_bool() {
                        // Try again
                        return connect_to_pipe();
                    }
                }
                None
            }
        }
    }
}

fn win32_error_code(error: &windows::core::Error) -> u32 {
    let raw = error.code().0 as u32;
    if raw & 0xffff_0000 == 0x8007_0000 {
        raw & 0x0000_ffff
    } else {
        raw
    }
}

fn connect_to_command_pipe() -> Option<HANDLE> {
    let pipe_name_wide: Vec<u16> = COMMAND_PIPE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        match CreateFileW(
            PWSTR(pipe_name_wide.as_ptr() as *mut _),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) {
            Ok(handle) => Some(handle),
            Err(e) => {
                let error_code = win32_error_code(&e);
                if error_code == ERROR_PIPE_BUSY.0
                    && WaitNamedPipeW(PWSTR(pipe_name_wide.as_ptr() as *mut _), 5000).as_bool()
                {
                    return connect_to_command_pipe();
                }
                None
            }
        }
    }
}

fn request_file_context_snapshot_inner(
    pipe_handle: HANDLE,
    limit: usize,
) -> Result<Vec<FileContextSnapshot>, String> {
    let request = IpcRequest::GetFileContextSnapshot { limit };
    let request_json =
        serde_json::to_string(&request).map_err(|e| format!("failed to serialize request: {e}"))?;

    unsafe {
        let mut bytes_written: u32 = 0;
        WriteFile(
            pipe_handle,
            Some(request_json.as_bytes()),
            Some(&mut bytes_written),
            None,
        )
        .map_err(|e| format!("failed to write request: {e:?}"))?;

        let response_bytes = read_command_response(pipe_handle)?;
        let response = serde_json::from_slice::<IpcResponse>(&response_bytes)
            .map_err(|e| format!("failed to parse response: {e}"))?;

        match response {
            IpcResponse::FileContextSnapshot { entries } => Ok(entries),
            IpcResponse::Error { message } => Err(message),
        }
    }
}

fn read_command_response(pipe_handle: HANDLE) -> Result<Vec<u8>, String> {
    let mut len_bytes = [0u8; size_of::<u64>()];
    read_command_bytes(pipe_handle, &mut len_bytes)?;

    let response_len = u64::from_le_bytes(len_bytes) as usize;
    let mut response = vec![0u8; response_len];
    read_command_bytes(pipe_handle, &mut response)?;

    Ok(response)
}

fn read_command_bytes(pipe_handle: HANDLE, output: &mut [u8]) -> Result<(), String> {
    let mut offset = 0;

    while offset < output.len() {
        unsafe {
            let mut bytes_read: u32 = 0;
            ReadFile(
                pipe_handle,
                Some(&mut output[offset..]),
                Some(&mut bytes_read),
                None,
            )
            .map_err(|e| format!("failed to read response: {e:?}"))?;

            if bytes_read == 0 {
                return Err("command response ended early".to_string());
            }

            offset += bytes_read as usize;
        }
    }

    Ok(())
}

fn read_messages(pipe_handle: HANDLE, sender: &Sender<IpcClientMessage>) {
    let mut buffer = vec![0u8; 65536]; // 64KB buffer

    loop {
        unsafe {
            let mut bytes_read: u32 = 0;

            match ReadFile(
                pipe_handle,
                Some(&mut buffer[..]),
                Some(&mut bytes_read),
                None,
            ) {
                Ok(_) => {
                    if bytes_read > 0 {
                        // Parse JSON message
                        let data = &buffer[..bytes_read as usize];
                        match serde_json::from_slice::<IpcMessage>(data) {
                            Ok(message) => {
                                if sender.send(IpcClientMessage::Message(message)).is_err() {
                                    break; // Channel closed
                                }
                            }
                            Err(e) => {
                                eprintln!("[IPC Client] Failed to parse message: {}", e);
                            }
                        }
                    }
                }
                Err(_) => {
                    // Pipe broken or error
                    break;
                }
            }
        }
    }
}
