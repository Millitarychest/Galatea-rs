use galatea_shared::ipc::{
    COMMAND_PIPE_NAME, IpcMessage, IpcRequest, IpcResponse, PIPE_BUFFER_SIZE, PIPE_NAME,
};
use mimic_core::{mimic_error, mimic_log};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL,
    INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    PIPE_ACCESS_DUPLEX, PIPE_ACCESS_OUTBOUND, ReadFile, WriteFile,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::core::{PWSTR, w};

use crate::FILE_CONTEXT_CACHE;
use crate::cache::file_context_cache::FileContextCache;

#[allow(dead_code)]
pub struct IpcServer {
    sender: Sender<IpcMessage>,
}

impl IpcServer {
    /// Start the IPC server and return a sender for broadcasting messages
    pub fn start() -> Option<Sender<IpcMessage>> {
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            run_ipc_server(rx);
        });
        thread::spawn(run_command_server);

        mimic_log!("IPC server listening on {}", PIPE_NAME);
        mimic_log!("IPC command server listening on {}", COMMAND_PIPE_NAME);
        Some(tx)
    }
}

fn run_ipc_server(receiver: Receiver<IpcMessage>) {
    let mut clients: Vec<HANDLE> = Vec::new();

    // Create listener thread for accepting new connections
    let (client_tx, client_rx) = mpsc::channel();
    thread::spawn(move || {
        accept_clients_loop(client_tx);
    });

    loop {
        // Check for new clients
        while let Ok(client_handle) = client_rx.try_recv() {
            mimic_log!("[IPC] New client connected");
            clients.push(client_handle.into());
        }

        // Check for messages to broadcast
        match receiver.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(message) => {
                broadcast_message(&mut clients, &message);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // No message, continue
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                mimic_error!("[IPC] Message channel disconnected, shutting down IPC server");
                break;
            }
        }
    }

    // Cleanup
    for handle in clients {
        unsafe {
            let _ = DisconnectNamedPipe(handle);
            let _ = CloseHandle(handle);
        }
    }
}

fn accept_clients_loop(client_sender: Sender<super::SendHandle>) {
    loop {
        match create_pipe_instance() {
            Some(pipe_handle) => {
                // Wait for client connection
                unsafe {
                    match ConnectNamedPipe(pipe_handle, None) {
                        Ok(_) => {
                            if client_sender.send(pipe_handle.into()).is_err() {
                                mimic_error!("[IPC] Failed to send client handle to main loop");
                                let _ = CloseHandle(pipe_handle);
                                break;
                            }
                        }
                        Err(e) => {
                            let error_code = win32_error_code(&e);
                            if error_code == ERROR_PIPE_CONNECTED.0 {
                                // Client already connected
                                if client_sender.send(pipe_handle.into()).is_err() {
                                    let _ = CloseHandle(pipe_handle);
                                    break;
                                }
                            } else {
                                mimic_error!("[IPC] ConnectNamedPipe failed: {:?}", e);
                                let _ = CloseHandle(pipe_handle);
                                thread::sleep(std::time::Duration::from_secs(1));
                            }
                        }
                    }
                }
            }
            None => {
                thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}

fn create_pipe_instance() -> Option<HANDLE> {
    // SYSTEM + Administrators full access; Interactive Users read access for non-admin client.
    let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
    let sddl = w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;IU)");
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            SDDL_REVISION_1 as u32,
            &mut security_descriptor,
            None,
        )
        .is_err()
        {
            mimic_error!("[IPC] Failed to build pipe security descriptor from SDDL");
            return None;
        }
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor.0,
        bInheritHandle: false.into(),
    };

    let pipe_name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    let result = unsafe {
        let handle = CreateNamedPipeW(
            PWSTR(pipe_name_wide.as_ptr() as *mut _),
            PIPE_ACCESS_OUTBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            Some(&sa as *const _),
        );

        if handle == INVALID_HANDLE_VALUE {
            mimic_error!("[IPC] CreateNamedPipeW failed");
            None
        } else {
            Some(handle)
        }
    };

    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(HLOCAL(security_descriptor.0)));
    }

    result
}

fn win32_error_code(error: &windows::core::Error) -> u32 {
    let raw = error.code().0 as u32;
    if raw & 0xffff_0000 == 0x8007_0000 {
        raw & 0x0000_ffff
    } else {
        raw
    }
}

fn run_command_server() {
    loop {
        match create_command_pipe_instance() {
            Some(pipe_handle) => unsafe {
                match ConnectNamedPipe(pipe_handle, None) {
                    Ok(_) => handle_command_client(pipe_handle),
                    Err(e) => {
                        let error_code = win32_error_code(&e);
                        if error_code == ERROR_PIPE_CONNECTED.0 {
                            handle_command_client(pipe_handle);
                        } else {
                            mimic_error!("[IPC] Command ConnectNamedPipe failed: {:?}", e);
                        }
                    }
                }

                let _ = DisconnectNamedPipe(pipe_handle);
                let _ = CloseHandle(pipe_handle);
            },
            None => thread::sleep(std::time::Duration::from_secs(1)),
        }
    }
}

fn create_command_pipe_instance() -> Option<HANDLE> {
    // SYSTEM + Administrators full access; Interactive Users read/write access.
    let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
    let sddl = w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)");
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            SDDL_REVISION_1 as u32,
            &mut security_descriptor,
            None,
        )
        .is_err()
        {
            mimic_error!("[IPC] Failed to build command pipe security descriptor from SDDL");
            return None;
        }
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor.0,
        bInheritHandle: false.into(),
    };

    let pipe_name_wide: Vec<u16> = COMMAND_PIPE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        let handle = CreateNamedPipeW(
            PWSTR(pipe_name_wide.as_ptr() as *mut _),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            Some(&sa as *const _),
        );

        if handle == INVALID_HANDLE_VALUE {
            mimic_error!("[IPC] CreateNamedPipeW command pipe failed");
            None
        } else {
            Some(handle)
        }
    };

    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(HLOCAL(security_descriptor.0)));
    }

    result
}

fn handle_command_client(pipe_handle: HANDLE) {
    let mut buffer = vec![0u8; PIPE_BUFFER_SIZE as usize];

    unsafe {
        let mut bytes_read: u32 = 0;
        if ReadFile(
            pipe_handle,
            Some(&mut buffer[..]),
            Some(&mut bytes_read),
            None,
        )
        .is_err()
        {
            mimic_error!("[IPC] Failed to read command request");
            return;
        }

        let response = if bytes_read == 0 {
            IpcResponse::Error {
                message: "empty request".to_string(),
            }
        } else {
            match serde_json::from_slice::<IpcRequest>(&buffer[..bytes_read as usize]) {
                Ok(IpcRequest::GetFileContextSnapshot { limit }) => {
                    let fs_cache = FILE_CONTEXT_CACHE.get_or_init(FileContextCache::new);
                    IpcResponse::FileContextSnapshot {
                        entries: fs_cache.snapshot(limit),
                    }
                }
                Err(e) => IpcResponse::Error {
                    message: format!("invalid request: {e}"),
                },
            }
        };

        let json = match serde_json::to_string(&response) {
            Ok(json) => json,
            Err(e) => {
                mimic_error!("[IPC] Failed to serialize command response: {e}");
                return;
            }
        };

        if !write_command_response(pipe_handle, json.as_bytes()) {
            mimic_error!("[IPC] Failed to write command response");
        }
    }
}

fn write_command_response(pipe_handle: HANDLE, data: &[u8]) -> bool {
    let response_len = (data.len() as u64).to_le_bytes();
    write_pipe_bytes(pipe_handle, &response_len) && write_pipe_bytes(pipe_handle, data)
}

fn write_pipe_bytes(pipe_handle: HANDLE, data: &[u8]) -> bool {
    for chunk in data.chunks(PIPE_BUFFER_SIZE as usize) {
        let mut bytes_written: u32 = 0;
        let write_result =
            unsafe { WriteFile(pipe_handle, Some(chunk), Some(&mut bytes_written), None) };

        if write_result.is_err() || bytes_written as usize != chunk.len() {
            return false;
        }
    }

    true
}

fn broadcast_message(clients: &mut Vec<HANDLE>, message: &IpcMessage) {
    let json = match serde_json::to_string(message) {
        Ok(j) => j,
        Err(e) => {
            mimic_error!("[IPC] Failed to serialize message: {}", e);
            return;
        }
    };

    let data = json.as_bytes();
    let mut disconnected_clients = Vec::new();

    for (idx, &handle) in clients.iter().enumerate() {
        unsafe {
            let mut bytes_written: u32 = 0;

            match WriteFile(handle, Some(data), Some(&mut bytes_written), None) {
                Ok(_) => {
                    // Success
                }
                Err(e) => {
                    let error_code = win32_error_code(&e);
                    if error_code == ERROR_NO_DATA.0 || error_code == ERROR_BROKEN_PIPE.0 {
                        mimic_log!("[IPC] Client disconnected");
                        disconnected_clients.push(idx);
                    } else {
                        mimic_error!("[IPC] WriteFile failed: {:?}", e);
                    }
                }
            }
        }
    }

    // Remove disconnected clients (in reverse order to maintain indices)
    for &idx in disconnected_clients.iter().rev() {
        let handle = clients.remove(idx);
        unsafe {
            let _ = DisconnectNamedPipe(handle);
            let _ = CloseHandle(handle);
        }
    }
}
