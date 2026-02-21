use mimic_core::{mimic_error, mimic_log};
use galatea_shared::ipc::{IpcMessage, PIPE_BUFFER_SIZE, PIPE_NAME};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, HANDLE,
    HLOCAL, INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{PIPE_ACCESS_OUTBOUND, WriteFile};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::core::{PWSTR, w};



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

        mimic_log!("IPC server listening on {}", PIPE_NAME);
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
                            let error_code = e.code().0 as u32;
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
                    let error_code = e.code().0 as u32;
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
