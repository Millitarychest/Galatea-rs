use shared::ipc::{IpcMessage, PIPE_NAME};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::{CloseHandle, ERROR_PIPE_BUSY, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, OPEN_EXISTING, ReadFile,
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
                let error_code = e.code().0 as u32;
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
