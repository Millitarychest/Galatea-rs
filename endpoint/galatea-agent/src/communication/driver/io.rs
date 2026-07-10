///! Module describes helper functions for communicating with Kernel mode,
///! mainly targeting the Galatea FS filter and Kernel Sensor
///! public interfaces should be prefixed with "kf_" for kernel filter or
///! public interfaces should be prefixed with "ks_" for kernel sensor
use std::ffi::c_void;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::SystemTime;

use galatea_shared::filter_port::{GalateaFSEvent, GalateaFilterMessageKind};
use galatea_shared::{
    GalateaVerdict, IOCTL_REGISTER_AGENT, IOCTL_SEND_VERDICT,
    filter_port::{FILTER_PORT_PAYLOAD_SIZE, GalateaFilterMessage},
};
use mimic_core::{mimic_error, mimic_log, mimic_success};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        Storage::InstallableFileSystems::{
            FILTER_MESSAGE_HEADER, FilterConnectCommunicationPort, FilterGetMessage,
        },
        System::IO::DeviceIoControl,
    },
    core::w,
};

use crate::FILE_CONTEXT_CACHE;
use crate::cache::file_context_cache::{self, FileContextCache, FileTelemetryUpdate};
use crate::communication::ipc::SendHandle;
use crate::engine::signatures::file_signatures::{self, FileFlags};

pub fn ks_send_verdict(handle: HANDLE, mut verdict: GalateaVerdict) {
    let mut bytes_verdict: u32 = 0;
    let verdict_result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_SEND_VERDICT,
            Some(&mut verdict as *mut _ as *mut c_void),
            size_of::<GalateaVerdict>() as u32,
            None,
            0,
            Some(&mut bytes_verdict),
            None,
        )
    };

    match verdict_result {
        Ok(_) => mimic_success!(" -> Verdict sent: {:?}", verdict.allow),
        Err(e) => mimic_error!(" -> Failed to submit Verdict: {:?}", e),
    }
}

pub fn ks_register_agent(handle: HANDLE) -> Result<(), String> {
    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_REGISTER_AGENT,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    match result {
        Ok(_) => {
            mimic_success!("Agent Registered with Kernel Driver.");
            Ok(())
        }
        Err(e) => {
            mimic_error!("Failed to Register Agent (Access Denied?): {:?}", e);
            Err(format!("{:?}", e))
        }
    }
}

///Filter stuff

const GALATEA_FILTER_PORT_NAME: windows::core::PCWSTR = w!("\\GalateaFilterPort");

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct FilterPortMessageBuffer {
    header: FILTER_MESSAGE_HEADER,
    message: GalateaFilterMessage,
}

/// Owns the filter communication-port listener thread.
pub struct FilterPortListener {
    port_handle: HANDLE,
    running: Arc<AtomicBool>,
    listener_thread: Option<JoinHandle<()>>,
}

impl Drop for FilterPortListener {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);

        if let Err(e) = unsafe { CloseHandle(self.port_handle) } {
            mimic_error!("Failed to close filter communication port handle: {:?}", e);
        }

        if let Some(listener_thread) = self.listener_thread.take()
            && listener_thread.join().is_err()
        {
            mimic_error!("Filter communication port listener thread panicked");
        }
    }
}

pub fn kf_connect_and_listen() -> Result<FilterPortListener, String> {
    let port_handle =
        unsafe { FilterConnectCommunicationPort(GALATEA_FILTER_PORT_NAME, 0, None, 0, None) };

    let port_handle = match port_handle {
        Ok(handle) => handle,
        Err(e) => {
            mimic_error!("Failed to connect to filter communication port: {:?}", e);
            return Err(format!("{e:?}"));
        }
    };

    mimic_success!("Connected to filter communication port.");

    let running = Arc::new(AtomicBool::new(true));
    let listener_running = Arc::clone(&running);
    let listener_handle = SendHandle::from(port_handle);

    let listener_thread = thread::spawn(move || {
        let port_handle = HANDLE::from(listener_handle);
        if let Err(e) = kf_listen_for_messages(port_handle, listener_running) {
            mimic_error!("Filter communication port listener stopped: {e}");
        }
    });

    Ok(FilterPortListener {
        port_handle,
        running,
        listener_thread: Some(listener_thread),
    })
}

fn kf_listen_for_messages(port_handle: HANDLE, running: Arc<AtomicBool>) -> Result<(), String> {
    while running.load(Ordering::SeqCst) {
        let mut message_buffer = FilterPortMessageBuffer::default();
        let message_result = unsafe {
            FilterGetMessage(
                port_handle,
                &raw mut message_buffer.header,
                size_of::<FilterPortMessageBuffer>() as u32,
                None,
            )
        };

        if let Err(e) = message_result {
            if !running.load(Ordering::SeqCst) {
                mimic_log!("Filter communication port listener shutting down");
                return Ok(());
            }

            mimic_error!("Failed to receive filter port message: {:?}", e);
            return Err(format!("{e:?}"));
        }

        match message_buffer.message.kind {
            GalateaFilterMessageKind::FileTelemetry => {
                let payload = &message_buffer.message.payload;
                // Safety: GalateaFSEvent is repr(C) and trivially copy; the
                // kernel guarantees the payload is a valid, fully-written struct
                // of exactly size_of::<GalateaFSEvent>() bytes.
                let mut fs_event: GalateaFSEvent = unsafe { core::mem::zeroed() };
                let copy_len = (message_buffer.message.payload_len as usize)
                    .min(core::mem::size_of::<GalateaFSEvent>());
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        payload.as_ptr(),
                        &mut fs_event as *mut _ as *mut u8,
                        copy_len,
                    );
                }

                let path = String::from_utf16_lossy(
                    &fs_event.file_path[..fs_event
                        .file_path
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(260)],
                );

                /*mimic_log!(
                    "FS telemetry: pid={}, start_key={:#x}, file_index={:#x}, event={:?}, path='{}'",
                    fs_event.process_id,
                    fs_event.process_start_key,
                    fs_event.file_index,
                    fs_event.event_type,
                    path,
                );*/

                // file_index of 0 means the kernel could not obtain it (e.g. FAT
                // volume); in that case fall back to the path-based cache key.
                let file_index = if fs_event.file_index != 0 {
                    Some(fs_event.file_index)
                } else {
                    None
                };

                match fs_event.event_type {
                    galatea_shared::filter_port::FSEventType::FileOpen => {}
                    galatea_shared::filter_port::FSEventType::FileCreate => {}
                    galatea_shared::filter_port::FSEventType::FileWrite => {
                        let normalized_path = file_context_cache::fsc_canonicalize_path(&path);
                        let key = file_context_cache::FileContextKey::from_identity(
                            &normalized_path,
                            file_index,
                        );
                        let mut matching_flags = vec![FileFlags::FileWriteSuccess];
                        matching_flags
                            .append(&mut file_signatures::get_location_flags(&normalized_path));

                        let update = FileTelemetryUpdate {
                            normalized_file_path: Some(normalized_path),
                            file_index,
                            // Process image resolved later once the process
                            // context cache is wired up TODO: change to get image from context
                            last_write_process: None,
                            last_write_time: Some(SystemTime::now()),
                            last_rename_time: None,
                            original_name: None,
                            matching_flags: Some(matching_flags),
                        };
                        mimic_log!("[FILE_CONTEXT] write_telemetry key={key:?}");

                        let fs_cache = FILE_CONTEXT_CACHE.get_or_init(FileContextCache::new);
                        fs_cache.write_telemetry(key, update);
                    }
                    galatea_shared::filter_port::FSEventType::FileModify => {}
                    galatea_shared::filter_port::FSEventType::FileDelete => {}
                }
            }
            _ => {
                let payload_len =
                    (message_buffer.message.payload_len as usize).min(FILTER_PORT_PAYLOAD_SIZE);
                let payload = &message_buffer.message.payload[..payload_len];
                let payload_text = String::from_utf8_lossy(payload);

                mimic_log!(
                    "Filter message received: id={}, reply_len={}, kind={:?}, payload_len={}, text='{}'",
                    message_buffer.header.MessageId,
                    message_buffer.header.ReplyLength,
                    message_buffer.message.kind,
                    payload_len,
                    payload_text,
                );
            }
        }
    }

    Ok(())
}
