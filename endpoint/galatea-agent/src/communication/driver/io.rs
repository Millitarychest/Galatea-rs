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

use crate::communication::ipc::SendHandle;

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
                let mut fs_event = GalateaFSEvent {
                    process_id: 0,
                    request_id: 0,
                    event_type: galatea_shared::filter_port::FSEventType::FileOpen,
                    file_path: [0; 260],
                };
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
                    &fs_event.file_path[..fs_event.file_path.iter()
                        .position(|&c| c == 0)
                        .unwrap_or(260)]
                );

                mimic_log!(
                    "FS telemetry: pid={}, event={:?}, path='{}'",
                    fs_event.process_id,
                    fs_event.event_type,
                    path,
                );
            }
            _ => {
                let payload_len = (message_buffer.message.payload_len as usize)
                    .min(FILTER_PORT_PAYLOAD_SIZE);
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
