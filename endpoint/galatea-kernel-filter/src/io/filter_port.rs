use core::ffi::c_void;
use core::ptr::null_mut;

use wdk_sys::ntddk::DbgPrint;
use wdk_sys::{
    NTSTATUS, STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, UNICODE_STRING,
};

use crate::ffi::flt::{
    FLT_PORT_ALL_ACCESS, FltBuildDefaultSecurityDescriptor, FltCloseClientPort, FltCloseCommunicationPort, FltCreateCommunicationPort, FltFreeSecurityDescriptor, FltSendMessage, OBJ_CASE_INSENSITIVE, OBJ_KERNEL_HANDLE, PfltFilter, PfltPort, SecurityDescriptor, initialize_object_attributes
};

use galatea_shared::filter_port::{
    FILTER_PORT_PAYLOAD_SIZE, GalateaFilterMessage, GalateaFilterMessageKind, GalateaFSEvent,
};

macro_rules! w {
    ($s:expr) => {{
        const S: &[u16] = &{
            let bs = $s.as_bytes();
            let mut out = [0u16; $s.len()];
            let mut i = 0;
            while i < $s.len() {
                out[i] = bs[i] as u16;
                i += 1;
            }
            out
        };
        S
    }};
}

static mut SERVER_PORT: PfltPort = null_mut();
static mut CLIENT_PORT: PfltPort = null_mut();

const PORT_NAME: &[u16] = w!("\\GalateaFilterPort");

unsafe extern "C" fn connect_notify(
    client_port: PfltPort,
    _server_port_cookie: *mut c_void,
    _connection_context: *mut c_void,
    _size_of_context: u32,
    connection_port_cookie: *mut *mut c_void,
) -> NTSTATUS {
    // Safety: FltMgr serializes the callback arguments for this invocation. We only
    // publish the accepted client port into a single global slot for the current PoC.
    unsafe {
        if !CLIENT_PORT.is_null() {
            DbgPrint(b"GalateaFlt: rejecting extra filter port client\n\0".as_ptr() as *const i8);
            return STATUS_ACCESS_DENIED;
        }

        CLIENT_PORT = client_port;
        if !connection_port_cookie.is_null() {
            *connection_port_cookie = client_port as *mut c_void;
        }

        DbgPrint(b"GalateaFlt: filter port client connected\n\0".as_ptr() as *const i8);
        STATUS_SUCCESS
    }
}

unsafe extern "C" fn disconnect_notify(_connection_cookie: *mut c_void) {
    // Safety: FILTER_HANDLE remains valid until filter unload unregisters the
    // minifilter. FltCloseClientPort nulls CLIENT_PORT for us.
    unsafe {
        if crate::FILTER_HANDLE.is_null() || CLIENT_PORT.is_null() {
            return;
        }

        DbgPrint(b"GalateaFlt: filter port client disconnected\n\0".as_ptr() as *const i8);
        FltCloseClientPort(crate::FILTER_HANDLE, &raw mut CLIENT_PORT);
    }
}

unsafe extern "C" fn message_notify(
    port_cookie: *mut c_void,
    input_buffer: *mut c_void,
    input_buffer_length: u32,
    output_buffer: *mut c_void,
    output_buffer_length: u32,
    return_output_buffer_length: *mut u32,
) -> NTSTATUS {
    // saftey: CLIENT_PORT should always be set at this point as to send a message the client will first have to connect which sets the var
    unsafe {
        if CLIENT_PORT == port_cookie {
            DbgPrint(b"hi, this was the real client".as_ptr() as *const i8);
        } else {
            DbgPrint(b"hi, this was a fake client".as_ptr() as *const i8);
        }
    }
    STATUS_SUCCESS
}

/// Creates the minifilter's user-mode communication server port.
pub(crate) unsafe fn initialize_port(filter: PfltFilter) -> NTSTATUS {
    if filter.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let mut security_descriptor: *mut SecurityDescriptor = null_mut();
    let mut port_name = UNICODE_STRING {
        Length: (PORT_NAME.len() * 2) as u16,
        MaximumLength: (PORT_NAME.len() * 2) as u16,
        Buffer: PORT_NAME.as_ptr() as *mut _,
    };

    // Safety: Filter Manager allocates a descriptor and writes the pointer into
    // security_descriptor on success. We free it before returning.
    let status = unsafe {
        FltBuildDefaultSecurityDescriptor(&raw mut security_descriptor, FLT_PORT_ALL_ACCESS)
    };
    if status != STATUS_SUCCESS {
        unsafe {
            DbgPrint(
                b"GalateaFlt: FltBuildDefaultSecurityDescriptor FAILED 0x%08x\n\0".as_ptr()
                    as *const i8,
                status,
            )
        };
        return status;
    }

    let mut object_attributes = initialize_object_attributes(
        &mut port_name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        null_mut(),
        security_descriptor,
    );

    // Safety: filter is a registered minifilter handle, object_attributes points
    // to a valid named object, and SERVER_PORT is a stable out-parameter.
    let status = unsafe {
        FltCreateCommunicationPort(
            filter,
            &raw mut SERVER_PORT,
            &mut object_attributes,
            null_mut(),
            Some(connect_notify),
            Some(disconnect_notify),
            Some(message_notify),
            1,
        )
    };

    // Safety: the descriptor was allocated by Filter Manager above.
    unsafe { FltFreeSecurityDescriptor(security_descriptor) };

    if status != STATUS_SUCCESS {
        unsafe {
            DbgPrint(
                b"GalateaFlt: FltCreateCommunicationPort FAILED 0x%08x\n\0".as_ptr() as *const i8,
                status,
            )
        };
        return status;
    }

    unsafe {
        DbgPrint(
            b"GalateaFlt: filter port created at \\\\GalateaFilterPort\n\0".as_ptr() as *const i8,
        )
    };
    STATUS_SUCCESS
}

/// Closes any active client connection and the server port.
pub(crate) unsafe fn teardown_port(filter: PfltFilter) {
    // Safety: FltCloseCommunicationPort/FltCloseClientPort accept null-checked
    // opaque handles. We only call them for handles created by this module.
    unsafe {
        if !SERVER_PORT.is_null() {
            FltCloseCommunicationPort(SERVER_PORT);
            SERVER_PORT = null_mut();
        }

        if !filter.is_null() && !CLIENT_PORT.is_null() {
            FltCloseClientPort(filter, &raw mut CLIENT_PORT);
        }
    }
}


/// Sends a filesystem telemetry event to the agent.
pub(crate) unsafe fn send_fs_telemetry(event: *const GalateaFSEvent) -> NTSTATUS {
    /// `event` must point to a valid, properly aligned [`GalateaFSEvent`].
    /// The filter communication port must be initialized with a connected client. As this should only be called by the callbacks this is a given
    unsafe {
        if crate::FILTER_HANDLE.is_null() || CLIENT_PORT.is_null() {
            return STATUS_INVALID_PARAMETER;
        }

        let mut message = GalateaFilterMessage::default();
        message.kind = GalateaFilterMessageKind::FileTelemetry;
        message.payload_len = core::mem::size_of::<GalateaFSEvent>() as u32;

        core::ptr::copy_nonoverlapping(
            event as *const u8,
            message.payload.as_mut_ptr(),
            message.payload_len as usize,
        );

        FltSendMessage(
            crate::FILTER_HANDLE,
            &raw mut CLIENT_PORT,
            &raw mut message as *mut c_void,
            core::mem::size_of::<GalateaFilterMessage>() as u32,
            null_mut(),
            null_mut(),
            null_mut(),
        )
    }
}