//! FFI bindings for `fltKernel.h` minifilter types and functions.
//!
//! `wdk-sys` 0.5.1 does not generate bindings for the Filter Manager API.
//! These declarations are the minimal subset needed to register a basic
//! minifilter, intercept operations, and tear down on unload.
//!
//! Layout and values are taken directly from the Windows 10 26100 WDK headers.

use core::ffi::c_void;
use core::ptr::null_mut;
use wdk_sys::{DRIVER_OBJECT, FILE_OBJECT, HANDLE, IO_STATUS_BLOCK, LARGE_INTEGER, NTSTATUS, UNICODE_STRING};

// ---- Opaque handles ----

/// Opaque filter handle returned by [`FltRegisterFilter`].
pub type PfltFilter = *mut c_void;

/// Opaque server or client communication port handle.
pub type PfltPort = *mut c_void;

/// Access mask used by [`FltBuildDefaultSecurityDescriptor`].
pub type AccessMask = u32;

/// Opaque security descriptor allocated by Filter Manager.
pub type SecurityDescriptor = c_void;

// ---- Callback return types ----

/// Return type for pre-operation callbacks.
pub type FltPreopCallbackStatus = i32;

/// Return type for post-operation callbacks.
pub type FltPostopCallbackStatus = i32;

/// Allow the I/O and invoke the matching post-operation callback.
pub const FLT_PREOP_SUCCESS_WITH_CALLBACK: FltPreopCallbackStatus = 0;

/// Allow the I/O, skip the post-operation callback.
pub const FLT_PREOP_SUCCESS_NO_CALLBACK: FltPreopCallbackStatus = 1;

/// Post-operation processing is complete.
pub const FLT_POSTOP_FINISHED_PROCESSING: FltPostopCallbackStatus = 0;

// ---- Constants ----

/// Marks the end of a [`FLT_OPERATION_REGISTRATION`] array.
pub const IRP_MJ_OPERATION_END: u8 = 0x80;

/// Version value for [`FLT_REGISTRATION::version`].
pub const FLT_REGISTRATION_VERSION: u16 = 0x0203;

/// `OBJECT_ATTRIBUTES::attributes` flag for case-insensitive name lookup.
pub const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

/// `OBJECT_ATTRIBUTES::attributes` flag required for kernel-only handles.
pub const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;

/// Grants a user-mode client permission to connect to a filter port.
pub const FLT_PORT_CONNECT: AccessMask = 0x0000_0001;

/// Full access for communication ports built from `FLT_PORT_CONNECT`.
pub const FLT_PORT_ALL_ACCESS: AccessMask = 0x001f_0000 | FLT_PORT_CONNECT;

// ---- Callback signatures ----

/// Pre-operation callback function pointer.
pub type PfltPreOperationCallback = Option<
    unsafe extern "C" fn(
        data: *mut FLT_CALLBACK_DATA,
        flt_objects: *const FLT_RELATED_OBJECTS,
        completion_context: *mut *mut c_void,
    ) -> FltPreopCallbackStatus,
>;

/// Post-operation callback function pointer.
pub type PfltPostOperationCallback = Option<
    unsafe extern "C" fn(
        data: *mut FLT_CALLBACK_DATA,
        flt_objects: *const FLT_RELATED_OBJECTS,
        completion_context: *mut c_void,
        flags: u32,
    ) -> FltPostopCallbackStatus,
>;

/// Filter-unload callback function pointer.
pub type PfltFilterUnloadCallback = Option<unsafe extern "C" fn(flags: u32) -> NTSTATUS>;

/// Connection-notification callback for a communication server port.
pub type PfltConnectNotify = Option<
    unsafe extern "C" fn(
        client_port: PfltPort,
        server_port_cookie: *mut c_void,
        connection_context: *mut c_void,
        size_of_context: u32,
        connection_port_cookie: *mut *mut c_void,
    ) -> NTSTATUS,
>;

/// Disconnect-notification callback for a communication client port.
pub type PfltDisconnectNotify = Option<unsafe extern "C" fn(connection_cookie: *mut c_void)>;

/// Message callback for user-mode `FilterSendMessage` traffic.
pub type PfltMessageNotify = Option<
    unsafe extern "C" fn(
        port_cookie: *mut c_void,
        input_buffer: *mut c_void,
        input_buffer_length: u32,
        output_buffer: *mut c_void,
        output_buffer_length: u32,
        return_output_buffer_length: *mut u32,
    ) -> NTSTATUS,
>;

// ---- Structures ----

/// Describes one I/O major function the minifilter wants to intercept.
///
/// An array of these is embedded in [`FLT_REGISTRATION`] and **must** be
/// terminated by an entry with `major_function == IRP_MJ_OPERATION_END`.
#[repr(C)]
pub struct FLT_OPERATION_REGISTRATION {
    /// IRP major function code (e.g. `IRP_MJ_CREATE`).
    pub major_function: u8,
    /// Combination of `FLTFL_OPERATION_REGISTRATION_*` flags.
    pub flags: u32,
    /// Called before the I/O is sent to the file system.
    pub pre_operation: PfltPreOperationCallback,
    /// Called after the I/O completes (if pre returned `..WITH_CALLBACK`).
    pub post_operation: PfltPostOperationCallback,
    /// Reserved — must be `null_mut()`.
    pub reserved1: *mut c_void,
}

// Safety: contains only function pointers, scalars, and a null reserved pointer.
// The static CALLBACKS array is read-only after initialisation.
unsafe impl Sync for FLT_OPERATION_REGISTRATION {}
unsafe impl Send for FLT_OPERATION_REGISTRATION {}

/// Top-level minifilter registration structure passed to [`FltRegisterFilter`].
///
/// Fields we don't use are typed as opaque `*const c_void` rather than
/// duplicating callback signatures we'll never call.
#[repr(C)]
pub struct FLT_REGISTRATION {
    /// Must be `size_of::<FLT_REGISTRATION>()`.
    pub size: u16,
    /// Must be [`FLT_REGISTRATION_VERSION`].
    pub version: u16,
    /// `FLTFL_REGISTRATION_*` flags (0 for defaults).
    pub flags: u32,
    /// Optional context registration array (null if unused).
    pub context_registration: *const c_void,
    /// Required pointer to the operation-callback array.
    pub operation_registration: *const FLT_OPERATION_REGISTRATION,
    /// Called when the filter is being unloaded.
    pub filter_unload_callback: PfltFilterUnloadCallback,
    /// Instance setup callback (null if unused).
    pub instance_setup_callback: *const c_void,
    /// Instance query-teardown callback (null if unused).
    pub instance_query_teardown_callback: *const c_void,
    /// Instance teardown-start callback (null if unused).
    pub instance_teardown_start_callback: *const c_void,
    /// Instance teardown-complete callback (null if unused).
    pub instance_teardown_complete_callback: *const c_void,
    /// Generate-file-name callback (null if unused).
    pub generate_file_name_callback: *const c_void,
    /// Normalize-name-component callback (null if unused).
    pub normalize_name_component_callback: *const c_void,
    /// Normalize-context-cleanup callback (null if unused).
    pub normalize_context_cleanup_callback: *const c_void,
    /// Transaction-notification callback (null if unused).
    pub transaction_notification_callback: *const c_void,
    /// Normalize-name-component-ex callback (null if unused).
    pub normalize_name_component_ex_callback: *const c_void,
    /// Section-notification callback (null if unused).
    pub section_notification_callback: *const c_void,
}

// Safety: immutable static with only function pointers and null pointers.
unsafe impl Sync for FLT_REGISTRATION {}
unsafe impl Send for FLT_REGISTRATION {}

/// Callback data passed to pre/post-operation callbacks.
///
/// We only access `io_status` for checking completion status in post-ops.
/// The leading fields (flags, thread, irp, etc.) are skipped with padding.
///
/// **x64 layout** (from fltKernel.h):
/// - `Flags` (u32) + padding = 8 bytes
/// - `Thread` (PETHREAD) = 8 bytes
/// - `Iopb` (PFLT_IO_PARAMETER_BLOCK) = 8 bytes
/// - `IoStatus` (IO_STATUS_BLOCK) = at offset 24
#[repr(C)]
pub struct FLT_CALLBACK_DATA {
    /// Flags + alignment padding.
    pub _flags: u64,
    /// Pointer to the calling thread.
    pub _thread: *mut c_void,
    /// Pointer to the I/O parameter block.
    pub _iopb: *mut c_void,
    /// I/O completion status — the field we actually read in post-ops.
    pub io_status: IO_STATUS_BLOCK,
    // remaining fields omitted — we don't access them
}

/// Objects related to the current I/O operation.
///
/// **x64 layout** (from fltKernel.h):
/// - `Size` (u16) + padding = 4 bytes
/// - `TransactionContext` (u16) — part of the padding above
/// - `Filter` (PFLT_FILTER) = 8 bytes
/// - `Volume` (PFLT_VOLUME) = 8 bytes
/// - `Instance` (PFLT_INSTANCE) = 8 bytes
/// - `FileObject` (PFILE_OBJECT) = 8 bytes
#[repr(C)]
pub struct FLT_RELATED_OBJECTS {
    /// Structure size.
    pub _size: u16,
    /// Transaction context flags.
    pub _transaction_context: u16,
    /// Padding for alignment on x64.
    pub _pad: u32,
    /// Opaque filter pointer.
    pub _filter: *const c_void,
    /// Opaque volume pointer.
    pub _volume: *const c_void,
    /// Opaque instance pointer.
    pub _instance: *const c_void,
    /// The file object for the current operation.
    pub file_object: *mut FILE_OBJECT,
}

/// Kernel object attributes used when creating a communication server port.
///
/// This matches the Windows `OBJECT_ATTRIBUTES` layout used by
/// `InitializeObjectAttributes`.
#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    /// Structure size in bytes.
    pub length: u32,
    /// Optional root directory handle for relative names.
    pub root_directory: HANDLE,
    /// Object name, usually a `\\Name`-style port path.
    pub object_name: *mut UNICODE_STRING,
    /// `OBJ_*` attribute flags.
    pub attributes: u32,
    /// Optional security descriptor for the created object.
    pub security_descriptor: *mut SecurityDescriptor,
    /// Reserved quality-of-service pointer, usually null.
    pub security_quality_of_service: *mut c_void,
}

/// Initializes [`OBJECT_ATTRIBUTES`] with the values expected by Filter Manager.
#[must_use]
pub const fn initialize_object_attributes(
    object_name: *mut UNICODE_STRING,
    attributes: u32,
    root_directory: HANDLE,
    security_descriptor: *mut SecurityDescriptor,
) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        root_directory,
        object_name,
        attributes,
        security_descriptor,
        security_quality_of_service: null_mut(),
    }
}

// ---- Function imports ----

// These link against fltMgr.lib which is provided by the WDK.
unsafe extern "C" {
    /// Registers a minifilter with the Filter Manager.
    pub fn FltRegisterFilter(
        driver: *mut DRIVER_OBJECT,
        registration: *const FLT_REGISTRATION,
        ret_filter: *mut PfltFilter,
    ) -> NTSTATUS;

    /// Tells the Filter Manager to begin sending I/O to the filter.
    pub fn FltStartFiltering(filter: PfltFilter) -> NTSTATUS;

    /// Unregisters a previously registered minifilter.
    pub fn FltUnregisterFilter(filter: PfltFilter);

    /// Creates a named server port for minifilter to user-mode communication.
    pub fn FltCreateCommunicationPort(
        filter: PfltFilter,
        server_port: *mut PfltPort,
        object_attributes: *mut OBJECT_ATTRIBUTES,
        server_port_cookie: *mut c_void,
        connect_notify_callback: PfltConnectNotify,
        disconnect_notify_callback: PfltDisconnectNotify,
        message_notify_callback: PfltMessageNotify,
        max_connections: i32,
    ) -> NTSTATUS;

    /// Closes a server communication port created by [`FltCreateCommunicationPort`].
    pub fn FltCloseCommunicationPort(server_port: PfltPort);

    /// Closes a connected client port and nulls the caller's handle.
    pub fn FltCloseClientPort(filter: PfltFilter, client_port: *mut PfltPort);

    /// Sends a message to a connected user-mode client port.
    pub fn FltSendMessage(
        filter: PfltFilter,
        client_port: *mut PfltPort,
        sender_buffer: *mut c_void,
        sender_buffer_length: u32,
        reply_buffer: *mut c_void,
        reply_length: *mut u32,
        timeout: *mut LARGE_INTEGER,
    ) -> NTSTATUS;

    /// Allocates a default security descriptor for a communication server port.
    pub fn FltBuildDefaultSecurityDescriptor(
        security_descriptor: *mut *mut SecurityDescriptor,
        desired_access: AccessMask,
    ) -> NTSTATUS;

    /// Frees a descriptor allocated by [`FltBuildDefaultSecurityDescriptor`].
    pub fn FltFreeSecurityDescriptor(security_descriptor: *mut SecurityDescriptor);
}
