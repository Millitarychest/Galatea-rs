//! Manual FFI bindings for `fltKernel.h` minifilter types and functions.
//!
//! `wdk-sys` 0.5.1 does not generate bindings for the Filter Manager API.
//! These declarations are the minimal subset needed to register a basic
//! minifilter, intercept operations, and tear down on unload.
//!
//! Layout and values are taken directly from the Windows 10 26100 WDK headers.

use core::ffi::c_void;
use wdk_sys::{DRIVER_OBJECT, FILE_OBJECT, IO_STATUS_BLOCK, NTSTATUS, UNICODE_STRING};

// ---- Opaque handles ----

/// Opaque filter handle returned by [`FltRegisterFilter`].
pub type PFLT_FILTER = *mut c_void;

// ---- Callback return types ----

/// Return type for pre-operation callbacks.
pub type FLT_PREOP_CALLBACK_STATUS = i32;

/// Return type for post-operation callbacks.
pub type FLT_POSTOP_CALLBACK_STATUS = i32;

/// Allow the I/O and invoke the matching post-operation callback.
pub const FLT_PREOP_SUCCESS_WITH_CALLBACK: FLT_PREOP_CALLBACK_STATUS = 0;

/// Allow the I/O, skip the post-operation callback.
pub const FLT_PREOP_SUCCESS_NO_CALLBACK: FLT_PREOP_CALLBACK_STATUS = 1;

/// Post-operation processing is complete.
pub const FLT_POSTOP_FINISHED_PROCESSING: FLT_POSTOP_CALLBACK_STATUS = 0;

// ---- Constants ----

/// Sentinel marking the end of a [`FLT_OPERATION_REGISTRATION`] array.
pub const IRP_MJ_OPERATION_END: u8 = 0x80;

/// Version value for [`FLT_REGISTRATION::version`].
pub const FLT_REGISTRATION_VERSION: u16 = 0x0203;

// ---- Callback signatures ----

/// Pre-operation callback function pointer.
pub type PFLT_PRE_OPERATION_CALLBACK = Option<
    unsafe extern "C" fn(
        data: *mut FLT_CALLBACK_DATA,
        flt_objects: *const FLT_RELATED_OBJECTS,
        completion_context: *mut *mut c_void,
    ) -> FLT_PREOP_CALLBACK_STATUS,
>;

/// Post-operation callback function pointer.
pub type PFLT_POST_OPERATION_CALLBACK = Option<
    unsafe extern "C" fn(
        data: *mut FLT_CALLBACK_DATA,
        flt_objects: *const FLT_RELATED_OBJECTS,
        completion_context: *mut c_void,
        flags: u32,
    ) -> FLT_POSTOP_CALLBACK_STATUS,
>;

/// Filter-unload callback function pointer.
pub type PFLT_FILTER_UNLOAD_CALLBACK = Option<unsafe extern "C" fn(flags: u32) -> NTSTATUS>;

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
    pub pre_operation: PFLT_PRE_OPERATION_CALLBACK,
    /// Called after the I/O completes (if pre returned `..WITH_CALLBACK`).
    pub post_operation: PFLT_POST_OPERATION_CALLBACK,
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
    pub filter_unload_callback: PFLT_FILTER_UNLOAD_CALLBACK,
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

// ---- Function imports ----

// These link against fltMgr.lib which is provided by the WDK.
unsafe extern "C" {
    /// Registers a minifilter with the Filter Manager.
    pub fn FltRegisterFilter(
        driver: *mut DRIVER_OBJECT,
        registration: *const FLT_REGISTRATION,
        ret_filter: *mut PFLT_FILTER,
    ) -> NTSTATUS;

    /// Tells the Filter Manager to begin sending I/O to the filter.
    pub fn FltStartFiltering(filter: PFLT_FILTER) -> NTSTATUS;

    /// Unregisters a previously registered minifilter.
    pub fn FltUnregisterFilter(filter: PFLT_FILTER);
}
