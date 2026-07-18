use win_etw_macros::trace_logging_provider;
use std::sync::OnceLock;

static ETW_PROVIDER: OnceLock<GalateaHookEvents> = OnceLock::new();

pub fn events() -> &'static GalateaHookEvents {
    ETW_PROVIDER.get_or_init(GalateaHookEvents::new)
}


#[trace_logging_provider(name = "mimicry.galatea_hooks")]
pub trait GalateaHookEvents {
    fn etw_process_handle_opened(ga_pid: &[u8], actor_pid: u32, target_pid: u32);
    fn etw_virtual_mem_allocated(ga_pid: &[u8], actor_pid: u32, target_pid: u32, base_address: usize, size: usize, flags: u32, protection: u32);

}