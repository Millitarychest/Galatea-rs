
// Predefined Flags that can are applied by the telemetry and Engine steps. These can be used for simplified Rule creation
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ProcessFlags {
    #[default]
    None = 0,
    // General
    WhiteListed,
    BlackListed,
    // Hooks
    OpenedRemoteProcess,
    AllocedVMemInRemoteProcess
}
