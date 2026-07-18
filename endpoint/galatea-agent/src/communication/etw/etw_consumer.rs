use ferrisetw::parser::Parser;
use ferrisetw::{UserTrace, provider::Provider};
use ferrisetw::EventRecord;
use ferrisetw::schema_locator::SchemaLocator;
use galatea_shared::id::GA_PID;
use mimic_core::{mimic_error, mimic_log};

use crate::engine::signatures::process_signatures;
use crate::{ETW_HOOK_PROVIDER_UUID, PROC_CONTEXT_CACHE};
use crate::cache::process_context_cache::{ProcessContextCache, ProcessContextUpdate};


pub fn register_etw_consumers() -> UserTrace{
    let hook_provider = Provider::by_guid(ETW_HOOK_PROVIDER_UUID).add_callback(etw_hook_callback).build();

    return UserTrace::new().enable(hook_provider).start_and_process().unwrap();
}

fn parse_ga_pid(parser: &Parser<'_, '_>) -> Option<GA_PID> {
    let ga_pid_lo: u64 = match parser.try_parse("ga_pid_lo") {
        Ok(value) => value,
        Err(error) => {
            mimic_error!("[ETW] Failed to parse ga_pid_lo: {error:?}");
            return None;
        }
    };
    let ga_pid_hi: u64 = match parser.try_parse("ga_pid_hi") {
        Ok(value) => value,
        Err(error) => {
            mimic_error!("[ETW] Failed to parse ga_pid_hi: {error:?}");
            return None;
        }
    };

    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&ga_pid_lo.to_le_bytes());
    bytes[8..].copy_from_slice(&ga_pid_hi.to_le_bytes());
    Some(GA_PID::from_bytes(bytes))
}

fn etw_hook_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    match schema_locator.event_schema(record) {
        Ok(schema) => {
            let parser = Parser::create(record, &schema);
            //OpenProcess
            if record.event_id() == 0 {
                let actor_pid: u32 = parser.try_parse("actor_pid").unwrap_or_default();
                let target_pid: u32 = parser.try_parse("target_pid").unwrap_or_default();

                let Some(actor_ga_pid) = parse_ga_pid(&parser) else {
                    return;
                };

                let update = ProcessContextUpdate { 
                    pid: None, 
                    process_start_key: None, 
                    behavioural_score: None, 
                    image_path: None, 
                    image_context_key: None, 
                    matching_flags: Some(vec![process_signatures::ProcessFlags::OpenedRemoteProcess]) 
                };

                let context_cache = PROC_CONTEXT_CACHE.get_or_init(ProcessContextCache::new);
                context_cache.write_telemetry(actor_ga_pid, update);

                mimic_log!(
                    "[ETW] OpenProcess actor_pid={} target_pid={}",
                    actor_pid,
                    target_pid,
                );
            }
            //AllocateVirtualMemory
            if record.event_id() == 1 {
                let actor_pid: u32 = parser.try_parse("actor_pid").unwrap_or_default();
                let target_pid: u32 = parser.try_parse("target_pid").unwrap_or_default();

                let Some(actor_ga_pid) = parse_ga_pid(&parser) else {
                    return;
                };


                // TODO: This will need to be refined into multiple flags aka AllocedVMemInRemoteProcess, AllocedExecutableVMemInRemoteProcess etc
                let update = ProcessContextUpdate { 
                    pid: None, 
                    process_start_key: None, 
                    behavioural_score: None, 
                    image_path: None, 
                    image_context_key: None, 
                    matching_flags: Some(vec![process_signatures::ProcessFlags::AllocedVMemInRemoteProcess]) 
                };

                let context_cache = PROC_CONTEXT_CACHE.get_or_init(ProcessContextCache::new);
                context_cache.write_telemetry(actor_ga_pid, update);

                mimic_log!(
                    "[ETW] AllocateVirtualMemory actor_pid={} target_pid={}",
                    actor_pid,
                    target_pid,
                );
            }
        }
        Err(err) => {
            mimic_error!("[ETW] Failed to resolve event schema: {:?}", err);
        }
    }
}