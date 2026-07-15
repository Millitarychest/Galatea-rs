use ferrisetw::parser::Parser;
use ferrisetw::{UserTrace, provider::Provider};
use ferrisetw::EventRecord;
use ferrisetw::schema_locator::SchemaLocator;
use mimic_core::{mimic_error, mimic_log};

use crate::ETW_HOOK_PROVIDER_UUID;


pub fn register_etw_consumers() -> UserTrace{
    let hook_provider = Provider::by_guid(ETW_HOOK_PROVIDER_UUID).add_callback(etw_hook_callback).build();

    return UserTrace::new().enable(hook_provider).start_and_process().unwrap();
}

fn etw_hook_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    match schema_locator.event_schema(record) {
        Ok(schema) => {
            let parser = Parser::create(record, &schema);
            
            if record.event_id() == 0 {
                let actor_pid: u32 = parser.try_parse("actor_pid").unwrap_or_default();
                let target_pid: u32 = parser.try_parse("target_pid").unwrap_or_default();

                mimic_log!(
                    "[ETW] OpenProcess actor_pid={} target_pid={}",
                    actor_pid,
                    target_pid,
                );
            }
            if record.event_id() == 1 {
                let actor_pid: u32 = parser.try_parse("actor_pid").unwrap_or_default();
                let target_pid: u32 = parser.try_parse("target_pid").unwrap_or_default();

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