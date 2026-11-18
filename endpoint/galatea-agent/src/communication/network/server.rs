use babel_api_definition::{
    AgentAuthentication, AgentHostInfo, AgentRegistration, secrets::Secret,
};
use mimic_core::{error, mimic_log};
use uuid::Uuid;

use crate::config;

/// POC Server register
// TODO: When server exists make it actually do stuff 
pub fn register_with_server(server_uri: &str) -> error::Result<()> {
    mimic_log!("----------------------------------------------------");
    mimic_log!("Registering with server");
    let auth = Secret::new(AgentAuthentication {
        psk: config::AGENT_PSK.to_owned(),
    });
    let host_info = AgentHostInfo {
        hostname: "fake".to_string(),
        os_version: "test".to_string(),
        agent_version: "0.1.0".to_string(),
        ip_address: None,
    };
    let send_body = AgentRegistration {
        uuid: Uuid::new_v4(),
        host_info: host_info,
        auth: auth,
    };

    mimic_log!("{:?}", send_body);

    let resp = ureq::post(server_uri.to_owned() + "/api/v1/agents/register")
        .send_json(&send_body)?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("Failed to read registration response: {e}"))?;
    mimic_log!("{:?}", resp);
    mimic_log!("----------------------------------------------------");
    Ok(())
}
