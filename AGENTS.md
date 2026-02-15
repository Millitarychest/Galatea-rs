## Project Information:

The project your currently viewing is a Rust based EDR implementation. This is a research project however your code should be as close to production code as posible.

The project is split up into the following components:
- enpoint : This folder contains the codebase for the different EDR parts running on the enpoint
    - [agent](/endpoint/agent/) : This crate is the main agent component orchestrating the other following components and correlating their output
    - [client](/endpoint/client/) : This crate is the local GUI displaying events detected by the agent.
    - [driver](/endpoint/driver/) : This crate is the main driver component, implementing the process creation callbacks and process freezing 
    - [hook](/endpoint/hook/) : This crate contains the code for the dll implementing userland hooks
    - [shared](/endpoint/shared/) : This crate defines the communication definitions used in IPC and IOCTL between the different agent components
- server : This folder contains the codebase for the central managment server and the needed API interface
    - [server](/server/server/) : This crate is the actual code of the server
    - [api-definitions](/server/api-definition/) : This crate defines the API interface definitions used for agent <-> server communication


## Skills:

For domain specific knowledge and skills i have defined skills in the [.agent/skills](./.agent/skills) folder. This folder contains a subfolder for each skill. These contain the skill specific files, with the specific `SKILL.md` files acting as the entry point for the skills.

**available skills:**
- [Rust code guide](./.agent/skills/rust_code_guide/) : This skill defines rules and best practices for rust implementations


## PR instructions
- Title format: `[<component_name>:<feature_name>] <Title>`