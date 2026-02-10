# Roadmap

<details open>
<summary>Endpoint</summary>

- [x] Basic Driver Setup

- [x] Static checks
    - [x] Known Bad (only md5 atm)
    - [x] Signature
    - [x] Heuristics (Packing)
    - [x] [ML classifier static detection](features/ml_classifier.md)

- [ ] Behavioural checks
    - [~] Dll based Userland hooks
    - [ ] Network
    - [ ] File system

- [ ] Configuration
    - [ ] Exclusions and custom indicators

- [~] Gui
    - [ ] Config screen
    - [X] Device Timeline View
 
- [~] Hardening
    - [x] Register Agent to prevent other processes from sending verdicts
    - [ ] Bilateral Health checks (Is Driver/agent alive?)
    - [ ] Split Agent and restrict driver to Service Principal

</details>

<br>

<details open>
<summary>Server</summary>

- [ ] Endpoint Log telemetry API


</details>

