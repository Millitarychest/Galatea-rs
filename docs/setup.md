# Setup

> [!CAUTION]
> **!! NEVER RUN OUTSIDE OF A VM !!**\
> This is an experimental project written by an idiot.
> Given that the EDR requires elevate permissions as well as a kernel driver, it can really screw up your PC or at the very least cause it to BSOD

## VM Setup

To run this project you need to setup your VM to allow self-signed drivers and debugging. Run the following commands in an elevated PowerShell prompt:

```powershell
# Enable test signing
bcdedit /set testsigning on

# Enable debugging
bcdedit /debug on
```

<br>

## Build

To build the project, you need to have the following tools installed:

- [cargo-make](https://github.com/sagiegurari/cargo-make)
- WDK (Windows Driver Kit)
- libclang (for bindgen as part of wdk crate)

<br>

To build the project, run the following command in the root directory:

```powershell
# Build the project
./build.ps1
```

This will build the project with most components in debug mode. If you want to build the project in release mode, run the following command:

```powershell
# Build the project in release mode
./build.ps1 -Release
```

These commands will create a `dist` folder in the target directory containing all needed files:

- `driver.sys` - The kernel driver and all its associated files
- `hook.dll` - The user-mode hook DLL
- `client.exe` - The user-mode UI
- `agent.exe` - The user-mode agent
- `model.onnx` - The ML model for static analysis

If available the following datasets will also be present:
- `galatea_dataset.db` - The known-badlist
- `userdb.txt` - The packer signatures
