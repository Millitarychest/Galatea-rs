$ErrorActionPreference = "Stop"

# --- CONFIGURATION ---
$DriverPath = "endpoint\driver"
$DistDir    = "target\dist"

$DriverName = "driver"
$AgentName = "agent.exe"
$HookDllName = "hook.dll"

$DriverTargetDir  = "target\x86_64-pc-windows-msvc\debug"
$GeneralDebugTargetDir  = "target\debug"
$GeneralReleaseTargetDir  = "target\release"
$AssetDir = "static\assets\*"

$ModelPath = "models"
$ModelName = "model.onnx"
$ModelFName = "features.txt"
# --- Driver build
Write-Host "`n[i] Starting Galatea Driver Build..." -ForegroundColor Cyan
Push-Location $DriverPath
try {
    Write-Host "[>>] Compiling Kernel Driver (Release)..."
    #cargo build --release --lib 
    cargo make
}
catch {
    Write-Error "[!] Compilation Failed!"
    Pop-Location
    exit 1
}
Pop-Location

Write-Host "[>>] Moving and renaming artifact..."
$DllPath = "$DriverTargetDir\driver_package\*"
$SysPath = "$DistDir"

if (!(Test-Path $DistDir)) {
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
}

if (Test-Path $DllPath) {
    Copy-Item -Path $DllPath -Destination $SysPath -Force -Recurse
    Write-Host "`n[+] Driver built at: $SysPath" -ForegroundColor Green
} else {
    Write-Error "[+] Build finished but output file not found at $DllPath"
    exit 1
}

# --- Agent build

Write-Host "`n[i] Starting Galatea Agent Build..." -ForegroundColor Cyan
Write-Host "[>>] Compiling Agent (Debug)..."
cargo build -p agent

$AgentBuildPath = "$GeneralDebugTargetDir\$AgentName"
$AgentDistPath = "$DistDir\$AgentName"
Copy-Item $AgentBuildPath $AgentDistPath -Force

# --- Hook dll build

Write-Host "`n[i] Starting Galatea Hooking Dll Build..." -ForegroundColor Cyan
Write-Host "[>>] Compiling Hook Dll (Debug)..."
cargo build -p hook

$DllBuildPath = "$GeneralDebugTargetDir\$HookDllName"
$DllDistPath = "$DistDir\$HookDllName"
Copy-Item $DllBuildPath $DllDistPath -Force

# --- Copy ML assets
$ModelInPath = "$ModelPath\$ModelName"
$ModelFInPath = "$ModelPath\$ModelName"
$ModelOutPath = "$DistDir\$ModelName"
$ModelFOutPath = "$DistDir\$ModelName"
Write-Host "`n[i] Gathering provided model..." -ForegroundColor Cyan
Copy-Item $ModelInPath $ModelOutPath -Force
Copy-Item $ModelFInPath $ModelFOutPath -Force

# --- Copy static assets

Write-Host "`n[i] Gathering provided assets..." -ForegroundColor Cyan
Copy-Item -Path $AssetDir -Destination $DistDir -Force -Recurse