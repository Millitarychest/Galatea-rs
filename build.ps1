param (
    [switch]$Release
)

$ErrorActionPreference = "Stop"

# --- CONFIGURATION ---
$DriverPath = "endpoint\driver"
$DistDir    = "target\dist"

$DriverName = "driver"
$AgentName = "agent.exe"
$HookDllName = "hook.dll"
$GuiName = "client.exe"

# Set build paths and flags based on mode
if ($Release) {
    Write-Host "[*] Building in RELEASE mode" -ForegroundColor Yellow
    $CargoProfileFlag = "--release"
    $CargoMakeProfile = "--profile release"
    $DriverTargetSourceDir = "target\x86_64-pc-windows-msvc\release"
    $GeneralTargetSourceDir = "target\release"
} else {
    Write-Host "[*] Building in DEBUG mode" -ForegroundColor Yellow
    $CargoProfileFlag = ""
    $CargoMakeProfile = "" # default profile for cargo make
    $DriverTargetSourceDir = "target\x86_64-pc-windows-msvc\debug"
    $GeneralTargetSourceDir = "target\debug"
}

$AssetDir = "static\assets\*"
$ModelPath = "models"
$ModelName = "model.onnx"
$ModelFName = "features.txt"


# --- Driver build
Write-Host "`n[i] Starting Galatea Driver Build..." -ForegroundColor Cyan
Push-Location $DriverPath
try {
    Write-Host "[>>] Compiling Kernel Driver..."
    # Invoke-Expression to handle the variable arguments cleanly
    Invoke-Expression "cargo make $CargoMakeProfile"
}
catch {
    Write-Error "[!] Compilation Failed!"
    Pop-Location
    exit 1
}
Pop-Location

Write-Host "[>>] Moving and renaming artifact..."
$DllPath = "$DriverTargetSourceDir\driver_package\*"

if (!(Test-Path $DistDir)) {
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
}

if (Test-Path $DllPath) {
    Copy-Item -Path $DllPath -Destination $DistDir -Force -Recurse
    Write-Host "[+] Driver built at: $DistDir" -ForegroundColor Green
} else {
    Write-Error "[!] Build finished but output file not found at $DllPath"
    exit 1
}

# --- Agent build

Write-Host "`n[i] Starting Galatea Agent Build..." -ForegroundColor Cyan
Write-Host "[>>] Compiling Agent..."
Invoke-Expression "cargo build -p agent $CargoProfileFlag"

$AgentBuildPath = "$GeneralTargetSourceDir\$AgentName"
$AgentDistPath = "$DistDir\$AgentName"
Copy-Item $AgentBuildPath $AgentDistPath -Force

# --- Hook dll build

Write-Host "`n[i] Starting Galatea Hooking Dll Build..." -ForegroundColor Cyan
Write-Host "[>>] Compiling Hook Dll..."
Invoke-Expression "cargo build -p hook $CargoProfileFlag"

$DllBuildPath = "$GeneralTargetSourceDir\$HookDllName"
$DllDistPath = "$DistDir\$HookDllName"
Copy-Item $DllBuildPath $DllDistPath -Force

# --- GUI build

Write-Host "`n[i] Starting Galatea GUI Build..." -ForegroundColor Cyan
Write-Host "[>>] Compiling GUI..."
Invoke-Expression "cargo build -p client $CargoProfileFlag"

$GuiBuildPath = "$GeneralTargetSourceDir\$GuiName"
$GuiDistPath = "$DistDir\$GuiName"
Copy-Item $GuiBuildPath $GuiDistPath -Force

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

Write-Host "`n[+] Build Complete!" -ForegroundColor Green
