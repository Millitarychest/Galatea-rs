param (
    [switch]$Release
)

$ErrorActionPreference = "Stop"

# --- CONFIGURATION ---
$DriverPath = "endpoint\galatea-kernel-sensor"
$FilterPath = "endpoint\galatea-kernel-filter"
$DistEndpointDir = "target\dist\endpoint"
$DistServerDir = "target\dist\server"

$DriverName = "galatea_kernel_sensor"
$FilterName = "galatea_kernel_filter"
$AgentName = "galatea-agent.exe"
$HookDllName = "galatea_userland_hooks.dll"
$GuiName = "galatea-client.exe"
$ServerName = "babel-server.exe"

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

$AssetDir = "static\assets\endpoint\*"
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
$DllPath = "$DriverTargetSourceDir\galatea_kernel_sensor_package\*"

$DistEndpointDriverDir = "$DistEndpointDir\driver"

if (!(Test-Path $DistEndpointDriverDir)) {
    New-Item -ItemType Directory -Force -Path $DistEndpointDriverDir | Out-Null
}

if (Test-Path $DllPath) {
    Copy-Item -Path $DllPath -Destination $DistEndpointDriverDir -Force -Recurse
    Write-Host "[+] Driver built at: $DistEndpointDriverDir" -ForegroundColor Green
} else {
    Write-Error "[!] Build finished but output file not found at $DllPath"
    exit 1
}

# --- Filter build
Write-Host "`n[i] Starting Galatea Filter Build..." -ForegroundColor Cyan
Push-Location $FilterPath
try {
    Write-Host "[>>] Compiling Kernel Filter..."
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
$FilterDllPath = "$DriverTargetSourceDir\galatea_kernel_filter_package\*"

$DistEndpointFilterDir = "$DistEndpointDir\filter"

if (!(Test-Path $DistEndpointFilterDir)) {
    New-Item -ItemType Directory -Force -Path $DistEndpointFilterDir | Out-Null
}

if (Test-Path $FilterDllPath) {
    Copy-Item -Path $FilterDllPath -Destination $DistEndpointFilterDir -Force -Recurse
    Write-Host "[+] Driver built at: $DistEndpointFilterDir" -ForegroundColor Green
} else {
    Write-Error "[!] Build finished but output file not found at $FilterDllPath"
    exit 1
}

# --- Agent build

Write-Host "`n[i] Starting Galatea Agent Build..." -ForegroundColor Cyan
Write-Host "[>>] Compiling Agent..."
Invoke-Expression "cargo build -p galatea-agent $CargoProfileFlag"

$AgentBuildPath = "$GeneralTargetSourceDir\$AgentName"
$AgentDistPath = "$DistEndpointDir\$AgentName"
Copy-Item $AgentBuildPath $AgentDistPath -Force

# --- Hook dll build

Write-Host "`n[i] Starting Galatea Hooking Dll Build..." -ForegroundColor Cyan
Write-Host "[>>] Compiling Hook Dll..."
Invoke-Expression "cargo build -p galatea-userland-hooks $CargoProfileFlag"

$DllBuildPath = "$GeneralTargetSourceDir\$HookDllName"
$DllDistPath = "$DistEndpointDir\$HookDllName"
Copy-Item $DllBuildPath $DllDistPath -Force

# --- GUI build

Write-Host "`n[i] Starting Galatea GUI Build..." -ForegroundColor Cyan
Write-Host "[>>] Compiling GUI..."
Invoke-Expression "cargo build -p galatea-client $CargoProfileFlag"

$GuiBuildPath = "$GeneralTargetSourceDir\$GuiName"
$GuiDistPath = "$DistEndpointDir\$GuiName"
Copy-Item $GuiBuildPath $GuiDistPath -Force

# --- Copy ML assets
$ModelInPath = "$ModelPath\$ModelName"
$ModelFInPath = "$ModelPath\$ModelName"
$ModelOutPath = "$DistEndpointDir\$ModelName"
$ModelFOutPath = "$DistEndpointDir\$ModelName"
Write-Host "`n[i] Gathering provided model..." -ForegroundColor Cyan
Copy-Item $ModelInPath $ModelOutPath -Force
Copy-Item $ModelFInPath $ModelFOutPath -Force

# --- Copy static assets

Write-Host "`n[i] Gathering provided assets..." -ForegroundColor Cyan
Copy-Item -Path $AssetDir -Destination $DistEndpointDir -Force -Recurse

# --- Server build

Write-Host "`n[i] Starting Galatea Server Build..." -ForegroundColor Cyan
Write-Host "[>>] Compiling Server..."
Invoke-Expression "cargo build -p babel-server $CargoProfileFlag"

if (!(Test-Path $DistServerDir)) {
    New-Item -ItemType Directory -Force -Path $DistServerDir | Out-Null
}

$ServerBuildPath = "$GeneralTargetSourceDir\$ServerName"
$ServerDistPath = "$DistServerDir\$ServerName"
Copy-Item $ServerBuildPath $ServerDistPath -Force

Write-Host "[>>] Copying server static assets..."
$ServerStaticDir = "server\babel-server\static"
$ServerWebDir = "server\babel-server\web"
Copy-Item -Path "$ServerStaticDir\*" -Destination $DistServerDir -Force -Recurse
Copy-Item -Path "$ServerWebDir\*" -Destination "$DistServerDir\web" -Force -Recurse

Write-Host "[>>] Copying server database..."
$ServerDbSource = "static\assets\server\galatea_server.db"
$ServerDbDest = "$DistServerDir\galatea_server.db"
Copy-Item -Path $ServerDbSource -Destination $ServerDbDest -Force

Write-Host "[+] Server built at: $DistServerDir" -ForegroundColor Green

Write-Host "`n[+] Build Complete!" -ForegroundColor Green
