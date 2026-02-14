param(
    [string]$ServerHost = "127.0.0.1",
    [int]$ServerPort = 18080,
    [string]$Psk = "galatea_secret",
    [Alias("UseRunningServer")]
    [switch]$UseExistingServer,
    [string]$DbPath
)

$ErrorActionPreference = "Stop"

function Wait-ForServer {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [int]$TimeoutSeconds = 90
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $null = Invoke-WebRequest -Uri "$BaseUrl/" -UseBasicParsing -TimeoutSec 2
            return
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }

    throw "Server did not become ready within $TimeoutSeconds seconds"
}

$baseUrl = "http://$ServerHost`:$ServerPort"
$serverProc = $null
$resolvedDbPath = $DbPath

if (-not $resolvedDbPath -and -not $UseExistingServer) {
    $resolvedDbPath = Join-Path $env:TEMP ("galatea_telemetry_full_{0}.db" -f ([Guid]::NewGuid().ToString("N")))
}

try {
    if (-not $UseExistingServer) {
        Write-Host "[+] Starting shared full-test server on $baseUrl"
        Write-Host "[+] DB path: $resolvedDbPath"

        $serverProc = Start-Process -FilePath "cargo" -ArgumentList @(
            "run", "-p", "server", "--", "--db-path", $resolvedDbPath, "--port", "$ServerPort"
        ) -PassThru -WindowStyle Hidden

        Wait-ForServer -BaseUrl $baseUrl
    }
    else {
        Write-Host "[+] Using existing server at $baseUrl"
        Wait-ForServer -BaseUrl $baseUrl -TimeoutSeconds 15
    }

    Write-Host "[+] Running smoke checks"
    & "$PSScriptRoot\test-telemetry-smoke.ps1" -ServerHost $ServerHost -ServerPort $ServerPort -Psk $Psk -UseExistingServer

    Write-Host "[+] Running medium/heavy load checks"
    & "$PSScriptRoot\test-telemetry-load.ps1" -ServerHost $ServerHost -ServerPort $ServerPort -Psk $Psk -UseExistingServer -TotalEvents 10000 -BatchSize 100 -Concurrency 16 -ReplayDuplicates

    Write-Host "[+] Running secondary multi-run load checks"
    & "$PSScriptRoot\test-telemetry-load.ps1" -ServerHost $ServerHost -ServerPort $ServerPort -Psk $Psk -UseExistingServer -TotalEvents 4000 -BatchSize 80 -Concurrency 12

    $eventsPage = Invoke-WebRequest -Uri "$baseUrl/events" -UseBasicParsing -TimeoutSec 10
    if ($eventsPage.Content -notmatch "Event Feed") {
        throw "UI check failed: /events page did not render expected content"
    }

    Write-Host "[OK] Full telemetry suite passed"
}
finally {
    if ($serverProc -and -not $serverProc.HasExited) {
        Write-Host "[+] Stopping shared full-test server (PID: $($serverProc.Id))"
        Stop-Process -Id $serverProc.Id -Force
    }
}
