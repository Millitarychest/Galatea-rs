param(
    [string]$ServerHost = "127.0.0.1",
    [int]$ServerPort = 18080,
    [string]$Psk = "galatea_secret",
    [Alias("UseRunningServer")]
    [switch]$UseExistingServer,
    [string]$DbPath
)

$ErrorActionPreference = "Stop"

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message (expected: $Expected, actual: $Actual)"
    }
}

function Invoke-JsonPost {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)]$Body
    )

    $json = $Body | ConvertTo-Json -Depth 10
    return Invoke-RestMethod -Method Post -Uri $Uri -ContentType "application/json" -Body $json
}

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
    $resolvedDbPath = Join-Path $env:TEMP ("galatea_telemetry_test_{0}.db" -f ([Guid]::NewGuid().ToString("N")))
}

try {
    if (-not $UseExistingServer) {
        if (-not $resolvedDbPath) {
            throw "DbPath resolution failed"
        }

        Write-Host "[+] Starting server on $baseUrl"
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

    $agentId = [Guid]::NewGuid().ToString()
    $eventId = [Guid]::NewGuid().ToString()
    $nowIso = (Get-Date).ToUniversalTime().ToString("o")

    Write-Host "[+] Registering agent $agentId"
    $registerBody = @{
        uuid = $agentId
        host_info = @{
            hostname = "telemetry-test-host"
            os_version = "windows-test"
            agent_version = "0.1.0-test"
            ip_address = "127.0.0.1"
        }
        auth = @{ psk = $Psk }
    }

    $registerResp = Invoke-JsonPost -Uri "$baseUrl/api/v1/agents/register" -Body $registerBody
    Assert-Equal -Actual $registerResp.agent_id -Expected $agentId -Message "register response agent_id mismatch"

    Write-Host "[+] Sending first telemetry event"
    $telemetryBody = @{
        uuid = $agentId
        auth = @{ psk = $Psk }
        schema_version = 1
        events = @(
            @{
                kind = "process"
                data = @{
                    event_id = $eventId
                    occurred_at = $nowIso
                    process_id = 4242
                    parent_process_id = 4
                    image_path = "C:\\Windows\\System32\\cmd.exe"
                    command_line = "cmd.exe /c whoami"
                    md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
                    threat_score = 87
                    verdict = "blocked"
                }
            }
        )
    }

    $telemetryResp1 = Invoke-JsonPost -Uri "$baseUrl/api/v1/agents/$agentId/telemetry" -Body $telemetryBody
    Assert-Equal -Actual ([int]$telemetryResp1.accepted) -Expected 1 -Message "first telemetry accepted count mismatch"
    Assert-Equal -Actual ([int]$telemetryResp1.rejected) -Expected 0 -Message "first telemetry rejected count mismatch"

    Write-Host "[+] Re-sending same telemetry event (idempotency check)"
    $telemetryResp2 = Invoke-JsonPost -Uri "$baseUrl/api/v1/agents/$agentId/telemetry" -Body $telemetryBody
    Assert-Equal -Actual ([int]$telemetryResp2.accepted) -Expected 0 -Message "duplicate telemetry accepted count mismatch"
    Assert-Equal -Actual ([int]$telemetryResp2.rejected) -Expected 1 -Message "duplicate telemetry rejected count mismatch"

    Write-Host "[+] Sending telemetry with invalid PSK (auth check)"
    $badBody = $telemetryBody.PSObject.Copy()
    $badBody.auth = @{ psk = "invalid_psk" }

    try {
        $null = Invoke-JsonPost -Uri "$baseUrl/api/v1/agents/$agentId/telemetry" -Body $badBody
        throw "invalid PSK telemetry request unexpectedly succeeded"
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($statusCode -ne 401) {
            throw "expected HTTP 401 for invalid PSK, got $statusCode"
        }
    }

    Write-Host "[OK] Telemetry smoke test passed"
    if ($resolvedDbPath) {
        Write-Host "[i] Test DB: $resolvedDbPath"
    }
}
finally {
    if ($serverProc -and -not $serverProc.HasExited) {
        Write-Host "[+] Stopping server process (PID: $($serverProc.Id))"
        Stop-Process -Id $serverProc.Id -Force
    }
}
