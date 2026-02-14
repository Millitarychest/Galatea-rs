param(
    [string]$ServerHost = "127.0.0.1",
    [int]$ServerPort = 18080,
    [string]$Psk = "galatea_secret",
    [Alias("UseRunningServer")]
    [switch]$UseExistingServer,
    [string]$DbPath,
    [int]$TotalEvents = 5000,
    [int]$BatchSize = 50,
    [int]$Concurrency = 8,
    [switch]$ReplayDuplicates
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

function Split-IntoChunks {
    param(
        [Parameter(Mandatory = $true)][array]$InputArray,
        [Parameter(Mandatory = $true)][int]$ChunkSize
    )

    $chunks = @()
    for ($i = 0; $i -lt $InputArray.Count; $i += $ChunkSize) {
        $end = [Math]::Min($i + $ChunkSize - 1, $InputArray.Count - 1)
        $chunks += ,@($InputArray[$i..$end])
    }
    return $chunks
}

$baseUrl = "http://$ServerHost`:$ServerPort"
$serverProc = $null
$resolvedDbPath = $DbPath

if ($TotalEvents -lt 1) { throw "TotalEvents must be > 0" }
if ($BatchSize -lt 1) { throw "BatchSize must be > 0" }
if ($Concurrency -lt 1) { throw "Concurrency must be > 0" }

if (-not $resolvedDbPath -and -not $UseExistingServer) {
    $resolvedDbPath = Join-Path $env:TEMP ("galatea_telemetry_load_{0}.db" -f ([Guid]::NewGuid().ToString("N")))
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
    Write-Host "[+] Registering load-test agent $agentId"

    $registerBody = @{
        uuid = $agentId
        host_info = @{
            hostname = "telemetry-load-test"
            os_version = "windows-test"
            agent_version = "0.1.0-test"
            ip_address = "127.0.0.1"
        }
        auth = @{ psk = $Psk }
    }

    $registerResp = Invoke-JsonPost -Uri "$baseUrl/api/v1/agents/register" -Body $registerBody
    Assert-Equal -Actual $registerResp.agent_id -Expected $agentId -Message "register response agent_id mismatch"

    $allEventIds = for ($i = 0; $i -lt $TotalEvents; $i++) { [Guid]::NewGuid().ToString() }
    $chunks = Split-IntoChunks -InputArray $allEventIds -ChunkSize $BatchSize

    Write-Host "[+] Sending $TotalEvents events in $($chunks.Count) request batches (batch=$BatchSize, concurrency=$Concurrency)"

    $jobScript = {
        param($uri, $bodyJson)

        $resp = Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Body $bodyJson
        [pscustomobject]@{
            accepted = [int]$resp.accepted
            rejected = [int]$resp.rejected
        }
    }

    $telemetryUri = "$baseUrl/api/v1/agents/$agentId/telemetry"
    $jobs = @()
    $acceptedTotal = 0
    $rejectedTotal = 0
    $sentBatches = 0

    $startTime = Get-Date

    foreach ($chunk in $chunks) {
        $events = @()
        foreach ($eventId in $chunk) {
            $events += @{
                kind = "process"
                data = @{
                    event_id = $eventId
                    occurred_at = (Get-Date).ToUniversalTime().ToString("o")
                    process_id = (1000 + (Get-Random -Minimum 1 -Maximum 100000))
                    parent_process_id = 4
                    image_path = "C:\\Windows\\System32\\cmd.exe"
                    command_line = "cmd.exe /c echo load_test"
                    md5_hash = $null
                    threat_score = (Get-Random -Minimum 0 -Maximum 100)
                    verdict = "blocked"
                }
            }
        }

        $body = @{
            uuid = $agentId
            auth = @{ psk = $Psk }
            schema_version = 1
            events = $events
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $jobs += Start-Job -ScriptBlock $jobScript -ArgumentList $telemetryUri, $bodyJson
        $sentBatches++

        while ($jobs.Count -ge $Concurrency) {
            $finished = Wait-Job -Job $jobs -Any
            $result = Receive-Job -Job $finished
            Remove-Job -Job $finished
            $jobs = @($jobs | Where-Object { $_.Id -ne $finished.Id })

            $acceptedTotal += [int]$result.accepted
            $rejectedTotal += [int]$result.rejected
        }
    }

    foreach ($job in $jobs) {
        Wait-Job -Job $job | Out-Null
        $result = Receive-Job -Job $job
        Remove-Job -Job $job

        $acceptedTotal += [int]$result.accepted
        $rejectedTotal += [int]$result.rejected
    }

    $elapsed = (Get-Date) - $startTime
    $eventsPerSec = [math]::Round($TotalEvents / [Math]::Max($elapsed.TotalSeconds, 0.001), 2)

    Write-Host "[i] Completed $sentBatches request batches in $([math]::Round($elapsed.TotalSeconds,2))s (~$eventsPerSec events/s)"
    Write-Host "[i] accepted=$acceptedTotal rejected=$rejectedTotal"

    Assert-Equal -Actual $acceptedTotal -Expected $TotalEvents -Message "event loss detected in accepted count"
    Assert-Equal -Actual $rejectedTotal -Expected 0 -Message "unexpected rejected events detected"

    if ($ReplayDuplicates) {
        Write-Host "[+] Replaying duplicate event IDs to verify dedupe under load"
        $dupEvents = @()
        foreach ($eventId in $allEventIds) {
            $dupEvents += @{
                kind = "process"
                data = @{
                    event_id = $eventId
                    occurred_at = (Get-Date).ToUniversalTime().ToString("o")
                    process_id = 4242
                    parent_process_id = 4
                    image_path = "C:\\Windows\\System32\\cmd.exe"
                    command_line = "cmd.exe /c echo duplicate"
                    md5_hash = $null
                    threat_score = 1
                    verdict = "allowed"
                }
            }
        }

        $dupBody = @{
            uuid = $agentId
            auth = @{ psk = $Psk }
            schema_version = 1
            events = $dupEvents
        }

        $dupResp = Invoke-JsonPost -Uri $telemetryUri -Body $dupBody
        Assert-Equal -Actual ([int]$dupResp.accepted) -Expected 0 -Message "duplicate replay should not accept new rows"
        Assert-Equal -Actual ([int]$dupResp.rejected) -Expected $TotalEvents -Message "duplicate replay rejected mismatch"
    }

    Write-Host "[OK] Telemetry load test passed (no loss detected by API accounting)"
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
