$ErrorActionPreference = 'Stop'
$BaseUrl = 'http://127.0.0.1:8080'
$Docker = (Get-Command docker -ErrorAction SilentlyContinue).Source
if (-not $Docker) { $Docker = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe' }
$Id = 'local-check-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$ConfigPath = (Resolve-Path (Join-Path $PSScriptRoot '../config/agent-linux.yaml')).Path
$Mount = 'type=bind,source=' + $ConfigPath + ',target=/etc/otelcol-contrib/agent.yaml,readonly'
$Registered = $false
$AgentStarted = $false
try {
    $Current = Invoke-RestMethod "$BaseUrl/api/snapshot"
    if ($Current.mode -ne 'live') { throw 'Start the live stack before running this check.' }
    $Details = @{ id=$Id; name='Local telemetry check'; provider='Local test'; region='Docker' } | ConvertTo-Json
    $null = Invoke-RestMethod "$BaseUrl/api/servers" -Method Post -ContentType 'application/json' -Body $Details
    $Registered = $true
    $AgentConfig = Invoke-WebRequest "$BaseUrl/api/servers/$Id/agent.yaml" -UseBasicParsing
    $YamlText = if ($AgentConfig.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($AgentConfig.Content) } else { [string]$AgentConfig.Content }
    if ($YamlText -notmatch [regex]::Escape($Id)) { throw 'Downloaded agent config is missing the server ID.' }

    & $Docker run -d --rm --name $Id --network lemonk_default --mount $Mount -e "SENTINEL_HOST_ID=$Id" -e 'SENTINEL_OTLP_ENDPOINT=http://gateway:4318' otel/opentelemetry-collector-contrib:0.138.0 --config=/etc/otelcol-contrib/agent.yaml
    if ($LASTEXITCODE -ne 0) { throw 'Could not start the local Collector agent.' }
    $AgentStarted = $true

    $UnixNanos = [string]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1000000L)
    $Message = "lemonK live smoke log $Id"
    $Payload = @{ resourceLogs = @(@{
        resource = @{ attributes = @(
            @{ key='host_id'; value=@{stringValue=$Id} },
            @{ key='service.name'; value=@{stringValue='sentinel-smoke'} }
        ) }
        scopeLogs = @(@{ logRecords = @(@{ timeUnixNano=$UnixNanos; severityText='INFO'; body=@{stringValue=$Message} }) })
    }) } | ConvertTo-Json -Depth 16 -Compress
    $null = Invoke-RestMethod 'http://127.0.0.1:4318/v1/logs' -Method Post -ContentType 'application/json' -Body $Payload

    $Deadline = (Get-Date).AddSeconds(50)
    do {
        $Snapshot = Invoke-RestMethod "$BaseUrl/api/snapshot?range=1h"
        $Asset = $Snapshot.hosts | Where-Object id -eq $Id
        $Log = $Snapshot.logs | Where-Object { $_.host -eq $Id -and $_.message -eq $Message }
        if ($null -ne $Asset.cpu -and $null -ne $Asset.memory -and $Asset.seen -and $Log) {
            Write-Host "Live check passed. Collector CPU and memory metrics and an OTLP log reached the dashboard API for $Id."
            break
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $Deadline)
    if ($null -eq $Asset.cpu -or $null -eq $Asset.memory -or -not $Asset.seen -or -not $Log) {
        $Asset | ConvertTo-Json -Depth 4
        $Snapshot.warnings
        & $Docker logs --tail 18 $Id
        throw "Live telemetry did not reach the API in time. Log found: $([bool]$Log)"
    }
} finally {
    if ($AgentStarted) { & $Docker stop $Id | Out-Null }
    if ($Registered) { $null = Invoke-RestMethod "$BaseUrl/api/servers/$Id" -Method Delete }
}
