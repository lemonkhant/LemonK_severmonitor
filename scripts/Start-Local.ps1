param([switch]$Test)

$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    $DockerPath = (Get-Command docker -ErrorAction SilentlyContinue).Source
    if (-not $DockerPath) {
        $DockerPath = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    }
    if (-not (Test-Path -LiteralPath $DockerPath -PathType Leaf)) {
        throw 'Docker CLI is missing. Install Docker Desktop and enable Linux containers.'
    }

    & $DockerPath version --format '{{.Server.Version}}'
    if ($LASTEXITCODE -ne 0) {
        throw 'Start Docker Desktop, wait for the Linux engine to report ready, then run this script again.'
    }

    if ($Test) {
        & $DockerPath build --target test .
        if ($LASTEXITCODE -ne 0) { throw 'Go checks failed.' }
    }

    & $DockerPath compose up --build -d
    if ($LASTEXITCODE -ne 0) { throw 'The local Docker stack could not start.' }

    $BaseUrl = 'http://127.0.0.1:8080'
    $Deadline = (Get-Date).AddSeconds(30)
    do {
        try {
            $Health = Invoke-WebRequest -Uri "$BaseUrl/healthz" -UseBasicParsing -TimeoutSec 3
            if ($Health.StatusCode -eq 204) { break }
        } catch {
            Start-Sleep -Seconds 1
        }
    } while ((Get-Date) -lt $Deadline)
    if (-not $Health -or $Health.StatusCode -ne 204) { throw 'The health endpoint did not become ready.' }

    $Snapshot = Invoke-RestMethod -Uri "$BaseUrl/api/snapshot?range=1h" -TimeoutSec 5
    if ($Snapshot.mode -ne 'live' -or $null -eq $Snapshot.hosts) { throw 'The snapshot smoke check failed.' }
    $Page = Invoke-WebRequest -Uri $BaseUrl -UseBasicParsing -TimeoutSec 5
    if ($Page.Content -notmatch '<title>lemonK</title>') { throw 'The frontend smoke check failed.' }

    Write-Host "lemonK is running at $BaseUrl"
} finally {
    Pop-Location
}
