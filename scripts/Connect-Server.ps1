[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$')]
    [string]$ServerId,

    [string]$KeyPath,

    [string]$KnownHostsPath,

    [ValidateRange(1, 65535)]
    [int]$SshPort = 22
)

$ErrorActionPreference = 'Stop'
$BaseUrl = 'http://127.0.0.1:8080'
$Ssh = Get-Command ssh -CommandType Application -ErrorAction Stop
$Registry = Invoke-RestMethod "$BaseUrl/api/servers" -TimeoutSec 10
$Server = $null
foreach ($Entry in $Registry) {
    if ($Entry.id -eq $ServerId) { $Server = $Entry; break }
}
if (-not $Server) { throw 'Add the server in lemonK first.' }
$Address = [string]$Server.address
$ParsedAddress = $null
if (-not [Net.IPAddress]::TryParse($Address, [ref]$ParsedAddress) -and
    $Address -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9.])?$') {
    throw 'Save an IP address or hostname under Edit connection in lemonK.'
}

$User = [string]$Server.sshUser
if (-not $User) { $User = (Read-Host 'SSH username').Trim() }
if ($User -notmatch '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$') { throw 'Enter a valid SSH username.' }

if (-not $PSBoundParameters.ContainsKey('KeyPath')) {
    $KeyPath = (Read-Host 'Path to your local SSH key, or Enter to use your SSH agent').Trim().Trim('"')
}
$SshArgs = @('-tt', '-p', [string]$SshPort, '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=30',
             '-o', 'ServerAliveCountMax=3', '-o', 'ForwardAgent=no', '-o', 'StrictHostKeyChecking=ask',
             '-R', '127.0.0.1:14318:127.0.0.1:4318')
if ($KnownHostsPath) {
    $HostKeys = Get-Item -LiteralPath $KnownHostsPath
    if ($HostKeys.PSIsContainer) { throw 'Select the SSH known_hosts file.' }
    $SshArgs += @('-o', ('UserKnownHostsFile="' + ($HostKeys.FullName -replace '\\', '/') + '"'))
}
if ($KeyPath) {
    $Key = Get-Item -LiteralPath $KeyPath
    if ($Key.PSIsContainer) { throw 'Select the local SSH key file.' }
    $SshArgs += @('-o', 'IdentitiesOnly=yes', '-i', $Key.FullName)
}

$Download = Invoke-WebRequest "$BaseUrl/api/servers/$ServerId/agent.yaml" -UseBasicParsing -TimeoutSec 10
$Config = if ($Download.Content -is [byte[]]) {
    [Text.Encoding]::UTF8.GetString($Download.Content)
} else {
    [string]$Download.Content
}
$ConfigPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Config))

$Remote = @'
set -eu
umask 077
export SENTINEL_OTLP_ENDPOINT=http://127.0.0.1:14318
if [ "$(uname -s)" != Linux ]; then
    printf '%s\n' 'This connector requires a Linux server.' >&2
    exit 1
fi

version=0.138.0
agent_dir="$HOME/.local/share/sentinel-monitor"
config_dir="$agent_dir/servers/__SENTINEL_ID__"
mkdir -p "$config_dir"
config="$(mktemp "$config_dir/config.XXXXXX")"
printf '%s' '__SENTINEL_CONFIG__' | base64 -d > "$config"
mv -f -- "$config" "$config_dir/agent.yaml"

collector="$(command -v otelcol-contrib || true)"
if [ -z "$collector" ] || ! "$collector" --version | grep -Fq "$version"; then
    collector="$agent_dir/otelcol-contrib-$version"
    if [ ! -x "$collector" ]; then
        case "$(uname -m)" in
            x86_64) arch=amd64
                checksum=9f6462ffa45829bce9e69a2995932a521e9d40f0658eddbe27f6e262c2e82b1d ;;
            aarch64|arm64) arch=arm64
                checksum=fef07f3c68ae0151554ddddc1d4005f84624a6376fc3e1a8c443675783e41fe0 ;;
            *) printf '%s\n' 'This connector supports x86-64 and ARM64 Linux.' >&2; exit 1 ;;
        esac
        work="$(mktemp -d "$agent_dir/download.XXXXXX")"
        trap 'rm -f -- "$work/collector.tar.gz" "$work/otelcol-contrib"; rmdir -- "$work"' EXIT
        release="https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v$version"
        curl -fsSL --connect-timeout 10 --max-time 240 "$release/otelcol-contrib_${version}_linux_${arch}.tar.gz" -o "$work/collector.tar.gz"
        printf '%s  %s\n' "$checksum" "$work/collector.tar.gz" | sha256sum -c -
        tar -xzf "$work/collector.tar.gz" -C "$work" otelcol-contrib
        chmod 700 "$work/otelcol-contrib"
        mv -f -- "$work/otelcol-contrib" "$collector"
        rm -f -- "$work/collector.tar.gz"
        rmdir -- "$work"
        trap - EXIT
    fi
fi

printf '%s\n' 'Starting the lemonK collector. Keep this SSH session open.'
exec "$collector" --config="$config_dir/agent.yaml"
'@

$Remote = $Remote.Replace('__SENTINEL_ID__', $ServerId).Replace('__SENTINEL_CONFIG__', $ConfigPayload)
$Remote = $Remote.Replace([string][char]13, '')
$Encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Remote))
$RemoteCommand = "printf '%s' '$Encoded' | base64 -d | bash"
Write-Host "Connecting to $User@$Address. Keep this window open and watch lemonK for telemetry."
& $Ssh.Source @SshArgs "$User@$Address" $RemoteCommand
if ($LASTEXITCODE -ne 0) { throw "SSH or the remote collector exited with code $LASTEXITCODE. Check the message above." }
