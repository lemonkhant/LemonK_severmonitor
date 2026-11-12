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
