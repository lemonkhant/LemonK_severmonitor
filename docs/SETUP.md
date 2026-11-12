# Set up and use lemonK

## Deploy on Ubuntu

1. Install [Docker Engine and Compose](https://docs.docker.com/engine/install/ubuntu/), then clone the repository.

   ```bash
   git clone https://github.com/lemonkhant/LemonK_severmonitor.git
   cd LemonK_severmonitor
   ```

2. Create the administrator password on the Ubuntu host. The dashboard runs as UID and GID `65532`. Keep this directory outside the checkout.

   ```bash
   sudo install -d -m 0750 -o root -g 65532 /etc/sentinel-monitor /etc/sentinel-monitor/ssh
   sudo bash -c 'umask 077
     if [ ! -e /etc/sentinel-monitor/admin-password ]; then
       openssl rand -hex 24 > /etc/sentinel-monitor/admin-password
     fi
     chown root:65532 /etc/sentinel-monitor/admin-password
     chmod 0640 /etc/sentinel-monitor/admin-password'
   ```

3. Start the authenticated profile.

   ```bash
   sudo docker compose -f compose.yaml -f compose.office.yaml up -d --build
   ```

4. From your computer, open an SSH tunnel to the verified dashboard host. Replace the example username and hostname with your own.

   ```bash
   ssh -N -L 127.0.0.1:18080:127.0.0.1:8080 adminuser@monitor.example.com
   ```

   Open [http://127.0.0.1:18080](http://127.0.0.1:18080/). The default username is `admin`. Retrieve the generated password privately on the Ubuntu host with `sudo cat /etc/sentinel-monitor/admin-password`.

For shared browser access, place a TLS reverse proxy in front of the loopback dashboard, preserve the request Host header, and set `SENTINEL_SECURE_COOKIES=1` in a local Compose `.env` file. The default telemetry receiver listens on loopback port `4318`. Use SSH forwarding or a private network with appropriately restricted access for collectors. A public ingest endpoint requires TLS and collector authentication.

## Connect a Linux server over SSH

1. In **Servers**, add a host with a unique ID. This guide uses the example ID `office-web-01`. Save the host address and a dedicated unprivileged SSH username.
2. On the dashboard host, generate a key for this server. Authorize its **public** half on the monitored server for the account saved in lemonK. The account needs permission to read the selected log sources and to use a loopback-only reverse SSH forward.

   ```bash
   sudo ssh-keygen -t ed25519 -N '' -f /etc/sentinel-monitor/ssh/office-web-01.key
   sudo chown 65532:65532 /etc/sentinel-monitor/ssh/office-web-01.key
   sudo chmod 0600 /etc/sentinel-monitor/ssh/office-web-01.key
   ```

3. Verify the monitored server’s SSH fingerprint against its cloud console or another trusted source. Put the verified public host key in `/etc/sentinel-monitor/ssh/known_hosts` on the dashboard host. Use the same hostname or IP as the one registered in lemonK. Set file ownership to `root:65532` and permissions to `0640`.
4. Select **Servers → Setup → Connect over SSH**. lemonK installs or reuses a checksum-verified Linux collector. The collector sends telemetry through a reverse SSH tunnel while the dashboard session to the server is active. After a dashboard restart, reconnect from **Setup**.

## Connect a collector on a private network

Download the YAML under **Servers → Setup** for the registered host. Install a compatible [OpenTelemetry Collector Contrib release](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.138.0) for that host and pass the downloaded YAML with `--config`. Set `SENTINEL_OTLP_ENDPOINT` in the collector environment to the approved OTLP HTTP endpoint reachable from the host. For a collector on the dashboard host, use `http://127.0.0.1:4318`.

The YAML embeds the host ID. Use the matching file for each host. For an existing collector, review and merge the pipelines to avoid collecting events twice.

## Collect logs and investigate

- The downloaded YAML reads new lines from `/var/log/sentinel/*.log`. Make an approved application or SSH authentication log available at a matching path and grant read access to the collector account. Keep sensitive fields such as tokens out of the collected stream.
- For built-in SSH detections, preserve the OpenSSH event text, username, and source address. Verify an incoming line in **Logs**, then review **Threat Detection → SIEM** and **UEBA**.
- Open **Detection Studio** to add a custom log rule. Enter the text to match, the minimum count per server in a five-minute UTC bucket, and the severity.
- Use **Threat Intelligence** to manage the IP watchlist. Use **SOAR** to review cases, record investigation notes, and change their status.
- To display Wazuh alerts, set `WAZUH_URL`, `WAZUH_USER`, and `WAZUH_PASSWORD` locally for a dedicated read-only account. Use the same asset ID as the Wazuh agent name. For a private CA, mount its certificate through `config/live` and set `WAZUH_CA_FILE` to the path inside the dashboard container.

## Troubleshoot

| Symptom | Check |
| --- | --- |
| **Awaiting agent** | Confirm the registered ID matches the YAML, the collector is running, and the gateway is reachable through the configured transport. CPU and throughput rates need multiple samples. |
| **SSH setup failed** | Verify the username, dedicated key permissions, host fingerprint, and reverse forwarding. |
| **No log events** | Check the file path and read permissions. Generate a new event because the default collector starts tailing at the end of the file. |
| **No security findings** | Confirm relevant events appear in **Logs**, the correct time range is selected, and the rule threshold was reached. |

Use `docker compose ps` and `docker compose logs --tail=50 dashboard gateway` from the checkout to inspect the stack. The default named volumes hold registry, cases, metrics, and logs. A routine `docker compose down` retains those volumes.
