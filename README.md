# NATashaa

<p align="center">
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen?logo=node.js" alt="Node.js" />
  <img src="https://img.shields.io/badge/version-1.0.1-blue" alt="Version" />
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License" />
  <img src="https://img.shields.io/badge/docker-supported-2496ed?logo=docker" alt="Docker" />
  <img src="https://img.shields.io/badge/Raspberry%20Pi-Zero%20%7C%203%20%7C%204%20%7C%205-red?logo=raspberrypi" alt="Raspberry Pi" />
  <img src="https://img.shields.io/badge/OS-Linux%20%7C%20Windows%20%7C%20Raspberry%20Pi-lightgrey" alt="OS" />
</p>

<p align="center">
  <img src="natashaa-logo.png" width="200" alt="NATashaa" />
</p>

A lightweight TCP port forwarder (NAT) written in Node.js. It listens on configurable ports and relays traffic to internal hosts without authentication or encryption at the forwarder level.

## What NATashaa Does

NATashaa acts as a TCP proxy. When a client connects to port X on the NATashaa host, the connection is forwarded to a configured IP:port on your internal network. Example: `80 -> 10.0.0.212:80` forwards external HTTP traffic to an internal web server.

Use cases:
- Expose internal services through a single host
- Remap ports (e.g. external 3305 to internal 10.0.0.229:3306)
- Run on a Raspberry Pi as a cheap, low-power gateway

## Limitations

NATashaa does not provide:
- Firewall or access control
- Encryption (use TLS on the services themselves)
- Rate limiting or DDoS protection
- Protocol inspection beyond basic SSH detection for logging

It only routes TCP traffic. Security must be handled by your applications and network design.

---

## Configuration: Port Forwards

Edit `mapping.txt` in the project root:

```
# port_source -> ip_destination:port_destination
80 -> 10.0.0.212:80
3305 -> 10.0.0.229:3306
4576 -> 10.0.0.175:8080
```

- One mapping per line
- Format: `port -> host:port`
- Lines starting with `#` are ignored
- Changes are hot-reloaded; no restart needed

### Config file: `config.conf`

All tunables live in `config.conf` at the project root (same folder as `index.js`). INI-style: easy to edit with `nano` on Linux or Notepad on Windows. If the file is missing, built-in defaults are used.

**Create the file:** copy the example then edit.

- **Linux:** `cp config.example.conf config.conf` then `nano config.conf`
- **Windows:** copy `config.example.conf` to `config.conf`, then open with Notepad or any text editor

**Format:** one setting per line. Lines starting with `#` are comments. A line `[section]` starts a section; below it use `key = value`. No quotes, no commas. Numbers and empty values are parsed automatically.

**Minimal example** (only what you might change):

```ini
# optional: path to mapping file (relative to app folder or absolute)
mappingFile = mapping.txt

[api]
port = 3000
key =
# leave key empty to auto-generate; set API_KEY in env for production

[log]
level = INFO
format = text
```

**Full reference:**

| Section | Keys | Description |
|---------|------|-------------|
| (top) | `mappingFile` | Mapping file path (relative to app dir or absolute) |
| `[host]` | `directIp`, `accessIp` | Host IPs for target substitution |
| `[api]` | `port`, `key`, `pingTimeoutMs`, `scanTimeoutMs` | REST API and network checks |
| `[log]` | `level`, `format` | DEBUG/INFO/WARN/ERROR; format: `text` or `json` |
| `[server]` | `bindAddress`, `upstreamTimeoutMs` | Listen address and upstream timeout |
| `[metrics]` | `intervalMs` | Performance metrics log interval |
| `[iptables]` | `chainName`, `nflogGroup`, `multiportChunkSize` | Firewall (Linux only) |
| `[ulog]` | `logPath`, `watchIntervalMs` | ULOG path and watch (Linux only) |
| `[ports]` | `availableMin`, `availableMax`, `availableListMax`, `availableResponseLimit` | Port range for `/api/ports` |

### Environment overrides

Env vars override `config.conf` (useful for Docker/CI):

| Variable | Overrides |
|----------|-----------|
| `API_KEY` | `api.key` |
| `API_PORT` | `api.port` |
| `HOST_DIRECT_IP` | `host.directIp` |
| `HOST_ACCESS_IP` | `host.accessIp` |
| `LOG_LEVEL` | `log.level` |
| `LOG_FORMAT` | `log.format` |

---

## Running on Windows (without Docker)

You can run NATashaa natively on Windows for TCP forwarding and the REST API.

**What works:** TCP port forwarding, REST API, application logs to stdout (connections, errors, metrics).  
**What does not work (Linux only):** iptables rules, ULOG, and any logging of *unmapped* connection attempts (those require the Linux firewall stack). On startup you will see a warning that the app is running in limited mode.

**Prerequisites:** [Node.js](https://nodejs.org/) (LTS, 18 or 20).

1. **Get the project**

   Clone or download the repo, then open a terminal in the project folder (PowerShell or CMD):

   ```powershell
   cd C:\path\to\natashaa
   ```

2. **Config**

   Copy the example config and edit it if needed:

   ```powershell
   copy config.example.conf config.conf
   notepad config.conf
   ```

   At least set `[api]` → `port` and optionally `key` (or use env var `API_KEY` later).

3. **Port forwards**

   Edit `mapping.txt` with your rules (same format as on Linux):

   ```
   8080 -> 192.168.1.10:80
   3305 -> 192.168.1.20:3306
   ```

4. **Run**

   ```powershell
   node index.js
   ```

   The app listens on the ports defined in `mapping.txt` and runs the API on the port set in `config.conf` (default 3000). To allow external traffic, open the needed ports in Windows Firewall (e.g. TCP 3000, 8080, 3305).

**Optional:** run in the background (e.g. with [pm2](https://www.npmjs.com/package/pm2) or a scheduled task), or use WSL2 if you need iptables/ulog.

---

## Static IP (Raspberry Pi)

Assign a fixed IP before installing NATashaa so the Pi is always reachable on the same address.

### Via `dhcpcd`

1. Edit `/etc/dhcpcd.conf`:

```bash
sudo nano /etc/dhcpcd.conf
```

2. Add at the end (replace with your values):

```
interface eth0
static ip_address=192.168.1.100/24
static routers=192.168.1.1
static domain_name_servers=8.8.8.8 1.1.1.1
```

For WiFi (`wlan0`):

```
interface wlan0
static ip_address=192.168.1.100/24
static routers=192.168.1.1
static domain_name_servers=8.8.8.8 1.1.1.1
```

3. Reboot:

```bash
sudo reboot
```

### Via `NetworkManager` (if installed)

```bash
nmcli con mod "Your connection" ipv4.addresses 192.168.1.100/24
nmcli con mod "Your connection" ipv4.gateway 192.168.1.1
nmcli con mod "Your connection" ipv4.dns "8.8.8.8 1.1.1.1"
nmcli con mod "Your connection" ipv4.method manual
nmcli con up "Your connection"
```

---

## Docker

Requires host network and capabilities for iptables.

### Linux

```bash
docker build -t natashaa .
docker run -d \
  --name natashaa \
  --network host \
  --cap-add NET_ADMIN \
  -v $(pwd)/mapping.txt:/app/mapping.txt \
  -v $(pwd)/config.conf:/app/config.conf \
  -e API_KEY=your-secret-key \
  natashaa
```

### Windows (Docker Desktop with WSL2)

On Windows, `--network host` behaves differently. Prefer running NATashaa in WSL2 or on a Linux VM for iptables/ULOG support.

If using Docker Desktop:
- Map ports explicitly instead of `--network host`
- iptables and ULOG do not work inside the container (same limitations as native Windows): TCP forwarding and API work; unmapped-connection logging does not. Configure Windows firewall separately.

```powershell
docker build -t natashaa .
docker run -d `
  --name natashaa `
  -p 3000:3000 `
  -p 80:80 `
  -p 3305:3305 `
  -v ${PWD}/mapping.txt:/app/mapping.txt `
  -v ${PWD}/config.conf:/app/config.conf `
  -e API_KEY=your-secret-key `
  natashaa
```

Note: Port mapping in Docker creates a bridge. For full iptables/NFLOG behavior (unmapped connection logging), run NATashaa natively on Linux.

### Docker Compose (Linux)

Create `docker-compose.yml`:

```yaml
services:
  natashaa:
    build: .
    container_name: natashaa
    network_mode: host
    cap_add:
      - NET_ADMIN
    volumes:
      - ./mapping.txt:/app/mapping.txt
      - ./config.conf:/app/config.conf
    environment:
      - API_KEY=your-secret-key
      - LOG_LEVEL=INFO
    restart: unless-stopped
```

```bash
docker compose up -d
```

---

## Installation on Raspberry Pi

Tested on Raspberry Pi Zero, Zero W, 3A+, 3, 4, and 5 with Raspberry Pi OS Lite 32-bit.

### 1. Flash Raspberry Pi OS Lite 32-bit

Use [Raspberry Pi Imager](https://www.raspberrypi.com/software/), choose Raspberry Pi OS Lite (32-bit), write to SD card, configure WiFi and SSH if needed.

### 2. Set Static IP

See [Static IP (Raspberry Pi)](#static-ip-raspberry-pi) above.

### 3. Disable WiFi Power Saving

Power saving can cause latency and dropouts. Create a service:

```bash
sudo nano /etc/systemd/system/wifi-powersave-off.service
```

Content:

```ini
[Unit]
Description=Disable WiFi power saving
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iwconfig wlan0 power off
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable wifi-powersave-off.service
sudo systemctl start wifi-powersave-off.service
```

For Ethernet only, this service is optional. If your WiFi interface is not `wlan0`, edit the service to use your interface (check with `ip link show`).

### 4. Install Dependencies

```bash
sudo apt-get update
sudo apt-get install -y nodejs npm ulogd2 ca-certificates iproute2 iptables
```

### 5. Clean Package Lists

```bash
sudo rm -rf /var/lib/apt/lists/*
```

`/var/lib/apt/lists/` stores cached package index files. After installation, these are no longer needed and can use hundreds of MB. Removing them frees space, which is important on small SD cards. Run `apt-get update` before the next `apt-get install`.

### 6. Clone and Run

```bash
mkdir -p ~/apps
cd ~/apps
git clone https://github.com/pupariaa/natashaa.git
cd natashaa
```

Edit `mapping.txt` with your port forwards, then run:

```bash
node index.js
```

### 7. Run as a Service

Create the systemd unit:

```bash
sudo nano /etc/systemd/system/natashaa.service
```

Content (adjust paths if needed):

```ini
[Unit]
Description=NATashaa TCP port forwarder
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/apps/natashaa
ExecStart=/usr/bin/node /home/pi/apps/natashaa/index.js
Restart=always
RestartSec=5
Environment=API_KEY=your-secret-key
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable natashaa.service
sudo systemctl start natashaa.service
sudo systemctl status natashaa.service
```

Logs: `journalctl -u natashaa.service -f`

---

## REST API

All endpoints require `Authorization: Bearer <API_KEY>`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Global status and mappings |
| GET | `/api/mappings` | Mappings with stats |
| POST | `/api/mappings` | Add mapping (JSON body) |
| DELETE | `/api/mappings?port=80` | Remove mapping |
| GET | `/api/ports` | Used/available ports |
| GET | `/api/ports?port=80` | Port detail |
| POST | `/api/network/ping` | Ping host (JSON: `host`, `timeout`) |
| POST | `/api/network/scan` | Scan network (JSON: `network`, e.g. `192.168.1`) |

Example:

```bash
curl -H "Authorization: Bearer your-secret-key" http://localhost:3000/api/status
```

---

## License

MIT
