<div align="center">

# 🛡️ Squad Traffic Analyzer

**Production-ready REST API for Squad game server network traffic analysis**  
**Анализ сетевого трафика Squad сервера с детекцией атак и аномалий**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![Nginx](https://img.shields.io/badge/Nginx-Reverse_Proxy-009639?style=for-the-badge&logo=nginx&logoColor=white)](https://nginx.org)
[![License](https://img.shields.io/badge/License-MIT-F7DF1E?style=for-the-badge)](LICENSE)

---

> **[🇬🇧 English](#english)** &nbsp;|&nbsp; **[🇷🇺 Русский](#русский)**

</div>

---

---

## English

<details open>
<summary><b>📖 Table of Contents</b></summary>

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Commands](#commands)
- [Operation Modes](#operation-modes)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Anomaly Detection](#anomaly-detection)
- [Notifications](#notifications)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)

</details>

---

### Overview

**Squad Traffic Analyzer** is a REST API service that captures, parses, and analyzes UDP/TCP traffic from [Squad](https://joinsquad.com) game servers. It automatically detects attacks (DDoS, port scans, SYN floods) and suspicious patterns using both rule-based heuristics and ML anomaly detection.

Capture traffic with `tcpdump`, send PCAP files to the API, and get back a full anomaly report with risk scores, source IPs, and recommendations — all in real-time.

---

### How It Works

```
Squad Server (UDP 7787 / 27165)
        │
        ▼
  [tcpdump / auto-capture]
        │
        ▼
   PCAP File (.pcap)
        │
        ▼
  POST /analyze/upload  ─────────────────────────────────────────┐
  POST /analyze/path                                              │
        │                                                         │
        ▼                                                         ▼
  [Scapy Parser]                                          [SQLite / PostgreSQL]
  Extract: IPs, ports,                                    Store analysis history
  sizes, timestamps                                       and baseline patterns
        │
        ▼
  [Heuristic Detector]         [ML Detector - Isolation Forest]
  - High PPS / BPS             - Feature extraction per IP
  - Port scan detection        - Unsupervised anomaly scoring
  - SYN flood                  - Contamination factor: 10%
  - Single-IP DDoS
  - Malformed packets
        │
        ▼
  [Risk Score 0.0 – 1.0]
        │
        ├──► Redis  (real-time stats cache)
        ├──► DB     (persistent history)
        └──► Alerts (Telegram / Email / Webhook)
```

---

### Features

| Feature | Description |
|---------|-------------|
| 🔍 **PCAP Parsing** | Full packet parsing via Scapy — IP, UDP, TCP, ICMP, Raw payload |
| 📊 **Traffic Stats** | PPS, BPS, unique IPs, protocol distribution, top talkers |
| 🚨 **Heuristic Detection** | 6 checks, 7 anomaly types: High PPS, High BPS, Port Scan, Suspicious Pattern (SYN flood / tiny packets), DDoS, Malformed, A2S Query Flood |
| 🤖 **ML Detection** | Isolation Forest — unsupervised, no labeled data required |
| 🎯 **Risk Scoring** | Composite 0.0–1.0 score with attack flag |
| ⚡ **3 Analysis Modes** | `manual`, `continuous` (interval), `scheduled` (cron) |
| 💾 **Dual Storage** | Redis for real-time + PostgreSQL/SQLite for history |
| 📬 **Alerts** | Telegram bot, Email (SMTP), custom Webhook |
| 🔒 **Security** | API Key auth, CORS, rate limiting, production mode hides docs |
| 🐳 **Docker Ready** | Full compose stack: App + Redis + PostgreSQL + Nginx |
| 🔄 **Auto Cleanup** | Configurable PCAP and DB retention policies |

---

### Project Structure

```
traffic_analyzer/
│
├── app/                        # Application source code
│   ├── main.py                 #   FastAPI app, all endpoints, middleware
│   ├── analyzer.py             #   Main analysis pipeline orchestrator
│   ├── pcap_parser.py          #   PCAP parsing via Scapy
│   ├── anomaly_detector.py     #   Heuristics + Isolation Forest ML
│   ├── models.py               #   Pydantic request/response models
│   ├── database.py             #   SQLAlchemy ORM models + session
│   ├── redis_client.py         #   Redis wrapper for stats caching
│   ├── scheduler.py            #   APScheduler: continuous/cron capture
│   ├── notifications.py        #   Telegram / Email / Webhook alerts
│   ├── config.py               #   All settings via pydantic-settings
│   └── __init__.py
│
├── docker/                     # Docker & infrastructure config
│   ├── Dockerfile              #   Python 3.11-slim image
│   ├── docker-compose.yml      #   App + Redis + PostgreSQL + Nginx
│   └── nginx/
│       └── nginx.conf          #   Reverse proxy (HTTP), rate limiting
│
├── tests/                      # pytest suite (synthetic PCAPs, API, detectors)
│
├── .github/workflows/ci.yml    # CI: ruff + pytest on 3.11/3.12, Docker smoke test
├── Makefile                    # docker compose + test/lint targets
├── pyproject.toml              # pytest and ruff configuration
├── requirements.txt            # Runtime dependencies
├── requirements-dev.txt        # + pytest, ruff, httpx2
├── .env.example                # Configuration template
├── .gitignore
├── LICENSE
└── README.md
```

---

### Requirements

| Requirement | Min Version | Notes |
|-------------|-------------|-------|
| Python | 3.11+ | |
| Redis | 6+ | Required for stats cache |
| tcpdump | any | Required for auto-capture |
| libpcap | any | Required for Scapy |
| Docker | 20+ | Optional, for Docker mode |
| PostgreSQL | 13+ | Optional, SQLite is default |

**Squad Server Ports:**

| Port | Protocol | Purpose | Captured by default |
|------|----------|---------|---------------------|
| `7787` (+`7788`) | UDP | Game traffic (Unreal NetDriver) | `7787` only |
| `27165` (+`27166`) | UDP | Steam A2S query | `27165` only |
| `15000` | UDP | EOS beacon (since Squad v7.0) | no |
| `21114` | TCP | Source RCON | no |

The default tcpdump filter is `udp port <SQUAD_GAME_PORT> or udp port <SQUAD_QUERY_PORT>`.
Set `CAPTURE_FILTER` to any BPF expression to widen it, e.g.
`udp portrange 7787-7788 or udp portrange 27165-27166 or udp port 15000`.

---

### Installation

#### Clone & configure

```bash
git clone https://github.com/your-org/squad-traffic-analyzer.git
cd squad-traffic-analyzer

cp .env.example .env
nano .env
```

#### Minimum required `.env` settings

```env
SQUAD_SERVER_IP=1.2.3.4          # Your Squad server IP
CAPTURE_INTERFACE=ens6           # Network interface (find with: ip a)
REDIS_PASSWORD=change_me         # Redis password
```

---

### Commands

All operations go through the `Makefile`:

| Command | Description |
|---------|-------------|
| `make up` | Build and start the full Docker stack (App + Redis + PostgreSQL + Nginx) |
| `make down` | Stop the stack |
| `make restart` | Restart all containers |
| `make rebuild` | Stop, rebuild images and start again |
| `make status` | `docker compose ps` |
| `make logs` / `make logs-app` | Tail logs of all containers / only the app |
| `make clean` | Stop the stack and delete the Redis and PostgreSQL volumes |
| `make venv` | Create `.venv` and install runtime + dev dependencies |
| `make test` | Run the pytest suite |
| `make lint` | `ruff check` + `ruff format --check` |
| `make fmt` | Auto-format and auto-fix lint findings |

#### Docker Compose

```bash
cp .env.example .env
nano .env        # passwords, SQUAD_SERVER_IP, CAPTURE_INTERFACE
make up
curl http://localhost/health      # via Nginx
curl http://localhost:8000/health # direct
```

- Requires `.env` to exist
- `data/`, `pcap_captures/`, and `logs/` are bind-mounted from the repository root; only
  Redis and PostgreSQL data live in named Docker volumes (`redis-data`, `postgres-data`)
- Nginx serves plain HTTP on port 80. Terminate TLS in front of it (a cloud load balancer,
  Caddy, or your own Nginx) if the API is exposed publicly

#### Local development

```bash
make venv
cp .env.example .env
cd app && ../.venv/bin/uvicorn main:app --reload
# API available at http://localhost:8000
# Swagger UI at  http://localhost:8000/docs
```

Redis is optional for local runs: every Redis call is non-blocking and only logged on failure.
Set `DATABASE_URL=sqlite:///./data/traffic_analyzer.db` (the default) to avoid PostgreSQL.

#### Tests and lint

```bash
make test   # pytest — no Redis, no PostgreSQL, no tcpdump needed
make lint   # ruff
```

The suite builds synthetic PCAP files with Scapy, so the parser, detectors, scoring, API
(including API-key handling and path restrictions), notifications, and scheduler are all
exercised end-to-end. CI runs the same checks on Python 3.11 and 3.12 and smoke-tests the
Docker image.

---

### Operation Modes

Set via `ANALYSIS_MODE` in `.env`:

#### `manual` (default)
Only analyzes when you call the API. No background activity.
```env
ANALYSIS_MODE=manual
AUTO_CAPTURE_ENABLED=false
```

#### `continuous`
Automatically captures and analyzes traffic every N seconds.
```env
ANALYSIS_MODE=continuous
AUTO_CAPTURE_ENABLED=true
CONTINUOUS_INTERVAL_SECONDS=300    # every 5 minutes
CAPTURE_DURATION_SECONDS=60        # capture window
CAPTURE_INTERFACE=ens6
```

#### `scheduled`
Captures and analyzes on a cron schedule.
```env
ANALYSIS_MODE=scheduled
AUTO_CAPTURE_ENABLED=true
SCHEDULED_CRON=0 */6 * * *         # every 6 hours
CAPTURE_DURATION_SECONDS=120
```

---

### API Reference

Base URL: `http://your-server:8000`  
Swagger UI: `http://your-server:8000/docs` (disabled in production mode)

#### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | — | Service info and version |
| `GET` | `/health` | — | Health check: API + Redis status |
| `GET` | `/mode` | ✓ | Current mode and capture config |
| `POST` | `/analyze/upload` | ✓ | Upload PCAP file for analysis |
| `POST` | `/analyze/path` | ✓ | Analyze PCAP file by server path (inside `PCAP_DIR` only, else `403`) |
| `POST` | `/capture/start` | ✓ | Start tcpdump capture (async) |
| `POST` | `/capture/analyze-latest` | ✓ | Analyze most recent PCAP file |
| `GET` | `/history` | ✓ | Analysis history (`limit`, most recent first) |
| `GET` | `/stats/summary` | ✓ | Aggregated DB statistics |
| `GET` | `/stats/realtime` | ✓ | Live stats from Redis |
| `DELETE` | `/cleanup` | ✓ | Delete old data + PCAP files |

> ✓ = requires `X-API-Key` header when `API_KEY_ENABLED=true`. If the flag is on but `API_KEY` is empty, every protected route answers `503` instead of silently allowing access.

#### Request Examples

```bash
# Health check (always open)
curl http://localhost:8000/health

# Analyze uploaded PCAP
# server_ip / game_port / query_port are query parameters, NOT form fields —
# only `file` goes in the multipart body.
curl -X POST "http://localhost:8000/analyze/upload?server_ip=1.2.3.4&game_port=7787" \
  -H "X-API-Key: your_key" \
  -F "file=@/path/to/capture.pcap"

# Analyze by path (file already on server, must be inside PCAP_DIR) — all fields are query parameters
curl -X POST "http://localhost:8000/analyze/path?pcap_path=/app/pcap_captures/capture.pcap&server_ip=1.2.3.4&game_port=7787&query_port=27165" \
  -H "X-API-Key: your_key"

# Start tcpdump capture for 60 seconds
curl -X POST "http://localhost:8000/capture/start?duration=60&interface=ens6" \
  -H "X-API-Key: your_key"

# Analyze most recently captured file
curl -X POST http://localhost:8000/capture/analyze-latest \
  -H "X-API-Key: your_key"

# Get history (last 20)
curl "http://localhost:8000/history?limit=20" \
  -H "X-API-Key: your_key"

# Summary stats
curl http://localhost:8000/stats/summary -H "X-API-Key: your_key"

# Cleanup old data
curl -X DELETE http://localhost:8000/cleanup -H "X-API-Key: your_key"
```

#### Full Response Schema

> Field names below match `app/models.py` exactly. Note that `recommendations`
> strings are always generated in Russian (see `analyzer.py::_generate_recommendations`),
> regardless of which language section of this README you're reading.

```json
{
  "analysis_id": "3f8a1b2c-...",
  "timestamp": "2026-09-01T10:00:00.123456",
  "duration_seconds": 2.47,
  "stats": {
    "total_packets": 85432,
    "total_bytes": 52428800,
    "unique_ips": 312,
    "packets_per_second": 1423.9,
    "bytes_per_second": 873813.3,
    "udp_packets": 82100,
    "tcp_packets": 3200,
    "icmp_packets": 132,
    "other_packets": 0,
    "game_port_packets": 79400,
    "query_port_packets": 2700,
    "top_talkers": [
      {"ip": "5.6.7.8", "packets": 45000}
    ],
    "protocol_distribution": {"UDP": 82100, "TCP": 3200, "ICMP": 132},
    "packet_size_distribution": {"0-64": 12000, "64-128": 30000, "128-256": 20000, "256-512": 10000, "512-1024": 8432, "1024-1500": 5000, "1500+": 0}
  },
  "anomalies": [
    {
      "type": "ddos_attack",
      "severity": 0.91,
      "description": "Возможная DDoS атака с 5.6.7.8: 52.7% трафика (45000 пакетов)",
      "source_ip": "5.6.7.8",
      "timestamp": "2026-09-01T10:00:05.000000",
      "details": {"packets": 45000, "percentage": 52.7}
    },
    {
      "type": "high_pps",
      "severity": 0.72,
      "description": "Высокий PPS: 1423.90 пакетов/сек",
      "source_ip": null,
      "timestamp": "2026-09-01T10:00:00.000000",
      "details": {"pps": 1423.9, "threshold": 10000}
    }
  ],
  "risk_score": 0.87,
  "is_under_attack": true,
  "recommendations": [
    "⚠️ КРИТИЧНО: Сервер под атакой! Рекомендуется немедленная проверка.",
    "Заблокировать IP 5.6.7.8 в firewall",
    "Включить rate limiting на уровне сети",
    "Проверить настройки DDoS защиты",
    "Рассмотреть использование CloudFlare/Qrator"
  ]
}
```

`recommendations` is deduplicated with `list(set(...))` before being returned, so its
order is not guaranteed to match the order anomalies were processed in.

---

### Anomaly Detection

#### Heuristic Rules

`type` below is the exact `AnomalyType` enum value returned by the API.

| Type | Trigger | Severity |
|------|---------|----------|
| `high_pps` | PPS > `ANOMALY_THRESHOLD_PPS` (default: 10,000) | up to 1.0 |
| `high_bps` | BPS > `ANOMALY_THRESHOLD_BPS` (default: 100 MB/s) | up to 1.0 |
| `port_scan` | Single IP hits > `ANOMALY_THRESHOLD_PORT_SCAN` unique destination ports (default: 20) | up to 1.0 |
| `suspicious_pattern` | SYN flood (>100 SYN packets with no ACK from one IP) or a flood of >500 packets under 64 bytes from one IP | up to 1.0 |
| `ddos_attack` | One of the top-10 IPs by packet count sends >30% of traffic (and >1000 packets), or unique IP count exceeds `ANOMALY_THRESHOLD_CONNECTIONS` while PPS > 1000 | up to 1.0 |
| `malformed_packet` | >50 UDP packets on the game/query port with length <20 or >1500 bytes | up to 1.0 |
| `query_flood` | Inbound datagrams to the query port (valid A2S or not — attackers also flood it with garbage) exceed `ANOMALY_THRESHOLD_QUERY_PPS` per second (default: 100). Reports unique sources and the bytes-out / bytes-in amplification ratio. Requires `server_ip` | up to 1.0 |
| `ml_detected` | Isolation Forest flags a 1-second window as an outlier (see below) | up to 1.0 |

There is no dedicated `syn_flood` or `ddos_single_source` type — both cases above are
reported under `suspicious_pattern` / `ddos_attack`, distinguishable only by `description`.

When `server_ip` is known (query parameter, or `SQUAD_SERVER_IP` for captures), packets
**sent by the server** are excluded from the per-source rules (`port_scan`, `suspicious_pattern`,
`ddos_attack`, `malformed_packet`, `ml_detected`). A busy server answers dozens of client ports and produces
most of the bytes on the wire, which would otherwise look like a port scan or a DDoS source.
Always pass `server_ip` for accurate results.

`query_flood` is calibrated against Valve's own guidance: the Steam game-server library drops
connectionless A2S packets above `STEAM_GAMESERVER_RATE_LIMIT_200MS` per source (recommended
25–75 per 200 ms), and a 25-byte `A2S_INFO` request draws a 200–1400-byte reply (Steam reflection
amplification averages ~5.5×, up to ~14×). Legitimate query traffic on a busy server is a trickle
from the Steam master and server browsers, so an aggregate rate above 100 requests/s is a flood.

#### ML Detection (Isolation Forest)

Skipped entirely if the capture has fewer than 100 packets. Features are extracted
per **1-second time window** (not per IP):
- Packet count in the window
- Total bytes in the window
- Number of unique source IPs in the window
- Average packet size in the window

Anomaly score threshold controlled by `ML_MODEL_CONTAMINATION` (default: `0.1` = 10% expected anomalies).
The model is retrained from scratch on every analysis — there is no persisted baseline.

Isolation Forest with a fixed contamination always marks *some* windows as outliers, even on
perfectly flat traffic. A flagged window is therefore only reported when its packet count or
byte volume is at least **2× the median window**. The anomaly is attributed to the packets
that actually fall into the flagged windows: `anomaly_count` / `anomaly_percentage` count those
packets, `top_sources` ranks their source IPs, and `details.windows` lists the offending
seconds (offset from the first packet). `ML_ENABLED=false` skips the model entirely.

#### Risk Score Calculation

```
risk_score = (max_severity × 0.5) + (avg_severity × 0.3) + (anomaly_count_factor × 0.2)
```
`is_under_attack` is `true` when `risk_score > 0.7` (see `analyzer.py::analyze_pcap`).

- `0.0 – 0.3` — Normal traffic
- `0.3 – 0.7` — Suspicious, monitor
- `0.7 – 1.0` — Under attack, act immediately

---

### Configuration

Full list of environment variables (set in `.env`):

<details>
<summary><b>Application</b></summary>

```env
APP_NAME=Squad Traffic Analyzer
VERSION=1.0.0
ENVIRONMENT=development     # production hides /docs
DEBUG=false
LOG_LEVEL=INFO              # DEBUG | INFO | WARNING | ERROR
HOST=0.0.0.0
PORT=8000
WORKERS=1                   # Production: 4+
RELOAD=false
```
</details>

<details>
<summary><b>Redis</b></summary>

```env
REDIS_HOST=localhost         # Docker: redis
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=change_me
REDIS_MAX_CONNECTIONS=50
STATS_RETENTION_HOURS=168   # 7 days
```
</details>

<details>
<summary><b>Database</b></summary>

```env
# SQLite (development)
DATABASE_URL=sqlite:///./data/traffic_analyzer.db

# PostgreSQL (production)
DATABASE_URL=postgresql://squad_analyzer:password@localhost:5432/traffic_analyzer
DB_CLEANUP_ENABLED=true
```
</details>

<details>
<summary><b>Squad Server</b></summary>

```env
SQUAD_SERVER_IP=1.2.3.4
SQUAD_GAME_PORT=7787
SQUAD_QUERY_PORT=27165
```
</details>

<details>
<summary><b>Anomaly Thresholds</b></summary>

```env
ANOMALY_THRESHOLD_PPS=10000         # packets/sec
ANOMALY_THRESHOLD_BPS=100000000     # bytes/sec (100 MB)
ANOMALY_THRESHOLD_CONNECTIONS=100   # concurrent connections
ANOMALY_THRESHOLD_PORT_SCAN=20      # unique ports from one IP
ANOMALY_THRESHOLD_QUERY_PPS=100     # inbound A2S requests/sec on the query port
ML_MODEL_CONTAMINATION=0.1          # 0.0–0.5
ML_ENABLED=true
```
</details>

<details>
<summary><b>Security</b></summary>

```env
API_KEY_ENABLED=true
API_KEY=your_random_32_char_key_here
CORS_ORIGINS=https://yourdomain.com
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60
```
</details>

<details>
<summary><b>Analysis Mode & Capture</b></summary>

```env
ANALYSIS_MODE=continuous
AUTO_CAPTURE_ENABLED=true
CONTINUOUS_INTERVAL_SECONDS=300
SCHEDULED_CRON=0 */6 * * *
CAPTURE_INTERFACE=ens6
CAPTURE_DURATION_SECONDS=60
CAPTURE_FILTER=               # BPF filter for tcpdump; empty = "udp port <game> or udp port <query>"
PCAP_DIR=/app/pcap_captures   # captures are written here; /analyze/path accepts only files inside it
PCAP_RETENTION_DAYS=7
```
</details>

<details>
<summary><b>Notifications</b></summary>

```env
# Telegram
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=123456:ABCdef...
TELEGRAM_CHAT_ID=-1001234567890

# Email
EMAIL_ENABLED=true
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_FROM=alerts@yourdomain.com
EMAIL_TO=admin@yourdomain.com
EMAIL_PASSWORD=app_password

# Webhook (POST JSON)
WEBHOOK_ENABLED=true
WEBHOOK_URL=https://your-service.com/hooks/squad-alerts
```
</details>

---

### Notifications

Alerts are sent when `risk_score > 0.5` or `is_under_attack = true`.

Message text (built by `notifications.py::_build_message`) is always Russian,
regardless of which README language section you're reading, and shows at most
the top 5 anomalies and top 3 recommendations:

```
🚨 АТАКА | Squad Traffic Analyzer
Risk Score: 0.91
Пакетов: 85432
Уникальных IP: 312
PPS: 1424
Аномалий: 3

• [0.91] Возможная DDoS атака с 5.6.7.8: 52.7% трафика (45000 пакетов)
• [0.72] Высокий PPS: 1423.90 пакетов/сек
• [0.34] Сканирование портов с 10.0.0.5: 34 портов

Рекомендации:
→ ⚠️ КРИТИЧНО: Сервер под атакой! Рекомендуется немедленная проверка.
→ Заблокировать IP 5.6.7.8 в firewall
→ Включить rate limiting на уровне сети
```

---

### Deployment

#### Debian 12 — Bare Metal

```bash
# 1. Install dependencies
apt update && apt install -y python3 python3-venv redis-server tcpdump libpcap-dev

# 2. Start Redis
systemctl enable --now redis-server
redis-cli ping   # PONG

# 3. Deploy code
git clone https://github.com/GRU98/squad-traffic-analyzer.git /opt/squad/traffic_analyzer
cd /opt/squad/traffic_analyzer
mkdir -p data pcap_captures logs

# 4. Setup venv
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 5. Configure
cp .env.example .env && nano .env   # set PCAP_DIR=/opt/squad/traffic_analyzer/pcap_captures

# 6. Run (or wrap this command in a systemd unit)
cd app && ../.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
```

Example systemd unit (`/etc/systemd/system/traffic-analyzer.service`):

```ini
[Unit]
Description=Squad Traffic Analyzer
After=network.target redis-server.service

[Service]
WorkingDirectory=/opt/squad/traffic_analyzer/app
EnvironmentFile=/opt/squad/traffic_analyzer/.env
ExecStart=/opt/squad/traffic_analyzer/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=on-failure
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

#### Docker Compose — Full Stack

```bash
cp .env.example .env
nano .env   # set passwords and server IP

make up

# Verify
curl http://localhost/health
```

Stack includes:
- `squad-traffic-analyzer` — FastAPI app (port 8000)
- `squad-redis` — Redis with password + memory limit
- `squad-postgres` — PostgreSQL 15
- `squad-nginx` — Reverse proxy on port 80 (HTTP only; put a TLS terminator in front for public exposure)

---

### Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `"redis": "unavailable"` in `/health` | Redis down, wrong `REDIS_HOST`, or bad `REDIS_PASSWORD` | `redis-cli -h $REDIS_HOST ping`; check `make logs` |
| `Address already in use` | Old process still running | `make down`, or `ss -tlpn \| grep 8000` and stop the process |
| `0 packets captured` | Wrong interface or Squad not running | `ip a` → find interface; `ss -tulpn \| grep 7787` |
| `tcpdump: Operation not permitted` | No raw socket permission | `setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump` |
| `No module named 'analyzer'` | Wrong working dir (modules import each other as top-level names) | Run uvicorn from the `app/` directory |
| Redis `NOAUTH` error | Password not set in `.env` | Set `REDIS_PASSWORD` in `.env` |
| Docker build fails | Missing `.env` or wrong paths | Run `make up` from the project root, not `docker/` |
| `403` on `/analyze/path` | The file is outside `PCAP_DIR` | Move it into `PCAP_DIR` or upload it via `/analyze/upload` |
| `503` on every protected route | `API_KEY_ENABLED=true` but `API_KEY` is empty | Set `API_KEY` (e.g. `openssl rand -hex 16`) |

```bash
# Universal debug command
make status

# Full logs dump
make logs-app
```

---

### License

MIT © 2026 — [LICENSE](LICENSE)

---

## Русский

<details open>
<summary><b>📖 Содержание</b></summary>

- [Обзор](#обзор)
- [Как это работает](#как-это-работает)
- [Возможности](#возможности)
- [Структура проекта](#структура-проекта)
- [Требования](#требования)
- [Установка](#установка)
- [Команды](#команды-1)
- [Режимы работы](#режимы-работы)
- [API](#api)
- [Конфигурация](#конфигурация)
- [Детекция аномалий](#детекция-аномалий)
- [Уведомления](#уведомления)
- [Деплой](#деплой)
- [Решение проблем](#решение-проблем)

</details>

---

### Обзор

**Squad Traffic Analyzer** — REST API сервис для захвата, парсинга и анализа UDP/TCP трафика игровых серверов [Squad](https://joinsquad.com). Автоматически обнаруживает атаки (DDoS, сканирование портов, SYN флуд) и подозрительные паттерны через эвристические правила и ML-модель без учителя.

Принцип работы: захватываешь трафик `tcpdump`, отправляешь PCAP файл в API, получаешь полный отчёт с оценкой риска, IP-источниками атак и рекомендациями — в реальном времени.

---

### Как это работает

```
Squad Server (UDP 7787 / 27165)
        │
        ▼
  [tcpdump / авто-захват]
        │
        ▼
   PCAP File (.pcap)
        │
        ▼
  POST /analyze/upload  ─────────────────────────────────────────┐
  POST /analyze/path                                              │
        │                                                         │
        ▼                                                         ▼
  [Scapy парсер]                                          [SQLite / PostgreSQL]
  Извлечение: IP, порты,                                  История анализов,
  размеры, временные метки                                базовые паттерны
        │
        ▼
  [Эвристики]                    [ML — Isolation Forest]
  - Высокий PPS / BPS            - Признаки по каждому IP
  - Сканирование портов          - Обнаружение без разметки
  - SYN флуд                     - Порог загрязнения: 10%
  - DDoS с одного IP
  - Битые пакеты
        │
        ▼
  [Risk Score 0.0 – 1.0]
        │
        ├──► Redis  (кэш real-time статистики)
        ├──► DB     (персистентная история)
        └──► Алерты (Telegram / Email / Webhook)
```

---

### Возможности

| Возможность | Описание |
|-------------|----------|
| 🔍 **Парсинг PCAP** | Полный парсинг через Scapy — IP, UDP, TCP, ICMP, Raw payload |
| 📊 **Статистика трафика** | PPS, BPS, уникальные IP, распределение протоколов, топ источников |
| 🚨 **Эвристики** | 6 проверок, 7 типов аномалий: High PPS, High BPS, Port Scan, Suspicious Pattern (SYN flood / мелкие пакеты), DDoS, Malformed, A2S Query Flood |
| 🤖 **ML детекция** | Isolation Forest — без обучающей разметки |
| 🎯 **Risk Score** | Комплексная оценка 0.0–1.0 + флаг атаки |
| ⚡ **3 режима** | `manual`, `continuous` (интервал), `scheduled` (cron) |
| 💾 **Двойное хранилище** | Redis для real-time + PostgreSQL/SQLite для истории |
| 📬 **Алерты** | Telegram бот, Email (SMTP), Webhook |
| 🔒 **Безопасность** | API Key, CORS, rate limiting, production скрывает /docs |
| 🐳 **Docker** | App + Redis + PostgreSQL + Nginx из коробки |
| 🔄 **Авто-очистка** | Настраиваемое хранение PCAP и БД |

---

### Структура проекта

```
traffic_analyzer/
│
├── app/                        # Python исходный код
│   ├── main.py                 #   FastAPI приложение, все endpoints, middleware
│   ├── analyzer.py             #   Оркестрация пайплайна анализа
│   ├── pcap_parser.py          #   Парсинг PCAP через Scapy
│   ├── anomaly_detector.py     #   Эвристики + Isolation Forest ML
│   ├── models.py               #   Pydantic модели запросов/ответов
│   ├── database.py             #   SQLAlchemy ORM + сессии
│   ├── redis_client.py         #   Обёртка Redis для кэша статистики
│   ├── scheduler.py            #   APScheduler: continuous/cron захват
│   ├── notifications.py        #   Telegram / Email / Webhook алерты
│   ├── config.py               #   Все настройки через pydantic-settings
│   └── __init__.py
│
├── docker/                     # Docker и инфраструктура
│   ├── Dockerfile              #   Python 3.11-slim образ
│   ├── docker-compose.yml      #   App + Redis + PostgreSQL + Nginx
│   └── nginx/
│       └── nginx.conf          #   Reverse proxy (HTTP), rate limiting
│
├── tests/                      # pytest-тесты (синтетические PCAP, API, детекторы)
│
├── .github/workflows/ci.yml    # CI: ruff + pytest на 3.11/3.12, smoke-тест Docker
├── Makefile                    # docker compose + test/lint цели
├── pyproject.toml              # конфигурация pytest и ruff
├── requirements.txt            # Runtime-зависимости
├── requirements-dev.txt        # + pytest, ruff, httpx2
├── .env.example                # Шаблон конфигурации
├── .gitignore
├── LICENSE
└── README.md
```

---

### Требования

| Компонент | Версия | Примечание |
|-----------|--------|------------|
| Python | 3.11+ | |
| Redis | 6+ | Обязателен для кэша |
| tcpdump | любая | Нужен для авто-захвата |
| libpcap | любая | Нужен для Scapy |
| Docker | 20+ | Опционально |
| PostgreSQL | 13+ | Опционально, по умолчанию SQLite |

**Порты Squad сервера:**

| Порт | Протокол | Назначение | Захватывается по умолчанию |
|------|----------|------------|----------------------------|
| `7787` (+`7788`) | UDP | Игровой трафик (Unreal NetDriver) | только `7787` |
| `27165` (+`27166`) | UDP | Steam A2S query | только `27165` |
| `15000` | UDP | EOS beacon (с Squad v7.0) | нет |
| `21114` | TCP | Source RCON | нет |

Фильтр tcpdump по умолчанию — `udp port <SQUAD_GAME_PORT> or udp port <SQUAD_QUERY_PORT>`.
Через `CAPTURE_FILTER` можно задать любое BPF-выражение, например
`udp portrange 7787-7788 or udp portrange 27165-27166 or udp port 15000`.

---

### Установка

```bash
git clone https://github.com/your-org/squad-traffic-analyzer.git
cd squad-traffic-analyzer

cp .env.example .env
nano .env
```

**Минимальные настройки `.env`:**

```env
SQUAD_SERVER_IP=1.2.3.4          # IP твоего Squad сервера
CAPTURE_INTERFACE=ens6           # Интерфейс (найти: ip a)
REDIS_PASSWORD=change_me         # Пароль Redis
```

---

### Команды

Все операции — через `Makefile`:

| Команда | Описание |
|---------|----------|
| `make up` | Собрать и запустить полный Docker-стек (App + Redis + PostgreSQL + Nginx) |
| `make down` | Остановить стек |
| `make restart` | Перезапустить контейнеры |
| `make rebuild` | Остановить, пересобрать образы и запустить снова |
| `make status` | `docker compose ps` |
| `make logs` / `make logs-app` | Логи всех контейнеров / только приложения |
| `make clean` | Остановить стек и удалить volumes Redis и PostgreSQL |
| `make venv` | Создать `.venv` и установить runtime + dev зависимости |
| `make test` | Запустить pytest |
| `make lint` | `ruff check` + `ruff format --check` |
| `make fmt` | Автоформатирование и автоисправление замечаний ruff |

#### Docker Compose

```bash
cp .env.example .env
nano .env        # пароли, SQUAD_SERVER_IP, CAPTURE_INTERFACE
make up
curl http://localhost/health      # через Nginx
curl http://localhost:8000/health # напрямую
```

- Требуется файл `.env`
- `data/`, `pcap_captures/` и `logs/` монтируются из корня репозитория; данные Redis и
  PostgreSQL живут в именованных volumes (`redis-data`, `postgres-data`)
- Nginx отдаёт обычный HTTP на порту 80. Если API публичный, терминируйте TLS перед ним
  (облачный балансировщик, Caddy или собственный Nginx)

#### Локальная разработка

```bash
make venv
cp .env.example .env
cd app && ../.venv/bin/uvicorn main:app --reload
# API: http://localhost:8000
# Swagger UI: http://localhost:8000/docs
```

Redis для локального запуска необязателен: все обращения к нему неблокирующие и при
ошибке только логируются. `DATABASE_URL=sqlite:///./data/traffic_analyzer.db` (по умолчанию)
позволяет обойтись без PostgreSQL.

#### Тесты и линтер

```bash
make test   # pytest — без Redis, PostgreSQL и tcpdump
make lint   # ruff
```

Тесты собирают синтетические PCAP через Scapy, поэтому парсер, детекторы, скоринг, API
(включая проверку API-ключа и ограничение путей), уведомления и планировщик проверяются
сквозным образом. CI выполняет те же проверки на Python 3.11 и 3.12 и делает smoke-тест
Docker-образа.

---

### Режимы работы

Задаётся через `ANALYSIS_MODE` в `.env`:

#### `manual` (по умолчанию)
Анализирует только по запросу через API. Нет фоновой активности.
```env
ANALYSIS_MODE=manual
AUTO_CAPTURE_ENABLED=false
```

#### `continuous`
Автоматически захватывает и анализирует трафик каждые N секунд.
```env
ANALYSIS_MODE=continuous
AUTO_CAPTURE_ENABLED=true
CONTINUOUS_INTERVAL_SECONDS=300    # каждые 5 минут
CAPTURE_DURATION_SECONDS=60        # окно захвата
CAPTURE_INTERFACE=ens6
CAPTURE_FILTER=                    # BPF-фильтр tcpdump; пусто = "udp port <game> or udp port <query>"
PCAP_DIR=/app/pcap_captures        # сюда пишутся захваты; /analyze/path принимает только файлы отсюда
```

#### `scheduled`
Захват и анализ по cron расписанию.
```env
ANALYSIS_MODE=scheduled
AUTO_CAPTURE_ENABLED=true
SCHEDULED_CRON=0 */6 * * *         # каждые 6 часов
CAPTURE_DURATION_SECONDS=120
```

---

### API

Base URL: `http://твой-сервер:8000`  
Swagger UI: `http://твой-сервер:8000/docs` (отключён в production)

#### Endpoints

| Метод | Путь | Auth | Описание |
|-------|------|------|----------|
| `GET` | `/` | — | Информация о сервисе |
| `GET` | `/health` | — | Health check: API + Redis |
| `GET` | `/mode` | ✓ | Текущий режим и настройки захвата |
| `POST` | `/analyze/upload` | ✓ | Загрузить PCAP для анализа |
| `POST` | `/analyze/path` | ✓ | Анализировать PCAP по пути на сервере (только внутри `PCAP_DIR`, иначе `403`) |
| `POST` | `/capture/start` | ✓ | Запустить tcpdump захват (async) |
| `POST` | `/capture/analyze-latest` | ✓ | Анализировать последний PCAP |
| `GET` | `/history` | ✓ | История анализов (`limit`, новые первыми) |
| `GET` | `/stats/summary` | ✓ | Агрегированная статистика из БД |
| `GET` | `/stats/realtime` | ✓ | Real-time данные из Redis |
| `DELETE` | `/cleanup` | ✓ | Удалить старые данные и PCAP файлы |

> ✓ = требует заголовок `X-API-Key` если `API_KEY_ENABLED=true`. Если флаг включён, а `API_KEY` пуст, все защищённые маршруты отвечают `503`, а не пропускают запросы.

#### Примеры запросов

```bash
# Health check (всегда открыт)
curl http://localhost:8000/health

# Загрузить PCAP файл для анализа
# server_ip / game_port / query_port — query-параметры, а НЕ поля multipart-формы
curl -X POST "http://localhost:8000/analyze/upload?server_ip=1.2.3.4" \
  -H "X-API-Key: your_key" \
  -F "file=@/path/to/capture.pcap"

# Анализировать файл по пути на сервере (только внутри PCAP_DIR) — все параметры в query-строке
curl -X POST "http://localhost:8000/analyze/path?pcap_path=/app/pcap_captures/capture.pcap&server_ip=1.2.3.4&game_port=7787&query_port=27165" \
  -H "X-API-Key: your_key"

# Запустить захват на 60 секунд
curl -X POST "http://localhost:8000/capture/start?duration=60&interface=ens6" \
  -H "X-API-Key: your_key"

# Анализировать последний захваченный файл
curl -X POST http://localhost:8000/capture/analyze-latest \
  -H "X-API-Key: your_key"

# История (последние 20)
curl "http://localhost:8000/history?limit=20" \
  -H "X-API-Key: your_key"

# Сводная статистика
curl http://localhost:8000/stats/summary -H "X-API-Key: your_key"

# Очистить старые данные
curl -X DELETE http://localhost:8000/cleanup -H "X-API-Key: your_key"
```

---

### Конфигурация

<details>
<summary><b>Приложение</b></summary>

```env
ENVIRONMENT=development     # production — скрывает /docs
LOG_LEVEL=INFO              # DEBUG | INFO | WARNING | ERROR
PORT=8000
WORKERS=1                   # Production: 4+
```
</details>

<details>
<summary><b>Redis</b></summary>

```env
REDIS_HOST=localhost         # Docker: redis
REDIS_PORT=6379
REDIS_PASSWORD=change_me
STATS_RETENTION_HOURS=168   # 7 дней
```
</details>

<details>
<summary><b>База данных</b></summary>

```env
# SQLite (разработка)
DATABASE_URL=sqlite:///./data/traffic_analyzer.db

# PostgreSQL (production)
DATABASE_URL=postgresql://squad_analyzer:password@localhost:5432/traffic_analyzer
```
</details>

<details>
<summary><b>Пороги детекции</b></summary>

```env
ANOMALY_THRESHOLD_PPS=10000         # пакетов/сек
ANOMALY_THRESHOLD_BPS=100000000     # байт/сек (100 МБ)
ANOMALY_THRESHOLD_PORT_SCAN=20      # уникальных портов с одного IP
ANOMALY_THRESHOLD_QUERY_PPS=100     # входящих A2S-запросов/сек на query-порт
ML_MODEL_CONTAMINATION=0.1          # ожидаемая доля аномалий 0–0.5
ML_ENABLED=true
```
</details>

<details>
<summary><b>Безопасность</b></summary>

```env
API_KEY_ENABLED=true
API_KEY=случайный_ключ_32_символа
CORS_ORIGINS=https://yourdomain.com
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60
```
</details>

<details>
<summary><b>Уведомления</b></summary>

```env
# Telegram
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=123456:ABCdef...
TELEGRAM_CHAT_ID=-1001234567890

# Email
EMAIL_ENABLED=true
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_FROM=alerts@yourdomain.com
EMAIL_TO=admin@yourdomain.com
EMAIL_PASSWORD=app_password

# Webhook
WEBHOOK_ENABLED=true
WEBHOOK_URL=https://your-service.com/hooks/squad-alerts
```
</details>

---

### Детекция аномалий

#### Эвристические правила

`Тип` — точное значение enum `AnomalyType`, которое возвращает API.

| Тип | Триггер | Severity |
|-----|---------|----------|
| `high_pps` | PPS > `ANOMALY_THRESHOLD_PPS` (default: 10 000) | до 1.0 |
| `high_bps` | BPS > `ANOMALY_THRESHOLD_BPS` (default: 100 МБ/с) | до 1.0 |
| `port_scan` | Один IP → более `ANOMALY_THRESHOLD_PORT_SCAN` уникальных портов назначения (default: 20) | до 1.0 |
| `suspicious_pattern` | SYN flood (>100 SYN-пакетов без ACK с одного IP) либо поток из >500 пакетов короче 64 байт с одного IP | до 1.0 |
| `ddos_attack` | Один из топ-10 IP по числу пакетов даёт >30% трафика (и >1000 пакетов), либо число уникальных IP превышает `ANOMALY_THRESHOLD_CONNECTIONS` при PPS > 1000 | до 1.0 |
| `malformed_packet` | >50 UDP-пакетов на игровом/query-порту с длиной <20 или >1500 байт | до 1.0 |
| `query_flood` | Входящих датаграмм на query-порт (валидных A2S или нет — атакующие флудят его и мусором) больше `ANOMALY_THRESHOLD_QUERY_PPS` в секунду (default: 100). В деталях — число уникальных источников и коэффициент усиления bytes-out / bytes-in. Требует `server_ip` | до 1.0 |
| `ml_detected` | Isolation Forest помечает 1-секундное окно как выброс (см. ниже) | до 1.0 |

Отдельных типов `syn_flood` или `ddos_single_source` не существует — оба случая
попадают в `suspicious_pattern` / `ddos_attack`, различить их можно только по `description`.

Если известен `server_ip` (query-параметр или `SQUAD_SERVER_IP` для захватов), пакеты,
**отправленные сервером**, исключаются из правил «по источнику» (`port_scan`, `suspicious_pattern`,
`ddos_attack`, `malformed_packet`, `ml_detected`). Нагруженный сервер отвечает десяткам клиентских портов и
генерирует большую часть байтов — без фильтра это выглядит как сканирование портов или DDoS.
Для точного результата всегда передавайте `server_ip`.

`query_flood` откалиброван по рекомендациям Valve: библиотека Steam game-server отбрасывает
connectionless A2S-пакеты выше `STEAM_GAMESERVER_RATE_LIMIT_200MS` на источник (рекомендуется
25–75 за 200 мс), а 25-байтовый запрос `A2S_INFO` вызывает ответ 200–1400 байт (усиление Steam
reflection в среднем ~5.5×, до ~14×). Легитимный query-трафик даже нагруженного сервера — это
редкие запросы Steam master и браузеров серверов, поэтому суммарно >100 запросов/с — флуд.

#### ML-детекция (Isolation Forest)

Полностью пропускается, если в захвате меньше 100 пакетов. Признаки считаются
по **1-секундным окнам** (не по IP):
- Число пакетов в окне
- Суммарные байты в окне
- Число уникальных src IP в окне
- Средний размер пакета в окне

Порог задаётся `ML_MODEL_CONTAMINATION` (default: `0.1` = ожидается 10% аномалий).
Модель переобучается заново на каждый анализ — сохранённого baseline между запусками нет.

Isolation Forest с фиксированным contamination всегда помечает *какие-то* окна как выбросы,
даже на идеально ровном трафике. Поэтому помеченное окно попадает в отчёт только если число
пакетов или объём байтов в нём не меньше **2× медианного окна**. Аномалия атрибутируется
пакетам, реально попавшим в помеченные окна: `anomaly_count` / `anomaly_percentage` считают
именно их, `top_sources` ранжирует их source IP, а `details.windows` перечисляет секунды
(смещение от первого пакета). `ML_ENABLED=false` полностью отключает модель.

#### Оценка риска

```
risk_score = (max_severity × 0.5) + (avg_severity × 0.3) + (count_factor × 0.2)
```
`is_under_attack = true`, когда `risk_score > 0.7` (см. `analyzer.py::analyze_pcap`).

| Диапазон | Интерпретация |
|----------|---------------|
| `0.0 – 0.3` | Нормальный трафик |
| `0.3 – 0.7` | Подозрительно, наблюдай |
| `0.7 – 1.0` | Под атакой, действуй немедленно |

---

### Уведомления

Алерты отправляются при `risk_score > 0.5` или `is_under_attack = true`.

Текст сообщения (`notifications.py::_build_message`) всегда на русском и
показывает не более 5 аномалий и 3 рекомендаций:

```
🚨 АТАКА | Squad Traffic Analyzer
Risk Score: 0.91
Пакетов: 85432
Уникальных IP: 312
PPS: 1424
Аномалий: 3

• [0.91] Возможная DDoS атака с 5.6.7.8: 52.7% трафика (45000 пакетов)
• [0.72] Высокий PPS: 1423.90 пакетов/сек
• [0.34] Сканирование портов с 10.0.0.5: 34 портов

Рекомендации:
→ ⚠️ КРИТИЧНО: Сервер под атакой! Рекомендуется немедленная проверка.
→ Заблокировать IP 5.6.7.8 в firewall
→ Включить rate limiting на уровне сети
```

---

### Деплой

#### Debian 12 — Bare Metal

```bash
# 1. Системные зависимости
apt update && apt install -y python3 python3-venv redis-server tcpdump libpcap-dev

# 2. Запустить Redis
systemctl enable --now redis-server
redis-cli ping   # PONG

# 3. Код
git clone https://github.com/GRU98/squad-traffic-analyzer.git /opt/squad/traffic_analyzer
cd /opt/squad/traffic_analyzer
mkdir -p data pcap_captures logs

# 4. Виртуальное окружение
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 5. Конфигурация
cp .env.example .env && nano .env   # укажите PCAP_DIR=/opt/squad/traffic_analyzer/pcap_captures

# 6. Запуск (или оберните команду в systemd unit)
cd app && ../.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
```

Пример systemd unit (`/etc/systemd/system/traffic-analyzer.service`):

```ini
[Unit]
Description=Squad Traffic Analyzer
After=network.target redis-server.service

[Service]
WorkingDirectory=/opt/squad/traffic_analyzer/app
EnvironmentFile=/opt/squad/traffic_analyzer/.env
ExecStart=/opt/squad/traffic_analyzer/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=on-failure
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

#### Docker Compose

```bash
cp .env.example .env
nano .env   # пароли и IP сервера

make up

curl http://localhost/health
```

Стек включает:
- `squad-traffic-analyzer` — FastAPI (порт 8000)
- `squad-redis` — Redis с паролем + лимит памяти
- `squad-postgres` — PostgreSQL 15
- `squad-nginx` — Reverse proxy на порту 80 (только HTTP; для публичного доступа поставьте TLS-терминатор перед ним)

---

### Решение проблем

| Проблема | Причина | Решение |
|----------|---------|---------|
| `"redis": "unavailable"` в `/health` | Redis не запущен, неверный `REDIS_HOST` или `REDIS_PASSWORD` | `redis-cli -h $REDIS_HOST ping`; `systemctl start redis-server` |
| `Address already in use` | Старый процесс жив | `make down`, либо `ss -tlpn \| grep 8000` и остановить процесс |
| `0 packets captured` | Неверный интерфейс / Squad не запущен | `ip a` → `ss -tulpn \| grep 7787` |
| `Operation not permitted` | Нет прав на raw socket | `setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump` |
| `No module named 'analyzer'` | Неверная рабочая директория (модули импортируют друг друга как top-level) | Запускать uvicorn из директории `app/` |
| Redis `NOAUTH` | Не задан `REDIS_PASSWORD` | Добавить в `.env` |
| `403` на `/analyze/path` | Файл вне `PCAP_DIR` | Переместить в `PCAP_DIR` или загрузить через `/analyze/upload` |
| `503` на всех защищённых маршрутах | `API_KEY_ENABLED=true`, но `API_KEY` пуст | Задать `API_KEY` (например, `openssl rand -hex 16`) |

```bash
# Универсальная диагностика
make status

# Полные логи
make logs-app
```

---

### Лицензия

MIT © 2026 — [LICENSE](LICENSE)
