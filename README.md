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
| 🚨 **Heuristic Detection** | 5 rule types: High PPS/BPS, Port Scan, SYN Flood, DDoS, Malformed |
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
│       └── nginx.conf          #   Reverse proxy, SSL, rate limiting
│
├── scripts/
│   └── start.sh                # Unified launch script (6 commands)
│
├── docs/                       # Additional documentation
│
├── requirements.txt            # Python dependencies
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

**Squad Server Ports captured:**
- `UDP 7787` — game traffic
- `UDP 27165` — Steam query

---

### Installation

#### Clone & configure

```bash
git clone https://github.com/your-org/squad-traffic-analyzer.git
cd squad-traffic-analyzer/traffic_analyzer

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

All operations through `scripts/start.sh`:

```bash
chmod +x scripts/start.sh
```

| Command | Description |
|---------|-------------|
| `./scripts/start.sh dev` | Start locally in venv (development) |
| `./scripts/start.sh prod` | Install & run as systemd service (production) |
| `./scripts/start.sh docker` | Run full stack via Docker Compose |
| `./scripts/start.sh stop` | Stop all running instances |
| `./scripts/start.sh status` | Show status: Redis, API, Docker, PCAP files |
| `./scripts/start.sh logs [app\|docker\|nginx]` | Tail logs from any component |

#### `dev` — Development mode

Starts a local server using a Python virtual environment. Ideal for testing.

```bash
./scripts/start.sh dev
# API available at http://localhost:8000
# Swagger UI at  http://localhost:8000/docs
```

- Auto-creates `venv/` if not present
- Installs dependencies from `requirements.txt`
- Creates `data/`, `pcap_captures/`, `logs/` directories

#### `prod` — Production (systemd)

Installs the app as a `traffic-analyzer` systemd service that survives reboots.

```bash
sudo ./scripts/start.sh prod
# Enables: systemctl enable --now traffic-analyzer
# View logs: journalctl -u traffic-analyzer -f
```

- Requires root
- Creates `/etc/systemd/system/traffic-analyzer.service`
- Restarts automatically on crash

#### `docker` — Docker Compose

Runs the full stack: **App + Redis + PostgreSQL + Nginx**.

```bash
./scripts/start.sh docker
# API:     http://localhost:8000
# Via Nginx: http://localhost:80 (or https with SSL configured)
```

- Requires `.env` to exist (auto-prompted if not)
- Creates `data/`, `pcap_captures/`, `logs/nginx/` directories
- All data persisted in Docker named volumes

#### `stop` — Stop everything

```bash
./scripts/start.sh stop
# Stops systemd service (if running)
# Stops Docker containers (if running)
# Kills any dev process
```

#### `status` — Check status

```bash
./scripts/start.sh status
# Outputs:
# === System ===
# Redis:  PONG
# API:    {"status":"healthy",...}
# === Systemd ===
# active / not running
# === Docker ===
# Container status table
# === PCAP files ===
# Last 5 captured files
```

#### `logs` — View logs

```bash
./scripts/start.sh logs             # systemd app logs (default)
./scripts/start.sh logs docker      # Docker container logs
./scripts/start.sh logs nginx       # Nginx access log
```

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
| `POST` | `/analyze/path` | ✓ | Analyze PCAP file by server path |
| `POST` | `/capture/start` | ✓ | Start tcpdump capture (async) |
| `POST` | `/capture/analyze-latest` | ✓ | Analyze most recent PCAP file |
| `GET` | `/history` | ✓ | Paginated analysis history |
| `GET` | `/stats/summary` | ✓ | Aggregated DB statistics |
| `GET` | `/stats/realtime` | ✓ | Live stats from Redis |
| `DELETE` | `/cleanup` | ✓ | Delete old data + PCAP files |

> ✓ = requires `X-API-Key` header when `API_KEY_ENABLED=true`

#### Request Examples

```bash
# Health check (always open)
curl http://localhost:8000/health

# Analyze uploaded PCAP
curl -X POST http://localhost:8000/analyze/upload \
  -H "X-API-Key: your_key" \
  -F "file=@/path/to/capture.pcap" \
  -F "server_ip=1.2.3.4" \
  -F "game_port=7787"

# Analyze by path (file already on server)
curl -X POST http://localhost:8000/analyze/path \
  -H "X-API-Key: your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "pcap_path": "/opt/squad/pcap_captures/capture.pcap",
    "server_ip": "1.2.3.4",
    "game_port": 7787,
    "query_port": 27165
  }'

# Start tcpdump capture for 60 seconds
curl -X POST "http://localhost:8000/capture/start?duration=60&interface=ens6" \
  -H "X-API-Key: your_key"

# Analyze most recently captured file
curl -X POST http://localhost:8000/capture/analyze-latest \
  -H "X-API-Key: your_key"

# Get history (last 20)
curl "http://localhost:8000/history?limit=20&offset=0" \
  -H "X-API-Key: your_key"

# Summary stats
curl http://localhost:8000/stats/summary -H "X-API-Key: your_key"

# Cleanup old data
curl -X DELETE http://localhost:8000/cleanup -H "X-API-Key: your_key"
```

#### Full Response Schema

```json
{
  "analysis_id": "3f8a1b2c-...",
  "timestamp": "2026-09-01T10:00:00.123456",
  "duration_seconds": 2.47,
  "stats": {
    "total_packets": 85432,
    "total_bytes": 52428800,
    "duration_seconds": 60.0,
    "packets_per_second": 1423.9,
    "bytes_per_second": 873813.3,
    "unique_ips": 312,
    "udp_packets": 82100,
    "tcp_packets": 3200,
    "icmp_packets": 132,
    "other_packets": 0,
    "game_port_packets": 79400,
    "query_port_packets": 2700,
    "top_talkers": [
      {"ip": "5.6.7.8", "packets": 45000, "bytes": 27000000, "percent": 52.7}
    ],
    "protocol_distribution": {"UDP": 96, "TCP": 4},
    "packet_size_distribution": {"small": 12000, "medium": 60000, "large": 13432}
  },
  "anomalies": [
    {
      "type": "ddos_single_source",
      "severity": 0.91,
      "description": "Single IP 5.6.7.8 responsible for 52.7% of all traffic",
      "source_ip": "5.6.7.8",
      "timestamp": "2026-09-01T10:00:05.000000",
      "details": {"packets": 45000, "percent": 52.7}
    },
    {
      "type": "high_pps",
      "severity": 0.72,
      "description": "Traffic rate 1423 PPS exceeds threshold 1000 PPS",
      "source_ip": null,
      "timestamp": "2026-09-01T10:00:00.000000",
      "details": {}
    }
  ],
  "risk_score": 0.87,
  "is_under_attack": true,
  "recommendations": [
    "Block IP 5.6.7.8 immediately — responsible for >50% traffic",
    "Enable rate limiting on UDP port 7787",
    "Contact your hosting provider about DDoS mitigation",
    "Consider enabling IP allowlist for known players"
  ]
}
```

---

### Anomaly Detection

#### Heuristic Rules

| Type | Trigger | Severity |
|------|---------|----------|
| `high_pps` | PPS > `ANOMALY_THRESHOLD_PPS` (default: 10,000) | 0.6–0.9 |
| `high_bps` | BPS > `ANOMALY_THRESHOLD_BPS` (default: 100 MB/s) | 0.6–0.9 |
| `port_scan` | Single IP hits > N unique ports | 0.7–1.0 |
| `ddos_single_source` | One IP > 30% of total traffic | 0.8–1.0 |
| `syn_flood` | High TCP SYN ratio with no ACK | 0.75–1.0 |
| `malformed_packet` | Packets with invalid headers/size | 0.5–0.8 |

#### ML Detection (Isolation Forest)

Features extracted per IP per time window:
- Packet count and byte volume
- Unique destination ports
- Packet size variance
- Protocol mix ratio
- Inter-arrival time statistics

Anomaly score threshold controlled by `ML_MODEL_CONTAMINATION` (default: `0.1` = 10% expected anomalies).

#### Risk Score Calculation

```
risk_score = (max_severity × 0.5) + (avg_severity × 0.3) + (anomaly_count_factor × 0.2)
```
- `0.0 – 0.3` — Normal traffic
- `0.3 – 0.6` — Suspicious, monitor
- `0.6 – 0.8` — High risk, investigate
- `0.8 – 1.0` — Under attack, act immediately

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

**Telegram message example:**
```
🚨 АТАКА | Squad Traffic Analyzer
Risk Score: 0.91
Пакетов: 85432
Уникальных IP: 312
PPS: 1424
Аномалий: 3

• [0.91] IP 5.6.7.8 — 52.7% всего трафика
• [0.72] Превышен порог PPS: 1424 > 1000
• [0.68] Port scan с 10.0.0.5: 34 порта

Рекомендации:
→ Заблокировать IP 5.6.7.8
→ Включить rate limiting на UDP 7787
→ Связаться с провайдером
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

# 3. Create directories
mkdir -p /opt/squad/traffic_analyzer/{data,pcap_captures,logs}

# 4. Deploy code
cd /opt/squad/traffic_analyzer
# (upload files via scp or git clone)

# 5. Setup venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 6. Configure
cp .env.example .env && nano .env

# 7. Start
sudo ./scripts/start.sh prod
```

#### Docker Compose — Full Stack

```bash
cp .env.example .env
nano .env   # set passwords and server IP

./scripts/start.sh docker

# Verify
curl http://localhost/health
```

Stack includes:
- `squad-traffic-analyzer` — FastAPI app (port 8000)
- `squad-redis` — Redis with password + memory limit
- `squad-postgres` — PostgreSQL 15
- `squad-nginx` — Reverse proxy on port 80/443

#### SSL with Let's Encrypt (optional)

```bash
apt install certbot python3-certbot-nginx
certbot certonly --standalone -d yourdomain.com

# Copy certs to nginx ssl folder
cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem docker/nginx/ssl/cert.pem
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem docker/nginx/ssl/key.pem

./scripts/start.sh docker
```

---

### Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `500 Internal Server Error /health` | Missing `datetime` import or Redis down | Check logs: `./scripts/start.sh logs` |
| `Address already in use` | Old process still running | `./scripts/start.sh stop` |
| `0 packets captured` | Wrong interface or Squad not running | `ip a` → find interface; `ss -tulpn \| grep 7787` |
| `tcpdump: Operation not permitted` | No raw socket permission | `setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump` |
| `No module named 'traffic_analyzer'` | Wrong working dir or relative imports | Run from `app/` directory or use `./scripts/start.sh` |
| Redis `NOAUTH` error | Password not set in `.env` | Set `REDIS_PASSWORD` in `.env` |
| Docker build fails | Missing `.env` or wrong paths | Run from project root, not `docker/` |

```bash
# Universal debug command
./scripts/start.sh status

# Full logs dump
./scripts/start.sh logs app
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
| 🚨 **Эвристики** | 6 типов правил: High PPS/BPS, Port Scan, SYN Flood, DDoS, Malformed |
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
│       └── nginx.conf          #   Reverse proxy, SSL, rate limiting
│
├── scripts/
│   └── start.sh                # Единый скрипт запуска (6 команд)
│
├── docs/                       # Дополнительная документация
│
├── requirements.txt            # Python зависимости
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
- `UDP 7787` — игровой трафик
- `UDP 27165` — Steam query

---

### Установка

```bash
git clone https://github.com/your-org/squad-traffic-analyzer.git
cd squad-traffic-analyzer/traffic_analyzer

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

Все операции через `scripts/start.sh`:

```bash
chmod +x scripts/start.sh
```

| Команда | Описание |
|---------|----------|
| `./scripts/start.sh dev` | Запустить локально в venv (разработка) |
| `./scripts/start.sh prod` | Установить и запустить как systemd сервис |
| `./scripts/start.sh docker` | Запустить полный стек через Docker Compose |
| `./scripts/start.sh stop` | Остановить все запущенные экземпляры |
| `./scripts/start.sh status` | Статус: Redis, API, Docker, PCAP файлы |
| `./scripts/start.sh logs [app\|docker\|nginx]` | Логи любого компонента |

#### `dev` — Режим разработки

Запускает локальный сервер через Python venv. Идеально для тестирования.

```bash
./scripts/start.sh dev
# API:      http://localhost:8000
# Swagger:  http://localhost:8000/docs
```

- Авто-создаёт `venv/` если нет
- Устанавливает зависимости из `requirements.txt`
- Создаёт `data/`, `pcap_captures/`, `logs/`

#### `prod` — Production (systemd)

Устанавливает приложение как systemd сервис `traffic-analyzer`.

```bash
sudo ./scripts/start.sh prod
# Включает: systemctl enable --now traffic-analyzer
# Логи:     journalctl -u traffic-analyzer -f
```

- Требует root
- Создаёт `/etc/systemd/system/traffic-analyzer.service`
- Автоматически перезапускается при падении

#### `docker` — Docker Compose

Запускает полный стек: **App + Redis + PostgreSQL + Nginx**.

```bash
./scripts/start.sh docker
# API:       http://localhost:8000
# Через Nginx: http://localhost (или https с настроенным SSL)
```

- Требует наличия `.env` (подсказывает если нет)
- Создаёт все нужные директории
- Данные хранятся в именованных Docker volumes

#### `stop` — Остановить всё

```bash
./scripts/start.sh stop
# Остановит systemd сервис (если запущен)
# Остановит Docker контейнеры (если запущены)
# Убьёт dev процесс
```

#### `status` — Проверить статус

```bash
./scripts/start.sh status
# === System ===
# Redis:  PONG
# API:    {"status":"healthy",...}
# === Systemd ===
# active / not running
# === Docker ===
# Таблица контейнеров
# === PCAP files ===
# Последние 5 захваченных файлов
```

#### `logs` — Просмотр логов

```bash
./scripts/start.sh logs             # логи приложения (systemd)
./scripts/start.sh logs docker      # логи Docker контейнера
./scripts/start.sh logs nginx       # логи Nginx access.log
```

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
| `POST` | `/analyze/path` | ✓ | Анализировать PCAP по пути на сервере |
| `POST` | `/capture/start` | ✓ | Запустить tcpdump захват (async) |
| `POST` | `/capture/analyze-latest` | ✓ | Анализировать последний PCAP |
| `GET` | `/history` | ✓ | История анализов с пагинацией |
| `GET` | `/stats/summary` | ✓ | Агрегированная статистика из БД |
| `GET` | `/stats/realtime` | ✓ | Real-time данные из Redis |
| `DELETE` | `/cleanup` | ✓ | Удалить старые данные и PCAP файлы |

> ✓ = требует заголовок `X-API-Key` если `API_KEY_ENABLED=true`

#### Примеры запросов

```bash
# Health check (всегда открыт)
curl http://localhost:8000/health

# Загрузить PCAP файл для анализа
curl -X POST http://localhost:8000/analyze/upload \
  -H "X-API-Key: your_key" \
  -F "file=@/path/to/capture.pcap" \
  -F "server_ip=1.2.3.4"

# Анализировать файл по пути на сервере
curl -X POST http://localhost:8000/analyze/path \
  -H "X-API-Key: your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "pcap_path": "/opt/squad/pcap_captures/capture.pcap",
    "server_ip": "1.2.3.4",
    "game_port": 7787,
    "query_port": 27165
  }'

# Запустить захват на 60 секунд
curl -X POST "http://localhost:8000/capture/start?duration=60&interface=ens6" \
  -H "X-API-Key: your_key"

# Анализировать последний захваченный файл
curl -X POST http://localhost:8000/capture/analyze-latest \
  -H "X-API-Key: your_key"

# История (последние 20)
curl "http://localhost:8000/history?limit=20&offset=0" \
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

| Тип | Триггер | Severity |
|-----|---------|----------|
| `high_pps` | PPS > порога (default: 10 000) | 0.6–0.9 |
| `high_bps` | BPS > порога (default: 100 МБ/с) | 0.6–0.9 |
| `port_scan` | Один IP → N уникальных портов | 0.7–1.0 |
| `ddos_single_source` | Один IP > 30% всего трафика | 0.8–1.0 |
| `syn_flood` | Высокий TCP SYN без ACK | 0.75–1.0 |
| `malformed_packet` | Пакеты с битыми заголовками | 0.5–0.8 |

#### Оценка риска

```
risk_score = (max_severity × 0.5) + (avg_severity × 0.3) + (count_factor × 0.2)
```

| Диапазон | Интерпретация |
|----------|---------------|
| `0.0 – 0.3` | Нормальный трафик |
| `0.3 – 0.6` | Подозрительно, наблюдай |
| `0.6 – 0.8` | Высокий риск, расследуй |
| `0.8 – 1.0` | Под атакой, действуй немедленно |

---

### Уведомления

Алерты отправляются при `risk_score > 0.5` или `is_under_attack = true`.

**Пример Telegram сообщения:**
```
🚨 АТАКА | Squad Traffic Analyzer
Risk Score: 0.91
Пакетов: 85 432
Уникальных IP: 312
PPS: 1 424
Аномалий: 3

• [0.91] IP 5.6.7.8 — 52.7% всего трафика
• [0.72] Превышен порог PPS: 1424 > 10000
• [0.68] Port scan с 10.0.0.5: 34 порта

Рекомендации:
→ Заблокировать IP 5.6.7.8
→ Включить rate limiting UDP 7787
→ Связаться с хостинг-провайдером
```

---

### Деплой

#### Debian 12 — Bare Metal

```bash
# 1. Системные зависимости
apt update && apt install -y \
    python3 python3-venv redis-server tcpdump libpcap-dev

# 2. Запустить Redis
systemctl enable --now redis-server
redis-cli ping   # PONG

# 3. Создать директории
mkdir -p /opt/squad/traffic_analyzer/{data,pcap_captures,logs}

# 4. Загрузить код (scp или git clone)
cd /opt/squad/traffic_analyzer

# 5. Виртуальное окружение
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 6. Конфигурация
cp .env.example .env && nano .env

# 7. Запуск
sudo ./scripts/start.sh prod
```

#### Docker Compose

```bash
cp .env.example .env
nano .env   # пароли и IP сервера

./scripts/start.sh docker

curl http://localhost/health
```

Стек включает:
- `squad-traffic-analyzer` — FastAPI (порт 8000)
- `squad-redis` — Redis с паролем + лимит памяти
- `squad-postgres` — PostgreSQL 15
- `squad-nginx` — Reverse proxy 80/443

#### SSL через Let's Encrypt

```bash
apt install certbot
certbot certonly --standalone -d yourdomain.com

cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem docker/nginx/ssl/cert.pem
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem docker/nginx/ssl/key.pem

./scripts/start.sh docker
```

---

### Решение проблем

| Проблема | Причина | Решение |
|----------|---------|---------|
| `500 Internal Server Error` | Redis не запущен | `systemctl start redis-server` |
| `Address already in use` | Старый процесс жив | `./scripts/start.sh stop` |
| `0 packets captured` | Неверный интерфейс / Squad не запущен | `ip a` → `ss -tulpn \| grep 7787` |
| `Operation not permitted` | Нет прав на raw socket | `setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump` |
| `No module named 'traffic_analyzer'` | Неверная рабочая директория | Используй `./scripts/start.sh` |
| Redis `NOAUTH` | Не задан `REDIS_PASSWORD` | Добавить в `.env` |

```bash
# Универсальная диагностика
./scripts/start.sh status

# Полные логи
./scripts/start.sh logs
```

---

### Лицензия

MIT © 2026 — [LICENSE](LICENSE)
