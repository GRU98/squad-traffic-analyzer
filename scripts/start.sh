#!/bin/bash
# Squad Traffic Analyzer - Launch Script
# Usage: ./scripts/start.sh [mode]
# Modes: dev | prod | docker | stop | status | logs

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$ROOT/app"
VENV="$ROOT/venv"
PYTHON="$VENV/bin/python"
SERVICE="traffic-analyzer"

cd "$ROOT"

case "${1:-dev}" in

  # ─────────────────────────────────────────────
  dev)
    echo ">>> Starting in DEVELOPMENT mode..."
    [ ! -d "$VENV" ] && python3 -m venv "$VENV"
    source "$VENV/bin/activate"
    pip install -q -r requirements.txt
    mkdir -p data pcap_captures logs
    cd "$APP_DIR"
    PYTHONPATH="$APP_DIR" python main.py
    ;;

  # ─────────────────────────────────────────────
  prod)
    echo ">>> Starting in PRODUCTION mode (systemd)..."
    if [ ! -f /etc/systemd/system/$SERVICE.service ]; then
      echo "Creating systemd service..."
      cat > /etc/systemd/system/$SERVICE.service << EOF
[Unit]
Description=Squad Traffic Analyzer API
After=network.target redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment="PATH=$VENV/bin"
ExecStart=$PYTHON main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      echo "Service created."
    fi
    systemctl enable --now $SERVICE
    systemctl status $SERVICE
    ;;

  # ─────────────────────────────────────────────
  docker)
    echo ">>> Starting with Docker Compose..."
    if [ ! -f "$ROOT/.env" ]; then
      cp "$ROOT/.env.example" "$ROOT/.env"
      echo "Created .env from .env.example — edit it before use!"
      exit 1
    fi
    mkdir -p data pcap_captures logs logs/nginx docker/nginx/ssl
    docker compose -f "$ROOT/docker/docker-compose.yml" up -d --build
    echo ""
    echo ">>> API:     http://localhost:8000"
    echo ">>> Docs:    http://localhost:8000/docs"
    echo ">>> Health:  http://localhost:8000/health"
    ;;

  # ─────────────────────────────────────────────
  stop)
    echo ">>> Stopping..."
    if systemctl is-active --quiet $SERVICE 2>/dev/null; then
      systemctl stop $SERVICE
      echo "Systemd service stopped."
    fi
    if docker compose -f "$ROOT/docker/docker-compose.yml" ps -q 2>/dev/null | grep -q .; then
      docker compose -f "$ROOT/docker/docker-compose.yml" down
      echo "Docker containers stopped."
    fi
    pkill -f "python main.py" 2>/dev/null && echo "Dev process killed." || true
    ;;

  # ─────────────────────────────────────────────
  status)
    echo "=== System ==="
    echo "Redis:  $(redis-cli ping 2>/dev/null || echo 'unavailable')"
    echo "API:    $(curl -s http://localhost:8000/health 2>/dev/null || echo 'unavailable')"
    echo ""
    echo "=== Systemd ==="
    systemctl is-active $SERVICE 2>/dev/null || echo "not running"
    echo ""
    echo "=== Docker ==="
    docker compose -f "$ROOT/docker/docker-compose.yml" ps 2>/dev/null || echo "not running"
    echo ""
    echo "=== PCAP files ==="
    ls -lh "$ROOT/pcap_captures/"*.pcap 2>/dev/null | tail -5 || echo "none"
    ;;

  # ─────────────────────────────────────────────
  logs)
    TARGET="${2:-app}"
    case "$TARGET" in
      app)     journalctl -u $SERVICE -f ;;
      docker)  docker compose -f "$ROOT/docker/docker-compose.yml" logs -f app ;;
      nginx)   tail -f "$ROOT/logs/nginx/access.log" ;;
      *)       echo "Usage: $0 logs [app|docker|nginx]" ;;
    esac
    ;;

  *)
    echo "Squad Traffic Analyzer - Start Script"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  dev      Start in development mode (local venv)"
    echo "  prod     Install and start as systemd service"
    echo "  docker   Start with Docker Compose"
    echo "  stop     Stop all running instances"
    echo "  status   Show status of all components"
    echo "  logs     Tail logs [app|docker|nginx]"
    ;;
esac
