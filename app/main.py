"""FastAPI-приложение: HTTP-эндпоинты для анализа трафика Squad-сервера, история и статистика."""

import asyncio
import glob
import logging
import os
import re
import secrets
import tempfile
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from analyzer import TrafficAnalyzer
from config import settings
from database import AnalysisRecord, get_db, init_db
from models import AnalysisResult
from redis_client import RedisClient

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Имя сетевого интерфейса передаётся в tcpdump; допускаем только символы, встречающиеся в именах интерфейсов.
INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing database...")
    init_db()
    logger.info("Application started successfully")

    if settings.AUTO_CAPTURE_ENABLED:
        from scheduler import start_scheduler

        await start_scheduler()
        logger.info(f"Scheduler started in {settings.ANALYSIS_MODE} mode")

    yield

    logger.info("Shutting down application...")
    if settings.AUTO_CAPTURE_ENABLED:
        from scheduler import stop_scheduler

        await stop_scheduler()


app = FastAPI(
    title=settings.APP_NAME,
    description="Анализ сетевого трафика Squad сервера с детекцией аномалий через эвристики и ML",
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    version=settings.VERSION,
    lifespan=lifespan,
)

_cors_origins = [origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    # Wildcard + credentials заставляет Starlette отражать любой Origin с credentials —
    # это классическая CORS-уязвимость, поэтому credentials разрешаем только для явного списка.
    allow_credentials="*" not in _cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    """Требовать заголовок X-API-Key (или query-параметр api_key), кроме путей из skip_paths.

    Если API_KEY_ENABLED=true, но сам ключ не задан, все защищённые запросы
    отклоняются с 503 — иначе пустой ключ означал бы отсутствие защиты.
    """
    if settings.API_KEY_ENABLED:
        skip_paths = ["/health", "/docs", "/redoc", "/openapi.json"]
        if request.url.path not in skip_paths:
            if not settings.API_KEY:
                return JSONResponse(status_code=503, content={"detail": "API_KEY_ENABLED is set but API_KEY is empty"})
            api_key = request.headers.get("X-API-Key") or request.query_params.get("api_key") or ""
            if not secrets.compare_digest(api_key.encode(), settings.API_KEY.encode()):
                return JSONResponse(status_code=403, content={"detail": "Invalid or missing API Key"})
    return await call_next(request)


analyzer = TrafficAnalyzer()
redis_client = RedisClient()


def _client_error_detail(prefix: str, exc: Exception) -> str:
    """В production не раскрывать текст исключений (пути, внутренности библиотек) клиенту."""
    if settings.ENVIRONMENT == "production":
        return prefix
    return f"{prefix}: {exc}"


def _resolve_pcap_in_capture_dir(pcap_path: str) -> Path:
    """Проверить, что путь лежит внутри settings.PCAP_DIR, и вернуть его в нормализованном виде.

    Raises:
        HTTPException 403: путь вне PCAP_DIR (включая обход через ".." и symlink).
        HTTPException 404: файл не существует.
    """
    capture_dir = Path(settings.PCAP_DIR).resolve()
    resolved = Path(pcap_path).resolve()
    if capture_dir not in resolved.parents:
        raise HTTPException(status_code=403, detail=f"PCAP файл должен находиться в {settings.PCAP_DIR}")
    if not resolved.is_file():
        raise HTTPException(status_code=404, detail="PCAP файл не найден")
    return resolved


@app.get("/")
async def root():
    return {"app": settings.APP_NAME, "version": settings.VERSION, "status": "running"}


@app.post("/analyze/upload", response_model=AnalysisResult)
async def analyze_pcap_upload(
    file: UploadFile = File(...),
    server_ip: str | None = None,
    game_port: int = settings.SQUAD_GAME_PORT,
    query_port: int = settings.SQUAD_QUERY_PORT,
):
    """
    Загрузить PCAP файл для анализа

    Args:
        file: PCAP файл из Wireshark
        server_ip: IP адрес Squad сервера (опционально)
        game_port: Игровой порт (по умолчанию 7787)
        query_port: Query порт (по умолчанию 27165)

    Returns:
        Результат анализа с детекцией аномалий
    """
    if not file.filename or not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Файл должен быть в формате PCAP или PCAPNG")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
            tmp_path = tmp_file.name
            content = await file.read()
            tmp_file.write(content)

        logger.info(f"Analyzing uploaded file: {file.filename} ({len(content)} bytes)")

        return await analyzer.analyze_pcap(tmp_path, server_ip, game_port, query_port)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=_client_error_detail("Ошибка анализа", e)) from e
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.post("/analyze/path", response_model=AnalysisResult)
async def analyze_pcap_path(
    pcap_path: str,
    server_ip: str | None = None,
    game_port: int = settings.SQUAD_GAME_PORT,
    query_port: int = settings.SQUAD_QUERY_PORT,
):
    """
    Анализировать PCAP файл по пути на сервере. Путь должен лежать внутри PCAP_DIR.
    """
    resolved = _resolve_pcap_in_capture_dir(pcap_path)

    try:
        return await analyzer.analyze_pcap(str(resolved), server_ip, game_port, query_port)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=_client_error_detail("Ошибка анализа", e)) from e


@app.get("/history", response_model=list[dict])
async def get_analysis_history(limit: int = Query(10, ge=1, le=1000), db: Session = Depends(get_db)):
    """
    Получить историю анализов
    """
    records = db.query(AnalysisRecord).order_by(AnalysisRecord.timestamp.desc()).limit(limit).all()

    return [
        {
            "analysis_id": r.analysis_id,
            "timestamp": r.timestamp,
            "total_packets": r.total_packets,
            "unique_ips": r.unique_ips,
            "anomaly_count": r.anomaly_count,
            "risk_score": r.risk_score,
            "is_under_attack": r.is_under_attack,
        }
        for r in records
    ]


@app.get("/analysis/{analysis_id}", response_model=dict)
async def get_analysis_details(analysis_id: str, db: Session = Depends(get_db)):
    """
    Получить детали конкретного анализа
    """
    record = db.query(AnalysisRecord).filter(AnalysisRecord.analysis_id == analysis_id).first()

    if not record:
        raise HTTPException(status_code=404, detail="Анализ не найден")

    return {
        "analysis_id": record.analysis_id,
        "timestamp": record.timestamp,
        "duration_seconds": record.duration_seconds,
        "stats": record.stats_json,
        "anomalies": record.anomalies_json,
        "recommendations": record.recommendations_json,
        "risk_score": record.risk_score,
        "is_under_attack": record.is_under_attack,
    }


@app.get("/stats/realtime")
async def get_realtime_stats():
    """
    Получить статистику в реальном времени из Redis
    """
    recent_stats = redis_client.get_recent_stats(hours=1)
    recent_anomalies = redis_client.get_recent_anomalies(limit=10)

    return {"recent_stats": recent_stats, "recent_anomalies": recent_anomalies}


@app.get("/stats/summary")
async def get_summary_stats(db: Session = Depends(get_db)):
    """
    Получить сводную статистику
    """
    total_analyses = db.query(AnalysisRecord).count()
    attacks_detected = db.query(AnalysisRecord).filter(AnalysisRecord.is_under_attack.is_(True)).count()

    recent = db.query(AnalysisRecord).order_by(AnalysisRecord.timestamp.desc()).limit(10).all()

    avg_risk = sum(r.risk_score for r in recent) / len(recent) if recent else 0

    return {
        "total_analyses": total_analyses,
        "attacks_detected": attacks_detected,
        "average_risk_score": avg_risk,
        "recent_analyses_count": len(recent),
    }


@app.delete("/cleanup")
async def cleanup_old_data():
    """Очистить старые данные из Redis и PCAP файлы старше PCAP_RETENTION_DAYS из PCAP_DIR."""
    try:
        redis_client.cleanup_old_data()

        deleted = 0
        if settings.PCAP_RETENTION_DAYS > 0:
            cutoff = time.time() - (settings.PCAP_RETENTION_DAYS * 86400)
            for f in glob.glob(os.path.join(settings.PCAP_DIR, "*.pcap")):
                if os.path.getmtime(f) < cutoff:
                    os.remove(f)
                    deleted += 1

        return {"status": "success", "deleted_pcaps": deleted, "message": f"Очищено. Удалено PCAP файлов: {deleted}"}
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=_client_error_detail("Ошибка очистки", e)) from e


@app.get("/mode")
async def get_current_mode():
    """Получить текущий режим работы"""
    return {
        "analysis_mode": settings.ANALYSIS_MODE,
        "auto_capture_enabled": settings.AUTO_CAPTURE_ENABLED,
        "continuous_interval_seconds": settings.CONTINUOUS_INTERVAL_SECONDS,
        "scheduled_cron": settings.SCHEDULED_CRON,
        "capture_interface": settings.CAPTURE_INTERFACE,
        "capture_duration_seconds": settings.CAPTURE_DURATION_SECONDS,
    }


@app.post("/capture/start")
async def start_manual_capture(
    duration: int = Query(60, ge=1, le=3600), interface: str | None = Query(None, pattern=INTERFACE_NAME.pattern)
):
    """Запустить ручной захват трафика tcpdump'ом в фоне; файл пишется в PCAP_DIR."""
    iface = interface or settings.CAPTURE_INTERFACE
    if not INTERFACE_NAME.match(iface):
        raise HTTPException(status_code=422, detail="Недопустимое имя интерфейса")

    os.makedirs(settings.PCAP_DIR, exist_ok=True)
    pcap_file = os.path.join(settings.PCAP_DIR, f"manual_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")

    cmd = [
        "tcpdump",
        "-i",
        iface,
        "-w",
        pcap_file,
        "-G",
        str(duration),
        "-W",
        "1",
        f"udp port {settings.SQUAD_GAME_PORT} or udp port {settings.SQUAD_QUERY_PORT}",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd)
    except Exception as e:
        logger.error(f"Failed to start tcpdump: {e}")
        raise HTTPException(status_code=500, detail=_client_error_detail("Не удалось запустить tcpdump", e)) from e

    # Дожидаемся завершения в фоне, чтобы процесс не оставался зомби.
    asyncio.ensure_future(proc.wait())

    return {
        "status": "started",
        "pcap_file": pcap_file,
        "duration": duration,
        "interface": iface,
        "pid": proc.pid,
        "message": f"Захват начат на {duration}s. Используй /capture/analyze-latest для анализа после завершения.",
    }


@app.post("/capture/analyze-latest", response_model=AnalysisResult)
async def analyze_latest_capture():
    """Проанализировать последний захваченный PCAP из PCAP_DIR"""
    pcap_files = sorted(glob.glob(os.path.join(settings.PCAP_DIR, "*.pcap")), key=os.path.getmtime, reverse=True)

    if not pcap_files:
        raise HTTPException(status_code=404, detail="PCAP файлы не найдены")

    latest = pcap_files[0]
    logger.info(f"Analyzing latest: {latest}")

    try:
        return await analyzer.analyze_pcap(
            latest,
            server_ip=settings.SQUAD_SERVER_IP,
            game_port=settings.SQUAD_GAME_PORT,
            query_port=settings.SQUAD_QUERY_PORT,
        )
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=_client_error_detail("Ошибка анализа", e)) from e


@app.get("/health")
async def health_check():
    """Проверка здоровья сервиса"""
    redis_ok = False
    try:
        redis_client.client.ping()
        redis_ok = True
    except Exception:
        pass

    return {
        "status": "healthy",
        "timestamp": str(datetime.now()),
        "environment": settings.ENVIRONMENT,
        "analysis_mode": settings.ANALYSIS_MODE,
        "redis": "ok" if redis_ok else "unavailable",
        "version": settings.VERSION,
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        workers=settings.WORKERS,
        reload=settings.RELOAD,
        log_level=settings.LOG_LEVEL.lower(),
    )
