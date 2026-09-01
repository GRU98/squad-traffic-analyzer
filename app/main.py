"""FastAPI-приложение: HTTP-эндпоинты для анализа трафика Squad-сервера, история и статистика."""

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import uvicorn
import os
import tempfile
import logging

from analyzer import TrafficAnalyzer
from models import AnalysisResult
from database import init_db, get_db, AnalysisRecord
from redis_client import RedisClient
from config import settings

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.APP_NAME,
    description="Анализ сетевого трафика Squad сервера с детекцией аномалий через эвристики и ML",
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    version=settings.VERSION
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_key_middleware(request, call_next):
    """Требовать заголовок X-API-Key (или query-параметр api_key), кроме путей из skip_paths."""
    if settings.API_KEY_ENABLED:
        skip_paths = ["/health", "/docs", "/redoc", "/openapi.json"]
        if request.url.path not in skip_paths:
            api_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
            if api_key != settings.API_KEY:
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=403, content={"detail": "Invalid or missing API Key"})
    return await call_next(request)

analyzer = TrafficAnalyzer()
redis_client = RedisClient()


@app.on_event("startup")
async def startup_event():
    logger.info("Initializing database...")
    init_db()
    logger.info("Application started successfully")
    
    # Start scheduler if enabled
    if settings.AUTO_CAPTURE_ENABLED:
        from scheduler import start_scheduler
        await start_scheduler()
        logger.info(f"Scheduler started in {settings.ANALYSIS_MODE} mode")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down application...")
    if settings.AUTO_CAPTURE_ENABLED:
        from scheduler import stop_scheduler
        await stop_scheduler()


@app.get("/")
async def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.VERSION,
        "status": "running"
    }


@app.post("/analyze/upload", response_model=AnalysisResult)
async def analyze_pcap_upload(
    file: UploadFile = File(...),
    server_ip: Optional[str] = None,
    game_port: int = settings.SQUAD_GAME_PORT,
    query_port: int = settings.SQUAD_QUERY_PORT
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
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Файл должен быть в формате PCAP или PCAPNG")
    
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = tmp_file.name
        
        logger.info(f"Analyzing uploaded file: {file.filename} ({len(content)} bytes)")
        
        result = await analyzer.analyze_pcap(tmp_path, server_ip, game_port, query_port)
        
        os.unlink(tmp_path)
        
        return result
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(status_code=500, detail=f"Ошибка анализа: {str(e)}")


@app.post("/analyze/path")
async def analyze_pcap_path(
    pcap_path: str,
    server_ip: Optional[str] = None,
    game_port: int = settings.SQUAD_GAME_PORT,
    query_port: int = settings.SQUAD_QUERY_PORT
):
    """
    Анализировать PCAP файл по пути на сервере
    """
    if not os.path.exists(pcap_path):
        raise HTTPException(status_code=404, detail="PCAP файл не найден")
    
    try:
        result = await analyzer.analyze_pcap(pcap_path, server_ip, game_port, query_port)
        return result
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка анализа: {str(e)}")


@app.get("/history", response_model=List[dict])
async def get_analysis_history(
    limit: int = 10,
    db: Session = Depends(get_db)
):
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
            "is_under_attack": r.is_under_attack
        }
        for r in records
    ]


@app.get("/analysis/{analysis_id}", response_model=dict)
async def get_analysis_details(
    analysis_id: str,
    db: Session = Depends(get_db)
):
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
        "is_under_attack": record.is_under_attack
    }


@app.get("/stats/realtime")
async def get_realtime_stats():
    """
    Получить статистику в реальном времени из Redis
    """
    recent_stats = redis_client.get_recent_stats(hours=1)
    recent_anomalies = redis_client.get_recent_anomalies(limit=10)
    
    return {
        "recent_stats": recent_stats,
        "recent_anomalies": recent_anomalies
    }


@app.get("/stats/summary")
async def get_summary_stats(db: Session = Depends(get_db)):
    """
    Получить сводную статистику
    """
    total_analyses = db.query(AnalysisRecord).count()
    attacks_detected = db.query(AnalysisRecord).filter(AnalysisRecord.is_under_attack == True).count()
    
    recent = db.query(AnalysisRecord).order_by(AnalysisRecord.timestamp.desc()).limit(10).all()
    
    avg_risk = sum(r.risk_score for r in recent) / len(recent) if recent else 0
    
    return {
        "total_analyses": total_analyses,
        "attacks_detected": attacks_detected,
        "average_risk_score": avg_risk,
        "recent_analyses_count": len(recent)
    }


@app.delete("/cleanup")
async def cleanup_old_data():
    """Очистить старые данные из Redis и PCAP файлы"""
    try:
        redis_client.cleanup_old_data()
        
        if settings.PCAP_RETENTION_DAYS > 0:
            import glob
            import time
            pcap_dir = "/app/pcap_captures"
            cutoff = time.time() - (settings.PCAP_RETENTION_DAYS * 86400)
            deleted = 0
            for f in glob.glob(f"{pcap_dir}/*.pcap"):
                if os.path.getmtime(f) < cutoff:
                    os.remove(f)
                    deleted += 1
            return {"status": "success", "message": f"Очищено. Удалено PCAP файлов: {deleted}"}
        
        return {"status": "success", "message": "Старые данные очищены"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
    duration: int = 60,
    interface: Optional[str] = None
):
    """Запустить ручной захват трафика"""
    import subprocess
    
    iface = interface or settings.CAPTURE_INTERFACE
    pcap_file = f"/app/pcap_captures/manual_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    
    try:
        cmd = [
            "tcpdump", "-i", iface, "-w", pcap_file,
            "-G", str(duration), "-W", "1",
            f"udp port {settings.SQUAD_GAME_PORT} or udp port {settings.SQUAD_QUERY_PORT}"
        ]
        proc = subprocess.Popen(cmd)
        
        return {
            "status": "started",
            "pcap_file": pcap_file,
            "duration": duration,
            "interface": iface,
            "pid": proc.pid,
            "message": f"Захват начат на {duration}s. Используй /capture/analyze для анализа после завершения."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/capture/analyze-latest")
async def analyze_latest_capture():
    """Проанализировать последний захваченный PCAP"""
    import glob
    
    pcap_files = sorted(glob.glob("/app/pcap_captures/*.pcap"), key=os.path.getmtime, reverse=True)
    
    if not pcap_files:
        raise HTTPException(status_code=404, detail="PCAP файлы не найдены")
    
    latest = pcap_files[0]
    logger.info(f"Analyzing latest: {latest}")
    
    try:
        result = await analyzer.analyze_pcap(
            latest,
            server_ip=settings.SQUAD_SERVER_IP,
            game_port=settings.SQUAD_GAME_PORT,
            query_port=settings.SQUAD_QUERY_PORT
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
        "version": settings.VERSION
    }


if __name__ == "__main__":
    import logging
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        workers=settings.WORKERS,
        reload=settings.RELOAD,
        log_level=settings.LOG_LEVEL.lower()
    )
