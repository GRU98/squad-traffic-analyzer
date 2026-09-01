"""APScheduler-планировщик для автоматического захвата и анализа трафика (continuous/scheduled режимы)."""

import asyncio
import subprocess
import logging
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from config import settings
from analyzer import TrafficAnalyzer

logger = logging.getLogger(__name__)


class AnalysisScheduler:
    """Планировщик для автоматического анализа трафика"""
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.analyzer = TrafficAnalyzer()
        self.is_running = False
        
    async def capture_and_analyze(self):
        """Захватить трафик и проанализировать"""
        try:
            logger.info("Starting automatic traffic capture...")
            
            # Захват трафика
            pcap_file = f"/app/pcap_captures/auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            
            capture_cmd = [
                "tcpdump",
                "-i", settings.CAPTURE_INTERFACE,
                "-w", pcap_file,
                "-G", str(settings.CAPTURE_DURATION_SECONDS),
                "-W", "1",
                f"udp port {settings.SQUAD_GAME_PORT} or udp port {settings.SQUAD_QUERY_PORT}"
            ]
            
            process = subprocess.run(
                capture_cmd,
                capture_output=True,
                timeout=settings.CAPTURE_DURATION_SECONDS + 10
            )
            
            if process.returncode != 0:
                logger.error(f"Capture failed: {process.stderr.decode()}")
                return
            
            logger.info(f"Captured traffic to {pcap_file}")
            
            # Анализ
            result = await self.analyzer.analyze_pcap(
                pcap_file,
                server_ip=settings.SQUAD_SERVER_IP,
                game_port=settings.SQUAD_GAME_PORT,
                query_port=settings.SQUAD_QUERY_PORT
            )
            
            logger.info(f"Analysis completed: {result.analysis_id}, risk: {result.risk_score:.2f}")
            
            # Отправить уведомления если есть аномалии
            if result.is_under_attack:
                await self.send_alert(result)
                
        except Exception as e:
            logger.error(f"Capture and analyze failed: {e}")
    
    async def send_alert(self, result):
        """Залогировать предупреждение об атаке.

        Не реализовано: не отправляет Telegram/Email/Webhook — эти каналы
        уже задействованы отдельно, через notifications.notifier внутри
        TrafficAnalyzer.analyze_pcap, которую вызывает capture_and_analyze.
        """
        logger.warning(f"⚠️ ALERT: Server under attack! Risk: {result.risk_score:.2f}")
    
    def start_continuous_mode(self):
        """Запустить непрерывный мониторинг"""
        logger.info(f"Starting continuous mode, interval: {settings.CONTINUOUS_INTERVAL_SECONDS}s")
        
        self.scheduler.add_job(
            self.capture_and_analyze,
            trigger=IntervalTrigger(seconds=settings.CONTINUOUS_INTERVAL_SECONDS),
            id='continuous_analysis',
            replace_existing=True
        )
        
        self.scheduler.start()
        self.is_running = True
    
    def start_scheduled_mode(self):
        """Запустить по расписанию (cron)"""
        logger.info(f"Starting scheduled mode, cron: {settings.SCHEDULED_CRON}")
        
        self.scheduler.add_job(
            self.capture_and_analyze,
            trigger=CronTrigger.from_crontab(settings.SCHEDULED_CRON),
            id='scheduled_analysis',
            replace_existing=True
        )
        
        self.scheduler.start()
        self.is_running = True
    
    def stop(self):
        """Остановить планировщик"""
        if self.is_running:
            self.scheduler.shutdown()
            self.is_running = False
            logger.info("Scheduler stopped")


# Глобальный экземпляр
scheduler = AnalysisScheduler()


async def start_scheduler():
    """Запустить планировщик согласно настройкам"""
    if not settings.AUTO_CAPTURE_ENABLED:
        logger.info("Auto capture disabled")
        return
    
    mode = settings.ANALYSIS_MODE.lower()
    
    if mode == "continuous":
        scheduler.start_continuous_mode()
    elif mode == "scheduled":
        scheduler.start_scheduled_mode()
    elif mode == "manual":
        logger.info("Manual mode - no automatic capture")
    else:
        logger.warning(f"Unknown analysis mode: {mode}")


async def stop_scheduler():
    """Остановить планировщик"""
    scheduler.stop()
