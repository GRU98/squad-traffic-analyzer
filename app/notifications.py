"""Рассылка алертов по каналам Telegram / Webhook / Email на основе результата анализа."""

import logging
import aiohttp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

from config import settings
from models import AnalysisResult

logger = logging.getLogger(__name__)


class NotificationService:
    """Сервис уведомлений об аномалиях"""

    async def send_alert(self, result: AnalysisResult):
        """Отправить уведомление по всем включённым каналам.

        Пропускает отправку, если is_under_attack не выставлен и risk_score < 0.5.
        Каналы (`tasks`) вызываются последовательно, не через asyncio.gather —
        сбой или задержка одного канала не мешает следующему, но и не
        ускоряет рассылку параллелизмом.
        """
        if not result.is_under_attack and result.risk_score < 0.5:
            return

        message = self._build_message(result)

        tasks = []
        if settings.TELEGRAM_ENABLED and settings.TELEGRAM_BOT_TOKEN:
            tasks.append(self._send_telegram(message))
        if settings.WEBHOOK_ENABLED and settings.WEBHOOK_URL:
            tasks.append(self._send_webhook(result))
        if settings.EMAIL_ENABLED and settings.EMAIL_FROM:
            tasks.append(self._send_email(message, result))

        for task in tasks:
            try:
                await task
            except Exception as e:
                logger.error(f"Notification failed: {e}")

    def _build_message(self, result: AnalysisResult) -> str:
        """Собрать текстовое сообщение (RU) для Telegram/Email: сводка + топ-5 аномалий + топ-3 рекомендации."""
        status = "🚨 АТАКА" if result.is_under_attack else "⚠️ АНОМАЛИЯ"
        lines = [
            f"{status} | Squad Traffic Analyzer",
            f"Risk Score: {result.risk_score:.2f}",
            f"Пакетов: {result.stats.total_packets}",
            f"Уникальных IP: {result.stats.unique_ips}",
            f"PPS: {result.stats.packets_per_second:.0f}",
            f"Аномалий: {len(result.anomalies)}",
            "",
        ]
        for anomaly in result.anomalies[:5]:
            lines.append(f"• [{anomaly.severity:.2f}] {anomaly.description}")
        if result.recommendations:
            lines.append("\nРекомендации:")
            for rec in result.recommendations[:3]:
                lines.append(f"→ {rec}")
        return "\n".join(lines)

    async def _send_telegram(self, message: str):
        """Отправить message через Telegram Bot API в TELEGRAM_CHAT_ID."""
        url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": settings.TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as resp:
                if resp.status == 200:
                    logger.info("Telegram alert sent")
                else:
                    logger.error(f"Telegram error: {resp.status}")

    async def _send_webhook(self, result: AnalysisResult):
        """POST-нуть структурированный JSON о найденных аномалиях на WEBHOOK_URL."""
        payload = {
            "event": "anomaly_detected",
            "risk_score": result.risk_score,
            "is_under_attack": result.is_under_attack,
            "anomalies_count": len(result.anomalies),
            "analysis_id": result.analysis_id,
            "timestamp": str(result.timestamp),
            "anomalies": [
                {"type": a.type, "severity": a.severity, "source_ip": a.source_ip}
                for a in result.anomalies
            ]
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(settings.WEBHOOK_URL, json=payload) as resp:
                if resp.status in (200, 201, 204):
                    logger.info("Webhook sent")
                else:
                    logger.error(f"Webhook error: {resp.status}")

    async def _send_email(self, message: str, result: AnalysisResult):
        """Отправить message по SMTP (STARTTLS) с EMAIL_FROM на EMAIL_TO."""
        msg = MIMEMultipart()
        msg["From"] = settings.EMAIL_FROM
        msg["To"] = settings.EMAIL_TO
        msg["Subject"] = f"[Squad Analyzer] {'АТАКА' if result.is_under_attack else 'Аномалия'} Risk={result.risk_score:.2f}"
        msg.attach(MIMEText(message, "plain"))

        try:
            with smtplib.SMTP(settings.EMAIL_SMTP_HOST, settings.EMAIL_SMTP_PORT) as server:
                server.starttls()
                server.login(settings.EMAIL_FROM, settings.EMAIL_PASSWORD)
                server.sendmail(settings.EMAIL_FROM, settings.EMAIL_TO, msg.as_string())
                logger.info("Email alert sent")
        except Exception as e:
            logger.error(f"Email failed: {e}")


notifier = NotificationService()
