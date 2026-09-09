import pytest

import scheduler as scheduler_module
from config import settings


@pytest.fixture
async def fresh_scheduler(monkeypatch):
    """Async-фикстура: остановка планировщика должна происходить, пока event loop теста ещё жив."""
    instance = scheduler_module.AnalysisScheduler()
    monkeypatch.setattr(scheduler_module, "scheduler", instance)
    yield instance
    instance.stop()


async def test_manual_mode_registers_no_jobs(fresh_scheduler, monkeypatch):
    monkeypatch.setattr(settings, "AUTO_CAPTURE_ENABLED", True)
    monkeypatch.setattr(settings, "ANALYSIS_MODE", "manual")

    await scheduler_module.start_scheduler()

    assert not fresh_scheduler.is_running


async def test_continuous_mode_registers_interval_job(fresh_scheduler, monkeypatch):
    monkeypatch.setattr(settings, "AUTO_CAPTURE_ENABLED", True)
    monkeypatch.setattr(settings, "ANALYSIS_MODE", "continuous")

    await scheduler_module.start_scheduler()

    assert fresh_scheduler.is_running
    assert fresh_scheduler.scheduler.get_job("continuous_analysis") is not None
    await scheduler_module.stop_scheduler()
    assert not fresh_scheduler.is_running


async def test_scheduled_mode_registers_cron_job(fresh_scheduler, monkeypatch):
    monkeypatch.setattr(settings, "AUTO_CAPTURE_ENABLED", True)
    monkeypatch.setattr(settings, "ANALYSIS_MODE", "scheduled")
    monkeypatch.setattr(settings, "SCHEDULED_CRON", "*/5 * * * *")

    await scheduler_module.start_scheduler()

    assert fresh_scheduler.scheduler.get_job("scheduled_analysis") is not None


async def test_capture_and_analyze_runs_tcpdump_then_analyzes(fresh_scheduler, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "PCAP_DIR", str(tmp_path / "captures"))
    monkeypatch.setattr(settings, "CAPTURE_DURATION_SECONDS", 1)
    analyzed = []

    class Done:
        returncode = 0
        stderr = b""

    def fake_run(cmd, **kwargs):
        assert cmd[0] == "tcpdump" and cmd[cmd.index("-w") + 1].startswith(str(tmp_path / "captures"))
        return Done()

    async def fake_analyze(path, **kwargs):
        analyzed.append(path)

        class R:
            analysis_id = "x"
            risk_score = 0.0
            is_under_attack = False

        return R()

    monkeypatch.setattr(scheduler_module.subprocess, "run", fake_run)
    monkeypatch.setattr(fresh_scheduler.analyzer, "analyze_pcap", fake_analyze)

    await fresh_scheduler.capture_and_analyze()

    assert len(analyzed) == 1 and (tmp_path / "captures").is_dir()


async def test_capture_failure_skips_analysis(fresh_scheduler, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "PCAP_DIR", str(tmp_path))
    analyzed = []

    class Failed:
        returncode = 1
        stderr = b"no such device"

    monkeypatch.setattr(scheduler_module.subprocess, "run", lambda cmd, **k: Failed())

    async def fake_analyze(path, **kwargs):
        analyzed.append(path)

    monkeypatch.setattr(fresh_scheduler.analyzer, "analyze_pcap", fake_analyze)

    await fresh_scheduler.capture_and_analyze()

    assert analyzed == []
