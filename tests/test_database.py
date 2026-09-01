"""Regression tests for database.py's sqlite setup.

Found by running the app outside Docker: init_db() crashed with
"sqlite3.OperationalError: unable to open database file" whenever
DATABASE_URL pointed at a directory that didn't exist yet. The Docker image
only worked by accident, because its Dockerfile pre-creates /app/data.
"""
import os
import subprocess
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"


def _run_init_db(database_url, cwd):
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    env["PYTHONPATH"] = str(APP_DIR)
    return subprocess.run(
        [sys.executable, "-c", "from database import init_db; init_db()"],
        env=env,
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def test_init_db_creates_missing_parent_directory(tmp_path):
    db_path = tmp_path / "does" / "not" / "exist" / "test.db"

    result = _run_init_db(f"sqlite:///{db_path}", cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    assert db_path.exists()


def test_in_memory_sqlite_url_is_not_treated_as_a_directory(tmp_path):
    result = _run_init_db("sqlite://", cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "sqlite:").exists()
