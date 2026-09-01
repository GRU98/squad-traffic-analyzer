"""Pytest bootstrap.

Puts app/ on sys.path (the app uses flat imports, e.g. `from config import
settings`) and points DATABASE_URL at an isolated tmp sqlite file before any
app module is imported — database.py creates the DB directory and engine as
import-time side effects, so this must happen first and land outside the repo.
"""
import os
import sys
import tempfile
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP_DIR))

_tmp_dir = tempfile.mkdtemp(prefix="squad-traffic-analyzer-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp_dir}/nested/test.db"
os.environ["ENVIRONMENT"] = "development"
