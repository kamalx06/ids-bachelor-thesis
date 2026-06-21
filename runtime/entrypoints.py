from __future__ import annotations

import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _ensure_project_root_on_path() -> None:
    root = str(ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def run_supervisor() -> None:
    """Start Web UI + IDS engine (main.py supervisor)."""
    _ensure_project_root_on_path()
    from main import main

    raise SystemExit(main())


def run_web_server() -> None:
    """Start Flask Web UI only (uni-srver.py)."""
    _ensure_project_root_on_path()
    runpy.run_path(str(ROOT / "uni-srver.py"), run_name="__main__")


def run_ids_engine() -> None:
    """Start IDS packet engine only (ids_engine.py)."""
    _ensure_project_root_on_path()
    runpy.run_path(str(ROOT / "ids_engine.py"), run_name="__main__")


def run_bootstrap_db() -> None:
    """Initialize database schema and seed data."""
    _ensure_project_root_on_path()
    from bootstrap_db import bootstrap_database

    raise SystemExit(bootstrap_database())


def run_retrain() -> None:
    """Retrain ML models from collected samples."""
    _ensure_project_root_on_path()
    from ai.retrainer import main

    raise SystemExit(main())
