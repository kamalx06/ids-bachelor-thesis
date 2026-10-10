"""
Custom build commands for the Enterprise AI IDS platform.

All package metadata lives in pyproject.toml. This file exists only because
`cmdclass` — the mechanism for registering custom `python setup.py ...`
commands — has no pyproject.toml equivalent. When setuptools finds both
files, static metadata comes from pyproject.toml and this module is only
consulted for cmdclass.

    python setup.py bootstrap_db

is equivalent to:

    ai-ids-bootstrap-db

and initializes the MySQL/SQLAlchemy/SQLite schemas without a full install.
"""

from __future__ import annotations

import pathlib
import sys
from typing import Sequence

from setuptools import Command, setup

ROOT = pathlib.Path(__file__).resolve().parent


def _bootstrap_database_best_effort() -> int:
    """Run the centralized, idempotent database bootstrap."""
    root = str(ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from bootstrap_db import bootstrap_database

    return bootstrap_database()


class BootstrapDatabaseCommand(Command):
    """python setup.py bootstrap_db"""

    description = "Initialize MySQL/SQLAlchemy/SQLite schemas (bootstrap_db.py)"
    user_options: list[tuple[str, str, str]] = []

    def initialize_options(self) -> None:
        pass

    def finalize_options(self) -> None:
        pass

    def run(self) -> None:
        rc = _bootstrap_database_best_effort()
        if rc != 0:
            raise SystemExit(rc)


# NOTE: DB bootstrap intentionally runs only via the explicit
# `bootstrap_db` command / `ai-ids-bootstrap-db` entry point. Running it
# from install/develop breaks `pip install -e .` when MySQL is not yet
# configured or unreachable.

setup(
    cmdclass={"bootstrap_db": BootstrapDatabaseCommand},
)