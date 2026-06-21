"""
Installation and distribution for the Enterprise AI IDS platform.

After install:
  ai-ids              — supervisor (Web UI + IDS engine)
  ai-ids-web          — Flask dashboard only
  ai-ids-engine       — IDS sensor only
  ai-ids-bootstrap-db — database schema bootstrap
  ai-ids-retrain      — model retraining CLI

  python setup.py bootstrap_db   — same as ai-ids-bootstrap-db (no full install required)
"""

from __future__ import annotations

import pathlib
import sys
from typing import Sequence

from setuptools import Command, find_packages, setup

ROOT = pathlib.Path(__file__).resolve().parent

# Application packages (flat layout under project root)
PACKAGE_NAMES: Sequence[str] = (
    "ai",
    "alerts",
    "api_client",
    "engine",
    "ids",
    "intelligence",
    "runtime",
    "storage",
)


def _read_requirements() -> list[str]:
    req_path = ROOT / "requirements.txt"
    if not req_path.exists():
        return []
    lines: list[str] = []
    for raw in req_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def _read_long_description() -> str:
    for name in ("README.md", "README.rst"):
        path = ROOT / name
        if path.is_file():
            return path.read_text(encoding="utf-8")
    return (
        "Enterprise AI IDS — modular intrusion detection with Flask dashboard, "
        "MySQL persistence, and scikit-learn models."
    )


def _discover_packages() -> list[str]:
    found = set(find_packages(where=str(ROOT), exclude=["tests", "tests.*"]))
    for name in PACKAGE_NAMES:
        if (ROOT / name).is_dir():
            found.add(name)
    return sorted(found)


def _bootstrap_database_best_effort() -> int:
    """Run centralized bootstrap (idempotent)."""
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


try:
    from setuptools.command.develop import develop as _develop

    class DevelopWithBootstrap(_develop):
        def run(self) -> None:
            super().run()
            _bootstrap_database_best_effort()

except ImportError:
    DevelopWithBootstrap = None


try:
    from setuptools.command.install import install as _install

    class InstallWithBootstrap(_install):
        def run(self) -> None:
            super().run()
            _bootstrap_database_best_effort()

except ImportError:
    InstallWithBootstrap = None


requirements = _read_requirements()
packages = _discover_packages()

cmdclass: dict = {
    "bootstrap_db": BootstrapDatabaseCommand,
}
if InstallWithBootstrap is not None:
    cmdclass["install"] = InstallWithBootstrap
if DevelopWithBootstrap is not None:
    cmdclass["develop"] = DevelopWithBootstrap

setup(
    name="ai-ids",
    version="1.1.0",
    description="Enterprise AI Intrusion Detection System with Web dashboard and ML pipeline",
    long_description=_read_long_description(),
    long_description_content_type="text/markdown",
    author="Kamal Khalilov",
    license="Proprietary",
    python_requires=">=3.10,<3.14",
    packages=packages,
    package_dir={"": "."},
    include_package_data=True,
    package_data={
        "": [],
    },
    data_files=[
        (
            "share/ai-ids/sql",
            [str(ROOT / "scripts" / "sql" / "migrate_ids_schema.sql")],
        ),
    ],
    install_requires=requirements,
    extras_require={
        "dev": ["pytest"],
    },
    entry_points={
        "console_scripts": [
            "ai-ids=runtime.entrypoints:run_supervisor",
            "ai-ids-web=runtime.entrypoints:run_web_server",
            "ai-ids-engine=runtime.entrypoints:run_ids_engine",
            "ai-ids-bootstrap-db=runtime.entrypoints:run_bootstrap_db",
            "ai-ids-retrain=runtime.entrypoints:run_retrain",
        ],
    },
    cmdclass=cmdclass,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
    ],
    keywords="ids intrusion-detection flask machine-learning security",
    project_urls={
        "Source": "https://github.com/kamalx06/ids-bachelor-thesis",
    },
)
