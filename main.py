"""
Enterprise AI IDS — application entry point (process supervisor).

Runs database bootstrap, checks AI models, then starts up to three separate
OS processes:
  1. ids_engine.py       — packet capture / AI / persistence
  2. uni-srver.py        — Flask Web UI / dashboard
  3. ssl_inspect/engine  — optional TLS interceptor (mitmproxy)

The SSL interceptor is only started when SSL_DECRYPTION_ENABLED=true.

If the IDS engine crashes, the Web UI keeps running and the dashboard
shows OFFLINE. If the SSL interceptor crashes, the rest of the stack is
unaffected; decrypted traffic analysis pauses until it restarts.

Usage:
  python main.py              # recommended: Web UI + IDS (+ SSL if enabled)
  python ids_engine.py        # IDS only
  python uni-srver.py         # Web UI only (optional IDS via WEBUI_START_IDS_SENSOR)
  python -m ssl_inspect.engine  # SSL interceptor only
  python bootstrap_db.py      # database setup only
"""

from __future__ import annotations

import sys

from ai.retrainer import ensure_models_available
from bootstrap_db import bootstrap_database
from logging_config import get_logger
from runtime.process_supervisor import ProcessSupervisor

logger = get_logger(__name__)


def main() -> int:
    logger.info("Bootstrapping database before starting services...")
    rc = bootstrap_database()
    if rc != 0:
        logger.error("Database bootstrap failed (exit=%s)", rc)
        return rc

    # Neither uni-srver.py nor ids_engine.py can do useful work without a
    # trained classifier (ai.classifier fails hard on missing rf/scaler
    # models), so check -- and bootstrap-train from the CIC-IDS CSV if
    # needed -- before either process is started, not after.
    logger.info("Checking AI models before starting uni-srver.py and ids_engine.py...")
    if not ensure_models_available():
        logger.error("AI models are not available and could not be trained — not starting services.")
        return 1

    supervisor = ProcessSupervisor()
    return supervisor.run_forever()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
