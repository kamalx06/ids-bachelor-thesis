import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key in ("worker_id", "event", "dropped", "queue_size"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, ensure_ascii=False)


def get_logger(name: str) -> logging.Logger:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    debug = (os.getenv("IDS_DEBUG", "false") or "false").lower() == "true"
    level = logging.DEBUG if debug else getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    if not root.handlers:
        root.setLevel(level)
        use_json = (os.getenv("IDS_LOG_JSON", "false") or "false").lower() == "true"

        if use_json:
            handler: logging.Handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(JsonFormatter())
        else:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
            )
        root.addHandler(handler)

        log_dir = Path(os.getenv("IDS_LOG_DIR", "logs"))
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_dir / "ids.log",
            maxBytes=int(os.getenv("IDS_LOG_MAX_BYTES", "10485760") or "10485760"),
            backupCount=int(os.getenv("IDS_LOG_BACKUP_COUNT", "5") or "5"),
        )
        if use_json:
            file_handler.setFormatter(JsonFormatter())
        else:
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
            )
        file_handler.setLevel(level)
        root.addHandler(file_handler)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger
