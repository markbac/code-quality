'''
pylogkit/log_setup.py
---------------------
Integrated Py-LogKit Logging Module with colorlog & standard fallback support.
'''

import logging
import os
import sys
import json
import time
import socket
import threading
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler, SysLogHandler
from typing import Optional, Dict, Any
from functools import wraps

try:
    import colorlog
except ImportError:
    colorlog = None

try:
    from pythonjsonlogger import jsonlogger
except ImportError:
    jsonlogger = None

_log_context = threading.local()

def set_log_context(**kwargs):
    _log_context.data = kwargs

def clear_log_context():
    _log_context.data = {}

def get_log_context() -> Dict[str, Any]:
    context = getattr(_log_context, 'data', {}).copy()
    context.setdefault("user_id", "-")
    context.setdefault("session_id", "-")
    context.setdefault("request_id", "-")
    context.setdefault("hostname", socket.gethostname())
    context.setdefault("env", os.getenv("APP_ENV", "dev"))
    context.setdefault("pid", os.getpid())
    return context

if colorlog:
    class SmartFieldFormatter(colorlog.ColoredFormatter):
        def format(self, record):
            for key in ["user_id", "session_id", "request_id", "hostname", "env", "pid"]:
                if not hasattr(record, key):
                    setattr(record, key, "")

            field_map = {
                "user_id": record.user_id,
                "session_id": record.session_id,
                "request_id": record.request_id,
                "hostname": record.hostname,
                "env": record.env,
                "pid": record.pid
            }

            dynamic_fields = []
            for k, v in field_map.items():
                if v and v != "-":
                    dynamic_fields.append(f"[{k}={v}]")

            record.context = " ".join(dynamic_fields)
            return super().format(record)
else:
    class SmartFieldFormatter(logging.Formatter):
        def format(self, record):
            record.context = ""
            return super().format(record)

class ContextFilter(logging.Filter):
    def filter(self, record):
        context = get_log_context()
        for k, v in context.items():
            setattr(record, k, v)
        # Omit emojis if running on Windows stdout without UTF-8 to prevent charmap errors
        is_win = sys.platform.startswith("win")
        emoji_map = {
            'DEBUG': '' if is_win else '🐛',
            'INFO': '' if is_win else 'ℹ️',
            'WARNING': '' if is_win else '⚠️',
            'ERROR': '' if is_win else '❌',
            'CRITICAL': '' if is_win else '💥',
            'SYSTEM': '' if is_win else '🖥️',
            'NETWORK': '' if is_win else '🌐',
            'DATABASE': '' if is_win else '🗄️',
            'STARTUP': '' if is_win else '🚀',
            'SHUTDOWN': '' if is_win else '🛑'
        }
        setattr(record, 'emoji', emoji_map.get(record.levelname, ''))
        return True

class ContextualLoggerAdapter(logging.LoggerAdapter):
    def __init__(self, logger):
        super().__init__(logger, {})

    def process(self, msg, kwargs):
        context = get_log_context()
        kwargs.setdefault("extra", {}).update(context)
        return msg, kwargs

    def with_context(self, **context):
        prev_context = get_log_context().copy()
        combined_context = prev_context.copy()
        combined_context.update(context)
        set_log_context(**combined_context)
        return self

def setup_logging(name: Optional[str] = "QuectelDashboard",
                  overwrite: bool = False,
                  to_console: bool = True,
                  to_file: bool = True,
                  file_path: Optional[str] = "dashboard_serial.log",
                  level: str = "INFO",
                  mode: str = "verbose",
                  rotation: str = "size",
                  max_bytes: int = 10*1024*1024,
                  backup_count: int = 3,
                  context: Optional[dict] = None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.addFilter(ContextFilter())

    if context:
        set_log_context(**context)

    log_format = "%(asctime)s [%(levelname)s %(emoji)s] [%(name)s] - %(message)s"

    if colorlog:
        formatter = SmartFieldFormatter(
            fmt="%(asctime)s [%(log_color)s%(levelname)s %(emoji)s%(reset)s] [%(name)s] - %(log_color)s%(message)s%(reset)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors={
                'DEBUG':    'cyan',
                'INFO':     'blue',
                'WARNING':  'yellow',
                'ERROR':    'red',
                'CRITICAL': 'bold_red'
            },
            reset=True
        )
    else:
        formatter = logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")

    if to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level.upper())
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    if to_file and file_path:
        os.makedirs(os.path.dirname(file_path), exist_ok=True) if os.path.dirname(file_path) else None
        file_handler = RotatingFileHandler(file_path, maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8')
        file_handler.setLevel(level.upper())
        file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] [%(name)s] - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger
