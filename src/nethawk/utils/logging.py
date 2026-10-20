"""Minimal application logging (console + rotating-free file log)."""
from __future__ import annotations

import logging

from .. import config


def get_logger(name: str = "nethawk", verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    config.ensure_directories()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    formatter = logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
                                  datefmt="%Y-%m-%d %H:%M:%S")
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    file_handler = logging.FileHandler(config.LOG_PATH)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger
