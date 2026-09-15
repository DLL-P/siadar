"""
Configuração central de logging do SIADAR.

Todos os módulos usam `get_logger(__name__)` em vez de `print()` — isso permite
redirecionar a saída (arquivo, syslog, etc.), filtrar por nível, e é considerado
prática padrão para qualquer coisa além de um script descartável.
"""

from __future__ import annotations

import logging
import os

_CONFIGURED = False


def _configure_root() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    level_name = os.environ.get("SIADAR_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Retorna um logger configurado para o módulo chamador (`get_logger(__name__)`)."""
    _configure_root()
    return logging.getLogger(name)
