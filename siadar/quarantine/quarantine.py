"""
M4 — Quarentena: isola automaticamente um host/IP suspeito assim que uma ameaça é
confirmada (acionado pelo M5 — Resposta).

Backend padrão: iptables (Linux). Roda em modo **dry-run por padrão** — só registra
o que faria, sem tocar no firewall de verdade — porque bloquear tráfego
automaticamente é a parte do projeto com maior potencial de causar dano real (um
falso positivo pode isolar um host legítimo, ou até a própria máquina). Passe
`enforce=True` conscientemente para de fato aplicar as regras.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from siadar.logging_config import get_logger

logger = get_logger(__name__)

STATE_PATH = Path(__file__).parent.parent.parent / "data" / "quarantine_state.json"

# IPs que nunca devem ser colocados em quarentena automaticamente, independente do
# que os modelos digam. Ajuste para incluir seu gateway, DNS local, etc.
NEVER_QUARANTINE = {"127.0.0.1", "0.0.0.0"}

DEFAULT_TTL = timedelta(hours=1)


@dataclass
class QuarantineAction:
    """Representa uma ação de quarentena a ser aplicada a um IP suspeito."""

    ip: str
    reason: str
    ttl: timedelta = DEFAULT_TTL


class QuarantineManager:
    """
    Aplica, rastreia e libera quarentenas de IP.

    Por padrão roda em modo dry-run (`enforce=False`): só loga e persiste o estado
    em `data/quarantine_state.json`, sem alterar o firewall de verdade.
    """

    def __init__(self, enforce: bool = False, state_path: Path = STATE_PATH):
        self.enforce = enforce
        self.state_path = state_path
        self._state: dict[str, dict] = self._load_state()

    # -- ciclo de vida ----------------------------------------------------

    def apply(self, action: QuarantineAction) -> bool:
        """Coloca um IP em quarentena. Retorna True se uma nova regra foi (ou seria) aplicada."""
        if action.ip in NEVER_QUARANTINE:
            logger.warning("ignorado — %s está na lista de exclusão (NEVER_QUARANTINE)", action.ip)
            return False

        if self.is_quarantined(action.ip):
            logger.debug("%s já está em quarentena, ignorando duplicata", action.ip)
            return False

        expires_at = datetime.now(timezone.utc) + action.ttl
        self._state[action.ip] = {
            "reason": action.reason,
            "applied_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
            "enforced": self.enforce,
        }
        self._save_state()

        if self.enforce:
            self._block_with_iptables(action.ip)
            logger.warning("BLOQUEADO %s até %s — %s", action.ip, expires_at.isoformat(), action.reason)
        else:
            logger.info(
                "(dry-run) bloquearia %s até %s — %s", action.ip, expires_at.isoformat(), action.reason
            )

        return True

    def release(self, ip: str) -> None:
        """Remove um IP da quarentena, revertendo o bloqueio se estiver ativo."""
        if ip not in self._state:
            return

        if self._state[ip].get("enforced"):
            self._unblock_with_iptables(ip)

        del self._state[ip]
        self._save_state()
        logger.info("%s liberado", ip)

    def release_expired(self) -> None:
        """Libera automaticamente qualquer IP cujo TTL já tenha vencido."""
        now = datetime.now(timezone.utc)
        expired = [
            ip for ip, info in self._state.items() if datetime.fromisoformat(info["expires_at"]) <= now
        ]
        for ip in expired:
            self.release(ip)

    def is_quarantined(self, ip: str) -> bool:
        return ip in self._state

    # -- backend (iptables) ------------------------------------------------

    def _block_with_iptables(self, ip: str) -> None:
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            logger.error("falha ao aplicar regra de firewall para %s: %s", ip, exc)

    def _unblock_with_iptables(self, ip: str) -> None:
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            logger.error("falha ao remover regra de firewall para %s: %s", ip, exc)

    # -- persistência -----------------------------------------------------

    def _load_state(self) -> dict[str, dict]:
        if self.state_path.exists():
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        return {}

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self._state, indent=2, ensure_ascii=False), encoding="utf-8")
