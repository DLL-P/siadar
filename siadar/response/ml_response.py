"""
M5 — Resposta: decide automaticamente qual ação tomar quando um flow é analisado,
combinando duas saídas dos modelos anteriores:

  - a família de ataque identificada pelo M2 — Triagem (Random Forest), quando
    diferente de BENIGN;
  - a severidade da anomalia dada pelo score contínuo do M3 — Anomalia (Isolation
    Forest) — quanto mais negativo, mais "fora da curva" o flow está.

A política (`RESPONSE_POLICY`, abaixo, via thresholds) é o que torna essa resposta
orientada por ML em vez de puramente por regra fixa: ela consome o score contínuo do
modelo de anomalia — não só um rótulo binário — para graduar a reação entre apenas
registrar, alertar, ou acionar a quarentena (M4).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from siadar.logging_config import get_logger
from siadar.quarantine.quarantine import QuarantineAction, QuarantineManager

logger = get_logger(__name__)


class ResponseLevel(str, Enum):
    LOG = "log"  # registra e segue — sem sinal relevante de ameaça
    ALERT = "alert"  # registra + alerta — merece atenção humana
    QUARANTINE = "quarantine"  # aciona o M4 e isola o host automaticamente


# Famílias de ataque graves o suficiente para acionar quarentena mesmo com um score
# de anomalia apenas moderado.
HIGH_SEVERITY_FAMILIES = {"DDoS", "DoS", "Botnet", "Infiltration"}

# Isolation Forest: quanto mais negativo o score, mais anômalo.
QUARANTINE_SCORE_THRESHOLD = -0.15
ALERT_SCORE_THRESHOLD = -0.05


@dataclass
class ResponseDecision:
    level: ResponseLevel
    reason: str


class ResponseEngine:
    """Decide e dispara a resposta automatizada para um flow analisado."""

    def __init__(self, quarantine_manager: QuarantineManager | None = None, enforce: bool = False):
        self.quarantine_manager = quarantine_manager or QuarantineManager(enforce=enforce)

    def decide(self, flow, label: str, anomaly_score: float | None) -> ResponseDecision:
        """Calcula o nível de resposta sem executar nada (útil para testar a política isolada)."""
        if label != "BENIGN" and label in HIGH_SEVERITY_FAMILIES:
            return ResponseDecision(
                level=ResponseLevel.QUARANTINE,
                reason=f"família de ataque de alta severidade: {label}",
            )

        if anomaly_score is None:
            # Sem score contínuo disponível (ex.: modelo de anomalia ainda não
            # treinado) — cai para o rótulo de triagem como sinal principal.
            if label != "BENIGN":
                return ResponseDecision(level=ResponseLevel.ALERT, reason=f"classificado como {label}")
            return ResponseDecision(level=ResponseLevel.LOG, reason="sem anomalia detectada")

        if anomaly_score <= QUARANTINE_SCORE_THRESHOLD:
            return ResponseDecision(
                level=ResponseLevel.QUARANTINE,
                reason=f"score de anomalia {anomaly_score:.3f} abaixo do limiar de quarentena",
            )
        if anomaly_score <= ALERT_SCORE_THRESHOLD:
            return ResponseDecision(
                level=ResponseLevel.ALERT,
                reason=f"score de anomalia {anomaly_score:.3f} abaixo do limiar de alerta",
            )
        return ResponseDecision(level=ResponseLevel.LOG, reason="dentro do padrão esperado")

    def handle_anomaly(
        self, flow, label: str = "BENIGN", anomaly_score: float | None = None
    ) -> ResponseDecision:
        """Decide e executa a resposta para um flow, incluindo acionar a quarentena (M4) se necessário."""
        decision = self.decide(flow, label=label, anomaly_score=anomaly_score)

        if decision.level is ResponseLevel.LOG:
            logger.debug("log        %s -> %s  |  %s", flow.src_ip, flow.dst_ip, decision.reason)
        elif decision.level is ResponseLevel.ALERT:
            logger.warning("ALERTA     %s -> %s  |  %s", flow.src_ip, flow.dst_ip, decision.reason)
        elif decision.level is ResponseLevel.QUARANTINE:
            logger.warning("QUARENTENA %s  |  %s", flow.src_ip, decision.reason)
            self.quarantine_manager.apply(QuarantineAction(ip=flow.src_ip, reason=decision.reason))

        return decision
