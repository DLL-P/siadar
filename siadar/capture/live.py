"""
M1 — Captura: agrega pacotes em flows por janela de tempo, direto da interface de rede.

Uso:
    python -m siadar.capture.live --interface eth0 --window 60
"""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass, field

try:
    from scapy.all import IP, TCP, sniff
except ImportError as exc:  # pragma: no cover
    raise SystemExit("scapy não está instalado. Rode: pip install -r requirements.txt") from exc

from siadar.anomaly.detector import AnomalyDetector
from siadar.logging_config import get_logger
from siadar.response.ml_response import ResponseEngine
from siadar.storage.db import save_flow
from siadar.triage.classifier import TrafficClassifier

logger = get_logger(__name__)


@dataclass
class Flow:
    """Representa um flow agregado (mesmo par origem/destino) dentro de uma janela de tempo."""

    src_ip: str
    dst_ip: str
    packet_count: int = 0
    byte_count: int = 0
    flags_seen: set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0


class FlowAggregator:
    """Agrega pacotes capturados em flows, por janela de tempo fixa."""

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self.flows: dict[tuple[str, str], Flow] = {}

    def add_packet(self, pkt) -> None:
        if IP not in pkt:
            return

        src, dst = pkt[IP].src, pkt[IP].dst
        key = (src, dst)
        now = time.time()

        flow = self.flows.get(key)
        if flow is None:
            flow = Flow(src_ip=src, dst_ip=dst, first_seen=now)
            self.flows[key] = flow

        flow.packet_count += 1
        flow.byte_count += len(pkt)
        flow.last_seen = now

        if TCP in pkt:
            flow.flags_seen.add(str(pkt[TCP].flags))

    def pop_window(self) -> list[Flow]:
        """Fecha a janela atual e devolve os flows acumulados, limpando o estado."""
        flows = list(self.flows.values())
        self.flows.clear()
        return flows


def run_capture(interface: str, window: int, enforce_quarantine: bool = False) -> None:
    aggregator = FlowAggregator(window_seconds=window)
    classifier = TrafficClassifier()
    detector = AnomalyDetector()
    response_engine = ResponseEngine(enforce=enforce_quarantine)

    if enforce_quarantine:
        logger.warning(
            "quarentena automática ATIVA (enforce=True) — IPs suspeitos serão bloqueados de verdade"
        )

    logger.info("capturando tráfego ao vivo em '%s'... classificando por janela de %ds", interface, window)

    window_index = 0
    while True:
        sniff(iface=interface, timeout=window, prn=aggregator.add_packet, store=False)
        window_index += 1
        flows = aggregator.pop_window()

        logger.info("[janela %d] %d flows", window_index, len(flows))
        for flow in flows:
            label = classifier.classify(flow)
            score = detector.score(flow)
            is_anomalous = detector.is_anomalous(flow)
            logger.info(
                "%s -> %s  |  %s  |  anômalo: %s",
                flow.src_ip,
                flow.dst_ip,
                label,
                "sim" if is_anomalous else "não",
            )
            save_flow(flow, label=label, anomalous=is_anomalous)

            # M5 — só aciona a política de resposta quando há algo fora do comum,
            # evitando ruído de log a cada flow benigno.
            if is_anomalous or label != "BENIGN":
                response_engine.handle_anomaly(flow, label=label, anomaly_score=score)


def main() -> None:
    parser = argparse.ArgumentParser(description="SIADAR — captura ao vivo (M1)")
    parser.add_argument("--interface", required=True, help="Interface de rede a monitorar (ex.: eth0)")
    parser.add_argument("--window", type=int, default=60, help="Janela de agregação de flows, em segundos")
    parser.add_argument(
        "--enforce-quarantine",
        action="store_true",
        help="Aplica bloqueios de firewall de verdade (M4). Por padrão roda em dry-run.",
    )
    args = parser.parse_args()

    run_capture(interface=args.interface, window=args.window, enforce_quarantine=args.enforce_quarantine)


if __name__ == "__main__":
    main()
