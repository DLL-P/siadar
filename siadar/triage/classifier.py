"""
M2 — Triagem: classifica o tráfego entre normal (BENIGN) e famílias de ataque conhecidas,
usando um Random Forest treinado offline.
"""

from __future__ import annotations

from pathlib import Path

import joblib

# Rótulos usados durante o treino. Ajustar conforme o dataset real usado para treinar o modelo.
ATTACK_FAMILIES = [
    "BENIGN",
    "PortScan",
    "DoS",
    "DDoS",
    "BruteForce",
    "Botnet",
    "Infiltration",
    "WebAttack",
    "Heartbleed",
    "FTP-Patator",
]

DEFAULT_MODEL_PATH = Path(__file__).parent / "model.joblib"


class TrafficClassifier:
    """Wrapper em torno de um RandomForestClassifier treinado offline."""

    def __init__(self, model_path: Path = DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self._model = None
        if model_path.exists():
            self._model = joblib.load(model_path)

    def classify(self, flow) -> str:
        if self._model is None:
            # Sem modelo treinado carregado ainda — modo stub para desenvolvimento.
            return "BENIGN"

        features = self._extract_features(flow)
        prediction = self._model.predict([features])[0]
        return prediction

    @staticmethod
    def _extract_features(flow) -> list[float]:
        """Extrai o vetor de features usado pelo modelo a partir de um Flow agregado."""
        duration = max(flow.last_seen - flow.first_seen, 1e-6)
        return [
            flow.packet_count,
            flow.byte_count,
            flow.byte_count / duration,
            len(flow.flags_seen),
        ]
