"""
M3 — Anomalia: sinaliza comportamento fora do padrão mesmo sem rótulo prévio,
usando Isolation Forest.
"""

from __future__ import annotations

from pathlib import Path

import joblib

DEFAULT_MODEL_PATH = Path(__file__).parent / "model.joblib"


class AnomalyDetector:
    """Wrapper em torno de um IsolationForest treinado offline sobre tráfego normal."""

    def __init__(self, model_path: Path = DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self._model = None
        if model_path.exists():
            self._model = joblib.load(model_path)

    def score(self, flow) -> float | None:
        """
        Score contínuo do Isolation Forest (decision_function): quanto mais negativo,
        mais anômalo. Retorna None quando não há modelo treinado carregado — usado
        pelo M5 para graduar a resposta em vez de reagir a um sinal binário.
        """
        if self._model is None:
            return None
        features = self._extract_features(flow)
        return float(self._model.decision_function([features])[0])

    def is_anomalous(self, flow) -> bool:
        score = self.score(flow)
        if score is None:
            # Sem modelo treinado carregado ainda — modo stub para desenvolvimento.
            return False
        return score < 0

    @staticmethod
    def _extract_features(flow) -> list[float]:
        duration = max(flow.last_seen - flow.first_seen, 1e-6)
        return [
            flow.packet_count,
            flow.byte_count,
            flow.byte_count / duration,
        ]
