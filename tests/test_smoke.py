"""Testes de fumaça — garantem que a estrutura do projeto e os imports básicos funcionam."""

from pathlib import Path

from siadar.anomaly.detector import AnomalyDetector
from siadar.capture.live import Flow, FlowAggregator
from siadar.triage.classifier import ATTACK_FAMILIES, TrafficClassifier

_NONEXISTENT_MODEL = Path("/nonexistent-model.joblib")


def _sample_flow() -> Flow:
    return Flow(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        packet_count=40,
        byte_count=4096,
        first_seen=0.0,
        last_seen=1.0,
    )


def test_classifier_stub_defaults_to_benign():
    classifier = TrafficClassifier(model_path=_NONEXISTENT_MODEL)
    assert classifier.classify(_sample_flow()) == "BENIGN"


def test_attack_families_includes_benign():
    assert "BENIGN" in ATTACK_FAMILIES
    assert len(ATTACK_FAMILIES) == 10  # BENIGN + 9 famílias de ataque


def test_anomaly_detector_stub_defaults_to_false():
    detector = AnomalyDetector(model_path=_NONEXISTENT_MODEL)
    assert detector.is_anomalous(_sample_flow()) is False


def test_flow_aggregator_starts_empty():
    aggregator = FlowAggregator(window_seconds=60)
    assert aggregator.pop_window() == []
