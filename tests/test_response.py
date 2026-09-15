"""Testes do M5 — Resposta orientada por ML."""

from siadar.capture.live import Flow
from siadar.quarantine.quarantine import QuarantineManager
from siadar.response.ml_response import ResponseEngine, ResponseLevel


def _sample_flow(src_ip: str = "203.0.113.5") -> Flow:
    return Flow(
        src_ip=src_ip, dst_ip="10.0.0.2", packet_count=40, byte_count=4096, first_seen=0.0, last_seen=1.0
    )


def _engine(tmp_path) -> ResponseEngine:
    manager = QuarantineManager(enforce=False, state_path=tmp_path / "quarantine_state.json")
    return ResponseEngine(quarantine_manager=manager)


def test_benign_with_no_anomaly_score_is_logged(tmp_path):
    decision = _engine(tmp_path).decide(_sample_flow(), label="BENIGN", anomaly_score=None)
    assert decision.level is ResponseLevel.LOG


def test_mild_anomaly_score_triggers_alert(tmp_path):
    decision = _engine(tmp_path).decide(_sample_flow(), label="BENIGN", anomaly_score=-0.08)
    assert decision.level is ResponseLevel.ALERT


def test_severe_anomaly_score_triggers_quarantine(tmp_path):
    decision = _engine(tmp_path).decide(_sample_flow(), label="BENIGN", anomaly_score=-0.3)
    assert decision.level is ResponseLevel.QUARANTINE


def test_high_severity_family_triggers_quarantine_regardless_of_score(tmp_path):
    decision = _engine(tmp_path).decide(_sample_flow(), label="DDoS", anomaly_score=0.9)
    assert decision.level is ResponseLevel.QUARANTINE


def test_handle_anomaly_actually_quarantines_the_ip(tmp_path):
    engine = _engine(tmp_path)
    flow = _sample_flow()

    engine.handle_anomaly(flow, label="DDoS", anomaly_score=None)

    assert engine.quarantine_manager.is_quarantined(flow.src_ip) is True
