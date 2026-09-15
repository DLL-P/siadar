"""Testes do M4 — Quarentena."""

from siadar.quarantine.quarantine import QuarantineAction, QuarantineManager


def _manager(tmp_path):
    return QuarantineManager(enforce=False, state_path=tmp_path / "quarantine_state.json")


def test_apply_in_dry_run_does_not_touch_firewall(tmp_path):
    manager = _manager(tmp_path)
    applied = manager.apply(QuarantineAction(ip="203.0.113.5", reason="teste"))

    assert applied is True
    assert manager.is_quarantined("203.0.113.5") is True
    assert manager.state_path.exists()


def test_never_quarantine_list_is_respected(tmp_path):
    manager = _manager(tmp_path)
    applied = manager.apply(QuarantineAction(ip="127.0.0.1", reason="jamais isso"))

    assert applied is False
    assert manager.is_quarantined("127.0.0.1") is False


def test_duplicate_apply_is_ignored(tmp_path):
    manager = _manager(tmp_path)
    manager.apply(QuarantineAction(ip="203.0.113.5", reason="primeira vez"))
    applied_again = manager.apply(QuarantineAction(ip="203.0.113.5", reason="segunda vez"))

    assert applied_again is False


def test_release_removes_ip(tmp_path):
    manager = _manager(tmp_path)
    manager.apply(QuarantineAction(ip="203.0.113.5", reason="teste"))
    manager.release("203.0.113.5")

    assert manager.is_quarantined("203.0.113.5") is False


def test_state_persists_across_instances(tmp_path):
    state_path = tmp_path / "quarantine_state.json"
    QuarantineManager(enforce=False, state_path=state_path).apply(
        QuarantineAction(ip="203.0.113.9", reason="persistência")
    )

    reloaded = QuarantineManager(enforce=False, state_path=state_path)
    assert reloaded.is_quarantined("203.0.113.9") is True
