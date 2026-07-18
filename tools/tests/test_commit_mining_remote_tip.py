"""Tests for the local-git-only commit-mining credit when the audit pin is the
remote default-branch tip (forward-mining provably vacuous), and the artifact-
selection fix. Network is NOT exercised (the remote-tip helper is monkeypatched
/ tested via its fail-closed paths)."""
import importlib.util
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "readme-step-integrity.py"
_spec = importlib.util.spec_from_file_location("rsi", _MOD)
rsi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rsi)


def test_pin_is_remote_tip_failclosed_no_repo():
    assert rsi._pin_is_remote_tip({}) is False
    assert rsi._pin_is_remote_tip({"upstream_repo": "owner/name"}) is False  # no pin
    assert rsi._pin_is_remote_tip({"audit_pin_sha": "abc"}) is False  # no repo


def _mining(ws, **fields):
    d = (ws / "mining_rounds" / "2026-01-01-bidirectional-commit-mining")
    d.mkdir(parents=True, exist_ok=True)
    import json
    base = {"commits_scanned": 30, "upstream_repo": "ssvlabs/ssv-network",
            "audit_pin_sha": "9bb7b21"}
    base.update(fields)
    (d / "ssvlabs_ssv-network_solidity_git_commits_mining.json").write_text(
        json.dumps(base), encoding="utf-8")


def test_local_git_only_with_pin_at_remote_tip_is_full(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    _mining(ws, fallback_mode="local-git-only")
    monkeypatch.setattr(rsi, "_pin_is_remote_tip", lambda d: True)
    status, reason = rsi.check_commit_mining(str(ws))
    assert status == rsi.FULL
    assert "forward-mining provably vacuous" in reason


def test_local_git_only_pin_lags_remote_is_degraded(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    _mining(ws, fallback_mode="local-git-only")
    monkeypatch.setattr(rsi, "_pin_is_remote_tip", lambda d: False)  # pin != tip
    status, reason = rsi.check_commit_mining(str(ws))
    assert status == rsi.DEGRADED
    assert "local-git-only" in reason


def test_local_git_only_zero_scanned_not_credited(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    _mining(ws, fallback_mode="local-git-only", commits_scanned=0)
    monkeypatch.setattr(rsi, "_pin_is_remote_tip", lambda d: True)
    status, _ = rsi.check_commit_mining(str(ws))
    assert status == rsi.DEGRADED  # 0 scanned never credited even if pin==tip


def test_selection_prefers_max_scanned_per_lang_over_manifest(tmp_path):
    ws = tmp_path / "ws"
    d = ws / "mining_rounds" / "r"
    d.mkdir(parents=True)
    import json
    # manifest with NO commits_scanned (the false "0 scanned" trap)
    (d / "commit_mining_manifest.json").write_text(json.dumps({"rounds": 1}), encoding="utf-8")
    # per-lang artifact (prefixed name) with real commits + gh auth
    (d / "ssvlabs_ssv-network_solidity_git_commits_mining.json").write_text(
        json.dumps({"commits_scanned": 42, "security_fix_count": 3}), encoding="utf-8")
    status, reason = rsi.check_commit_mining(str(ws))
    assert status == rsi.FULL
    assert "42" in reason
