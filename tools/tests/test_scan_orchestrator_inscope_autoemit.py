"""Regression: workspace-scan-orchestrator auto-emits inscope_units.jsonl when
absent so a fresh multi-repo Solidity workspace does not fail the scan stage with
"no in-scope Solidity compilation input resolved" (Morpho Cantina 2026-06-26: 15
foundry repos under src/<repo>/src/, 655 .sol units; the heuristic fallback does
not recognise that layout, so the manifest resolver must self-heal by emitting)."""
import importlib.util
import sys
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "workspace-scan-orchestrator.py"
_spec = importlib.util.spec_from_file_location("wso_autoemit", _MOD)
wso = importlib.util.module_from_spec(_spec)
sys.modules["wso_autoemit"] = wso
_spec.loader.exec_module(wso)


def test_ensure_manifest_noop_when_present(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    manifest.write_text('{"file": "src/A.sol", "lang": "solidity"}\n', encoding="utf-8")
    # Present -> returns True without invoking the emitter subprocess.
    assert wso._ensure_inscope_manifest(ws) is True
    # Unchanged.
    assert manifest.read_text(encoding="utf-8").startswith('{"file": "src/A.sol"')


def test_ensure_manifest_graceful_when_emitter_missing(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    # Point HERE at an empty dir so the emitter path does not resolve -> graceful
    # False (never raises), and the manifest stays absent.
    monkeypatch.setattr(wso, "HERE", tmp_path / "no_tools")
    assert wso._ensure_inscope_manifest(ws) is False
    assert not (ws / ".auditooor" / "inscope_units.jsonl").is_file()


def test_inscope_resolver_returns_empty_without_manifest_or_emit(tmp_path, monkeypatch):
    # When the manifest is absent AND auto-emit cannot produce one, the resolver
    # returns [] (legacy contract -> caller falls back to the heuristic). Never raises.
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    monkeypatch.setattr(wso, "HERE", tmp_path / "no_tools")
    assert wso._inscope_solidity_files(ws) == []


def test_inscope_resolver_reads_manifest_when_present(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    sol = ws / "src" / "vault-v2" / "src" / "VaultV2.sol"
    sol.parent.mkdir(parents=True)
    sol.write_text("contract VaultV2 {}\n", encoding="utf-8")
    (ws / ".auditooor" / "inscope_units.jsonl").write_text(
        '{"file": "src/vault-v2/src/VaultV2.sol", "lang": "solidity"}\n', encoding="utf-8")
    files = wso._inscope_solidity_files(ws)
    assert len(files) == 1
    assert files[0].name == "VaultV2.sol"
