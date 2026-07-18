"""Tests for the function-coverage mutation-reader discovery widening: it must
read durable mutation sidecars under BOTH .auditooor/cross-function-coverage/ AND
.auditooor/mvc_sidecar/ with a '*.json' glob (operator-named, not only
'mutation*.json') - mirroring the sibling readers core-coverage:354 +
cross-function:1012. Discovery only; the kill-required bar is unchanged."""
import importlib.util
import json
import sys
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "function-coverage-completeness.py"
_spec = importlib.util.spec_from_file_location("fcc", _MOD)
fcc = importlib.util.module_from_spec(_spec)
sys.modules["fcc"] = fcc  # dataclasses need the module registered for type resolution
_spec.loader.exec_module(fcc)


def _kill_record(ws, fn="withdraw", killed=2, mutants=3, verdict="non-vacuous"):
    return {
        "schema": "auditooor.mutation_verify_coverage.v1",
        "workspace": str(ws),
        "source_file": "src/Vault.sol",
        "function": fn,
        "function_span": [10, 20],
        "harness": f"forge test --match-path test/Halmos_Vault_{fn}.t.sol",
        "mutant_count": mutants,
        "killed_count": killed,
        "verdict": verdict,
    }


def _has_kill(by_fn, by_harness):
    return any(v == "killed" for v in {**by_fn, **by_harness}.values())


def test_mvc_sidecar_kill_discovered(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
    (ws / ".auditooor" / "mvc_sidecar" / "vault_withdraw_premade_mutant.json").write_text(
        json.dumps(_kill_record(ws)), encoding="utf-8")
    by_fn, by_harness = fcc._load_mutation_verdicts(ws, allow_live=False)
    assert _has_kill(by_fn, by_harness), "a kill recorded under mvc_sidecar/ must be credited"


def test_operator_named_in_cross_function_coverage_discovered(tmp_path):
    # operator name does NOT match the old 'mutation*.json' glob
    ws = tmp_path / "ws"
    (ws / ".auditooor" / "cross-function-coverage").mkdir(parents=True)
    (ws / ".auditooor" / "cross-function-coverage" / "liqctl_mint_premade_mutant.json").write_text(
        json.dumps(_kill_record(ws, fn="mint")), encoding="utf-8")
    by_fn, by_harness = fcc._load_mutation_verdicts(ws, allow_live=False)
    assert _has_kill(by_fn, by_harness), "operator-named sidecar (not mutation*) must be credited"


def test_vacuous_sidecar_not_credited_as_kill(tmp_path):
    # never-false-pass: a 0-kill record must NOT be credited as a kill
    ws = tmp_path / "ws"
    (ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
    (ws / ".auditooor" / "mvc_sidecar" / "vacuous.json").write_text(
        json.dumps(_kill_record(ws, killed=0, verdict="vacuous")), encoding="utf-8")
    by_fn, by_harness = fcc._load_mutation_verdicts(ws, allow_live=False)
    assert not _has_kill(by_fn, by_harness), "a 0-kill record must never be credited as killed"


def test_real_evidence_globs_cover_recursive_and_root_hunt_sidecars():
    g = fcc._REAL_EVIDENCE_GLOBS
    assert ".auditooor/hunt_findings_sidecars/**/*.json" in g
    assert "hunt_findings_sidecars/**/*.json" in g  # workspace-root variant
