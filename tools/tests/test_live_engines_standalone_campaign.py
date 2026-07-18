"""Tests for the standalone coverage-guided campaign accept-path in
check_live_engines (_standalone_coverage_campaign_executed).

Serving-join fix: a real step-2c echidna(>=500k)/medusa(>=1M) campaign over the
real CUT, recorded in .auditooor/fuzz_campaign_receipt.json + corroborated by the
raw fuzz_logs + carrying a non-vacuity mutant kill, must credit the live-engines
Solidity arm even though it lives outside the solidity-deep-audit manifest. It
must NEVER false-pass a no-log / sub-threshold / vacuous / mock-CUT campaign.
"""
import importlib.util
import json
import sys
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parents[1] / "audit-completeness-check.py"
_spec = importlib.util.spec_from_file_location("audit_completeness_check", _MOD_PATH)
acc = importlib.util.module_from_spec(_spec)
sys.modules["audit_completeness_check"] = acc
_spec.loader.exec_module(acc)


def _mk_ws(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".auditooor" / "fuzz_logs").mkdir(parents=True)
    (ws / "src" / "echidna").mkdir(parents=True)
    (ws / "src" / "echidna" / "H.sol").write_text("contract H{}", encoding="utf-8")
    return ws


def _receipt(ws, **over):
    camp = {
        "name": "Solvency", "engine": "echidna",
        "harness": "src/echidna/H.sol",
        "result": {"calls": 1_000_127, "passed": 5, "failed": 0},
        "non_vacuity_kills": 2,
        "mutation_detail": [{"baseline": "PASS", "mutant_result": "FAIL"}],
    }
    camp.update(over.pop("campaign", {}))
    data = {"schema": "auditooor.fuzz_campaign_receipt.v1",
            "workspace": ws.name, "campaigns": [camp]}
    data.update(over)
    (ws / ".auditooor" / "fuzz_campaign_receipt.json").write_text(
        json.dumps(data), encoding="utf-8")


def _log(ws, calls=600_000):
    (ws / ".auditooor" / "fuzz_logs" / "c.log").write_text(
        f"[status] fuzzing\nTotal calls: {calls}\nechidna_x: passing\n", encoding="utf-8")


def test_positive_real_campaign_credits(tmp_path):
    ws = _mk_ws(tmp_path)
    _receipt(ws)
    _log(ws, 600_000)
    r = acc._standalone_coverage_campaign_executed(ws)
    assert r["ok"] is True
    assert r["calls"] >= 500_000


def test_negative_no_raw_log(tmp_path):
    ws = _mk_ws(tmp_path)
    _receipt(ws)  # receipt says 1M calls...
    # ...but NO fuzz log -> cannot corroborate -> fail
    r = acc._standalone_coverage_campaign_executed(ws)
    assert r["ok"] is False


def test_negative_sub_threshold_log(tmp_path):
    ws = _mk_ws(tmp_path)
    _receipt(ws)
    _log(ws, 100_000)  # below 500k echidna bar
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is False


def test_negative_vacuous_no_kill(tmp_path):
    ws = _mk_ws(tmp_path)
    _receipt(ws, campaign={"non_vacuity_kills": 0, "mutation_detail": []})
    _log(ws, 600_000)
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is False


def test_negative_receipt_calls_below_threshold(tmp_path):
    ws = _mk_ws(tmp_path)
    _receipt(ws, campaign={"result": {"calls": 200_000, "passed": 5, "failed": 0}})
    _log(ws, 600_000)
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is False


def test_negative_failed_nonzero_non_mutant(tmp_path):
    ws = _mk_ws(tmp_path)
    _receipt(ws, campaign={"result": {"calls": 1_000_000, "passed": 4, "failed": 1}})
    _log(ws, 600_000)
    # a non-mutant campaign with a falsified property does not credit live-engines
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is False


def test_mutant_campaign_failed_is_a_kill(tmp_path):
    ws = _mk_ws(tmp_path)
    _receipt(ws, campaign={"name": "Solvency-mutant-a",
                           "result": {"calls": 1_000_000, "passed": 4, "failed": 1}})
    _log(ws, 600_000)
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is True


def test_negative_mock_harness(tmp_path):
    ws = _mk_ws(tmp_path)
    (ws / "src" / "echidna" / "MockH.sol").write_text("contract MockH{}", encoding="utf-8")
    _receipt(ws, campaign={"harness": "src/echidna/MockH.sol"})
    _log(ws, 600_000)
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is False


def test_negative_harness_outside_ws(tmp_path):
    ws = _mk_ws(tmp_path)
    _receipt(ws, campaign={"harness": "../../etc/passwd"})
    _log(ws, 600_000)
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is False


def test_negative_schema_mismatch(tmp_path):
    ws = _mk_ws(tmp_path)
    _receipt(ws, schema="wrong.schema.v1")
    _log(ws, 600_000)
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is False


def test_negative_workspace_mismatch(tmp_path):
    ws = _mk_ws(tmp_path)
    _receipt(ws, workspace="some-other-workspace")
    _log(ws, 600_000)
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is False


def test_medusa_needs_1m(tmp_path):
    ws = _mk_ws(tmp_path)
    # medusa campaign at only 600k -> below the 1M medusa bar
    _receipt(ws, campaign={"engine": "medusa",
                           "result": {"calls": 600_000, "passed": 5, "failed": 0}})
    _log(ws, 600_000)
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is False
    # at 1M with a corroborating log -> credits
    _receipt(ws, campaign={"engine": "medusa",
                           "result": {"calls": 1_000_000, "passed": 5, "failed": 0}})
    _log(ws, 1_000_000)
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is True


def test_missing_receipt(tmp_path):
    ws = _mk_ws(tmp_path)
    _log(ws, 600_000)
    assert acc._standalone_coverage_campaign_executed(ws)["ok"] is False
