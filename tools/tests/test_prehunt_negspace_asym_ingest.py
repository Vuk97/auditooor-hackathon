"""Regression tests for tools/prehunt-negspace-asym-ingest.py (ORDER rewire).

Proves the pre-hunt ingest:
  1. detects staleness against inscope_units.jsonl,
  2. counts index rows / flags empty,
  3. WARNs (advisory) but exits 0 on an empty negspace/asym index by default,
  4. exits 3 under --fail-closed when negspace/asym is empty,
  5. does NOT fail-close on an empty invariant-ledger,
  6. writes a receipt asserting the ingest ran BEFORE the hunt.
"""
import importlib.util
import json
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parents[1] / "prehunt-negspace-asym-ingest.py"
_spec = importlib.util.spec_from_file_location("prehunt_ingest", _MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _mk_ws(tmp_path, inscope=True):
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    if inscope:
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            '{"unit":"a"}\n', encoding="utf-8")
    return ws


def test_count_jsonl_rows(tmp_path):
    p = tmp_path / "x.jsonl"
    assert mod._count_jsonl_rows(p) == 0  # absent
    p.write_text('{"a":1}\n\n{"b":2}\n', encoding="utf-8")
    assert mod._count_jsonl_rows(p) == 2  # blank line ignored


def test_is_stale(tmp_path):
    idx = tmp_path / "idx.jsonl"
    inscope = tmp_path / "inscope.jsonl"
    assert mod._is_stale(idx, inscope) is True  # index absent
    idx.write_text("{}\n", encoding="utf-8")
    # inscope absent -> present index reused (not stale)
    assert mod._is_stale(idx, inscope) is False
    # inscope newer than index -> stale
    import os
    import time
    inscope.write_text("{}\n", encoding="utf-8")
    t = time.time()
    os.utime(idx, (t - 100, t - 100))
    os.utime(inscope, (t, t))
    assert mod._is_stale(idx, inscope) is True


def _patch_producers(monkeypatch, ws, negspace_rows, sibling_rows, ledger_rows):
    """Make _run_producer materialize the target index instead of spawning."""
    audit = ws / ".auditooor"

    def fake_run(argv, *, timeout):
        joined = " ".join(argv)
        if "guard-negative-space-analyzer" in joined:
            (audit / "negative_space_worklist.jsonl").write_text(
                "".join('{"r":%d}\n' % i for i in range(negspace_rows)),
                encoding="utf-8")
        elif "sibling-path-guard-diff" in joined:
            (audit / "sibling_guard_asymmetries.jsonl").write_text(
                "".join('{"r":%d}\n' % i for i in range(sibling_rows)),
                encoding="utf-8")
        elif "exploit-queue-to-invariant-ledger" in joined:
            (audit / "invariant_ledger.json").write_text(
                "".join('{"r":%d}\n' % i for i in range(ledger_rows)),
                encoding="utf-8")
        return {"argv": argv, "rc": 0, "stderr_tail": []}

    monkeypatch.setattr(mod, "_run_producer", fake_run)


def test_populated_indices_status_ok(tmp_path, monkeypatch):
    ws = _mk_ws(tmp_path)
    _patch_producers(monkeypatch, ws, negspace_rows=5, sibling_rows=3, ledger_rows=2)
    summary = mod.run(ws, fail_closed=False, timeout=10)
    assert summary["ran_before_hunt"] is True
    assert summary["status"] == "ok"
    assert summary["empty_gated_indices"] == []
    # all three regenerated because indices were absent (stale)
    assert all(p["regenerated"] for p in summary["producers"])
    rows = {p["index_key"]: p["rows_after"] for p in summary["producers"]}
    assert rows["negspace"] == 5 and rows["asym"] == 3


def test_empty_negspace_warns_but_exit0_advisory(tmp_path, monkeypatch):
    ws = _mk_ws(tmp_path)
    _patch_producers(monkeypatch, ws, negspace_rows=0, sibling_rows=4, ledger_rows=1)
    rc = mod.main(["--workspace", str(ws)])
    assert rc == 0  # advisory default
    receipt = json.loads((ws / ".auditooor" /
                          "prehunt_negspace_asym_ingest.json").read_text())
    assert receipt["ran_before_hunt"] is True
    assert "negspace" in receipt["empty_gated_indices"]
    assert receipt["status"] == "empty-index-warn"


def test_empty_asym_fail_closed_exits_3(tmp_path, monkeypatch):
    ws = _mk_ws(tmp_path)
    _patch_producers(monkeypatch, ws, negspace_rows=7, sibling_rows=0, ledger_rows=1)
    rc = mod.main(["--workspace", str(ws), "--fail-closed"])
    assert rc == 3
    receipt = json.loads((ws / ".auditooor" /
                          "prehunt_negspace_asym_ingest.json").read_text())
    assert "asym" in receipt["empty_gated_indices"]


def test_empty_ledger_never_fail_closed(tmp_path, monkeypatch):
    ws = _mk_ws(tmp_path)
    # negspace + asym populated, ledger empty -> must NOT gate
    _patch_producers(monkeypatch, ws, negspace_rows=2, sibling_rows=2, ledger_rows=0)
    rc = mod.main(["--workspace", str(ws), "--fail-closed"])
    assert rc == 0
    receipt = json.loads((ws / ".auditooor" /
                          "prehunt_negspace_asym_ingest.json").read_text())
    assert receipt["empty_gated_indices"] == []


def test_missing_workspace_exit2(tmp_path):
    rc = mod.main(["--workspace", str(tmp_path / "does-not-exist")])
    assert rc == 2


def test_strict_env_enabled_parsing():
    for val in ("1", "true", "TRUE", "yes", "On"):
        assert mod._strict_env_enabled({mod.STRICT_ENV: val}) is True, val
    for val in ("", "0", "false", "no", "off", "maybe"):
        assert mod._strict_env_enabled({mod.STRICT_ENV: val}) is False, val
    assert mod._strict_env_enabled({}) is False


def test_empty_negspace_env_strict_exits_3(tmp_path, monkeypatch):
    # AUDITOOOR_PREHUNT_STRICT=1 must flip empty-index to fail-closed WITHOUT
    # the --fail-closed CLI flag (the STRICT path the pipeline opts into).
    ws = _mk_ws(tmp_path)
    _patch_producers(monkeypatch, ws, negspace_rows=0, sibling_rows=4, ledger_rows=1)
    monkeypatch.setenv(mod.STRICT_ENV, "1")
    rc = mod.main(["--workspace", str(ws)])
    assert rc == 3
    receipt = json.loads((ws / ".auditooor" /
                          "prehunt_negspace_asym_ingest.json").read_text())
    assert "negspace" in receipt["empty_gated_indices"]
    assert receipt["status"] == "empty-index-fail"
    assert receipt["strict_source"] == f"env:{mod.STRICT_ENV}"


def test_populated_indices_env_strict_passes(tmp_path, monkeypatch):
    # Real populated index under env-strict => exit 0 (fail-closed path does NOT
    # trigger on the populated workspace).
    ws = _mk_ws(tmp_path)
    _patch_producers(monkeypatch, ws, negspace_rows=5, sibling_rows=3, ledger_rows=2)
    monkeypatch.setenv(mod.STRICT_ENV, "1")
    rc = mod.main(["--workspace", str(ws)])
    assert rc == 0
    receipt = json.loads((ws / ".auditooor" /
                          "prehunt_negspace_asym_ingest.json").read_text())
    assert receipt["empty_gated_indices"] == []
    assert receipt["status"] == "ok"
    assert receipt["fail_closed"] is True


def test_env_strict_off_stays_advisory(tmp_path, monkeypatch):
    ws = _mk_ws(tmp_path)
    _patch_producers(monkeypatch, ws, negspace_rows=0, sibling_rows=4, ledger_rows=1)
    monkeypatch.setenv(mod.STRICT_ENV, "0")
    rc = mod.main(["--workspace", str(ws)])
    assert rc == 0
    receipt = json.loads((ws / ".auditooor" /
                          "prehunt_negspace_asym_ingest.json").read_text())
    assert receipt["status"] == "empty-index-warn"
    assert receipt["strict_source"] == "advisory"
