#!/usr/bin/env python3
"""Non-vacuity fixture test for the ZK (circom) signal-flow def-use backend.

Mutation-pair discipline (R-C non-vacuity): the fixture pair is IDENTICAL data
flow (`out` derives from `in + 1`); the ONLY difference is the operator that
binds `out`:

  under_constrained.circom : out <-- in + 1     (witness assign, NO constraint)
  constrained.circom       : out <== in + 1; out === in + 1   (constrained)

Asserts:
  - under_constrained yields exactly one UNGUARDED signal DefUsePath for `out`
    (source.kind=="signal", unguarded==True, signal_via has a signal-assign edge
    and NO signal-constrain edge).
  - constrained yields the SAME structural path but unguarded==False with a
    populated guard_nodes list (the constraint edge) and a signal-constrain hop.
  - The unguarded flag is the discriminator and MUST flip between the pair - an
    assert(true) property cannot do that (the constraint is the injected/removed
    behavior). This is the mutation-verification witness.
  - Every emitted record passes the SHARED tools/dataflow_schema.py validator.
  - R80 degrade: a non-circom workspace is a clean no-op (verdict
    no-circom-circuits), and the pure-parser path (no circomspect) still flags.

Run: python3 tools/tests/test_zk_dataflow.py     (or via pytest)
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "zk-dataflow.py"
FIX = REPO / "tests" / "fixtures" / "dataflow_zk"

sys.path.insert(0, str(REPO / "tools"))
import dataflow_schema as dfs  # noqa: E402


def _run(fixture_name: str, extra_args=None):
    circ = FIX / fixture_name
    assert circ.exists(), f"fixture missing: {circ}"
    out = Path(tempfile.mkdtemp(prefix=f"zkdftest_{fixture_name}_")) / "zk_dataflow_paths.jsonl"
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--target", str(circ),
         "--output-jsonl", str(out), "--json"] + (extra_args or []),
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"tool failed rc={proc.returncode}\n{proc.stderr}\n{proc.stdout}"
    recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()] if out.exists() else []
    return recs, json.loads(proc.stdout)


def _out_signal_path(recs):
    cands = [r for r in recs if r["source"]["kind"] == "signal" and r["source"]["var"] == "out"]
    assert len(cands) == 1, f"expected exactly 1 `out` signal path, got {len(cands)}: {cands}"
    return cands[0]


def _signal_vias(rec):
    return [h.get("signal_via") for h in rec["hops"]]


def test_schema_conformance_all_records():
    """Every emitted record must pass the shared dataflow_schema validator."""
    for fx in ("under_constrained.circom", "constrained.circom"):
        recs, _ = _run(fx)
        assert recs, f"{fx} emitted no records"
        for r in recs:
            ok, errs = dfs.validate(r)
            assert ok, f"{fx} record failed schema.validate: {errs}\n{r}"


def test_under_constrained_yields_unguarded_signal_path():
    recs, summary = _run("under_constrained.circom")
    p = _out_signal_path(recs)
    assert p["source"]["kind"] == "signal", f"source.kind={p['source']['kind']}"
    assert p["unguarded"] is True, f"under-constrained `out` must be unguarded, got {p['unguarded']}"
    assert p["signal_confidence"] == "signal-shape", f"signal_confidence={p['signal_confidence']}"
    assert p["degraded"] is False
    vias = _signal_vias(p)
    assert "signal-assign" in vias, f"must have a signal-assign edge, got {vias}"
    assert "signal-constrain" not in vias, f"under-constrained must have NO constrain edge, got {vias}"
    assert not p["guard_nodes"], f"under-constrained must have empty guard_nodes, got {p['guard_nodes']}"
    # the witness-assign edge is NEVER itself a guard (kills the over-credit mutant)
    assign_hops = [h for h in p["hops"] if h.get("signal_via") == "signal-assign"]
    assert assign_hops and all(h["guarded"] is False for h in assign_hops), \
        f"signal-assign hop must be guarded=False, got {assign_hops}"
    assert summary["unguarded_records"] == 1, f"summary unguarded_records={summary['unguarded_records']}"


def test_constrained_not_flagged():
    recs, summary = _run("constrained.circom")
    p = _out_signal_path(recs)
    assert p["unguarded"] is False, f"constrained `out` must be guarded, got unguarded={p['unguarded']}"
    assert len(p["guard_nodes"]) >= 1, f"constrained must populate guard_nodes, got {p['guard_nodes']}"
    vias = _signal_vias(p)
    assert "signal-assign" in vias and "signal-constrain" in vias, \
        f"constrained must have BOTH assign and constrain edges, got {vias}"
    assert summary["unguarded_records"] == 0, f"constrained must yield 0 unguarded, got {summary['unguarded_records']}"


def test_nonvacuity_constraint_flips_unguarded():
    """Mutation-pair witness: same flow, the constraint is the ONLY difference and
    it flips `unguarded`. An assert(true) property could not do this."""
    ru, _ = _run("under_constrained.circom")
    rc, _ = _run("constrained.circom")
    pu = _out_signal_path(ru)
    pc = _out_signal_path(rc)
    # both recover the same `out` signal source
    assert pu["source"]["var"] == pc["source"]["var"] == "out"
    # the discriminator MUST differ
    assert pu["unguarded"] is True and pc["unguarded"] is False, \
        f"non-vacuity FAILED: under.unguarded={pu['unguarded']} constrained.unguarded={pc['unguarded']}"


def test_pure_parser_path_still_flags():
    """Native parser is the PRIMARY signal: --no-circomspect must still flag the
    under-constrained signal (corroboration is optional, not load-bearing)."""
    recs, summary = _run("under_constrained.circom", extra_args=["--no-circomspect"])
    p = _out_signal_path(recs)
    assert p["unguarded"] is True
    assert p["circomspect_ran"] is False, "expected circomspect disabled"
    assert summary["unguarded_records"] == 1


def test_circomspect_corroboration_when_available():
    """If circomspect is on PATH, the under-constrained record is corroborated.
    Skipped honestly when circomspect is absent (no false PASS)."""
    import shutil
    if not shutil.which("circomspect"):
        print("SKIP test_circomspect_corroboration (circomspect not installed)")
        return
    recs, _ = _run("under_constrained.circom")
    p = _out_signal_path(recs)
    assert p["circomspect_ran"] is True
    assert p["circomspect_corroborated"] is True, \
        "circomspect should corroborate the under-constrained `out` signal"


def test_r80_noop_on_non_circom_workspace():
    """R80: a workspace with no .circom files is a clean no-op (no fabricated flow)."""
    ws = Path(tempfile.mkdtemp(prefix="zkdf_nocircom_"))
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--workspace", str(ws), "--json"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"no-op should exit 0, rc={proc.returncode}\n{proc.stderr}"
    s = json.loads(proc.stdout)
    assert s["verdict"] == "no-circom-circuits", f"verdict={s['verdict']}"
    assert s["records_emitted"] == 0


if __name__ == "__main__":
    tests = [
        test_schema_conformance_all_records,
        test_under_constrained_yields_unguarded_signal_path,
        test_constrained_not_flagged,
        test_nonvacuity_constraint_flips_unguarded,
        test_pure_parser_path_still_flags,
        test_circomspect_corroboration_when_available,
        test_r80_noop_on_non_circom_workspace,
    ]
    for t in tests:
        t()
        print(f"PASS {t.__name__}")
    print(f"ALL PASS ({len(tests)}/{len(tests)})")
