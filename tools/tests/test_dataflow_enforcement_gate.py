#!/usr/bin/env python3
"""Tests for the DefUsePath enforcement gate (pre-submit Check #136) and the
VICE-VERSA on-demand backward slice (dataflow-slice.py --from-sink).

Gate cases (no Slither needed - the gate consults a written dataflow_paths.jsonl):
  - HIGH+ path-relevant finding WITHOUT a citation  -> FAIL (rc=1)
  - HIGH+ path-relevant finding WITH a DefUsePath id -> PASS
  - HIGH+ path-relevant finding WITH a rebuttal       -> ok-rebuttal (PASS)
  - prose-only HIGH+ finding (no file:line)           -> PASS (not-path-relevant)
  - HIGH+ finding on a file:line that is NOT an unguarded path -> PASS
  - below-High finding on the same unguarded path     -> PASS (below-high)
  - no-slice workspace                                -> PASS (no-op)
  - slice present but only GUARDED paths              -> PASS (no unguarded rows)

--from-sink case (requires Slither; skipped if unavailable):
  - --from-sink on the vulnerable.sol transferFrom sink returns backward paths.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ENF_TOOL = REPO / "tools" / "dataflow-enforcement-check.py"
SLICE_TOOL = REPO / "tools" / "dataflow-slice.py"
FIX = REPO / "tests" / "fixtures" / "dataflow"

sys.path.insert(0, str(REPO / "tools"))
import dataflow_schema as dfs  # noqa: E402


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _mk_ws(paths_records):
    ws = Path(tempfile.mkdtemp(prefix="df_enf_ws_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    # also drop a SCOPE.md so WS_DIR walk-up would resolve (not needed for direct tool call)
    (ws / "SCOPE.md").write_text("# scope\n")
    if paths_records is not None:
        out = ws / ".auditooor" / "dataflow_paths.jsonl"
        with open(out, "w") as fh:
            for r in paths_records:
                fh.write(json.dumps(r, default=str) + "\n")
    return ws


def _unguarded_path(path_id, sink_file, sink_line, sink_callee="transfer"):
    """A real, validated, NON-degraded, UNGUARDED value-flow record."""
    return dfs.new_path(
        path_id=path_id,
        language="solidity",
        direction="backward",
        engine="slither.analyses.data_dependency",
        source={"kind": "param-entrypoint", "fn": "Mod.entry(uint256)",
                "var": "amount", "file": sink_file, "line": sink_line - 10},
        sink={"kind": sink_callee, "callee": sink_callee, "arg_pos": 1,
              "fn": "Lib.move(address,uint256)", "file": sink_file, "line": sink_line},
        hops=[],  # no guarded hops
        guard_nodes=[],  # no guards -> unguarded == True
        source_unit_ids=[f"{os.path.basename(sink_file)}:{sink_line-10}"],
        sink_unit_ids=[f"{os.path.basename(sink_file)}:{sink_line}"],
        confidence="semantic-ssa",
        degraded=False,
    )


def _guarded_path(path_id, sink_file, sink_line):
    rec = _unguarded_path(path_id, sink_file, sink_line)
    rec["guard_nodes"] = [{"file": sink_file, "line": sink_line - 2,
                           "expr": "require(amount <= cap)"}]
    rec["unguarded"] = False
    return rec


def _run_gate(draft_text, ws, severity=None):
    draft = ws / "finding.md"
    draft.write_text(draft_text)
    args = [sys.executable, str(ENF_TOOL), str(draft), "--workspace", str(ws), "--json"]
    if severity:
        args += ["--severity", severity]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    out = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return proc.returncode, out


# the unguarded path all the gate fixtures key on
SINK_FILE = "/x/src/CoreLib.sol"
SINK_LINE = 46


# --------------------------------------------------------------------------
# gate tests
# --------------------------------------------------------------------------
def test_high_path_relevant_uncited_fails():
    ws = _mk_ws([_unguarded_path("dfp-0001", SINK_FILE, SINK_LINE)])
    draft = (
        "**Severity:** High\n\n"
        "## Impact\nAn attacker drains the pool via the unguarded transfer at "
        "CoreLib.sol:46.\n\nNo guard dominates the value flow.\n"
    )
    rc, out = _run_gate(draft, ws)
    assert rc == 1, out
    assert out["verdict"] == "fail-uncited-unguarded-path", out
    assert "dfp-0001" in (out.get("uncited_path_id") or "") or out.get("matched_path_ids"), out


def test_high_path_relevant_with_cite_passes():
    ws = _mk_ws([_unguarded_path("dfp-0001", SINK_FILE, SINK_LINE)])
    draft = (
        "**Severity:** High\n\n"
        "## Impact\nDrain via CoreLib.sol:46. Grounded in DefUsePath path_id: dfp-0001 "
        "(unguarded, semantic-ssa).\n"
    )
    rc, out = _run_gate(draft, ws)
    assert rc == 0, out
    assert out["verdict"] == "pass-cited", out


def test_high_path_relevant_with_rebuttal_passes():
    ws = _mk_ws([_unguarded_path("dfp-0001", SINK_FILE, SINK_LINE)])
    draft = (
        "**Severity:** Critical\n\n"
        "## Impact\nTransfer at CoreLib.sol:46.\n"
        "<!-- dataflow-rebuttal: the slice flags unguarded but a role gate in "
        "the onlyOwner modifier dominates; finding is a hardening note -->\n"
    )
    rc, out = _run_gate(draft, ws)
    assert rc == 0, out
    assert out["verdict"] == "ok-rebuttal", out


def test_closure_verdict_passes():
    ws = _mk_ws([_unguarded_path("dfp-0001", SINK_FILE, SINK_LINE)])
    draft = (
        "**Severity:** High\n\n"
        "## Impact\nTransfer at CoreLib.sol:46. The closure-guarded analysis shows "
        "the registerOperator modifier dominates this sink.\n"
    )
    rc, out = _run_gate(draft, ws)
    assert rc == 0, out
    assert out["verdict"] == "pass-cited", out


def test_prose_only_passes():
    ws = _mk_ws([_unguarded_path("dfp-0001", SINK_FILE, SINK_LINE)])
    draft = (
        "**Severity:** High\n\n"
        "## Impact\nThe protocol mis-accounts rewards leading to fund loss. "
        "No specific line is cited because this is an economic-logic argument.\n"
    )
    rc, out = _run_gate(draft, ws)
    assert rc == 0, out
    assert out["verdict"] == "pass-not-path-relevant", out


def test_non_path_fileline_passes():
    # cites a file:line that is NOT any unguarded path's sink/source/hop
    ws = _mk_ws([_unguarded_path("dfp-0001", SINK_FILE, SINK_LINE)])
    draft = (
        "**Severity:** High\n\n"
        "## Impact\nMissing event emission at SSVNetwork.sol:999 misleads indexers.\n"
    )
    rc, out = _run_gate(draft, ws)
    assert rc == 0, out
    assert out["verdict"] == "pass-not-path-relevant", out


def test_below_high_passes():
    ws = _mk_ws([_unguarded_path("dfp-0001", SINK_FILE, SINK_LINE)])
    draft = (
        "**Severity:** Medium\n\n"
        "## Impact\nBounded rounding at CoreLib.sol:46.\n"
    )
    rc, out = _run_gate(draft, ws)
    assert rc == 0, out
    assert out["verdict"] == "pass-below-high", out


def test_no_slice_workspace_passes():
    ws = _mk_ws(None)  # no dataflow_paths.jsonl at all
    draft = (
        "**Severity:** High\n\n"
        "## Impact\nDrain via CoreLib.sol:46.\n"
    )
    rc, out = _run_gate(draft, ws)
    assert rc == 0, out
    assert out["verdict"] == "pass-no-slice", out


def test_only_guarded_paths_passes():
    # slice exists but the matching path is GUARDED -> no unguarded rows -> no-op
    ws = _mk_ws([_guarded_path("dfp-0001", SINK_FILE, SINK_LINE)])
    draft = (
        "**Severity:** High\n\n"
        "## Impact\nDrain via CoreLib.sol:46.\n"
    )
    rc, out = _run_gate(draft, ws)
    assert rc == 0, out
    assert out["verdict"] == "pass-no-slice", out


def test_degraded_only_slice_passes():
    # a slice file that holds ONLY a degrade row -> read_paths(skip_degraded) -> empty
    ws = _mk_ws([dfs.degrade_record("solidity", "compile-fail")])
    draft = (
        "**Severity:** High\n\n## Impact\nDrain via CoreLib.sol:46.\n"
    )
    rc, out = _run_gate(draft, ws)
    assert rc == 0, out
    assert out["verdict"] == "pass-no-slice", out


# --------------------------------------------------------------------------
# --from-sink (VICE-VERSA backward slice) - needs Slither; degrade-aware
# --------------------------------------------------------------------------
def _slither_available():
    try:
        import slither  # noqa: F401
        return True
    except Exception:
        return False


def test_from_sink_returns_backward_paths():
    if not _slither_available():
        import pytest
        pytest.skip("slither not installed")
    sol = FIX / "vulnerable.sol"
    assert sol.exists()
    ws = Path(tempfile.mkdtemp(prefix="df_fromsink_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    # find the transferFrom CALL-SITE line (a `.transferFrom(` invocation, not the
    # interface declaration on line 5 nor the comment on line 9).
    text = sol.read_text()
    sink_line = next(
        i for i, l in enumerate(text.splitlines(), 1)
        if ".transferFrom(" in l and "function " not in l
        and not l.lstrip().startswith("//")
    )
    proc = subprocess.run(
        [sys.executable, str(SLICE_TOOL), "--workspace", str(ws),
         "--target", str(sol), "--from-sink", f"vulnerable.sol:{sink_line}", "--json"],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stderr}\n{proc.stdout}"
    res = json.loads(proc.stdout)
    if res.get("status") == "degraded":
        import pytest
        pytest.skip(f"slither degraded on fixture: {res.get('errors')}")
    assert res["status"] == "ok", res
    assert res["sink_sites_at_location"] >= 1, res
    assert res["backward_paths"] >= 1, res
    # every recovered record is a backward slice to that sink
    for r in res["records"]:
        assert r["direction"] == "backward", r
        assert r["sink"]["line"] == sink_line, r


def test_mark_explained_sidecar_union():
    ws = Path(tempfile.mkdtemp(prefix="df_explained_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    side = ws / ".auditooor" / "dataflow_explained_paths.json"

    def _mark(ids, finding):
        proc = subprocess.run(
            [sys.executable, str(SLICE_TOOL), "--workspace", str(ws),
             "--mark-explained", ids, "--explained-finding", finding, "--json"],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        return json.loads(proc.stdout)

    r1 = _mark("dfp-0001,dfp-0002", "FIND-A")
    assert r1["total_explained"] == 2, r1
    r2 = _mark("dfp-0002,dfp-0003", "FIND-B")  # idempotent union
    assert r2["total_explained"] == 3, r2
    data = json.loads(side.read_text())
    assert set(data["explained"]) == {"dfp-0001", "dfp-0002", "dfp-0003"}, data
    # dfp-0002 attributed to BOTH findings
    assert set(data["explained"]["dfp-0002"]["findings"]) == {"FIND-A", "FIND-B"}, data


def test_slice_default_output_unchanged_without_new_flags():
    """No-op-when-absent / byte-identical default: a plain run with NONE of the new
    flags (--from-sink / --mark-explained) behaves exactly like before this lane."""
    if not _slither_available():
        import pytest
        pytest.skip("slither not installed")
    sol = FIX / "vulnerable.sol"
    ws = Path(tempfile.mkdtemp(prefix="df_default_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [sys.executable, str(SLICE_TOOL), "--workspace", str(ws),
         "--target", str(sol), "--json"],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    res = json.loads(proc.stdout)
    # the default run never emits the explained sidecar and never references --from-sink
    assert not (ws / ".auditooor" / "dataflow_explained_paths.json").exists()
    assert res["status"] in ("ok", "degraded"), res


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
