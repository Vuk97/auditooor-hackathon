"""Tests for the FIX #2 additions to completeness-matrix-build.py:

1. The per-unit enumeration WORKLIST artifact
   (.auditooor/completeness_enumeration_worklist.jsonl) - one actionable row per
   NOT-ENUMERATED value-moving cell, deterministic + idempotent, ALWAYS written.
2. The STRICT-gated terminal verdict honoring AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE:
   - enforce + incomplete -> hard fail (rc 1).
   - enforce + complete   -> pass (rc 0).
   - default (no env) + incomplete + no --check -> WARN-pass (rc 0), worklist still
     written.
   - a complete matrix passes regardless of env (never-false-pass: stricter only).

Both directions of the NEVER-FALSE-PASS contract are exercised: a genuine
fully-enumerated matrix still passes under enforce; a vacuous/incomplete one that
previously WARN-passed now FAILS under enforce.
"""
import importlib.util
import json
import os
from pathlib import Path

import pytest

_MOD = Path(__file__).resolve().parents[1] / "completeness-matrix-build.py"
_spec = importlib.util.spec_from_file_location("cmb_wl", _MOD)
cmb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cmb)


def _mk(ws: Path, *, inscope=None, dossiers=None, impact=None, fncov=None, rebuttal=None):
    a = ws / ".auditooor"
    a.mkdir(parents=True, exist_ok=True)
    if inscope is not None:
        (a / "inscope_units.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in inscope), encoding="utf-8")
    if dossiers is not None:
        cd = a / "comprehension"
        cd.mkdir(exist_ok=True)
        for name, body in dossiers.items():
            (cd / name).write_text(body, encoding="utf-8")
    if impact is not None:
        (a / "exploit_class_coverage.json").write_text(json.dumps(impact), encoding="utf-8")
    if fncov is not None:
        (a / "function_coverage_completeness.json").write_text(json.dumps(fncov), encoding="utf-8")
    if rebuttal is not None:
        (a / "completeness_matrix_rebuttal.md").write_text(rebuttal, encoding="utf-8")


def _full_dossier(asset_repo):
    return (f"# {asset_repo} dossier\nINV-1 conservation: totalAssets == sum of adapter. "
            "INV-2 monotonicity: share price never decrease. INV-3 authorization: onlyOwner role. "
            "INV-4 atomicity: reentrancy CEI. INV-5 uniqueness: no double-claim nonce. "
            "INV-6 freshness: timelock validAt. INV-7 determinism: no overflow wexp. "
            "INV-8 bounds: cap <= max. INV-9 custody: no residue sweep. INV-10 ordering: accrue before mutate.\n")


def _scan_all_mechanisms_clean(ws):
    """v2 mechanism axis: a genuinely-complete workspace has also RUN every mechanism
    detector for its languages with 0 findings. Emit a clean mechanism_scan sidecar
    per distinct library mechanism so the [impact x mechanism] plane is enumerated."""
    msd = ws / ".auditooor" / "mechanism_scan"
    msd.mkdir(parents=True, exist_ok=True)
    seen = set()
    for mechs in cmb._MECHANISM_LIBRARY_SEED.values():
        for mm in mechs:
            mech = mm["mechanism"]
            if mech in seen:
                continue
            seen.add(mech)
            (msd / f"{mech}.json").write_text(
                json.dumps({"mechanism": mech, "findings": []}), encoding="utf-8")


def _complete_ws(ws):
    """A genuinely fully-enumerated workspace -> verdict complete."""
    _mk(ws,
        inscope=[{"file": "src/foo/src/A.sol", "function": "f"}],
        dossiers={"foo.md": _full_dossier("foo")},
        impact={"classes": {"theft": "ruled-out-source-cited", "freeze": "not-applicable"}},
        fncov={"functions": [{"file": "src/foo/src/A.sol", "function": "f",
                              "classification": "real-attack",
                              "evidence": ["mutation-killed:A.sol:f:1"]}]})
    _scan_all_mechanisms_clean(ws)


def _incomplete_ws(ws):
    """An incomplete workspace: bar has no dossier (asset axis), bar::g has no
    coverage record (function axis), one impact class blank (impact axis)."""
    _mk(ws,
        inscope=[{"file": "src/foo/src/A.sol", "function": "f"},
                 {"file": "src/bar/src/B.sol", "function": "g"}],
        dossiers={"foo.md": _full_dossier("foo")},
        impact={"classes": {"theft": "ruled-out", "freeze": ""}},
        fncov={"functions": [{"file": "src/foo/src/A.sol", "function": "f",
                              "classification": "real-attack",
                              "evidence": ["mutation-killed:A.sol:f:1"]}]})


@pytest.fixture(autouse=True)
def _clean_enforce_env():
    """Isolate every test from an ambient enforce env in the runner shell."""
    saved = os.environ.pop("AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE", None)
    try:
        yield
    finally:
        if saved is not None:
            os.environ["AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE"] = saved
        else:
            os.environ.pop("AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE", None)


# --------------------------------------------------------------------------- #
# Worklist artifact
# --------------------------------------------------------------------------- #
def test_worklist_written_with_rows_for_each_not_enumerated_axis(tmp_path):
    ws = tmp_path / "ws"
    _incomplete_ws(ws)
    rc = cmb.main(["--workspace", str(ws)])  # default posture, no --check
    assert rc == 0  # default WARN-pass
    wl = ws / ".auditooor" / "completeness_enumeration_worklist.jsonl"
    assert wl.is_file()
    rows = [json.loads(l) for l in wl.read_text(encoding="utf-8").splitlines() if l.strip()]
    axes = {r["axis"] for r in rows}
    # function axis: bar::g has no coverage record
    fn_rows = [r for r in rows if r["axis"] == "function"]
    assert any(r["asset"] == "src/bar" and r["function"] == "g" for r in fn_rows)
    # invariant axis: bar has 0/10 enumerated -> 10 invariant rows
    inv_rows = [r for r in rows if r["axis"] == "invariant" and r["asset"] == "src/bar"]
    assert len(inv_rows) == 10
    # impact axis: freeze is blank
    assert any(r["axis"] == "impact" and r["impact_category"] == "freeze" for r in rows)
    assert {"function", "invariant", "impact"} <= axes
    # every row is actionable
    assert all(r.get("action") for r in rows)


def test_worklist_is_deterministic_and_idempotent(tmp_path):
    ws = tmp_path / "ws"
    _incomplete_ws(ws)
    wl = ws / ".auditooor" / "completeness_enumeration_worklist.jsonl"
    cmb.main(["--workspace", str(ws)])
    first = wl.read_text(encoding="utf-8")
    # re-run: byte-identical (overwritten in full, sorted, no append duplication)
    cmb.main(["--workspace", str(ws)])
    second = wl.read_text(encoding="utf-8")
    assert first == second
    # rows are sorted by the stable key
    rows = [json.loads(l) for l in first.splitlines() if l.strip()]
    sorted_rows = sorted(rows, key=lambda r: (
        str(r.get("axis") or ""), str(r.get("asset") or ""),
        str(r.get("function") or r.get("invariant_category")
            or r.get("mechanism") or r.get("impact_category") or ""),
        str(r.get("file") or "")))
    assert rows == sorted_rows


def test_worklist_empty_file_when_matrix_complete(tmp_path):
    ws = tmp_path / "ws"
    _complete_ws(ws)
    cmb.main(["--workspace", str(ws)])
    wl = ws / ".auditooor" / "completeness_enumeration_worklist.jsonl"
    assert wl.is_file()  # ALWAYS written
    assert wl.read_text(encoding="utf-8").strip() == ""  # zero rows


def test_missing_impact_ledger_yields_star_impact_row(tmp_path):
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/foo/src/A.sol", "function": "f"}],
        dossiers={"foo.md": _full_dossier("foo")},
        # NO exploit_class_coverage.json -> impact ledger absent
        fncov={"functions": [{"file": "src/foo/src/A.sol", "function": "f",
                              "classification": "real-attack",
                              "evidence": ["mutation-killed:A.sol:f:1"]}]})
    m = cmb.build_matrix(ws)
    rows = m["enumeration_worklist"]
    impact_rows = [r for r in rows if r["axis"] == "impact"]
    assert len(impact_rows) == 1 and impact_rows[0]["asset"] == "*"
    assert impact_rows[0]["status"] == "absent"


# --------------------------------------------------------------------------- #
# Enforce-gated terminal verdict - NEVER-FALSE-PASS both directions
# --------------------------------------------------------------------------- #
def test_enforce_incomplete_fails(tmp_path):
    ws = tmp_path / "ws"
    _incomplete_ws(ws)
    os.environ["AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE"] = "1"
    rc = cmb.main(["--workspace", str(ws)])  # no --check; enforce drives the fail
    assert rc == 1
    # worklist still emitted even on the fail path
    assert (ws / ".auditooor" / "completeness_enumeration_worklist.jsonl").is_file()


def test_enforce_complete_passes(tmp_path):
    ws = tmp_path / "ws"
    _complete_ws(ws)
    os.environ["AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE"] = "1"
    rc = cmb.main(["--workspace", str(ws)])
    assert rc == 0  # genuine fully-enumerated matrix still passes under enforce


def test_default_incomplete_warn_passes(tmp_path):
    ws = tmp_path / "ws"
    _incomplete_ws(ws)
    # no env, no --check -> WARN-pass (does not retroactively brick legacy ws)
    rc = cmb.main(["--workspace", str(ws), "--json"])
    assert rc == 0


def test_enforce_falsey_values_stay_warn(tmp_path):
    ws = tmp_path / "ws"
    _incomplete_ws(ws)
    for val in ("", "0", "false", "no"):
        os.environ["AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE"] = val
        assert cmb.main(["--workspace", str(ws)]) == 0, val


def test_enforce_incomplete_with_rebuttal_passes(tmp_path):
    ws = tmp_path / "ws"
    _incomplete_ws(ws)
    _mk(ws, rebuttal="<!-- completeness-matrix-rebuttal: bar is a test-only shim, operator-approved -->")
    os.environ["AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE"] = "1"
    rc = cmb.main(["--workspace", str(ws)])
    assert rc == 0  # operator rebuttal greens an otherwise-failing enforce verdict


def test_check_flag_still_fails_without_env(tmp_path):
    """Back-compat: explicit --check is strict-by-intent regardless of the env."""
    ws = tmp_path / "ws"
    _incomplete_ws(ws)
    assert cmb.main(["--workspace", str(ws), "--check"]) == 1


def test_matrix_dict_carries_worklist(tmp_path):
    ws = tmp_path / "ws"
    _incomplete_ws(ws)
    m = cmb.build_matrix(ws)
    assert "enumeration_worklist" in m
    assert m["enumeration_worklist_count"] == len(m["enumeration_worklist"])
    assert m["enumeration_worklist_count"] > 0
