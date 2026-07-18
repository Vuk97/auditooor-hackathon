"""Regression tests for the per-FILE asset denominator + harness-backed enumeration
floor in completeness-matrix-build.py.

THE GAP (strata 2026-07-01): the matrix collapsed every in-scope FILE under
`src/<repo>` into ONE asset (denominators.assets == 1 for 19 files), and marked all
10 invariant categories 'enumerated' from .md prose (source comprehension) even when
only a few files had a real campaign - hiding which files lacked an economic
invariant.

Fix (generic, all-language, backward-compat + advisory-first):
  (a) an asset denominator per DISTINCT in-scope FILE (via _perfile_asset_of), so
      denominators.assets_perfile reflects the real file count with no double-count.
  (b) under AUDITOOOR_MATRIX_PERFILE_STRICT, an invariant category counts ENUMERATED
      only when backed by a RUN + mutation-verified harness (mvc_sidecar /
      fuzz_campaign_receipt) - a comprehension-only category becomes the distinct
      NON-TERMINAL status 'enumerated-comprehension-only'.
  Default posture is unchanged (never bricks prior audits) but ALWAYS emits the
  per-file breakdown so the gap is visible.
"""
import importlib.util
import json
from pathlib import Path

import pytest

_MOD = Path(__file__).resolve().parents[1] / "completeness-matrix-build.py"
_spec = importlib.util.spec_from_file_location("cmb_perfile", _MOD)
cmb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cmb)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    # every test starts from the default (non-strict) posture unless it opts in.
    for k in ("AUDITOOOR_MATRIX_PERFILE_STRICT",
              "AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE"):
        monkeypatch.delenv(k, raising=False)


def _mk(ws: Path, *, inscope=None, dossiers=None, impact=None, fncov=None):
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


def _multifile_inscope():
    # 3 files under the SAME src/<repo> root -> collapses to a single legacy asset
    # (src/contracts), but 3 distinct per-file assets.
    return [
        {"file": "src/contracts/Tranche.sol", "function": "deposit"},
        {"file": "src/contracts/Accounting.sol", "function": "accrue"},
        {"file": "src/contracts/Rebalancer.sol", "function": "rebalance"},
    ]


# ---------------------------------------------------------------------------
# (a) per-FILE asset denominator
# ---------------------------------------------------------------------------
def test_perfile_asset_of_is_relpath_generic():
    # generic across languages via relpath normalization (no src/ or ext assumption)
    assert cmb._perfile_asset_of("src/contracts/Tranche.sol") == "src/contracts/Tranche.sol"
    assert cmb._perfile_asset_of("x/y/keeper/deposit.go") == "x/y/keeper/deposit.go"
    assert cmb._perfile_asset_of("./a//b/c.rs") == "a/b/c.rs"
    assert cmb._perfile_asset_of("") is None
    # legacy _asset_of collapses all these to one src/contracts
    assert cmb._asset_of("src/contracts/Tranche.sol") == "src/contracts"
    assert cmb._asset_of("src/contracts/Accounting.sol") == "src/contracts"


def test_perfile_denominator_greater_than_one_for_multifile_ws(tmp_path):
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=_multifile_inscope(),
        dossiers={"contracts.md": "invariant conservation totalAssets == sum"},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": []})
    m = cmb.build_matrix(ws)
    # legacy per-repo denominator collapses to 1; the real per-file count is 3.
    assert m["denominators"]["assets"] == 1  # default posture keeps legacy grouping
    assert m["denominators"]["assets_perfile"] == 3  # THE fix: real file count exposed
    assert m["denominators"]["asset_grouping"] == "per-repo"
    # per-file breakdown ALWAYS emitted so the gap is visible without strict.
    assert m["perfile_breakdown"]["denominator_assets"] == 3
    assert len(m["perfile_breakdown"]["assets"]) == 3
    ids = sorted(a["asset_id"] for a in m["perfile_breakdown"]["assets"])
    assert ids == ["src/contracts/Accounting.sol", "src/contracts/Rebalancer.sol",
                   "src/contracts/Tranche.sol"]


def test_no_double_count_across_files(tmp_path):
    # two functions in the SAME file -> ONE per-file asset (no double count)
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/contracts/Tranche.sol", "function": "deposit"},
                 {"file": "src/contracts/Tranche.sol", "function": "withdraw"}],
        dossiers={"c.md": "invariant conservation"},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": []})
    m = cmb.build_matrix(ws)
    assert m["denominators"]["assets_perfile"] == 1
    assert m["perfile_breakdown"]["assets"][0]["function_count"] == 2


def test_strict_switches_primary_grouping_to_perfile(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=_multifile_inscope(),
        dossiers={"contracts.md": "invariant conservation totalAssets == sum"},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": []})
    m = cmb.build_matrix(ws)
    assert m["denominators"]["assets"] == 3  # primary grouping IS per-file now
    assert m["denominators"]["asset_grouping"] == "per-file"
    assert m["perfile_strict"] is True


# ---------------------------------------------------------------------------
# (b) comprehension-only category is NON-TERMINAL under strict
# ---------------------------------------------------------------------------
def test_comprehension_only_is_non_terminal_under_strict(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    # a dossier referencing the file with a conservation cue - prose only, NO harness.
    _mk(ws,
        inscope=[{"file": "src/contracts/Tranche.sol", "function": "deposit"}],
        dossiers={"tranche.md": ("# Tranche dossier\nINV-1 conservation: totalAssets == "
                                 "sum of adapter balances. no funds left behind.\n")},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": []})
    m = cmb.build_matrix(ws)
    inv = m["assets"][0]["invariant_enumeration"]
    # conservation was DESCRIBED in prose but never proven by a campaign -> non-terminal
    assert inv["conservation"]["status"] == "enumerated-comprehension-only"
    assert inv["conservation"]["source"] == "comprehension-only"
    # 0 TERMINALLY-enumerated categories -> the asset fails the invariant floor.
    assert m["assets"][0]["invariant_categories_enumerated"] == 0
    assert "src/contracts/Tranche.sol" in [x["asset_id"] for x in m["not_enumerated_assets"]]
    assert m["verdict"] == "incomplete"


def test_comprehension_terminally_enumerates_in_default_posture(tmp_path):
    # backward-compat: WITHOUT strict, comprehension prose still terminally enumerates.
    # (default posture groups per-repo -> asset 'src/contracts'; the dossier references
    # the repo token 'contracts' so it matches the per-repo asset.)
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/contracts/Tranche.sol", "function": "deposit"}],
        dossiers={"contracts.md": ("# contracts dossier\nINV-1 conservation: totalAssets == "
                                   "sum of adapter balances.\n")},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": []})
    m = cmb.build_matrix(ws)
    inv = m["assets"][0]["invariant_enumeration"]
    assert inv["conservation"]["status"] == "enumerated"
    assert inv["conservation"]["source"] == "comprehension"


def test_mvc_harness_terminally_enumerates_under_strict(tmp_path, monkeypatch):
    # a RUN + mutation-verified harness on the file DOES terminally enumerate under strict.
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/contracts/Tranche.sol", "function": "deposit"}],
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": [{"file": "src/contracts/Tranche.sol", "function": "deposit",
                              "classification": "real-attack"}]})
    d = ws / ".auditooor" / "mvc_sidecar"
    d.mkdir(parents=True, exist_ok=True)
    (d / "s0.json").write_text(json.dumps({
        "cut": "src/contracts/Tranche.sol", "mutation_verified": True,
        "invariants": [{"id": "INV-1", "name": "conservation_no_value_created"}]}))
    m = cmb.build_matrix(ws)
    inv = m["assets"][0]["invariant_enumeration"]
    assert inv["conservation"]["status"] == "enumerated"
    assert inv["conservation"]["source"] == "mvc-harness"
    # the file is NOT in the not-enumerated set (harness-backed).
    assert "src/contracts/Tranche.sol" not in [x["asset_id"] for x in m["not_enumerated_assets"]]


def test_fuzz_campaign_receipt_credits_file_under_strict(tmp_path, monkeypatch):
    # a real fuzz_campaign_receipt over a file is run+campaign evidence -> credits
    # the conservation category (not comprehension-only) under strict.
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/contracts/Tranche.sol", "function": "deposit"}],
        dossiers={"tranche.md": "invariant conservation totalAssets == sum"},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": [{"file": "src/contracts/Tranche.sol", "function": "deposit",
                              "classification": "real-attack"}]})
    (ws / ".auditooor" / "fuzz_campaign_receipt.json").write_text(json.dumps({
        "schema": "auditooor.fuzz_campaign_receipt.v1",
        "campaigns": [{"engine": "medusa", "cut": "src/contracts/Tranche.sol",
                       "result": {"calls": 2_000_000}}]}))
    m = cmb.build_matrix(ws)
    inv = m["assets"][0]["invariant_enumeration"]
    assert inv["conservation"]["status"] == "enumerated"
    assert inv["conservation"]["source"] == "mvc-harness"  # credited as harness-backed
    assert "src/contracts/Tranche.sol" not in [x["asset_id"] for x in m["not_enumerated_assets"]]


# ---------------------------------------------------------------------------
# advisory-first / backward-compat
# ---------------------------------------------------------------------------
def test_default_posture_never_bricks_only_warns(tmp_path):
    # a multi-file ws where the collapsed per-repo dossier terminally enumerates
    # (default) but per-file some files lack a harness. Default posture: the primary
    # verdict is driven by the legacy per-repo grouping; the per-file gap is a WARN
    # reason, NOT a hard verdict flip introduced by this change.
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=_multifile_inscope(),
        # dossier references only 'Tranche' + carries a conservation cue; the repo
        # token 'contracts' also matches so the per-repo asset is terminally enumerated.
        dossiers={"contracts.md": ("# contracts dossier\nINV-1 conservation totalAssets == "
                                   "sum of adapters.\n")},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": [
                   {"file": "src/contracts/Tranche.sol", "function": "deposit", "classification": "real-attack"},
                   {"file": "src/contracts/Accounting.sol", "function": "accrue", "classification": "real-attack"},
                   {"file": "src/contracts/Rebalancer.sol", "function": "rebalance", "classification": "real-attack"}]})
    m = cmb.build_matrix(ws)
    # legacy per-repo asset is terminally enumerated -> not in the fail set.
    assert m["not_enumerated_assets"] == []
    # but a per-file WARN reason surfaces the collapsed gap (Accounting/Rebalancer have
    # no conservation cue referencing them under the per-file token match).
    assert any(r.startswith("WARN: per-file breakdown") for r in m["reasons"]), m["reasons"]


def test_strict_default_off_matches_legacy_denominator(tmp_path):
    # with strict unset, denominators.assets stays the LEGACY per-repo count (no
    # retroactive brick of a prior audit's saved matrix expectations).
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/foo/src/A.sol", "function": "f"},
                 {"file": "src/bar/src/B.sol", "function": "g"}],
        dossiers={"foo.md": "invariant conservation", "bar.md": "invariant conservation"},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": []})
    m = cmb.build_matrix(ws)
    assert m["denominators"]["assets"] == 2  # src/foo + src/bar (legacy)
    assert m["denominators"]["asset_grouping"] == "per-repo"
