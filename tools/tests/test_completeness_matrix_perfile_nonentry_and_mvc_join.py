"""Regression tests for the per-FILE floor's (1) non-entry file DROP and (2) empty-
invariants mvc per-file JOIN in completeness-matrix-build.py.

THE GAP (NUVA 2026-07-02): under AUDITOOOR_MATRIX_PERFILE_STRICT the per-file floor
reported 51 in-scope files with 0/10 enumerated invariants - the ONLY remaining
audit-complete FAIL. It was TWO problems:

(A) ~20 were NON-VALUE-MOVING / boilerplate / interface / sim files wrongly in the
    per-file denominator (Cosmos module codec/errors/events/keys/genesis boilerplate,
    module.go, query_server.go, simulation/simapp/testutil scaffolding, pure util
    slices/tools/query helpers, Solidity interfaces I<Name>.sol, pure crypto/byte
    libs). They expose no value-moving attack-surface function so they carry no
    invariant to enumerate - they must be DROPPED from the floor.

(B) value-moving Go files WITH a mutation-verified economic harness (reconcile/
    payout/valuation_engine/interest/shares - registered with invariants=[] but a
    named conservation `contract` test + a behavior-changing kill) still showed 0/10.
    The join skipped any sidecar with an empty `invariants` array = a serving-join.

Both fixes are STRICT-ONLY + never-false-pass: the default (flag-unset) posture is
byte-identical to before; a file is dropped ONLY when EVERY function is non-entry;
an empty-invariants sidecar credits a category ONLY when it carries a genuine
behavior-changing kill.
"""
import importlib.util
import json
from pathlib import Path

import pytest

_MOD = Path(__file__).resolve().parents[1] / "completeness-matrix-build.py"
_spec = importlib.util.spec_from_file_location("cmb_nonentry_mvc", _MOD)
cmb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cmb)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("AUDITOOOR_MATRIX_PERFILE_STRICT",
              "AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE"):
        monkeypatch.delenv(k, raising=False)


def _mk(ws: Path, *, inscope=None, dossiers=None, impact=None, fncov=None,
        mvc_sidecars=None, sol_sources=None):
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
    if mvc_sidecars is not None:
        d = a / "mvc_sidecar"
        d.mkdir(exist_ok=True)
        for name, body in mvc_sidecars.items():
            (d / name).write_text(json.dumps(body), encoding="utf-8")
    if sol_sources is not None:
        for rel, body in sol_sources.items():
            p = ws / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")


def _neset(m):
    return {x["asset_id"] for x in m["not_enumerated_assets"]}


# ---------------------------------------------------------------------------
# FIX 1 - non-entry file DROP (strict-only, never-false-pass)
# ---------------------------------------------------------------------------
def test_go_cosmos_nonentry_helper_recognizes_boilerplate():
    # dir-based
    assert cmb._is_go_cosmos_nonentry("src/vault/simulation/genesis.go", "")
    assert cmb._is_go_cosmos_nonentry("src/vault/simapp/app.go", "")
    assert cmb._is_go_cosmos_nonentry("x/foo/testutil/setup.go", "")
    # basename-based
    assert cmb._is_go_cosmos_nonentry("src/vault/types/codec.go", "")
    assert cmb._is_go_cosmos_nonentry("src/vault/types/errors.go", "")
    assert cmb._is_go_cosmos_nonentry("src/vault/module.go", "")
    assert cmb._is_go_cosmos_nonentry("src/vault/keeper/query_server.go", "")
    assert cmb._is_go_cosmos_nonentry("src/vault/utils/slices.go", "")
    # a value-moving keeper file is NOT non-entry (fail-closed)
    assert not cmb._is_go_cosmos_nonentry("src/vault/keeper/reconcile.go", "")
    assert not cmb._is_go_cosmos_nonentry("src/vault/keeper/payout.go", "")
    assert not cmb._is_go_cosmos_nonentry("src/vault/keeper/abci.go", "")
    # non-Go never matches here (Solidity handled by _is_fcc_filtered_nonentry)
    assert not cmb._is_go_cosmos_nonentry("src/contracts/Tranche.sol", "deposit")


def test_all_nonentry_go_boilerplate_dropped_under_strict(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[
            {"file": "src/vault/types/codec.go", "function": ""},
            {"file": "src/vault/simapp/app.go", "function": ""},
            {"file": "src/vault/module.go", "function": ""},
        ],
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": []})
    m = cmb.build_matrix(ws)
    # all three files are non-entry boilerplate -> NONE in the invariant floor.
    assert _neset(m) == set(), _neset(m)


def test_solidity_interface_and_crypto_lib_dropped_under_strict(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[
            # I<Upper>.sol interface, nameless body row
            {"file": "src/c/IFullERC20.sol", "function": ""},
            # I<Upper>.sol interface with named signatures (bare sigs -> non-entry)
            {"file": "src/c/modules/utils/ICustomToken.sol", "function": "burn"},
            {"file": "src/c/modules/utils/ICustomToken.sol", "function": "burnFrom"},
            # pure byte lib: all functions internal/pure -> non-entry
            {"file": "src/c/modules/utils/BytesLib.sol", "function": "toAddress"},
        ],
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": []},
        sol_sources={
            "src/c/IFullERC20.sol": "interface IFullERC20 { function totalSupply() external view returns (uint256); }",
            "src/c/modules/utils/ICustomToken.sol": (
                "interface ICustomToken { function burn(uint256 a) external; "
                "function burnFrom(address f, uint256 a) external; }"),
            "src/c/modules/utils/BytesLib.sol": (
                "library BytesLib { function toAddress(bytes memory b, uint256 s) "
                "internal pure returns (address) { return address(0); } }"),
        })
    m = cmb.build_matrix(ws)
    assert _neset(m) == set(), _neset(m)


def test_value_moving_file_with_entry_fn_NOT_dropped(tmp_path, monkeypatch):
    # NEVER-FALSE-PASS: a file with >=1 real value-moving external entry stays an
    # obligation even though a sibling function of it is internal/non-entry.
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[
            {"file": "src/c/Vault.sol", "function": "_helper"},   # internal
            {"file": "src/c/Vault.sol", "function": "deposit"},   # external entry
        ],
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": []},
        sol_sources={
            "src/c/Vault.sol": (
                "contract Vault { function _helper() internal {} "
                "function deposit(uint256 a) external { balance += a; } uint256 balance; }"),
        })
    m = cmb.build_matrix(ws)
    # Vault.sol has a real value-moving entry (deposit) and no harness -> stays.
    assert "src/c/Vault.sol" in _neset(m)


# ---------------------------------------------------------------------------
# FIX 2 - empty-invariants mvc per-file JOIN (strict-only, never-false-pass)
# ---------------------------------------------------------------------------
def _go_value_mover_inscope():
    # a genuine value-moving keeper file, registered in inscope as a nameless body row
    # (how the Go enumerator emits it) - it is NOT boilerplate (reconcile.go).
    return [{"file": "src/vault/keeper/reconcile.go", "function": ""}]


def test_empty_invariants_mvc_with_kill_credits_conservation_under_strict(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=_go_value_mover_inscope(),
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": []},
        mvc_sidecars={"reconcile.json": {
            "mutation_verified": True,
            "cut": "src/vault/keeper/reconcile.go",
            "invariants": [],  # THE gap: economic harness registered with no inv array
            "contract": "TestKeeperTestSuite/TestEconomicInvariant_Reconcile_Conservation",
            "cut_fn": "Keeper.PerformVaultInterestTransfer",
            "behavior_changing_kill_count": 1,
            "mutants_killed": 1,
            "mutant_results": [{"killed": True, "kill_kind": "behavior-changing",
                                "kill_invariant_frame": "reconcile conservation: reserves drop by exactly interest"}],
        }})
    m = cmb.build_matrix(ws)
    byid = {a["asset_id"]: a for a in m["assets"]}
    inv = byid["src/vault/keeper/reconcile.go"]["invariant_enumeration"]
    assert inv["conservation"]["status"] == "enumerated"
    assert inv["conservation"]["source"] == "mvc-harness"
    assert "src/vault/keeper/reconcile.go" not in _neset(m)


def test_empty_invariants_mvc_WITHOUT_kill_stays_not_enumerated(tmp_path, monkeypatch):
    # NEVER-FALSE-PASS: an empty-invariants sidecar with NO behavior-changing kill is
    # a vacuous/unrun harness -> credits nothing; the value-mover stays not-enumerated.
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/vault/keeper/reconcile.go", "function": "Reconcile"}],
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": [{"file": "src/vault/keeper/reconcile.go",
                              "function": "Reconcile", "classification": "real-attack"}]},
        mvc_sidecars={"reconcile.json": {
            "mutation_verified": True,
            "cut": "src/vault/keeper/reconcile.go",
            "invariants": [],
            "contract": "TestEconomicInvariant_Reconcile_Conservation",
            "behavior_changing_kill_count": 0,
            "mutants_killed": 0,
        }})
    m = cmb.build_matrix(ws)
    # Reconcile is a named external entry (not dropped by FIX 1) and its harness is
    # vacuous (no kill) -> the file is a genuine unharnessed value-mover, stays flagged.
    assert "src/vault/keeper/reconcile.go" in _neset(m)


def test_empty_invariants_credit_is_strict_only(tmp_path):
    # BACKWARD-COMPAT: in the DEFAULT (flag-unset) posture the empty-invariants-with-kill
    # crediting is NOT applied (the legacy per-repo grouping is byte-identical).
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/vault/keeper/reconcile.go", "function": "Reconcile"}],
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": []},
        mvc_sidecars={"reconcile.json": {
            "mutation_verified": True,
            "cut": "src/vault/keeper/reconcile.go",
            "invariants": [],
            "contract": "TestEconomicInvariant_Reconcile_Conservation",
            "behavior_changing_kill_count": 1,
            "mutants_killed": 1,
        }})
    # default posture: the repo-level mvc join does NOT credit an empty-invariants sidecar
    mvc_repo = cmb._mvc_asset_invariant_categories(ws)  # credit_empty_invariants defaults False
    assert "src/vault" not in mvc_repo or "conservation" not in mvc_repo.get("src/vault", set())
    # strict-flavoured per-file join DOES credit it
    mvc_file = cmb._mvc_asset_invariant_categories(
        ws, asset_key=cmb._perfile_asset_of, credit_empty_invariants=True)
    assert "conservation" in mvc_file.get("src/vault/keeper/reconcile.go", set())


# ---------------------------------------------------------------------------
# backward-compat: default posture unaffected by BOTH fixes
# ---------------------------------------------------------------------------
def test_default_posture_boilerplate_not_dropped_and_no_extra_credit(tmp_path):
    # In default posture neither the non-entry DROP nor the empty-invariants credit
    # engages: the per-file breakdown still lists the boilerplate file (visibility),
    # matching pre-fix behavior.
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/vault/types/codec.go", "function": ""},
                 {"file": "src/vault/keeper/reconcile.go", "function": ""}],
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": []},
        mvc_sidecars={"reconcile.json": {
            "mutation_verified": True, "cut": "src/vault/keeper/reconcile.go",
            "invariants": [], "behavior_changing_kill_count": 1, "mutants_killed": 1}})
    m = cmb.build_matrix(ws)
    # default primary grouping is per-repo (src/vault) - single asset; the per-file
    # breakdown still shows BOTH files with no harness-backed set (no strict drop/credit).
    pf_neg = {x["asset_id"] for x in m["perfile_breakdown"]["not_enumerated_assets"]}
    assert "src/vault/types/codec.go" in pf_neg
    assert "src/vault/keeper/reconcile.go" in pf_neg
