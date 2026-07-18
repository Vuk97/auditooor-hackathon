"""Tests for completeness-matrix-build.py - the enumeration-floor JOIN gate.

Core guarantee under test: a cell that was NEVER ENUMERATED (asset with no
invariant set, blank impact ledger, function with no coverage record) FAILS
CLOSED - it is not WARN-passed. This is the fix for the absence-is-invisible
class (workflow wf_67f3f2c3, Morpho 11/15-undossiered-assets hole)."""
import importlib.util
import json
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "completeness-matrix-build.py"
_spec = importlib.util.spec_from_file_location("cmb", _MOD)
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
    # references the asset + carries cues for several categories + invariant words
    return (f"# {asset_repo} dossier\nINV-1 conservation: totalAssets == sum of adapter. "
            "INV-2 monotonicity: share price never decrease. INV-3 authorization: onlyOwner role. "
            "INV-4 atomicity: reentrancy CEI. INV-5 uniqueness: no double-claim nonce. "
            "INV-6 freshness: timelock validAt. INV-7 determinism: no overflow wexp. "
            "INV-8 bounds: cap <= max. INV-9 custody: no residue sweep. INV-10 ordering: accrue before mutate.\n")


def test_undossiered_asset_fails_closed(tmp_path):
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/foo/src/A.sol", "function": "f"},
                 {"file": "src/bar/src/B.sol", "function": "g"}],
        dossiers={"foo.md": _full_dossier("foo")},  # bar has NO dossier
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": [{"file": "src/foo/src/A.sol", "function": "f", "classification": "real-attack"},
                             {"file": "src/bar/src/B.sol", "function": "g", "classification": "real-attack"}]})
    m = cmb.build_matrix(ws)
    assert m["verdict"] == "incomplete"
    ids = [x["asset_id"] for x in m["not_enumerated_assets"]]
    assert "src/bar" in ids and "src/foo" not in ids


def test_blank_impact_ledger_fails(tmp_path):
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/foo/src/A.sol", "function": "f"}],
        dossiers={"foo.md": _full_dossier("foo")},
        impact={"classes": {"theft": "", "freeze": "not-enumerated"}},
        fncov={"functions": [{"file": "src/foo/src/A.sol", "function": "f", "classification": "real-attack"}]})
    m = cmb.build_matrix(ws)
    assert m["verdict"] == "incomplete"
    assert any("impact" in r.lower() for r in m["reasons"])


def test_missing_inscope_fails_closed(tmp_path):
    ws = tmp_path / "ws"
    _mk(ws, dossiers={"foo.md": _full_dossier("foo")})  # NO inscope_units.jsonl
    m = cmb.build_matrix(ws)
    assert m["verdict"] == "incomplete"
    assert any("inscope" in r.lower() for r in m["reasons"])


def test_function_with_no_record_is_not_enumerated(tmp_path):
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/foo/src/A.sol", "function": "f"},
                 {"file": "src/foo/src/A.sol", "function": "h"}],
        dossiers={"foo.md": _full_dossier("foo")},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": [{"file": "src/foo/src/A.sol", "function": "f", "classification": "real-attack"}]})
    m = cmb.build_matrix(ws)  # h has no coverage record -> not-enumerated
    assert m["cells"]["not_enumerated"] == 1
    assert m["verdict"] == "incomplete"


def test_all_enumerated_passes(tmp_path):
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/foo/src/A.sol", "function": "f"}],
        dossiers={"foo.md": _full_dossier("foo")},
        impact={"classes": {"theft": "ruled-out-source-cited", "freeze": "not-applicable"}},
        fncov={"functions": [{"file": "src/foo/src/A.sol", "function": "f",
                              "classification": "real-attack",
                              "evidence": ["mutation-killed:A.sol:f:1"]}]})
    m = cmb.build_matrix(ws)
    assert m["verdict"] == "complete", m["reasons"]
    assert m["cells"]["not_enumerated"] == 0
    assert m["cells"]["terminal"] == 1


def test_check_mode_rc_and_rebuttal(tmp_path):
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/foo/src/A.sol", "function": "f"},
                 {"file": "src/bar/src/B.sol", "function": "g"}],
        dossiers={"foo.md": _full_dossier("foo")},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": []})
    # incomplete -> --check returns 1
    rc = cmb.main(["--workspace", str(ws), "--check"])
    assert rc == 1
    # add rebuttal -> ok-rebuttal -> rc 0
    _mk(ws, rebuttal="<!-- completeness-matrix-rebuttal: bar is a test-only shim, operator-approved -->")
    rc2 = cmb.main(["--workspace", str(ws), "--check"])
    assert rc2 == 0
    # artifacts written
    assert (ws / ".auditooor" / "completeness_matrix.json").is_file()
    assert (ws / "COMPLETENESS_MATRIX.md").is_file()


def test_phantom_receive_from_comment_is_credited(tmp_path):
    """A `receive`/`fallback` cell misparsed from a COMMENT (no real declaration)
    must be credited as a non-entry (strata 2026-07-01: Tranche.sol had only a
    'wishes to receive.' comment, no receive() decl, pinning the matrix INCOMPLETE
    forever). FALSE-GREEN-SAFE: a REAL receive() external {...} is still flagged."""
    ws = tmp_path / "ws"
    src = ws / "src" / "contracts"
    src.mkdir(parents=True, exist_ok=True)
    # phantom: only a comment mentions receive, no declaration
    (src / "Phantom.sol").write_text(
        "pragma solidity ^0.8.28;\n"
        "contract Phantom {\n"
        "    // whoever wishes to receive. this is prose, not a decl\n"
        "    function real() external {}\n"
        "}\n", encoding="utf-8")
    assert cmb._is_fcc_filtered_nonentry(ws, "src/contracts/Phantom.sol", "receive") is True
    assert cmb._is_fcc_filtered_nonentry(ws, "src/contracts/Phantom.sol", "fallback") is True

    # real receive() external with logic body -> NOT filtered (still an attack surface)
    (src / "Real.sol").write_text(
        "pragma solidity ^0.8.28;\n"
        "contract Real {\n"
        "    receive() external payable { doStuff(); }\n"
        "}\n", encoding="utf-8")
    assert cmb._is_fcc_filtered_nonentry(ws, "src/contracts/Real.sol", "receive") is False


def test_flow_axis_undriven_flow_is_incomplete_cell(tmp_path):
    """business-flow (cross-module combination) axis: a drivable flow no hunt
    touched -> matrix incomplete + a 'flow' worklist row (de-orphans
    business_flows into a real enumeration requirement)."""
    ws = tmp_path / "ws"
    a = ws / ".auditooor"
    a.mkdir(parents=True)
    # two 'deposit' fns across modules, NO hunt sidecar -> undriven flow
    (a / "inscope_units.jsonl").write_text(
        json.dumps({"file": "src/Vault.sol", "function": "deposit"}) + "\n" +
        json.dumps({"file": "src/Router.sol", "function": "deposit"}) + "\n", encoding="utf-8")
    m = cmb.build_matrix(ws)
    assert m["flows"]["present"] is True
    assert m["flows"]["undriven_count"] >= 1
    assert "BF-asset-lifecycle-deposit" in m["flows"]["undriven"]
    assert m["verdict"] == "incomplete"
    assert any(r.get("axis") == "flow" for r in m["enumeration_worklist"]), m["enumeration_worklist"]


def _mk_mvc(ws: Path, sidecars):
    d = ws / ".auditooor" / "mvc_sidecar"
    d.mkdir(parents=True, exist_ok=True)
    for i, sc in enumerate(sidecars):
        (d / f"s{i}.json").write_text(json.dumps(sc), encoding="utf-8")


def _mk_hunt(ws: Path, anchors):
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    d.mkdir(parents=True, exist_ok=True)
    for i, fa in enumerate(anchors):
        (d / f"h{i}.json").write_text(json.dumps({"function_anchor": fa, "result": {"verdict": "kill"}}))


def test_mvc_harness_enumerates_asset_invariant(tmp_path):
    # NUVA regression: an asset with NO comprehension dossier but a mutation-verified
    # conservation harness must be credited (mvc-harness) -> not falsely NOT-ENUMERATED.
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/vault/keeper/x.go", "function": "Deposit"}],
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": [{"file": "src/vault/keeper/x.go", "function": "Deposit", "classification": "real-attack"}]})
    _mk_mvc(ws, [{"cut": "src/vault/keeper/x.go", "mutation_verified": True,
                  "invariants": [{"id": "INV-1", "name": "conservation_no_value_created"}]}])
    m = cmb.build_matrix(ws)
    assert not m["not_enumerated_assets"], "mvc-harness must enumerate the asset invariant set"
    inv = m["assets"][0]["invariant_enumeration"]
    assert inv["conservation"]["status"] == "enumerated"
    assert inv["conservation"]["source"] == "mvc-harness"


def test_empty_function_cell_is_not_a_gap(tmp_path):
    # a file-level inscope row with no function name is not a callable attack surface
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/vault/keeper/codec.go", "function": ""}],
        dossiers={"vault.md": _full_dossier("vault")},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0}, "functions": []})
    m = cmb.build_matrix(ws)
    assert m["cells"]["not_enumerated"] == 0
    assert m["assets"][0]["functions"][0]["coverage_status"] == "no-callable-function"


def test_hunt_verdict_credits_fcc_absent_fn(tmp_path):
    # an fcc-absent named fn with a real hunt verdict is credited (multi-store)
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/p/prime/DVR.sol", "function": "sweep"}],
        dossiers={"p.md": _full_dossier("p")},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0}, "functions": []})
    _mk_hunt(ws, [{"file": "src/p/prime/DVR.sol", "fn": "DVR.sol::sweep"}])
    m = cmb.build_matrix(ws)
    assert m["cells"]["not_enumerated"] == 0
    assert m["assets"][0]["functions"][0]["coverage_status"] == "covered-hunt-verdict"


def test_interface_convention_file_credited_nonentry(tmp_path):
    # I<Upper>.sol interface signature (not under /interfaces/) is non-attack-surface
    ws = tmp_path / "ws"
    (ws / "src" / "p" / "modules").mkdir(parents=True, exist_ok=True)
    (ws / "src" / "p" / "modules" / "ICustomToken.sol").write_text(
        "interface ICustomToken { function burn(uint256 a) external; }", encoding="utf-8")
    _mk(ws,
        inscope=[{"file": "src/p/modules/ICustomToken.sol", "function": "burn"}],
        dossiers={"p.md": _full_dossier("p")},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0}, "functions": []})
    m = cmb.build_matrix(ws)
    assert m["cells"]["not_enumerated"] == 0
    assert m["assets"][0]["functions"][0]["coverage_status"] == "out-of-scope-fcc-filtered"


def test_real_uncovered_fn_still_fails_closed(tmp_path):
    # NEVER-FALSE-PASS: a real named fn with NO fcc record, NO hunt verdict, and a
    # non-interface impl file stays NOT-ENUMERATED (the floor holds).
    ws = tmp_path / "ws"
    (ws / "src" / "p").mkdir(parents=True, exist_ok=True)
    (ws / "src" / "p" / "Vault.sol").write_text(
        "contract Vault { function steal(uint256 a) external { } }", encoding="utf-8")
    _mk(ws,
        inscope=[{"file": "src/p/Vault.sol", "function": "steal"}],
        dossiers={"p.md": _full_dossier("p")},
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0}, "functions": []})
    m = cmb.build_matrix(ws)
    assert m["cells"]["not_enumerated"] == 1
    assert m["verdict"] == "incomplete"


# ---------------------------------------------------------------------------
# F1 invariant-axis nonentry parity (2026-07-03): the INVARIANT-axis worklist
# rows must tag dropped_nonentry for genuinely non-value-moving files (interface/
# library/boilerplate) EXACTLY as the function axis does - but MUST stay
# value_moving (fail-closed) for a file whose non-entry rests only on a
# function='' enumeration-failure placeholder (never green-wash a Go value-mover).
# ---------------------------------------------------------------------------
def _inv_kinds(rows, asset_substr):
    return {r["cell_kind"] for r in rows
            if r.get("axis") == "invariant" and asset_substr in str(r.get("asset", ""))}


def test_invariant_axis_demotes_solidity_interface_but_not_broken_enum_go():
    m = {
        "assets": [
            # 1. Solidity interface: all_nonentry via REAL signatures -> demoted.
            {"asset_id": "src/contracts/IFullERC20.sol",
             "invariant_categories_not_enumerated": ["conservation", "authorization"],
             "all_nonentry": True, "has_real_function": True, "file_dispositioned": False,
             "functions": [{"function": "transfer", "coverage_status": "out-of-scope-fcc-filtered"}]},
            # 2. Solidity value-mover: has a real entry fn -> value_moving obligation stands.
            {"asset_id": "src/contracts/CrossChainManager.sol",
             "invariant_categories_not_enumerated": ["conservation"],
             "all_nonentry": False, "has_real_function": True, "file_dispositioned": False,
             "functions": [{"function": "burn", "coverage_status": "not-enumerated"}]},
            # 3. Go value-mover with BROKEN enumeration (function='' placeholder): all_nonentry
            #    True but has_real_function False -> MUST stay value_moving (no green-wash).
            {"asset_id": "src/vault/keeper/reconcile.go",
             "invariant_categories_not_enumerated": ["conservation", "monotonicity"],
             "all_nonentry": True, "has_real_function": False, "file_dispositioned": False,
             "functions": [{"function": "", "coverage_status": "no-callable-function"}]},
            # 4. Explicitly-dispositioned file -> demoted regardless of enumeration.
            {"asset_id": "src/contracts/PrivilegedOnly.sol",
             "invariant_categories_not_enumerated": ["conservation"],
             "all_nonentry": False, "has_real_function": True, "file_dispositioned": True,
             "functions": [{"function": "adminSet", "coverage_status": "not-enumerated"}]},
        ],
        "impact_enumeration": {}, "flows": {}, "mechanism_axis": {},
    }
    rows = cmb.build_enumeration_worklist(m)
    # Solidity interface: demoted.
    assert _inv_kinds(rows, "IFullERC20.sol") == {"dropped_nonentry"}, "interface must demote"
    # Solidity value-mover: obligation stands.
    assert _inv_kinds(rows, "CrossChainManager.sol") == {"value_moving"}, "value-mover must stay"
    # Go broken-enum value-mover: FAIL-CLOSED -> stays value_moving (never green-washed).
    assert _inv_kinds(rows, "reconcile.go") == {"value_moving"}, \
        "broken-enum Go value-mover must NOT be demoted (fail-closed)"
    # Dispositioned file: demoted.
    assert _inv_kinds(rows, "PrivilegedOnly.sol") == {"dropped_nonentry"}, "dispositioned must demote"


def test_invariant_axis_path_shape_demotes_even_without_all_nonentry_flag():
    # A stale matrix built BEFORE all_nonentry/has_real_function were emitted: the
    # unambiguous interface PATH shape still demotes (belt-and-suspenders).
    m = {
        "assets": [
            {"asset_id": "src/interfaces/ICCTPv1WithExecutor.sol",
             "invariant_categories_not_enumerated": ["conservation"],
             "functions": [{"function": "depositForBurn", "coverage_status": "out-of-scope-fcc-filtered"}]},
        ],
        "impact_enumeration": {}, "flows": {}, "mechanism_axis": {},
    }
    rows = cmb.build_enumeration_worklist(m)
    assert _inv_kinds(rows, "ICCTPv1WithExecutor.sol") == {"dropped_nonentry"}
