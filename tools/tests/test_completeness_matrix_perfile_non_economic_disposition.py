"""Regression tests for the per-FILE floor's NON-ECONOMIC-DISPOSITION credit in
completeness-matrix-build.py.

THE GAP (NUVA 2026-07-02): under AUDITOOOR_MATRIX_PERFILE_STRICT the per-file floor
pinned onlyOwner-only config/deploy files (DepositorFactory / WithdrawalFactory -
Ownable2Step EIP-1167 clone factories, transfer_hit=false) as NOT-ENUMERATED,
demanding a fund/share ECONOMIC-invariant fuzz harness even though the file has NO
unprivileged economic surface (nothing to conserve). The SAME per-unit
non_economic_dispositions.json artifact + never-false-pass guards that the
invariant-fuzz / cross-function / honesty gates already honor was simply NOT read by
the completeness matrix - a serving-join over-strictness bug.

THE FIX (strict-only + artifact-gated + never-false-pass): when EVERY in-scope
function of a file maps to an ACCEPTED disposition (bounded classification +
>=40-char rationale + on-disk + NOT a transfer_hit value-mover), the file is credited
terminal (non-economic-surface-dispositioned) and dropped from the floor - the same
credit label the sibling gates use. Custody (a real token transfer) can NEVER be
silenced: the shared lib rejects any transfer_hit file. Default (flag-unset) posture
is byte-identical to before.
"""
import importlib.util
import json
import os
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parents[1]
_MOD = _TOOLS / "completeness-matrix-build.py"
_spec = importlib.util.spec_from_file_location("cmb_ned", _MOD)
cmb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cmb)

# Hermetic HMAC secret so the operator-approval token verifies (FIX 1: a
# disposition now needs an operator-signed disposition-approve token).
os.environ.setdefault("AUDITOOOR_MCP_SECRET", "test-secret-for-non-economic-disposition")
_tspec = importlib.util.spec_from_file_location(
    "auditooor_mcp_token_cmb", _TOOLS / "auditooor_mcp_token.py")
_tok = importlib.util.module_from_spec(_tspec)
_tspec.loader.exec_module(_tok)

_SCHEMA = "auditooor.non_economic_disposition.v1"


def _approval(ws: Path) -> str:
    token, _ = _tok.issue_token(str(ws), owner="operator",
                                scope=["disposition-approve"], log=False)
    return token


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("AUDITOOOR_MATRIX_PERFILE_STRICT",
              "AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE"):
        monkeypatch.delenv(k, raising=False)


def _mk(ws: Path, *, inscope=None, impact=None, fncov=None, sol_sources=None,
        dispositions=None, value_moving=None):
    a = ws / ".auditooor"
    a.mkdir(parents=True, exist_ok=True)
    if inscope is not None:
        (a / "inscope_units.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in inscope), encoding="utf-8")
    if impact is not None:
        (a / "exploit_class_coverage.json").write_text(json.dumps(impact), encoding="utf-8")
    if fncov is not None:
        (a / "function_coverage_completeness.json").write_text(json.dumps(fncov), encoding="utf-8")
    if sol_sources is not None:
        for rel, body in sol_sources.items():
            p = ws / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
    if dispositions is not None:
        (a / "non_economic_dispositions.json").write_text(
            json.dumps({"schema": _SCHEMA, "approval_ref": _approval(ws),
                        "dispositions": dispositions}), encoding="utf-8")
    if value_moving is not None:
        (a / "value_moving_functions.json").write_text(
            json.dumps({"functions": value_moving}), encoding="utf-8")


def _neset(m):
    out = set()
    for x in m["not_enumerated_assets"]:
        out.add(x if isinstance(x, str) else x.get("asset_id"))
    return out


_FACTORY_SRC = (
    "contract DepositorFactory { mapping(address=>address) public depositors; "
    "function createDepositor(address s) external onlyOwner returns (address d) "
    "{ depositors[s] = address(1); return address(1); } }")

_RATIONALE = (
    "onlyOwner EIP-1167 clone factory - Ownable2Step-gated admin wiring that deploys "
    "clones; custodies no user funds (transfer_hit=false), privileged-only. No "
    "fund/share conservation invariant applies to the factory.")


def _factory_inscope():
    return [
        {"file": "src/c/DepositorFactory.sol", "function": "createDepositor"},
    ]


def test_dispositioned_factory_credited_terminal_under_strict(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=_factory_inscope(),
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": []},
        sol_sources={"src/c/DepositorFactory.sol": _FACTORY_SRC},
        value_moving=[{"file": "src/c/DepositorFactory.sol", "function": "createDepositor",
                       "transfer_hit": False, "ledger_write_hit": True}],
        dispositions=[{"repo": "src/c/DepositorFactory.sol",
                       "classification": "non-economic-rationale",
                       "cut_path": "src/c/DepositorFactory.sol",
                       "rationale": _RATIONALE}])
    m = cmb.build_matrix(ws)
    # the factory is dispositioned -> NOT in the invariant floor, no not-enum cell.
    assert "src/c/DepositorFactory.sol" not in _neset(m)
    assert m["cells"]["not_enumerated"] == 0
    byid = {a["asset_id"]: a for a in m["assets"]}
    row = byid["src/c/DepositorFactory.sol"]
    assert row.get("non_economic_disposition", {}).get("credited") is True
    fn = row["functions"][0]
    assert fn["coverage_status"] == cmb._NED_MOD.CREDIT_LABEL


def test_transfer_hit_file_NOT_dispositioned_even_with_artifact(tmp_path, monkeypatch):
    # NEVER-FALSE-PASS: a file whose value-moving record has transfer_hit=true is a real
    # custody mover; the shared lib REJECTS the disposition -> the file stays an obligation.
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=[{"file": "src/c/Vault.sol", "function": "withdraw"}],
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": []},
        sol_sources={"src/c/Vault.sol": (
            "contract Vault { function withdraw(uint256 a) external "
            "{ token.transfer(msg.sender, a); } }")},
        value_moving=[{"file": "src/c/Vault.sol", "function": "withdraw",
                       "transfer_hit": True, "ledger_write_hit": True}],
        dispositions=[{"repo": "src/c/Vault.sol",
                       "classification": "non-economic-rationale",
                       "cut_path": "src/c/Vault.sol",
                       "rationale": _RATIONALE}])
    m = cmb.build_matrix(ws)
    assert "src/c/Vault.sol" in _neset(m)


def test_short_rationale_disposition_rejected(tmp_path, monkeypatch):
    # NEVER-FALSE-PASS: a rubber-stamp rationale (<40 chars) never credits.
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=_factory_inscope(),
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": []},
        sol_sources={"src/c/DepositorFactory.sol": _FACTORY_SRC},
        value_moving=[{"file": "src/c/DepositorFactory.sol", "function": "createDepositor",
                       "transfer_hit": False, "ledger_write_hit": True}],
        dispositions=[{"repo": "src/c/DepositorFactory.sol",
                       "classification": "non-economic-rationale",
                       "cut_path": "src/c/DepositorFactory.sol",
                       "rationale": "config only"}])
    m = cmb.build_matrix(ws)
    assert "src/c/DepositorFactory.sol" in _neset(m)


def test_disposition_credit_is_strict_only(tmp_path):
    # BACKWARD-COMPAT: in the DEFAULT (flag-unset) posture the disposition credit is
    # NOT applied (only the per-repo grouping runs; per-file breakdown still lists it).
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=_factory_inscope(),
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"functions": []},
        sol_sources={"src/c/DepositorFactory.sol": _FACTORY_SRC},
        value_moving=[{"file": "src/c/DepositorFactory.sol", "function": "createDepositor",
                       "transfer_hit": False, "ledger_write_hit": True}],
        dispositions=[{"repo": "src/c/DepositorFactory.sol",
                       "classification": "non-economic-rationale",
                       "cut_path": "src/c/DepositorFactory.sol",
                       "rationale": _RATIONALE}])
    m = cmb.build_matrix(ws)
    # per-file breakdown (always emitted) still shows the file with no harness-backed
    # set in default posture (the disposition credit is strict-only).
    pf_neg = {x["asset_id"] for x in m["perfile_breakdown"]["not_enumerated_assets"]}
    assert "src/c/DepositorFactory.sol" in pf_neg


def test_no_artifact_behaves_identically(tmp_path, monkeypatch):
    # BACKWARD-COMPAT: a ws WITHOUT the disposition artifact keeps the pre-fix strict
    # behavior (the factory is flagged - no silent free pass).
    monkeypatch.setenv("AUDITOOOR_MATRIX_PERFILE_STRICT", "1")
    ws = tmp_path / "ws"
    _mk(ws,
        inscope=_factory_inscope(),
        impact={"classes": {"theft": "ruled-out"}},
        fncov={"verdict": "pass-fully-covered", "counts": {"hollow": 0, "untouched": 0},
               "functions": []},
        sol_sources={"src/c/DepositorFactory.sol": _FACTORY_SRC})
    m = cmb.build_matrix(ws)
    assert "src/c/DepositorFactory.sol" in _neset(m)
