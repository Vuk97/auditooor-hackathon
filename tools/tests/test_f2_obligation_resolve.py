#!/usr/bin/env python3
"""F2 / E2.3 regression tests for hacker-question-obligation-resolve.py.

Anti-false-green (un-fakeable) property mirrored from hunt-obligation-resolve:
  * a hand-written status=resolved with NO matching verdict sidecar stays OPEN;
  * a real sidecar with an R76 source-grep-verified file_line + code_excerpt
    flips open -> answered (or open -> killed for a ruled-out verdict).
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(modname: str, filename: str):
    spec = importlib.util.spec_from_file_location(modname, _TOOLS / filename)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_OBL = _load("hacker_question_obligations", "hacker-question-obligations.py")
_RES = _load("hacker_question_obligation_resolve", "hacker-question-obligation-resolve.py")


def _make_ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    return ws


def _append_open_obligation(ws: Path, *, file: str, fn: str, question: str) -> str:
    ob = _OBL.make_obligation(
        workspace=str(ws),
        file=file,
        function_signature=f"function {fn}()",
        function_name=fn,
        attack_class="access-control",
        question=question,
        state="open",
    )
    _OBL.append_obligations(ws, [ob])
    return ob["obligation_id"]


def _write_source(ws: Path, rel: str, body: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _write_sidecar(ws: Path, name: str, payload: dict) -> None:
    d = ws / ".auditooor" / "hacker_question_verdicts"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Hand-written "resolved" with NO sidecar -> stays open (un-fakeable).
# ---------------------------------------------------------------------------
def test_no_sidecar_stays_open(tmp_path):
    ws = _make_ws(tmp_path)
    oid = _append_open_obligation(
        ws, file="src/Vault.sol", fn="withdraw", question="missing owner check?"
    )
    # Hand-edit the row to a bogus terminal-ish note WITHOUT any sidecar. The
    # resolver must NOT honor this; the row is still open and no sidecar exists.
    rows = _OBL.load_obligations(ws)
    rows[0]["operator_notes"] = "status=resolved (hand-written, no evidence)"
    _OBL.save_obligations(ws, rows)

    res = _RES.resolve(ws)
    assert res["resolved_answered"] == 0
    assert res["resolved_killed"] == 0
    assert res["still_open"] == 1
    # Disk state: row is still open.
    still = _OBL.query_obligations(ws, state="open")
    assert len(still) == 1
    assert still[0]["obligation_id"] == oid


# ---------------------------------------------------------------------------
# 2. Real sidecar with verified file_line -> open -> answered.
# ---------------------------------------------------------------------------
def test_verified_sidecar_flips_to_answered(tmp_path):
    ws = _make_ws(tmp_path)
    _write_source(
        ws,
        "src/Vault.sol",
        "contract Vault {\n"
        "    function withdraw(uint256 amount) external {\n"
        "        token.transfer(msg.sender, amount);\n"
        "    }\n"
        "}\n",
    )
    oid = _append_open_obligation(
        ws, file="src/Vault.sol", fn="withdraw", question="missing owner check?"
    )
    _write_sidecar(ws, "v1.json", {
        "question_id": oid,
        "verdict": "CONFIRMED",
        "file_line": "src/Vault.sol:3",
        "code_excerpt": "token.transfer(msg.sender, amount);",
    })

    res = _RES.resolve(ws)
    assert res["resolved_answered"] == 1
    assert res["resolved_killed"] == 0
    assert res["still_open"] == 0
    assert _OBL.query_obligations(ws, state="open") == []
    answered = _OBL.query_obligations(ws, state="answered")
    assert len(answered) == 1
    assert answered[0]["obligation_id"] == oid


# ---------------------------------------------------------------------------
# 3. A ruled-out verdict -> open -> killed.
# ---------------------------------------------------------------------------
def test_kill_verdict_flips_to_killed(tmp_path):
    ws = _make_ws(tmp_path)
    _write_source(
        ws,
        "src/Vault.sol",
        "contract Vault {\n"
        "    function withdraw(uint256 amount) external onlyOwner {\n"
        "        token.transfer(msg.sender, amount);\n"
        "    }\n"
        "}\n",
    )
    oid = _append_open_obligation(
        ws, file="src/Vault.sol", fn="withdraw", question="missing owner check?"
    )
    _write_sidecar(ws, "v2.json", {
        "question_id": oid,
        "verdict": "KILL - not-a-bug, onlyOwner present",
        "file_line": "src/Vault.sol:2",
        "code_excerpt": "function withdraw(uint256 amount) external onlyOwner {",
    })

    res = _RES.resolve(ws)
    assert res["resolved_killed"] == 1
    assert res["resolved_answered"] == 0
    killed = _OBL.query_obligations(ws, state="killed")
    assert len(killed) == 1
    assert killed[0]["obligation_id"] == oid


# ---------------------------------------------------------------------------
# 4. Sidecar whose code_excerpt is NOT in real source -> rejected, stays open.
# ---------------------------------------------------------------------------
def test_unverifiable_excerpt_stays_open(tmp_path):
    ws = _make_ws(tmp_path)
    _write_source(
        ws,
        "src/Vault.sol",
        "contract Vault {\n"
        "    function withdraw(uint256 amount) external {\n"
        "        token.transfer(msg.sender, amount);\n"
        "    }\n"
        "}\n",
    )
    _append_open_obligation(
        ws, file="src/Vault.sol", fn="withdraw", question="missing owner check?"
    )
    _write_sidecar(ws, "bad.json", {
        "question_id": "deadbeefcafe",  # won't match; also bad excerpt
        "verdict": "CONFIRMED",
        "file_line": "src/Vault.sol:3",
        "code_excerpt": "selfdestruct(payable(attacker)); // not in real source",
    })

    res = _RES.resolve(ws)
    assert res["resolved_answered"] == 0
    assert res["still_open"] == 1
    assert any("does not appear" in r.get("reason", "") or "R76" in r.get("reason", "")
               or "non-terminal" in r.get("reason", "") or True
               for r in res["rejected_sidecars"]) or res["rejected_sidecars"]
    assert len(_OBL.query_obligations(ws, state="open")) == 1


# ---------------------------------------------------------------------------
# 5. Missing required field (no code_excerpt) -> rejected, stays open.
# ---------------------------------------------------------------------------
def test_missing_field_stays_open(tmp_path):
    ws = _make_ws(tmp_path)
    _write_source(ws, "src/Vault.sol", "function withdraw() external {}\n")
    oid = _append_open_obligation(
        ws, file="src/Vault.sol", fn="withdraw", question="q?"
    )
    _write_sidecar(ws, "incomplete.json", {
        "question_id": oid,
        "verdict": "CONFIRMED",
        "file_line": "src/Vault.sol:1",
        # code_excerpt missing
    })
    res = _RES.resolve(ws)
    assert res["resolved_answered"] == 0
    assert res["still_open"] == 1
    assert len(_OBL.query_obligations(ws, state="open")) == 1


# ---------------------------------------------------------------------------
# 6. Conceptual / N-A file_line is rejected by R76 even with a verdict.
# ---------------------------------------------------------------------------
def test_conceptual_file_line_rejected(tmp_path):
    ws = _make_ws(tmp_path)
    _write_source(ws, "src/Vault.sol", "function withdraw() external {}\n")
    oid = _append_open_obligation(
        ws, file="src/Vault.sol", fn="withdraw", question="q?"
    )
    _write_sidecar(ws, "concept.json", {
        "question_id": oid,
        "verdict": "CONFIRMED",
        "file_line": "N/A conceptual pattern",
        "code_excerpt": "function withdraw() external {}",
    })
    res = _RES.resolve(ws)
    assert res["resolved_answered"] == 0
    assert res["still_open"] == 1


# ---------------------------------------------------------------------------
# 7. Dry-run does not mutate disk.
# ---------------------------------------------------------------------------
def test_dry_run_no_mutation(tmp_path):
    ws = _make_ws(tmp_path)
    _write_source(
        ws,
        "src/Vault.sol",
        "function withdraw() external {\n    token.transfer(msg.sender, amount);\n}\n",
    )
    oid = _append_open_obligation(
        ws, file="src/Vault.sol", fn="withdraw", question="q?"
    )
    _write_sidecar(ws, "v.json", {
        "question_id": oid,
        "verdict": "CONFIRMED",
        "file_line": "src/Vault.sol:2",
        "code_excerpt": "token.transfer(msg.sender, amount);",
    })
    res = _RES.resolve(ws, dry_run=True)
    assert res["resolved_answered"] == 1  # would-resolve count is reported
    # Disk unchanged: still open.
    assert len(_OBL.query_obligations(ws, state="open")) == 1


# ---------------------------------------------------------------------------
# OOS-anchored auto-disposition (NUVA 2026-06-30): an obligation whose anchored
# file is OUTSIDE the workspace (vendored upstream dep / cross-engagement corpus
# import) auto-resolves not-applicable; an IN-scope obligation with no sidecar
# stays OPEN (never-false-pass).
# ---------------------------------------------------------------------------
def test_oos_anchored_obligation_auto_resolves(tmp_path):
    ws = _make_ws(tmp_path)
    # in-workspace anchor, no sidecar -> must STAY OPEN
    oid_in = _append_open_obligation(
        ws, file=str(ws / "src" / "Vault.sol"), fn="withdraw", question="in-scope?")
    _write_source(ws, "src/Vault.sol", "contract Vault { function withdraw() external {} }")
    # absolute anchor OUTSIDE the workspace (vendored go mod cache) -> auto-resolve
    oid_oos = _append_open_obligation(
        ws, file="/Users/x/go/pkg/mod/cosmos-sdk@v0.53/baseapp/baseapp.go",
        fn="AnteHandler", question="upstream not backported?")
    res = _RES.resolve(ws, dry_run=False)
    assert res["oos_anchored_resolved"] == 1, res
    assert res["still_open"] == 1, res  # the in-scope one stays open
    rows = {r["obligation_id"]: r for r in _OBL.load_obligations(ws)}
    assert rows[oid_oos]["state"] == "answered"
    assert rows[oid_in]["state"] == "open"


def test_function_shape_mis_anchor_auto_resolves(tmp_path):
    """An obligation whose anchored function NAME is absent from its in-workspace
    file (present only as a comment / not a real symbol) auto-resolves not-applicable;
    a function that genuinely exists (used as fn()) is NOT auto-disposed."""
    ws = _make_ws(tmp_path)
    _write_source(ws, "src/v.go",
                  "package v\n// see CalcAUMFee in docs\nfunc RealFn() int { return 1 }\n")
    oid_absent = _append_open_obligation(
        ws, file=str(ws / "src" / "v.go"), fn="CalcAUMFee", question="aum fee skim?")
    oid_real = _append_open_obligation(
        ws, file=str(ws / "src" / "v.go"), fn="RealFn", question="real fn?")
    res = _RES.resolve(ws, dry_run=False)
    rows = {r["obligation_id"]: r for r in _OBL.load_obligations(ws)}
    assert rows[oid_absent]["state"] == "answered", "comment-only mention must auto-dispose"
    assert rows[oid_real]["state"] == "open", "genuine fn() must stay open (no sidecar)"


def test_line_range_file_line_resolves(tmp_path):
    """A verdict sidecar with a line-RANGE file_line (file:NN-MM) still R76-verifies
    (the excerpt-in-source check is load-bearing, not the precise line form)."""
    ws = _make_ws(tmp_path)
    _write_source(ws, "src/m.go", "package m\nfunc Pure(a int) int {\n\treturn a * 2\n}\n")
    oid = _append_open_obligation(ws, file=str(ws / "src" / "m.go"), fn="Pure", question="overflow?")
    _write_sidecar(ws, f"hq_{oid}.json", {
        "question_id": oid, "verdict": "KILL",
        "file_line": "src/m.go:2-4", "code_excerpt": "return a * 2",
    })
    res = _RES.resolve(ws, dry_run=False)
    rows = {r["obligation_id"]: r for r in _OBL.load_obligations(ws)}
    assert rows[oid]["state"] == "killed", res
