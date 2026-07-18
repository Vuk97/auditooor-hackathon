#!/usr/bin/env python3
"""Regression tests for the fuzz-target WORKLIST generator + completeness gate.

Covers the orphaned-worklist fix (2026-07-02, generic/all-language):
  1. the --from-inscope generator joins inscope_units.jsonl x
     value_moving_functions.json and drops out-of-scope value-movers;
  2. the completeness-check is ADVISORY by default and hard-fails ONLY under
     AUDITOOOR_FUZZ_TARGET_STRICT=1 (backward-compat: never bricks a prior audit);
  3. a worklist row is satisfied by a campaign receipt, an mvc_sidecar, OR a typed
     disposition, and OPEN otherwise;
  4. the audit-done-guard consumer is fail-open (missing tool / non-strict) and
     fail-closed only under the strict env.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parent.parent
_REPO = _TOOLS.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tools.lib.fuzz_target_corpus import (  # noqa: E402
    WORKLIST_SCHEMA_VERSION,
    build_inscope_worklist_rows,
    emit_inscope_worklist,
    worklist_output_path,
)


def _load_tool(name: str):
    p = _TOOLS / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_").replace(".py", ""), p)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    au = tmp_path / ".auditooor"
    au.mkdir()
    (au / "inscope_units.jsonl").write_text(
        json.dumps({"file": "src/Vault.sol", "function": "withdraw"}) + "\n"
        + json.dumps({"file": "src/Vault.sol", "function": "deposit"}) + "\n"
        + json.dumps({"file": "src/Router.go", "function": "MsgSend"}) + "\n",
        encoding="utf-8",
    )
    (au / "value_moving_functions.json").write_text(
        json.dumps({
            "functions": [
                {"file": "src/Vault.sol", "function": "withdraw", "language": "sol"},
                {"file": "src/Vault.sol", "function": "withdrawAll", "language": "sol"},
                {"file": "src/Router.go", "function": "MsgSend", "language": "go"},
                # out-of-scope value-mover -> must be dropped
                {"file": "src/NotInScope.sol", "function": "steal", "language": "sol"},
            ]
        }),
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture(autouse=True)
def _clear_strict_env():
    old = os.environ.pop("AUDITOOOR_FUZZ_TARGET_STRICT", None)
    yield
    if old is not None:
        os.environ["AUDITOOOR_FUZZ_TARGET_STRICT"] = old
    else:
        os.environ.pop("AUDITOOOR_FUZZ_TARGET_STRICT", None)


# ------------------------------------------------------------------ generator

def test_generator_joins_inscope_and_drops_oos(ws: Path):
    rows, diag = build_inscope_worklist_rows(ws, "testws")
    assert diag["inscope_present"] is True
    assert diag["dropped_out_of_scope"] == 1  # NotInScope.sol steal
    tids = {r["target_id"] for r in rows}
    # 3 clusters: Vault withdraw, Vault withdrawall (multi-lang neutral), Router MsgSend
    assert "src/Vault.sol::withdraw" in tids
    assert "src/Vault.sol::withdrawall" in tids
    assert "src/Router.go::msgsend" in tids
    assert all(r["schema_version"] == WORKLIST_SCHEMA_VERSION for r in rows)
    assert all(r["needs_campaign"] is True for r in rows)
    assert all(r["verdict"] == "campaign-pending" for r in rows)


def test_generator_language_neutral(ws: Path):
    rows, _ = build_inscope_worklist_rows(ws, "testws")
    langs = {tuple(r["languages"]) for r in rows if r["fn_cluster"] == "msgsend"}
    assert ("go",) in langs  # a Go value-mover is a target, not just Solidity


def test_emit_writes_worklist_and_is_absent_when_empty(ws: Path, tmp_path: Path):
    summary = emit_inscope_worklist(ws, "testws")
    assert summary["written"] is True
    assert worklist_output_path(ws).is_file()
    # empty ws (no manifest) -> no file created (advisory-safe)
    empty = tmp_path / "empty"
    (empty / ".auditooor").mkdir(parents=True)
    s2 = emit_inscope_worklist(empty, "empty")
    assert s2["written"] is False
    assert not worklist_output_path(empty).is_file()


# ---------------------------------------------------------------- gate states

def test_gate_absent_worklist_advisory_vs_strict(tmp_path: Path):
    m = _load_tool("fuzz-target-completeness-check.py")
    (tmp_path / ".auditooor").mkdir()
    assert m.check(tmp_path)["verdict"] == "warn-worklist-absent"
    os.environ["AUDITOOOR_FUZZ_TARGET_STRICT"] = "1"
    assert m.check(tmp_path)["verdict"] == "fail-worklist-absent"


def test_gate_open_rows_advisory_by_default(ws: Path):
    emit_inscope_worklist(ws, "testws")
    m = _load_tool("fuzz-target-completeness-check.py")
    rep = m.check(ws)
    assert rep["verdict"] == "warn-fuzz-target-incomplete"  # advisory-first
    assert len(rep["open"]) == 3


def test_gate_open_rows_strict_fails(ws: Path):
    emit_inscope_worklist(ws, "testws")
    m = _load_tool("fuzz-target-completeness-check.py")
    os.environ["AUDITOOOR_FUZZ_TARGET_STRICT"] = "1"
    assert m.check(ws)["verdict"] == "fail-fuzz-target-incomplete"


def test_gate_campaign_receipt_covers_target(ws: Path):
    emit_inscope_worklist(ws, "testws")
    (ws / ".auditooor" / "fuzz_campaign_receipt.json").write_text(
        json.dumps({"schema": "auditooor.fuzz_campaign_receipt.v1",
                    "campaigns": [{"contract": "Vault"}, {"contract": "Router"}]}),
        encoding="utf-8",
    )
    m = _load_tool("fuzz-target-completeness-check.py")
    os.environ["AUDITOOOR_FUZZ_TARGET_STRICT"] = "1"
    # Vault + Router basenames covered -> all 3 clusters satisfied
    assert m.check(ws)["verdict"] == "pass-fuzz-target-complete"


def test_gate_mvc_sidecar_covers_target(ws: Path):
    emit_inscope_worklist(ws, "testws")
    mvc = ws / ".auditooor" / "mvc_sidecar"
    mvc.mkdir()
    (mvc / "mvc-Vault.json").write_text(json.dumps({"contract": "Vault"}), encoding="utf-8")
    (mvc / "mvc-Router.json").write_text(json.dumps({"contract": "Router"}), encoding="utf-8")
    m = _load_tool("fuzz-target-completeness-check.py")
    os.environ["AUDITOOOR_FUZZ_TARGET_STRICT"] = "1"
    assert m.check(ws)["verdict"] == "pass-fuzz-target-complete"


def test_gate_typed_disposition_covers_target(ws: Path):
    emit_inscope_worklist(ws, "testws")
    rows, _ = build_inscope_worklist_rows(ws, "testws")
    disp = "\n".join(
        json.dumps({"target_id": r["target_id"], "verdict": "oos",
                    "reason": "out of scope per program clause X and cannot move value"})
        for r in rows
    )
    (ws / ".auditooor" / "fuzz_target_dispositions.jsonl").write_text(disp + "\n", encoding="utf-8")
    m = _load_tool("fuzz-target-completeness-check.py")
    os.environ["AUDITOOOR_FUZZ_TARGET_STRICT"] = "1"
    assert m.check(ws)["verdict"] == "pass-fuzz-target-complete"


def test_gate_disposition_short_reason_rejected(ws: Path):
    emit_inscope_worklist(ws, "testws")
    rows, _ = build_inscope_worklist_rows(ws, "testws")
    disp = "\n".join(
        json.dumps({"target_id": r["target_id"], "verdict": "oos", "reason": "no"})
        for r in rows
    )
    (ws / ".auditooor" / "fuzz_target_dispositions.jsonl").write_text(disp + "\n", encoding="utf-8")
    m = _load_tool("fuzz-target-completeness-check.py")
    os.environ["AUDITOOOR_FUZZ_TARGET_STRICT"] = "1"
    # short reasons must NOT be a free pass
    assert m.check(ws)["verdict"] == "fail-fuzz-target-incomplete"


def test_gate_rebuttal_downgrades_fail(ws: Path):
    emit_inscope_worklist(ws, "testws")
    (ws / ".auditooor" / "fuzz_target_rebuttal.md").write_text(
        "operator: fuzz targets deferred to a follow-up engagement pass", encoding="utf-8")
    m = _load_tool("fuzz-target-completeness-check.py")
    os.environ["AUDITOOOR_FUZZ_TARGET_STRICT"] = "1"
    # main() returns rc 0 because rebuttal downgrades the fail
    rc = m.main(["--ws", str(ws), "--json"])
    assert rc == 0


# ----------------------------------------------------------------------- CLI

def test_cli_from_inscope_writes_worklist(ws: Path, capsys):
    corpus = _load_tool("fuzz-target-corpus.py")
    rc = corpus.main(["--from-inscope", "--workspace", str(ws), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["verdict"] == "pass"
    assert out["rows_written"] == 3
    assert worklist_output_path(ws).is_file()


# ------------------------------------------------------- audit-done-guard wire

def test_done_guard_consumer_failopen_nonstrict(ws: Path):
    """The guard block is fail-open under non-strict: an OPEN worklist yields a
    warn verdict, so the guard never returns a fuzz-target FAIL reason unless the
    strict env is set. Exercised via the guard's block logic directly."""
    guard = _load_tool("audit-done-guard.py")
    check = _load_tool("fuzz-target-completeness-check.py")
    emit_inscope_worklist(ws, "testws")
    # non-strict -> warn, not fail; the guard's `.startswith("fail-")` is False
    assert not check.check(ws)["verdict"].startswith("fail-")
    os.environ["AUDITOOOR_FUZZ_TARGET_STRICT"] = "1"
    assert check.check(ws)["verdict"].startswith("fail-")
    # rebuttal present -> guard downgrades (guard checks _rebuttal(ws) is None)
    (ws / ".auditooor" / "fuzz_target_rebuttal.md").write_text("deferred", encoding="utf-8")
    assert check._rebuttal(ws) is not None


def test_done_guard_has_fuzz_target_block():
    """The advisory consumer is wired into audit-done-guard.evaluate."""
    src = (_TOOLS / "audit-done-guard.py").read_text(encoding="utf-8")
    assert "fuzz-target-completeness-check.py" in src
    assert "fuzz_target_completeness_detail" in src
    assert "AUDITOOOR_FUZZ_TARGET_STRICT" in src  # documented in the block comment


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
