#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "reasoner-regen-pass.py"
SPEC = importlib.util.spec_from_file_location("reasoner_regen", TOOL)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MOD)


def test_unresolved_operator_placeholders_are_not_executed():
    assert MOD.resolve_command_argv(
        "python3 tools/x.py --workspace <ws> --input <operator-file>", "/tmp/ws"
    ) is None
    assert MOD.resolve_command_argv(
        "python3 tools/x.py --workspace <ws>", "/tmp/ws"
    ) == ["python3", "tools/x.py", "--workspace", "/tmp/ws"]


def test_language_specific_reasoners_are_skipped_when_arm_absent():
    plan = [
        {"lang": "rust", "verdict": "stale", "will_rerun": True,
         "command": "python3 tools/r.py --workspace <ws>"},
        {"lang": "sol", "verdict": "stale", "will_rerun": True,
         "command": "python3 tools/s.py --workspace <ws>"},
    ]
    MOD.apply_language_applicability(
        plan, {"solidity": True, "rust": False, "go": False, "zk": False, "javascript": True}
    )
    assert plan[0]["verdict"] == "language-not-applicable"
    assert plan[0]["will_rerun"] is False
    assert plan[1]["will_rerun"] is True


def test_placeholder_command_is_classified_manual_input_required():
    plan = [{"lang": "any", "verdict": "missing", "will_rerun": True,
             "command": "python3 tools/x.py --input <operator-file>"}]
    MOD.apply_language_applicability(plan, {"solidity": True})
    assert plan[0]["verdict"] == "manual-input-required"
    assert plan[0]["will_rerun"] is False


def test_nested_ledger_path_is_preserved_in_specs():
    runbook = {"steps": [{
        "step_id": "dirm",
        "emit_artifact": ".auditooor/dirm/residual.jsonl",
        "reads": ".auditooor/dataflow_paths.jsonl",
        "what_must_be_done": "Run `python3 tools/dirm.py --workspace <ws>`.",
    }]}
    specs = MOD.build_reasoner_specs(runbook, (("dirm/residual.jsonl", "dirm.py", "any"),))
    assert specs[0]["ledger"] == "dirm/residual.jsonl"


def test_apply_persists_machine_cited_language_exemption():
    aud = Path(tempfile.mkdtemp()) / ".auditooor"
    aud.mkdir()
    plan = [{"ledger": "rust.jsonl", "lang": "rust", "verdict": "language-not-applicable"}]
    n = MOD.persist_machine_applicability_exemptions(plan, aud, {"solidity": True, "rust": False})
    assert n == 1
    row = json.loads((aud / "reasoner_firing_exemptions.jsonl").read_text())
    assert row["ledger"] == "rust.jsonl"
    assert "machine-language-inventory" in row["citation"]


def test_successful_empty_ledger_gets_examined_receipt_only_on_success():
    aud = Path(tempfile.mkdtemp()) / ".auditooor"
    aud.mkdir()
    (aud / "clean.jsonl").write_text("")
    (aud / "failed.jsonl").write_text("")
    receipts = [
        {"ledger": "clean.jsonl", "rc": 0, "tool": "clean.py", "argv": ["python3", "clean.py"], "ts": "t"},
        {"ledger": "failed.jsonl", "rc": 1, "tool": "failed.py", "argv": ["python3", "failed.py"], "ts": "t"},
    ]
    assert MOD.persist_successful_empty_run_receipts(receipts, aud) == 1
    assert json.loads((aud / "clean.jsonl").read_text())["survivors"] == 0
    assert (aud / "failed.jsonl").read_text() == ""
