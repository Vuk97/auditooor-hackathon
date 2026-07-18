from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "provider-result-local-verify.py"


def _import():
    spec = importlib.util.spec_from_file_location("provider_result_local_verify_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_provider_row(root: Path, task_id: str, *, kimi: str, minimax: str = "{}") -> dict:
    batch = root / ".audit_logs" / "batch"
    kimi_dir = batch / "kimi"
    minimax_dir = batch / "minimax"
    final_dir = batch / "final"
    kimi_dir.mkdir(parents=True)
    minimax_dir.mkdir(parents=True)
    final_dir.mkdir(parents=True)
    kimi_path = kimi_dir / f"{task_id}.kimi.out.jsonl"
    minimax_path = minimax_dir / f"{task_id}.minimax.out.jsonl"
    final_path = final_dir / f"{task_id}.provider-assist.json"
    kimi_path.write_text(kimi, encoding="utf-8")
    minimax_path.write_text(minimax, encoding="utf-8")
    final_path.write_text("{}", encoding="utf-8")
    return {
        "task_id": task_id,
        "primary_category": "candidate_harvest",
        "categories": ["candidate_harvest", "needs_local_grep"],
        "kimi_output": str(kimi_path),
        "minimax_output": str(minimax_path),
        "final": str(final_path),
    }


class ProviderResultLocalVerifyTests(unittest.TestCase):
    def test_confirms_source_symbol_and_fixture_need(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tool_file = root / "tools" / "example.py"
            tool_file.parent.mkdir()
            tool_file.write_text("def target_symbol():\n    return True\n", encoding="utf-8")
            row = _write_provider_row(
                root,
                "row-1",
                kimi=json.dumps(
                    {
                        "task_id": "row-1",
                        "extracted_source_facts": {"file": "tools/example.py", "symbol": "target_symbol"},
                        "local_checks_required": ["grep target_symbol", "add fixture coverage"],
                    }
                ),
            )
            result = mod._row_verification(row, mod._load_triage_parser(), root)
        self.assertEqual(result["local_status"], "source_symbol_confirmed")
        self.assertIn("needs_fixture", result["classifications"])
        self.assertEqual(result["local_check_count"], 2)

    def test_missing_source_without_grep_hits_is_impossible(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            row = _write_provider_row(
                root,
                "row-2",
                kimi=json.dumps(
                    {
                        "task_id": "row-2",
                        "extracted_source_facts": {"file": "tools/missing.py", "symbol": "missing_symbol"},
                    }
                ),
            )
            result = mod._row_verification(row, mod._load_triage_parser(), root)
        self.assertEqual(result["local_status"], "no_local_evidence")
        self.assertIn("impossible", result["classifications"])

    def test_preserved_triage_checks_drive_local_verification_when_outputs_missing(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "tools").mkdir()
            (root / "tools" / "example.py").write_text("def saved_symbol():\n    return True\n", encoding="utf-8")
            row = {
                "task_id": "row-preserved",
                "primary_category": "candidate_harvest",
                "categories": ["candidate_harvest", "needs_local_grep"],
                "kimi_output": str(root / "missing.kimi.out.jsonl"),
                "minimax_output": str(root / "missing.minimax.out.jsonl"),
                "final": str(root / "final" / "row-preserved.provider-assist.json"),
                "local_checks_required": ["grep saved_symbol"],
                "minimum_followup_checks": ["confirm fixture coverage"],
            }
            result = mod._row_verification(row, mod._load_triage_parser(), root)
        self.assertEqual(result["local_status"], "repo_grep_confirmed")
        self.assertEqual(result["local_check_count"], 2)
        self.assertEqual(result["local_checks"], ["grep saved_symbol", "confirm fixture coverage"])
        self.assertNotIn("impossible", result["classifications"])

    def test_build_verification_filters_candidate_harvest_rows(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "tools").mkdir()
            (root / "tools" / "example.py").write_text("class ReadinessError(Exception):\n    pass\n", encoding="utf-8")
            row = _write_provider_row(
                root,
                "row-keep",
                kimi=textwrap.dedent(
                    """
                    ```json
                    {"task_id":"row-keep","extracted_source_facts":{"file":"tools/example.py","symbol":"ReadinessError"}}
                    ```
                    """
                ),
            )
            triage = root / "triage.json"
            triage.write_text(
                json.dumps({"rows": [row, {"task_id": "row-kill", "primary_category": "killed_by_minimax"}]}),
                encoding="utf-8",
            )
            payload = mod.build_verification(triage, root)
        self.assertEqual(payload["candidate_harvest_count"], 1)
        self.assertEqual(payload["verified_row_count"], 1)
        self.assertFalse(payload["promotion_authority"])
        self.assertFalse(payload["severity_assigned"])


if __name__ == "__main__":
    unittest.main()
