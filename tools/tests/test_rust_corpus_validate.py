from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-corpus-validate.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("rust_corpus_validate", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["rust_corpus_validate"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _record(item_id: str, severity: str, component: str = "io") -> dict[str, object]:
    stem = item_id.lower()
    return {
        "item_id": item_id,
        "title": f"{item_id} bounded reproducer",
        "corpus_severity": severity,
        "component": component,
        "rel_path": f"findings/{severity.lower()}/{stem}.md",
        "source_kind": "md",
        "normalized": True,
        "route": "detector",
        "terminal_state": "routed_with_fixture_or_replay",
        "blockers": [],
        "source_pointers": [f"findings/{severity.lower()}/{stem}.md"],
        "patch_pointers": [f"findings/{severity.lower()}/{stem}.patch"],
        "poc_pointers": [f"findings/{severity.lower()}/{stem}-poc.rs"],
        "fixture_pointers": [
            f"findings/{severity.lower()}/{stem}.patch",
            f"findings/{severity.lower()}/{stem}-poc.rs",
        ],
        "replay_commands": [],
    }


def _complete_payload() -> dict[str, object]:
    records: list[dict[str, object]] = []
    for severity, count in MOD.EXPECTED_SEVERITIES.items():
        prefix = MOD.SEVERITY_PREFIX[severity]
        for idx in range(1, count + 1):
            records.append(_record(f"{prefix}-{idx:03d}", severity, component="io" if idx % 2 else "sync"))
    return {
        "schema": "auditooor.rust_corpus_ingest.v1",
        "summary": {"item_count": len(records)},
        "records": records,
    }


class RustCorpusValidateTests(unittest.TestCase):
    def test_complete_151_row_payload_unblocks_detectorization(self) -> None:
        payload = MOD.validate_payload(_complete_payload())

        self.assertTrue(payload["acceptance"]["detectorization_unblocked"])
        self.assertEqual(payload["summary"]["found_total"], 151)
        self.assertEqual(payload["summary"]["unique_normalized_ids"], 151)
        self.assertEqual(payload["summary"]["blocker_count"], 0)
        self.assertEqual(payload["summary"]["by_severity"], {"High": 27, "Low": 9, "Medium": 115})

    def test_complete_numeric_swival_payload_unblocks_detectorization(self) -> None:
        records: list[dict[str, object]] = []
        severities = ["High"] * 27 + ["Medium"] * 115 + ["Low"] * 9
        for idx, severity in enumerate(severities, 1):
            item_id = f"{idx:03d}-stdlib-finding"
            records.append(_record(item_id, severity, component="io" if idx % 2 else "sync"))
            records[-1]["rel_path"] = f"{item_id}.md"
            records[-1]["source_pointers"] = [f"{item_id}.md"]
            records[-1]["patch_pointers"] = [f"{item_id}.patch"]
            records[-1]["poc_pointers"] = [f"pocs/{item_id}-poc.rs"]
            records[-1]["fixture_pointers"] = [f"{item_id}.patch", f"pocs/{item_id}-poc.rs"]

        payload = MOD.validate_payload({"schema": "auditooor.rust_corpus_ingest.v1", "records": records})

        self.assertTrue(payload["acceptance"]["detectorization_unblocked"])
        self.assertEqual(payload["summary"]["id_scheme"], "numeric_swival")
        self.assertEqual(payload["summary"]["found_total"], 151)
        self.assertEqual(payload["summary"]["unexpected_id_count"], 0)
        self.assertEqual(payload["summary"]["missing_id_count"], 0)

    def test_zero_ingest_artifact_reports_missing_all_expected_ids_and_evidence(self) -> None:
        payload = MOD.validate_payload(
            {
                "schema": "auditooor.rust_corpus_ingest.v1",
                "summary": {"item_count": 0},
                "records": [],
            }
        )

        blockers = {row["blocker_id"]: row for row in payload["blockers"]}
        self.assertFalse(payload["acceptance"]["detectorization_unblocked"])
        self.assertEqual(payload["summary"]["found_total"], 0)
        self.assertEqual(blockers["swival-total-count-mismatch"]["count"], 1)
        self.assertEqual(blockers["swival-id-missing"]["count"], 151)
        self.assertEqual(payload["summary"]["markdown_covered"], 0)
        self.assertEqual(payload["summary"]["patch_covered"], 0)
        self.assertEqual(payload["summary"]["poc_covered"], 0)

    def test_duplicate_missing_severity_component_and_evidence_fail_closed(self) -> None:
        complete = _complete_payload()
        records = list(complete["records"])  # shallow copy is enough for row replacement
        bad = dict(records[0])
        bad["item_id"] = "H-002"
        bad["corpus_severity"] = "Medium"
        bad["component"] = "unknown"
        bad["patch_pointers"] = []
        bad["poc_pointers"] = []
        bad["fixture_pointers"] = []
        bad["blockers"] = ["missing_vulnerable_clean_or_replay_fixture"]
        records[0] = bad
        complete["records"] = records

        payload = MOD.validate_payload(complete)
        blockers = {row["blocker_id"]: row for row in payload["blockers"]}

        self.assertFalse(payload["acceptance"]["detectorization_unblocked"])
        self.assertIn("swival-id-duplicate", blockers)
        self.assertIn("swival-id-missing", blockers)
        self.assertIn("swival-severity-count-mismatch", blockers)
        self.assertIn("swival-severity-id-mismatch", blockers)
        self.assertIn("swival-component-missing", blockers)
        self.assertIn("swival-patch-missing", blockers)
        self.assertIn("swival-poc-missing", blockers)
        self.assertIn("swival-source-blockers-present", blockers)
        self.assertIn("H-001", payload["missing_expected_ids"])
        self.assertIn("H-002", payload["duplicate_ids"])

    def test_cli_writes_artifacts_and_strict_exits_nonzero_on_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            index = ws / ".audit_logs" / "rust_corpus_mining" / "rust_corpus_index.json"
            index.parent.mkdir(parents=True)
            index.write_text(json.dumps({"records": []}), encoding="utf-8")

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--strict",
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 1, proc.stderr)
            result = json.loads(proc.stdout)
            self.assertEqual(result["summary"]["found_total"], 0)
            self.assertTrue((ws / ".audit_logs" / "rust_corpus_mining" / "rust_corpus_validation.json").is_file())
            self.assertTrue((ws / ".auditooor" / "rust_corpus_validation.md").is_file())


if __name__ == "__main__":
    unittest.main()
