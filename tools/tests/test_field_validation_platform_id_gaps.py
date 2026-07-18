from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "field-validation-platform-id-gaps.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("field_validation_platform_id_gaps_test", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["field_validation_platform_id_gaps_test"] = mod
    spec.loader.exec_module(mod)
    return mod


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


SUBMISSIONS = """# Submissions - hyperbridge

## filed/ (submitted to HackenProof)

- filed/hb-arbitrum-orbit-unconfirmed-node-HIGH/ - High - Arbitrum-Orbit consensus client finalizes a forged unconfirmed L2 state root.
- filed/hb-optimism-l2oracle-unfinalized-output-HIGH/ - High - Optimism L2OutputOracle consensus path accepts an unfinalized root.
- filed/hb-univ3-univ4-wrapper-refund-deployer-MEDIUM/ - Medium - UniV3/UniV4 wrappers misroute exact-output ETH refunds.

<!-- AUDITOOOR_TRACKER_MANAGED_START -->
| HackenProof # | Date | Severity | Status | Title |
|---:|---|---|---|---|
| — | 2026-05-22 | High | Submitted without platform ID (operator-reported HackenProof filing) | Arbitrum-Orbit consensus client finalizes a forged unconfirmed L2 state root |
| — | 2026-05-22 | High | Submitted without platform ID (operator-reported HackenProof filing) | Optimism L2OutputOracle consensus path accepts an unfinalized root |
| — | 2026-05-22 | Medium | Submitted without platform ID (operator-reported HackenProof filing) | UniV3/UniV4 wrappers misroute exact-output ETH refunds |
<!-- AUDITOOOR_TRACKER_MANAGED_END -->
"""


class FieldValidationPlatformIdGapsTests(unittest.TestCase):
    def test_three_missing_hyperbridge_rows_are_reported_without_mutating_workspace(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "hyperbridge"
            submissions = ws / "submissions" / "SUBMISSIONS.md"
            outcomes = ws / "reference" / "outcomes.jsonl"
            pending = ws / "reference" / "pending_filed_without_platform_id.jsonl"
            _write(submissions, SUBMISSIONS)
            _write_jsonl(outcomes, [])
            _write_jsonl(
                pending,
                [
                    {
                        "schema": "auditooor.pending_filed_without_platform_id.v1",
                        "local_id": "hb-arbitrum-orbit-unconfirmed-node-HIGH",
                        "report_id": "hb-arbitrum-orbit-unconfirmed-node-HIGH",
                        "requires_platform_id_backfill": True,
                        "counts_as_outcome_evidence": False,
                    }
                ],
            )
            before = {path: path.read_bytes() for path in (submissions, outcomes, pending)}

            report = mod.build_report(ws)

            self.assertEqual(report["schema"], "auditooor.field_validation_platform_id_gaps.v1")
            self.assertTrue(report["safety"]["read_only_workspace_inputs"])
            self.assertFalse(report["safety"]["submissions_edited"])
            self.assertEqual(report["counts"]["submitted_without_platform_id_candidates"], 3)
            self.assertEqual(report["counts"]["gap_rows"], 3)
            self.assertEqual(report["counts"]["next_action_rows"], len(report["next_action_rows"]))
            self.assertEqual([row["local_id"] for row in report["gap_rows"]], [
                "hb-arbitrum-orbit-unconfirmed-node-HIGH",
                "hb-optimism-l2oracle-unfinalized-output-HIGH",
                "hb-univ3-univ4-wrapper-refund-deployer-MEDIUM",
            ])
            for row in report["gap_rows"]:
                self.assertTrue(row["needs_platform_filing_row"])
                self.assertTrue(row["needs_platform_outcome_row"])
                self.assertIn("record-submission", "\n".join(row["commands"]))
                self.assertIn("record-outcome", "\n".join(row["commands"]))
                self.assertTrue(row["next_action_rows"])
                self.assertIn(":record_submission", row["next_action_rows"][0]["action_id"])
                self.assertEqual(row["platform_id"], "")
                self.assertEqual(row["platform_url"], "")
            self.assertEqual(before, {path: path.read_bytes() for path in (submissions, outcomes, pending)})

    def test_existing_real_filing_row_only_requires_outcome_backfill(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "hyperbridge"
            _write(ws / "submissions" / "SUBMISSIONS.md", SUBMISSIONS)
            _write_jsonl(
                ws / "reference" / "outcomes.jsonl",
                [
                    {
                        "workspace": "hyperbridge",
                        "platform": "hackenproof",
                        "report_id": "HP-100",
                        "url": "https://hackenproof.com/reports/100",
                        "title": "Arbitrum-Orbit consensus client finalizes a forged unconfirmed L2 state root",
                        "severity": "High",
                        "outcome": "pending",
                    }
                ],
            )

            report = mod.build_report(ws)

            first = next(row for row in report["gap_rows"] if row["local_id"] == "hb-arbitrum-orbit-unconfirmed-node-HIGH")
            self.assertFalse(first["needs_platform_filing_row"])
            self.assertTrue(first["needs_platform_outcome_row"])
            self.assertEqual(first["platform_id"], "HP-100")
            self.assertEqual(first["platform_url"], "https://hackenproof.com/reports/100")
            commands = "\n".join(first["commands"])
            self.assertNotIn("record-submission", commands)
            self.assertIn("ID=HP-100", commands)
            self.assertIn("record-outcome", commands)
            action_kinds = [row["action_kind"] for row in first["next_action_rows"]]
            self.assertNotIn("record_submission", action_kinds)
            self.assertIn("record_outcome", action_kinds)

    def test_terminal_outcome_marks_row_complete(self) -> None:
        mod = _load_module()
        title = "Arbitrum-Orbit consensus client finalizes a forged unconfirmed L2 state root"
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "hyperbridge"
            _write(ws / "submissions" / "SUBMISSIONS.md", SUBMISSIONS)
            _write_jsonl(
                ws / "reference" / "outcomes.jsonl",
                [
                    {
                        "workspace": "hyperbridge",
                        "platform": "hackenproof",
                        "report_id": "HP-100",
                        "url": "https://hackenproof.com/reports/100",
                        "title": title,
                        "severity": "High",
                        "outcome": "pending",
                    },
                    {
                        "workspace": "hyperbridge",
                        "platform": "hackenproof",
                        "report_id": "HP-100",
                        "url": "https://hackenproof.com/reports/100",
                        "title": title,
                        "severity": "High",
                        "outcome": "accepted",
                    },
                ],
            )

            report = mod.build_report(ws)

            complete_ids = {row["local_id"] for row in report["complete_rows"]}
            gap_ids = {row["local_id"] for row in report["gap_rows"]}
            self.assertIn("hb-arbitrum-orbit-unconfirmed-node-HIGH", complete_ids)
            self.assertNotIn("hb-arbitrum-orbit-unconfirmed-node-HIGH", gap_ids)

    def test_cli_writes_report_artifacts_only(self) -> None:
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "hyperbridge"
            _write(ws / "submissions" / "SUBMISSIONS.md", SUBMISSIONS)
            _write_jsonl(ws / "reference" / "outcomes.jsonl", [])
            out_json = root / "lane" / "platform_id_gaps.json"
            out_md = root / "lane" / "platform_id_gaps.md"

            rc = mod.main(["--workspace", str(ws), "--out-json", str(out_json), "--out-md", str(out_md)])

            self.assertEqual(rc, 0)
            self.assertTrue(out_json.is_file())
            self.assertTrue(out_md.is_file())
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["counts"]["gap_rows"], 3)
            self.assertIn("read-only backfill helper", out_md.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
