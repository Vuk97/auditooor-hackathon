#!/usr/bin/env python3
"""P0-4 burn-down: tests for the outcome-linkage manifest emitted by
`tools/outcome-telemetry.py`.

Covers:
  - empty workspace (manifest still written, summary all zeros)
  - workspace with only complete rows (all required fields present)
  - mixed workspace (some incomplete rows surface in summary + per-row audit)
  - manifest persists at <workspace>/.auditooor/outcome_linkage_manifest.json
  - schema sanity (manifest_version, required_fields, summary keys)
  - --no-linkage-manifest suppresses the write

Loaded via importlib because the module filename contains a hyphen.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))


def _load_outcome_telemetry():
    path = TOOLS / "outcome-telemetry.py"
    spec = importlib.util.spec_from_file_location("outcome_telemetry", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec so frozen-dataclass introspection on Python 3.14
    # can find the module's __dict__ via sys.modules — see CPython dataclasses
    # _is_type lookup. Without this the second import path raises
    # AttributeError on @dataclass.
    sys.modules.setdefault("outcome_telemetry", module)
    spec.loader.exec_module(module)
    return module


outcome_telemetry = _load_outcome_telemetry()


def _seed_workspace(
    workspace: Path,
    submissions: list[dict[str, str]],
    outcome_rows: list[dict],
) -> None:
    """Write a SUBMISSIONS.md ledger + outcomes.jsonl using the same shape
    test_outcome_telemetry.py uses (Cantina-style 5-column table)."""
    submissions_dir = workspace / "submissions"
    submissions_dir.mkdir(parents=True, exist_ok=True)
    header = (
        "| Cantina # | Date | Severity | Status | Title |\n"
        "|---:|---|---|---|---|\n"
    )
    body_lines = []
    for entry in submissions:
        body_lines.append(
            f"| **{entry['id']}** | {entry.get('date', '2026-04-29')} | "
            f"{entry.get('severity', 'High')} | {entry.get('status', 'Pending')} | "
            f"{entry.get('title', 'fixture row')} |"
        )
    (submissions_dir / "SUBMISSIONS.md").write_text(
        "# Test Submissions\n\n" + header + "\n".join(body_lines) + "\n"
    )
    if outcome_rows is not None:
        reference_dir = workspace / "reference"
        reference_dir.mkdir(parents=True, exist_ok=True)
        with (reference_dir / "outcomes.jsonl").open("w", encoding="utf-8") as fh:
            for row in outcome_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")


def _read_manifest(workspace: Path) -> dict:
    path = workspace / ".auditooor" / "outcome_linkage_manifest.json"
    return json.loads(path.read_text())


class TestLinkageManifestBuild(unittest.TestCase):
    def test_empty_workspace_emits_zeroed_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "empty"
            _seed_workspace(ws, [], [])
            records = outcome_telemetry.load_workspace_records(ws)
            manifest = outcome_telemetry.build_linkage_manifest(
                ws, records, generated_at="2026-04-29T00:00:00Z"
            )
            self.assertEqual(manifest["workspace"], "empty")
            self.assertEqual(manifest["manifest_version"], 1)
            self.assertEqual(manifest["summary"]["total_rows"], 0)
            self.assertEqual(manifest["summary"]["complete_rows"], 0)
            self.assertEqual(manifest["summary"]["incomplete_rows"], 0)
            for count in manifest["summary"]["missing_per_field"].values():
                self.assertEqual(count, 0)
            self.assertEqual(manifest["rows"], [])

    def test_complete_rows_only_yields_zero_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "complete-only"
            submissions = [
                {"id": "1", "status": "Paid", "title": "fully linked"},
                {"id": "2", "status": "Pending", "title": "fully linked too"},
            ]
            outcomes = [
                {
                    "report_id": "1",
                    "outcome": "paid",
                    "lane": "source-mine",
                    "model_route": "kimi->minimax->codex",
                    "proof_artifact": "submissions/packaged/1",
                    "production_path_blockers_cleared": "yes",
                    "final_triager_outcome": "paid",
                },
                {
                    "report_id": "2",
                    "outcome": "pending",
                    "lane": "audit-deep",
                    "model_route": "kimi",
                    "proof_artifact": "submissions/packaged/2",
                    "production_path_blockers_cleared": "no",
                    "final_triager_outcome": "unknown",
                },
            ]
            _seed_workspace(ws, submissions, outcomes)
            records = outcome_telemetry.load_workspace_records(ws)
            manifest = outcome_telemetry.build_linkage_manifest(ws, records)
            summary = manifest["summary"]
            self.assertEqual(summary["total_rows"], 2)
            self.assertEqual(summary["complete_rows"], 2)
            self.assertEqual(summary["incomplete_rows"], 0)
            self.assertEqual(summary["missing_final_triager_field"], 0)
            for count in summary["missing_per_field"].values():
                self.assertEqual(count, 0)
            for row in manifest["rows"]:
                self.assertTrue(row["complete"])
                self.assertEqual(row["missing_required_fields"], [])

    def test_mixed_workspace_surfaces_incomplete_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "mixed"
            submissions = [
                {"id": "1", "status": "Paid", "title": "complete"},
                {"id": "2", "status": "Pending", "title": "missing several"},
                {"id": "3", "status": "Pending", "title": "no outcome row"},
            ]
            outcomes = [
                {
                    "report_id": "1",
                    "outcome": "paid",
                    "lane": "source-mine",
                    "model_route": "kimi",
                    "proof_artifact": "submissions/packaged/1",
                    "production_path_blockers_cleared": "yes",
                    "final_triager_outcome": "paid",
                },
                {
                    "report_id": "2",
                    "outcome": "pending",
                    # Only lane present.
                    "lane": "source-mine",
                },
                # Note: id "3" intentionally has no outcomes.jsonl row.
            ]
            _seed_workspace(ws, submissions, outcomes)
            records = outcome_telemetry.load_workspace_records(ws)
            manifest = outcome_telemetry.build_linkage_manifest(ws, records)
            summary = manifest["summary"]
            self.assertEqual(summary["total_rows"], 3)
            self.assertEqual(summary["complete_rows"], 1)
            self.assertEqual(summary["incomplete_rows"], 2)
            # Row 2 missing 3 fields, row 3 missing all 4 (no outcomes.jsonl
            # row at all -> all required values empty).
            self.assertEqual(summary["missing_per_field"]["lane"], 1)
            self.assertEqual(summary["missing_per_field"]["model_route"], 2)
            self.assertEqual(summary["missing_per_field"]["proof_artifact"], 2)
            self.assertEqual(
                summary["missing_per_field"]["production_path_blockers_cleared"],
                2,
            )
            self.assertEqual(summary["missing_final_triager_field"], 2)

            by_id = {row["finding_id"]: row for row in manifest["rows"]}
            self.assertTrue(by_id["1"]["complete"])
            self.assertFalse(by_id["2"]["complete"])
            self.assertFalse(by_id["3"]["complete"])
            self.assertIn("model_route", by_id["2"]["missing_required_fields"])
            # Row 3 has no outcome row; outcome_row_present must reflect that.
            self.assertFalse(by_id["3"]["outcome_row_present"])

    def test_base_rate_only_declines_do_not_create_linkage_pressure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "base-rate-only"
            _seed_workspace(
                ws,
                [{"id": "I2.A", "status": "Rejected", "title": "unknown decline"}],
                [
                    {
                        "report_id": "I2.A",
                        "outcome": "rejected",
                        "rejection_reason": "unknown:no decline reason provided by platform",
                    }
                ],
            )
            records = outcome_telemetry.load_workspace_records(ws)
            telemetry_summary = outcome_telemetry.summarize(records)
            manifest = outcome_telemetry.build_linkage_manifest(ws, records)

            self.assertEqual(telemetry_summary["outcome_linkage"]["base_rate_only_rejections"], 1)
            self.assertEqual(telemetry_summary["outcome_linkage"]["linkage_required_rows"], 0)
            self.assertEqual(telemetry_summary["outcome_linkage"]["missing_lane"], 0)
            self.assertEqual(manifest["summary"]["total_rows"], 1)
            self.assertEqual(manifest["summary"]["linkage_required_rows"], 0)
            self.assertEqual(manifest["summary"]["base_rate_only_rows"], 1)
            self.assertEqual(manifest["summary"]["incomplete_rows"], 0)
            row = manifest["rows"][0]
            self.assertFalse(row["linkage_required"])
            self.assertEqual(row["linkage_skip_reason"], "platform_base_rate_only_decline")
            self.assertEqual(row["missing_required_fields"], [])
            self.assertTrue(row["complete"])

    def test_blank_reason_no_reason_status_skips_linkage_pressure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "blank-reason-base-rate"
            _seed_workspace(
                ws,
                [{"id": "418", "status": "Rejected", "title": "unknown decline"}],
                [
                    {
                        "report_id": "418",
                        "outcome_class": "rejected",
                        "status": "DECLINED (no decline reason provided to operator)",
                        "rejection_reason": "",
                    }
                ],
            )
            records = outcome_telemetry.load_workspace_records(ws)
            telemetry_summary = outcome_telemetry.summarize(records)
            manifest = outcome_telemetry.build_linkage_manifest(ws, records)

            self.assertEqual(telemetry_summary["outcome_linkage"]["base_rate_only_rejections"], 1)
            self.assertEqual(telemetry_summary["outcome_linkage"]["linkage_required_rows"], 0)
            self.assertEqual(manifest["summary"]["linkage_required_rows"], 0)
            self.assertEqual(manifest["summary"]["base_rate_only_rows"], 1)
            self.assertEqual(manifest["rows"][0]["linkage_skip_reason"], "platform_base_rate_only_decline")


class TestLinkageManifestPersistence(unittest.TestCase):
    def test_manifest_written_to_dot_auditooor_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "persist"
            _seed_workspace(
                ws,
                [{"id": "1", "status": "Paid", "title": "row"}],
                [{
                    "report_id": "1",
                    "outcome": "paid",
                    "lane": "source-mine",
                    "model_route": "kimi",
                    "proof_artifact": "x",
                    "production_path_blockers_cleared": "yes",
                    "final_triager_outcome": "paid",
                }],
            )
            records = outcome_telemetry.load_workspace_records(ws)
            paths = outcome_telemetry.emit_linkage_manifests(
                [ws], records, generated_at="2026-04-29T00:00:00Z"
            )
            self.assertIn("persist", paths)
            expected_path = ws / ".auditooor" / "outcome_linkage_manifest.json"
            self.assertEqual(paths["persist"], expected_path)
            self.assertTrue(expected_path.exists())

            payload = _read_manifest(ws)
            # Schema sanity: required top-level keys.
            for key in (
                "manifest_version",
                "workspace",
                "workspace_path",
                "generated_at",
                "required_fields",
                "final_triager_field",
                "summary",
                "rows",
            ):
                self.assertIn(key, payload)
            self.assertEqual(payload["manifest_version"], 1)
            self.assertEqual(payload["generated_at"], "2026-04-29T00:00:00Z")
            self.assertEqual(
                payload["required_fields"],
                list(outcome_telemetry.LINKAGE_REQUIRED_FIELDS),
            )
            self.assertEqual(payload["summary"]["total_rows"], 1)
            self.assertEqual(payload["summary"]["complete_rows"], 1)

    def test_manifest_summary_matches_telemetry_linkage_section(self) -> None:
        """Cross-check: the manifest counts mirror the legacy linkage section
        emitted by `summarize()`. Drift between the two would silently
        de-sync downstream dashboards from the new machine-readable view."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "crosscheck"
            _seed_workspace(
                ws,
                [
                    {"id": "1", "status": "Paid", "title": "row1"},
                    {"id": "2", "status": "Pending", "title": "row2"},
                ],
                [
                    {
                        "report_id": "1",
                        "outcome": "paid",
                        "lane": "source-mine",
                        "model_route": "kimi",
                        "proof_artifact": "submissions/packaged/1",
                        "production_path_blockers_cleared": "yes",
                        "final_triager_outcome": "paid",
                    },
                    {
                        "report_id": "2",
                        "outcome": "pending",
                    },
                ],
            )
            records = outcome_telemetry.load_workspace_records(ws)
            telemetry_summary = outcome_telemetry.summarize(records)
            manifest = outcome_telemetry.build_linkage_manifest(ws, records)
            telemetry_linkage = telemetry_summary["outcome_linkage"]
            manifest_summary = manifest["summary"]
            # Cross-tool agreement on the new required-field counters.
            self.assertEqual(
                telemetry_linkage["missing_lane"],
                manifest_summary["missing_per_field"]["lane"],
            )
            self.assertEqual(
                telemetry_linkage["missing_model_route"],
                manifest_summary["missing_per_field"]["model_route"],
            )
            self.assertEqual(
                telemetry_linkage["missing_proof_artifact"],
                manifest_summary["missing_per_field"]["proof_artifact"],
            )
            self.assertEqual(
                telemetry_linkage["missing_production_path_blockers_cleared"],
                manifest_summary["missing_per_field"][
                    "production_path_blockers_cleared"
                ],
            )
            self.assertEqual(
                telemetry_linkage["missing_final_triager_field"],
                manifest_summary["missing_final_triager_field"],
            )


if __name__ == "__main__":
    unittest.main()
