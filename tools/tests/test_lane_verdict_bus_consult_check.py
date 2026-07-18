"""Tests for tools/lane-verdict-bus-consult-check.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "lane-verdict-bus-consult-check.py"
SCHEMA = ROOT / "tools" / "schemas" / "auditooor.r71_lane_verdict_bus_consult.v1.json"


def _load_tool():
    spec = importlib.util.spec_from_file_location("lane_verdict_bus_consult_check", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


mod = _load_tool()


class LaneVerdictBusConsultCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="r71_bus_consult_")
        self.ws = Path(self.tmp.name)
        self.draft = self.ws / "reports" / "lane_M1" / "results.md"
        self.draft.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_draft(self, body: str) -> Path:
        self.draft.write_text(body, encoding="utf-8")
        return self.draft

    def _write_aggregate(self, record_count: int) -> Path:
        bus_dir = self.ws / ".auditooor" / "lane_verdict_bus"
        bus_dir.mkdir(parents=True, exist_ok=True)
        path = bus_dir / "aggregated.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "auditooor.lane_verdict_bus.aggregate.v1",
                    "bus_empty": record_count == 0,
                    "record_count": record_count,
                    "records": [],
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_section_present_passes_with_non_empty_bus(self) -> None:
        self._write_aggregate(2)
        self._write_draft(
            "lane_type: drill\n"
            "attack_class: rounding\n\n"
            "## Lane-Verdict-Bus Consultation\n"
            "- Bus snapshot path: .auditooor/lane_verdict_bus/aggregated.json\n"
            "- Snapshot timestamp: 2026-05-27T00:00:00Z\n"
        )
        payload = mod.check(self.draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "pass-section-present")
        self.assertTrue(payload["evidence"]["section"]["has_snapshot_timestamp"])

    def test_final_section_15n_alias_passes(self) -> None:
        self._write_aggregate(1)
        self._write_draft(
            "lane_type: hunt\n\n"
            "## Section 15n: lane-verdict-bus consult\n"
            "- Bus snapshot path: .auditooor/lane_verdict_bus/aggregated.json\n"
            "- Snapshot timestamp: 2026-05-27T00:00:00Z\n"
        )
        payload = mod.check(self.draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "pass-section-present")

    def test_section_without_snapshot_path_fails(self) -> None:
        self._write_aggregate(1)
        self._write_draft(
            "lane_type: drill\n\n"
            "## Lane-Verdict-Bus Consultation\n"
            "- Snapshot timestamp: 2026-05-27T00:00:00Z\n"
        )
        payload = mod.check(self.draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "fail-no-consult")
        self.assertIn("bus snapshot path", payload["reason"])

    def test_section_without_timestamp_fails(self) -> None:
        self._write_aggregate(1)
        self._write_draft(
            "lane_type: drill\n\n"
            "## Lane-Verdict-Bus Consultation\n"
            "- Bus snapshot path: .auditooor/lane_verdict_bus/aggregated.json\n"
        )
        payload = mod.check(self.draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "fail-no-consult")
        self.assertIn("snapshot timestamp", payload["reason"])

    def test_missing_section_fails_when_bus_has_records(self) -> None:
        self._write_aggregate(1)
        self._write_draft("lane_type: drill\nattack_class: access-control\n")
        payload = mod.check(self.draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "fail-no-consult")
        self.assertEqual(mod.rc_for(payload), 1)

    def test_empty_bus_passes_without_section(self) -> None:
        self._write_aggregate(0)
        self._write_draft("lane_type: triage\nattack_class: replay\n")
        payload = mod.check(self.draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "pass-empty-bus")

    def test_fresh_workspace_passes_as_empty_bus(self) -> None:
        self._write_draft("lane_type: drill\nattack_class: accounting\n")
        payload = mod.check(self.draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "pass-empty-bus")

    def test_rebuttal_accepted(self) -> None:
        self._write_aggregate(1)
        self._write_draft(
            "lane_type: drill\n"
            "<!-- r71-rebuttal: phase-A learning value despite known bus verdict -->\n"
        )
        payload = mod.check(self.draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertEqual(mod.rc_for(payload), 0)

    def test_oversized_rebuttal_ignored(self) -> None:
        self._write_aggregate(1)
        self._write_draft(
            "lane_type: drill\n"
            f"<!-- r71-rebuttal: {'x' * 201} -->\n"
        )
        payload = mod.check(self.draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "fail-no-consult")

    def test_malformed_bus_snapshot_fails_without_section(self) -> None:
        bus_dir = self.ws / ".auditooor" / "lane_verdict_bus"
        bus_dir.mkdir(parents=True, exist_ok=True)
        (bus_dir / "aggregated.json").write_text("{not-json", encoding="utf-8")
        self._write_draft("lane_type: drill\nattack_class: dos\n")
        payload = mod.check(self.draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "fail-malformed-bus-snapshot")
        self.assertEqual(mod.rc_for(payload), 1)

    def test_jsonl_records_require_section_when_aggregate_missing(self) -> None:
        bus_dir = self.ws / ".auditooor" / "lane_verdict_bus"
        bus_dir.mkdir(parents=True, exist_ok=True)
        (bus_dir / "lane-A.jsonl").write_text(
            json.dumps({"lane_id": "lane-A", "verdict": "DROPPED"}) + "\n",
            encoding="utf-8",
        )
        self._write_draft("lane_type: hunt\nattack_class: oos\n")
        payload = mod.check(self.draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "fail-no-consult")
        self.assertEqual(payload["evidence"]["bus"]["record_count"], 1)

    def test_non_lane_document_is_out_of_scope(self) -> None:
        draft = self.ws / "submission.md"
        draft.write_text("Severity: Medium\nImpact: loss of funds\n", encoding="utf-8")
        self._write_aggregate(1)
        payload = mod.check(draft, workspace=self.ws)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_schema_file_matches_runtime_identity(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(schema["$id"], mod.SCHEMA_VERSION)
        self.assertEqual(schema["properties"]["gate"]["const"], mod.GATE)
        self.assertIn("fail-no-consult", schema["properties"]["verdict"]["enum"])


if __name__ == "__main__":
    unittest.main()
