#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "source-miner-backlog-actions.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("source_miner_backlog_actions", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mod = _load_tool()


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def closure_fixture() -> dict:
    return {
        "schema": "auditooor.v3_iter.remaining_source_miners_closure.v1",
        "verdict": {"can_close_source_miners_now": False},
        "remaining_source_obligations": [
            {
                "source": "solodit",
                "status": "downgraded_supported_allowlist_proven_residual_unsupported_enum_probe",
                "external_state_required": True,
                "open_obligations": [
                    "huff enum evidence or approved live probe",
                    "assembly enum evidence or approved live probe; do not alias Yul without explicit semantic encoding and tests",
                    "leo enum evidence or approved live probe",
                    "cairo-zk enum evidence or approved live probe",
                ],
                "closed_or_narrowed": ["REST cursor stale blocker closed"],
            },
            {
                "source": "defimon",
                "status": "blocked_with_reason",
                "external_state_required": True,
                "open_obligations": [
                    "stable RSS/API/feed/cursor evidence, or explicit acceptance of blog-only SSG coverage as sufficient",
                    "runtime build-id discovery must remain part of any Next.js SSG blog miner",
                ],
                "closed_or_narrowed": ["narrowed to blog-only-source-available, not full live alert feed"],
            },
            {
                "source": "map_butter_bridge_incident_2026_05",
                "status": "backlog",
                "external_state_required": True,
                "open_obligations": [
                    "recover or verify helper 0x2475396A308861559EF30dc46aad6136367a1C30 source/ABI to name selector 0x7d217d5b",
                    "recover, verify, or source-backed-decompile exploit-time implementation 0x92fEADA957BbEB17868F9F59AEd548e50191283d at block 25137572",
                ],
                "closed_or_narrowed": ["primary response source closed"],
            },
            {
                "source": "pashov_public_audits",
                "status": "fresh",
                "external_state_required": False,
                "open_obligations": [],
            },
            {
                "source": "sb_security_public_audits",
                "status": "fresh",
                "external_state_required": False,
                "open_obligations": [],
            },
            *[
                {
                    "source": f"{firm}_public_audits",
                    "status": "fresh",
                    "external_state_required": False,
                    "open_obligations": [],
                }
                for firm in mod._FIRM_PDF_FAMILIES
            ],
        ],
    }


def dashboard_fixture() -> dict:
    return {
        "schema": "auditooor.mining_coverage_dashboard.v1",
        "generated_at": "2026-05-24T07:07:52.604417+00:00",
        "summary": {"total_sources": 12, "fresh": 11, "backlog": 1},
        "rows": [
            {
                "source_id": "solodit_high_plus_findings",
                "name": "Solodit high-plus findings delta",
                "status": "fresh",
                "cursor_value": 66047,
                "last_mined_at": "2026-05-23T22:40:46.080947+00:00",
                "mined_record_count": 9128,
                "network_required": True,
                "source_obligations": [],
            },
            {
                "source_id": "defimon_delta_blocked_no_live_source",
                "name": "Defimon public alerts and blog refresh",
                "status": "fresh",
                "last_mined_at": "2026-05-20T19:08:21.246787+00:00",
                "mined_record_count": 6,
                "network_required": True,
                "source_obligations": [],
            },
            {
                "source_id": "map_butter_bridge_incident_2026_05",
                "name": "MAP/Butter Bridge incident backlog item",
                "status": "backlog",
                "cursor_value": "sharpened_open_waiting_exploit_time_impl_source",
                "last_mined_at": "2026-05-23T22:33:35.033584+00:00",
                "mined_record_count": 2,
                "network_required": True,
                "source_obligations": [
                    {
                        "obligation_id": "map-butter-selector-and-call-path",
                        "status": "open",
                        "required_evidence": "recover helper source/name for selector 0x7d217d5b",
                    },
                    {
                        "obligation_id": "map-butter-primary-response-source",
                        "status": "closed",
                        "required_evidence": "primary response source",
                    },
                ],
            },
            {
                "source_id": "pashov_public_audits",
                "name": "Pashov Audit Group public reports",
                "status": "fresh",
                "mined_record_count": 1553,
                "network_required": False,
                "source_obligations": [],
            },
            {
                "source_id": "sb_security_public_audits",
                "name": "SB Security public reports",
                "status": "fresh",
                "mined_record_count": 398,
                "network_required": False,
                "source_obligations": [],
            },
            *[
                {
                    "source_id": f"{firm}_public_audits",
                    "name": f"{firm} public reports",
                    "status": "fresh",
                    "mined_record_count": 0,
                    "network_required": False,
                    "source_obligations": [],
                }
                for firm in mod._FIRM_PDF_FAMILIES
            ],
        ],
    }


class SourceMinerBacklogActionsTest(unittest.TestCase):
    def test_report_marks_only_real_backlog_and_keeps_no_closure_claim(self) -> None:
        report = mod.build_report(closure_fixture(), dashboard_fixture(), generated_on="2026-05-24")

        self.assertEqual(report["schema"], "auditooor.source_miner_backlog_actions.v1")
        self.assertTrue(report["read_only"])
        self.assertFalse(report["closure_claim"])
        self.assertEqual(report["overall_status"], "open_backlog")
        self.assertEqual(len(report["next_action_rows"]), 5 + len(mod._FIRM_PDF_FAMILIES))
        self.assertEqual(len(report["active_next_action_ids"]), 1)
        self.assertIn("source_miner:solodit:refresh", report["active_next_action_ids"])

        by_family = {item["family"]: item for item in report["sources"]}
        self.assertEqual(
            {item["family"] for item in report["active_backlog_items"]},
            {"solodit"},
        )
        self.assertEqual(by_family["pashov"]["status_bucket"], "fresh_no_backlog")
        self.assertEqual(by_family["sb_security"]["status_bucket"], "fresh_no_backlog")
        self.assertEqual(by_family["defimon"]["status_bucket"], "operator_authorized_source_closure")
        self.assertEqual(by_family["map_butter"]["status_bucket"], "operator_authorized_source_closure")
        self.assertFalse(by_family["pashov"]["next_action"]["action_required"])
        self.assertFalse(by_family["defimon"]["next_action"]["action_required"])
        self.assertFalse(by_family["map_butter"]["next_action"]["action_required"])
        self.assertTrue(by_family["solodit"]["next_action"]["action_required"])
        self.assertEqual(by_family["solodit"]["next_action"]["action_id"], "source_miner:solodit:refresh")
        self.assertEqual(by_family["pashov"]["next_command"], "make hackerman-etl-from-audit-firm-pdf-pashov JSON=1")
        self.assertEqual(
            by_family["sb_security"]["next_command"],
            "make hackerman-etl-from-audit-firm-pdf-sb-security JSON=1",
        )

    def test_backlog_commands_preserve_boundaries(self) -> None:
        report = mod.build_report(closure_fixture(), dashboard_fixture(), generated_on="2026-05-24")
        by_family = {item["family"]: item for item in report["sources"]}

        self.assertEqual(
            by_family["solodit"]["next_command"],
            "python3 tools/solodit-rest-direct.py --plan-language-backlog "
            "--planning-manifest-out reports/solodit_additional_language_plan_2026-05-24.json",
        )
        self.assertIn("Offline planning only", by_family["solodit"]["command_boundary"])
        self.assertIn("cairo-zk enum evidence", "\n".join(by_family["solodit"]["open_obligations"]))

        self.assertEqual(
            by_family["defimon"]["next_command"],
            "python3 tools/defimon-nextjs-blog-miner.py --max-posts 12 --json-only --timeout-seconds 8",
        )
        self.assertEqual(by_family["defimon"]["open_obligations"], [])
        self.assertEqual(by_family["defimon"]["open_source_obligations"], [])
        self.assertIn(
            "https://t.me/s/defimon_alerts",
            by_family["defimon"]["operator_authorized_closure"]["source_refs"],
        )
        self.assertIn(
            "not external platform outcome evidence",
            by_family["defimon"]["operator_authorized_closure"]["closure_boundary"],
        )
        self.assertIn(
            "stable RSS/API/feed/cursor evidence",
            "\n".join(by_family["defimon"]["nonblocking_former_open_obligations"]),
        )

        self.assertEqual(
            by_family["map_butter"]["next_command"],
            "make external-intel-refresh SOURCE=map_butter_bridge_incident_2026_05 "
            "ALLOW_LIVE_FETCH=1 FETCH_SINGLE_INCIDENT=1 JSON=1 "
            "OUT=.auditooor/external_intel_single_incident_map_butter_bridge_incident_2026_05.json",
        )
        self.assertEqual(by_family["map_butter"]["open_obligations"], [])
        self.assertEqual(by_family["map_butter"]["open_source_obligations"], [])
        self.assertEqual(len(by_family["map_butter"]["nonblocking_former_source_obligations"]), 1)
        self.assertIn(
            "source-code root-cause promotion",
            by_family["map_butter"]["operator_authorized_closure"]["closure_boundary"],
        )
        self.assertEqual(
            by_family["map_butter"]["operator_authorized_closure"]["formerly_blocking_source_obligation_ids"],
            ["map-butter-selector-and-call-path"],
        )

    def test_cli_reads_fixtures_and_writes_json_and_markdown_reports(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            closure = root / "summary.json"
            dashboard = root / "dashboard.json"
            out_json = root / "out" / "summary.json"
            out_md = root / "out" / "results.md"
            write_json(closure, closure_fixture())
            write_json(dashboard, dashboard_fixture())

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--closure-summary",
                    str(closure),
                    "--dashboard",
                    str(dashboard),
                    "--generated-on",
                    "2026-05-24",
                    "--out",
                    str(out_json),
                    "--markdown-out",
                    str(out_md),
                    "--json",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            stdout_report = json.loads(proc.stdout)
            file_report = json.loads(out_json.read_text(encoding="utf-8"))
            markdown = out_md.read_text(encoding="utf-8")
            self.assertEqual(stdout_report, file_report)
            self.assertEqual(file_report["active_backlog_count"], 1)
            self.assertIn("Source Miner Backlog Actions", markdown)
            self.assertIn("closure_claim: `false`", markdown)
            self.assertIn("Operator-Authorized Source Closures", markdown)
            self.assertIn("map-butter-selector-and-call-path", markdown)


if __name__ == "__main__":
    unittest.main()
