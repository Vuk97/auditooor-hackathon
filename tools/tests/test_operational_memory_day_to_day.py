#!/usr/bin/env python3
"""Regression tests for tools/operational-memory-day-to-day.py."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "operational-memory-day-to-day.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "operational_memory_day_to_day", SCRIPT
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["operational_memory_day_to_day"] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stage_root(tmp: Path) -> tuple[Path, Path, Path]:
    root = tmp / "repo"
    for rel in (
        "docs/MEMORY_ARCHITECTURE_2026-05-04.md",
        "docs/KNOWN_LIMITATIONS_BURNDOWN_MAP.md",
        "docs/PROJECT_SOURCE_ROOTS.md",
        "docs/RUST_SOURCE_GRAPH.md",
        "docs/RUST_SYMBOLIC_GAP.md",
        "docs/INVARIANT_LEDGER.md",
        "docs/HARNESS_HARDENING_2026-05-04.md",
        "tools/memory-deep-crawler.py",
        "tools/obsidian-vault-emit.py",
        "tools/project-source-root-readiness.py",
        "tools/rust-base-readiness.py",
        "tools/invariant-harness-planner.py",
        "tools/high-impact-execution-bridge.py",
        "Makefile",
    ):
        _write(root / rel, f"# {rel}\nrust-scan-readiness:\n")
    _write(
        root / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
        json.dumps(
            {
                "rows": [
                    {
                        "limitation_id": "priority-1",
                        "priority_group": "current_priority",
                        "title": "Impact-contract gating",
                        "terminal_state": "deferred_with_owner",
                        "stop_condition_met": False,
                        "next_command": "make impact-contract-check WS=<workspace> STRICT=1",
                        "stop_condition": "No candidate skips impact-contract validation.",
                    },
                    {
                        "limitation_id": "priority-5",
                        "priority_group": "current_priority",
                        "title": "Targeted harness execution",
                        "terminal_state": "deferred_with_owner",
                        "stop_condition_met": False,
                        "next_command": "make harness-plan WS=<workspace>",
                        "stop_condition": "Move rows through execution manifest.",
                    },
                    {
                        "limitation_id": "p2-closed",
                        "priority_group": "P2",
                        "title": "Closed row",
                        "terminal_state": "closed",
                        "stop_condition_met": True,
                        "next_command": "",
                        "stop_condition": "Closed.",
                    },
                ]
            }
        )
        + "\n",
    )
    memory = tmp / "memory.md"
    _write(
        memory,
        "# Memory\n- Next highest lifts are MCL-3 finalization, MFL-7 MCP wiring, and MCL-6 knowledge-gap ledger.\n",
    )
    vault = tmp / "vault"
    _write(
        vault / "INDEX.md",
        "---\ngenerated: \"2026-05-05T00:00Z\"\ntotal_notes: \"10\"\n---\n\n# Index\n\n`%s`\n"
        % root,
    )
    _write(
        vault / "INDEX_active.md",
        "---\nverified_detectors: \"7\"\nloops_in_flight: \"2\"\n---\n# Active\n",
    )
    _write(
        vault / "DASHBOARD.md",
        "---\nlast_sync: \"2026-05-05T00:00Z\"\n---\n# Dashboard\n",
    )
    _write(
        vault / "NEXT_LOOP.md",
        "---\ntotal_candidates: \"2\"\ntop_n: \"2\"\n---\n"
        "| Rank | Gap ID | Category | Priority | Title |\n"
        "|---|---|---|---:|---|\n"
        "| 1 | `G6-001` | `G6` | 2.60 | Recently touched prompt template |\n",
    )
    return root, memory, vault


class PacketShapeTests(unittest.TestCase):
    def test_packet_imports_required_operational_lanes(self) -> None:
        with TemporaryDirectory() as td:
            root, memory, vault = _stage_root(Path(td))

            packet = tool.build_packet(root, "2026-05-05", memory, vault)

            self.assertEqual(packet["summary"]["lane_count"], 6)
            self.assertEqual(packet["summary"]["required_artifacts_missing"], 0)
            self.assertEqual(
                packet["lane_ids"],
                [
                    "memory_brief_index",
                    "commit_scan_tasks",
                    "source_mirror_verify",
                    "known_limitation_dispatch",
                    "rust_coverage",
                    "harness_queues",
                ],
            )
            self.assertEqual(packet["known_limitations"]["row_count"], 3)
            self.assertEqual(packet["known_limitations"]["open_count"], 2)
            self.assertEqual(
                len(packet["known_limitations"]["harness_related_open_rows"]), 1
            )
            self.assertIn("MCL-3", packet["memory_lifts"][0])
            self.assertEqual(packet["vault_status"]["status"], "current-root")

    def test_source_mirror_mismatch_becomes_global_blocker(self) -> None:
        with TemporaryDirectory() as td:
            root, memory, vault = _stage_root(Path(td))
            _write(
                vault / "INDEX.md",
                "---\ngenerated: \"2026-05-05T00:00Z\"\ntotal_notes: \"10\"\n---\n\n`/other/repo`\n",
            )

            packet = tool.build_packet(root, "2026-05-05", memory, vault)

            self.assertEqual(packet["vault_status"]["status"], "external-or-stale-root")
            self.assertTrue(
                any(blocker["id"] == "source-mirror-cross-check" for blocker in packet["global_blockers"]),
                packet["global_blockers"],
            )

    def test_missing_required_artifacts_become_blockers(self) -> None:
        with TemporaryDirectory() as td:
            root, memory, vault = _stage_root(Path(td))
            (root / "docs" / "RUST_SOURCE_GRAPH.md").unlink()

            packet = tool.build_packet(root, "2026-05-05", memory, vault)

            self.assertEqual(packet["summary"]["required_artifacts_missing"], 1)
            self.assertTrue(
                any(
                    blocker["id"] == "missing-required-artifact"
                    and "docs/RUST_SOURCE_GRAPH.md" in blocker["condition"]
                    for blocker in packet["global_blockers"]
                ),
                packet["global_blockers"],
            )


class CliWriteTests(unittest.TestCase):
    def test_cli_writes_markdown_and_json(self) -> None:
        with TemporaryDirectory() as td:
            root, memory, vault = _stage_root(Path(td))
            md_out = Path("docs") / "OPERATIONAL_MEMORY_DAY_TO_DAY_2026-05-05.md"
            json_out = Path("reports") / "operational_memory_day_to_day_2026-05-05.json"

            rc = tool.main(
                [
                    "--root",
                    str(root),
                    "--date",
                    "2026-05-05",
                    "--memory-path",
                    str(memory),
                    "--vault-path",
                    str(vault),
                    "--md-out",
                    str(md_out),
                    "--json-out",
                    str(json_out),
                ]
            )

            self.assertEqual(rc, 0)
            md_text = (root / md_out).read_text(encoding="utf-8")
            report = json.loads((root / json_out).read_text(encoding="utf-8"))
            self.assertIn("# Operational Memory Day-to-Day Packet", md_text)
            self.assertIn("Source Mirror Verify", md_text)
            self.assertEqual(report["summary"]["lane_count"], 6)
            self.assertEqual(
                report["summary"]["dispatch_blocker_count"],
                sum(len(lane["dispatch_blockers"]) for lane in report["lanes"]),
            )


if __name__ == "__main__":
    unittest.main()
