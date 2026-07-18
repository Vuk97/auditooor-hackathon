#!/usr/bin/env python3
"""T7-KG-V2 round-2 regression: KG ledger consumers tolerate v2 progression rows.

Lane scope: verify that `tools/memory-gap-analyzer.py`,
`tools/obsidian-vault-sync.py`, and `tools/memory-deep-crawler.py` handle
knowledge-gap-event v2 rows (event_type in {progressed, partially_resolved,
blocked_sharper, narrowed}) without crashing.

Key findings codified by these tests:

1. `memory-gap-analyzer.py` consumes the ledger via
   `knowledge_gap_log_module().latest_states(...)`. Because v2 progression
   events keep `status="open"` and the analyzer filters on `status=="open"`,
   v2 rows must surface as G8 candidates without any v2-specific branching.

2. `obsidian-vault-sync.py` does NOT consume the KG ledger. This test asserts
   that surface invariant; if that ever changes, this test fails loudly so a
   future v2 wiring decision is forced.

3. `memory-deep-crawler.py` does NOT consume the KG ledger. Same invariant.

These are read-path / no-crash regressions; they do not assume any specific
priority score or sort order beyond "the v2 gap_id appears as a G8 candidate".
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
KG_TOOL_PATH = REPO_ROOT / "tools" / "knowledge-gap-log.py"
GAP_ANALYZER_PATH = REPO_ROOT / "tools" / "memory-gap-analyzer.py"
VAULT_SYNC_PATH = REPO_ROOT / "tools" / "obsidian-vault-sync.py"
DEEP_CRAWLER_PATH = REPO_ROOT / "tools" / "memory-deep-crawler.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _base_open_row(kg_tool, gap_id: str = "KG-20260507-V2CONSUMER-001") -> dict:
    return kg_tool.normalize_row({
        "schema": kg_tool.SCHEMA,
        "event_id": f"{gap_id}:opened:20260507T000000Z",
        "event_type": "opened",
        "gap_id": gap_id,
        "candidate_gap_id": f"G8-{gap_id}",
        "status": "open",
        "occurred_at": "2026-05-07T00:00:00+00:00",
        "actor": "claude-worker-eee",
        "area": "memory",
        "gap_type": "missing_fixture",
        "severity": "medium",
        "title": "v2 progression consumer regression fixture",
        "question": "Do KG consumers tolerate v2 progression rows?",
        "description": "Round-2 audit fixture for T7-KG-V2.",
        "evidence": "tools/memory-gap-analyzer.py:gather_g8 reads via latest_states.",
        "remediation": "Treat status=open v2 rows like any other open KG.",
        "blocked_by_artifacts": [],
        "downstream_blocked_tasks": [],
        "source_paths": ["reports/knowledge_gaps.jsonl"],
        # Use ledger path itself as analyzer target — guaranteed to exist
        # under the per-test repo root.
        "analyzer_target_paths": ["reports/knowledge_gaps.jsonl"],
        "yield_estimate": "med",
        "effort_estimate": "low",
        "heuristic_fp_risk": "",
        "heuristic_fn_risk": "",
        "resolution_summary": "",
        "resolution_evidence_paths": [],
        "terminal_artifact": "",
        "verification": {"commands": [], "passed": False},
        "reopen_reason": "",
    })


class GapAnalyzerG8V2Tests(unittest.TestCase):
    """memory-gap-analyzer.py: gather_g8 must surface v2 progression rows."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="kg-v2-consumer-mga-")
        self.root = Path(self.tmp.name)
        self.ledger = self.root / "reports" / "knowledge_gaps.jsonl"
        self.notes = self.root / "obsidian-vault" / "knowledge-gaps"
        self.ledger.parent.mkdir(parents=True)
        self.notes.mkdir(parents=True)
        # progress_evidence target must exist (knowledge-gap-log validates path).
        progress_note = self.root / "docs" / "next-loop" / "progress_note.md"
        progress_note.parent.mkdir(parents=True)
        progress_note.write_text("# progress\n", encoding="utf-8")

        self.kg_tool = _load("kg_tool_for_v2_consumer", KG_TOOL_PATH)
        # Reload the analyzer fresh so we can override REPO.
        self.analyzer = _load("memory_gap_analyzer_for_v2_consumer", GAP_ANALYZER_PATH)
        # The analyzer caches the kg-log module under _KNOWLEDGE_GAP_LOG; clear so
        # it picks up the per-test repo on first call (the module-level path is
        # still global REPO, but gather_g8 takes a `repo` param).
        self.analyzer._KNOWLEDGE_GAP_LOG = None

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _seed_open_then_progressed(self, gap_id: str = "KG-20260507-V2CONSUMER-001") -> None:
        opened = _base_open_row(self.kg_tool, gap_id)
        self.kg_tool.append_event(opened, self.ledger, self.notes, repo=self.root)
        progressed = self.kg_tool.normalize_row({
            **opened,
            "schema": self.kg_tool.SCHEMA_V2,
            "event_id": f"{gap_id}:progressed:20260507T010000Z",
            "event_type": "progressed",
            "occurred_at": "2026-05-07T01:00:00+00:00",
            "progress_evidence": "docs/next-loop/progress_note.md",
        })
        self.kg_tool.append_event(progressed, self.ledger, self.notes, repo=self.root)

    def test_gather_g8_surfaces_v2_progressed_row_as_open_candidate(self) -> None:
        self._seed_open_then_progressed("KG-20260507-V2CONSUMER-001")
        # Sanity: the latest event is the v2 progression event.
        states = self.kg_tool.latest_states(self.ledger, repo=self.root)
        self.assertEqual(states["KG-20260507-V2CONSUMER-001"]["event_type"], "progressed")
        self.assertEqual(states["KG-20260507-V2CONSUMER-001"]["status"], "open")
        self.assertEqual(
            states["KG-20260507-V2CONSUMER-001"]["schema"],
            self.kg_tool.SCHEMA_V2,
        )

        candidates = self.analyzer.gather_g8(self.root, max_items=10)
        gap_ids = [c.gap_id for c in candidates]
        self.assertIn("G8-KG-20260507-V2CONSUMER-001", gap_ids,
                      f"v2 progression row not surfaced; got: {gap_ids}")

    def test_gather_g8_handles_partially_resolved_v2_event(self) -> None:
        gap_id = "KG-20260507-V2CONSUMER-002"
        opened = _base_open_row(self.kg_tool, gap_id)
        self.kg_tool.append_event(opened, self.ledger, self.notes, repo=self.root)
        partial = self.kg_tool.normalize_row({
            **opened,
            "schema": self.kg_tool.SCHEMA_V2,
            "event_id": f"{gap_id}:partially_resolved:20260507T020000Z",
            "event_type": "partially_resolved",
            "occurred_at": "2026-05-07T02:00:00+00:00",
            "progress_evidence": "docs/next-loop/progress_note.md",
            "remaining_blocker": "Need second fixture confirmation in L13.",
        })
        self.kg_tool.append_event(partial, self.ledger, self.notes, repo=self.root)

        candidates = self.analyzer.gather_g8(self.root, max_items=10)
        gap_ids = [c.gap_id for c in candidates]
        self.assertIn(f"G8-{gap_id}", gap_ids,
                      f"v2 partially_resolved row not surfaced; got: {gap_ids}")


class ObsidianVaultSyncKgLedgerInvariant(unittest.TestCase):
    """obsidian-vault-sync.py invariant: it must not consume the KG ledger.

    If a future change starts reading reports/knowledge_gaps.jsonl from this
    module, this test will fail and force a deliberate v2-wiring decision.
    """

    def test_obsidian_vault_sync_does_not_reference_kg_ledger(self) -> None:
        text = VAULT_SYNC_PATH.read_text(encoding="utf-8")
        self.assertNotIn("knowledge_gaps.jsonl", text,
                         "obsidian-vault-sync.py started referencing KG ledger; "
                         "wire v2 progression event_types explicitly.")
        self.assertNotIn("knowledge-gap-log", text,
                         "obsidian-vault-sync.py started loading knowledge-gap-log; "
                         "wire v2 progression event_types explicitly.")

    def test_obsidian_vault_sync_module_loads_clean(self) -> None:
        # Load the module to assert no import-time side effect breaks if the
        # KG ledger contains v2 rows (it doesn't read it, but a regression here
        # would surface as an exception at module load time).
        mod = _load("obsidian_vault_sync_v2_consumer_check", VAULT_SYNC_PATH)
        # Surface invariants the audit relies on.
        self.assertTrue(hasattr(mod, "SECTION_SOURCES"))


class MemoryDeepCrawlerKgLedgerInvariant(unittest.TestCase):
    """memory-deep-crawler.py invariant: it must not consume the KG ledger."""

    def test_memory_deep_crawler_does_not_reference_kg_ledger(self) -> None:
        text = DEEP_CRAWLER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("knowledge_gaps.jsonl", text,
                         "memory-deep-crawler.py started referencing KG ledger; "
                         "wire v2 progression event_types explicitly.")
        self.assertNotIn("knowledge-gap-log", text,
                         "memory-deep-crawler.py started loading knowledge-gap-log; "
                         "wire v2 progression event_types explicitly.")

    def test_memory_deep_crawler_module_loads_clean(self) -> None:
        mod = _load("memory_deep_crawler_v2_consumer_check", DEEP_CRAWLER_PATH)
        # The crawler scans claude-memory + codex dirs, not the KG ledger.
        self.assertTrue(hasattr(mod, "CODEX_DIR"))
        self.assertTrue(hasattr(mod, "CLAUDE_MEMORY_DIR"))


if __name__ == "__main__":
    unittest.main()
