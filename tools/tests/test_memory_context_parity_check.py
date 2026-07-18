import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


parity = _load_module("memory_context_parity_check", REPO_ROOT / "tools" / "memory-context-parity-check.py")


class MemoryContextParityCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "tools").mkdir(parents=True, exist_ok=True)
        (self.root / "obsidian-vault").mkdir(parents=True, exist_ok=True)
        (self.root / "reports").mkdir(parents=True, exist_ok=True)
        for name in ("knowledge-gap-log.py", "vault-mcp-server.py"):
            target = self.root / "tools" / name
            target.write_text((REPO_ROOT / "tools" / name).read_text(encoding="utf-8"), encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def knowledge_gap_row(self, **overrides):
        row = {
            "schema": "auditooor.knowledge_gap_event.v1",
            "event_id": "KG-20260506-001:opened:20260506T000000Z",
            "event_type": "opened",
            "gap_id": "KG-20260506-001",
            "candidate_gap_id": "G8-KG-20260506-001",
            "status": "open",
            "occurred_at": "2026-05-06T00:00:00+00:00",
            "actor": "codex",
            "area": "memory",
            "gap_type": "missing_context_pack",
            "severity": "high",
            "title": "Open knowledge gap",
            "question": "How do we prove memory context parity?",
            "description": "Latest-state open rows should match vault context output.",
            "evidence": "reports/knowledge_gaps.jsonl shows one unresolved gap.",
            "remediation": "Add a narrow parity checker.",
            "blocked_by_artifacts": ["docs/CURRENT_STATE.md"],
            "downstream_blocked_tasks": ["NBQ-001"],
            "source_paths": ["reports/knowledge_gaps.jsonl", "docs/CURRENT_STATE.md"],
            "analyzer_target_paths": ["tools/memory-context-parity-check.py"],
            "yield_estimate": "high",
            "effort_estimate": "low",
            "heuristic_fp_risk": "A stale context pack could hide the row.",
            "heuristic_fn_risk": "Other open rows may exist elsewhere.",
            "resolution_summary": "",
            "resolution_evidence_paths": [],
            "terminal_artifact": "",
            "verification": {"commands": [], "passed": False},
            "reopen_reason": "",
        }
        row.update(overrides)
        return row

    def write_support_files(self) -> None:
        for rel in ("docs/CURRENT_STATE.md", "tools/memory-context-parity-check.py"):
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text("# support\n", encoding="utf-8")

    def write_ledger(self, rows) -> Path:
        self.write_support_files()
        ledger = self.root / "reports" / "knowledge_gaps.jsonl"
        ledger.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return ledger

    def test_load_latest_open_rows_filters_resolved_latest_state(self):
        opened = self.knowledge_gap_row()
        resolved = self.knowledge_gap_row(
            event_id="KG-20260506-001:resolved:20260506T010000Z",
            event_type="resolved",
            status="resolved",
            occurred_at="2026-05-06T01:00:00+00:00",
            resolution_summary="Closed.",
            resolution_evidence_paths=["docs/CURRENT_STATE.md"],
            terminal_artifact="docs/CURRENT_STATE.md",
            verification={"commands": [{"command": "python3 -m unittest", "exit_code": 0}], "passed": True},
        )
        still_open = self.knowledge_gap_row(
            event_id="KG-20260506-002:opened:20260506T020000Z",
            gap_id="KG-20260506-002",
            candidate_gap_id="G8-KG-20260506-002",
            title="Still open",
            question="What is still open?",
        )
        self.write_ledger([opened, resolved, still_open])

        ledger_path, rows = parity.load_latest_open_rows(self.root)

        self.assertEqual(ledger_path, (self.root / "reports" / "knowledge_gaps.jsonl").resolve())
        self.assertEqual([row["gap_id"] for row in rows], ["KG-20260506-002"])

    def test_build_report_matches_vault_context_output(self):
        self.write_ledger([self.knowledge_gap_row()])

        report = parity.build_report(self.root)

        self.assertEqual(report["comparison"]["expected_open_gap_ids"], ["KG-20260506-001"])
        self.assertEqual(report["comparison"]["returned_open_gap_ids"], ["KG-20260506-001"])
        self.assertEqual(report["comparison"]["missing_gap_ids"], [])
        self.assertEqual(report["summary"]["parity_ok"], True)
        self.assertEqual(report["summary"]["strict_ready"], True)
        self.assertEqual(report["pack_status"]["error"], "")

    def test_main_strict_fails_when_context_omits_known_open_row(self):
        self.write_ledger([self.knowledge_gap_row()])

        def stub_fetcher(repo_root: Path, expected_open_count: int) -> dict[str, object]:
            self.assertEqual(repo_root, self.root.resolve())
            self.assertEqual(expected_open_count, 1)
            return {"schema": "auditooor.vault_knowledge_gap_context.v1", "gaps": [], "summary": {"returned_count": 0, "open_count": 0}}

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = parity.main(["--repo-root", str(self.root), "--strict"], fetcher=stub_fetcher, stdout=output)

        self.assertEqual(code, 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["comparison"]["missing_gap_ids"], ["KG-20260506-001"])
        self.assertEqual(report["summary"]["strict_ready"], False)


if __name__ == "__main__":
    unittest.main()
