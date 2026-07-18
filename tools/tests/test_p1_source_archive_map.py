#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "p1-source-archive-map.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("p1_source_archive_map_test_subject", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class P1SourceArchiveMapTest(unittest.TestCase):
    def _fixture_tree(self, root: Path) -> dict[str, Path]:
        dsl = root / "reference" / "patterns.dsl"
        dsl.mkdir(parents=True)
        (dsl / "local-complete.yaml").write_text(
            textwrap.dedent(
                """\
                pattern: local-complete
                source: polymarket
                severity: MEDIUM
                """
            ),
            encoding="utf-8",
        )
        (dsl / "missing-fixture.yaml").write_text(
            textwrap.dedent(
                """\
                pattern: missing-fixture
                source: economic-mining-R61
                severity: HIGH
                """
            ),
            encoding="utf-8",
        )
        (dsl / "archive-fixture.yaml").write_text(
            textwrap.dedent(
                """\
                pattern: archive-fixture
                source: kelp-rseth-exploit-2026-04-18-banteg-postmortem
                severity: HIGH
                """
            ),
            encoding="utf-8",
        )
        run_tests = root / "detectors" / "test_fixtures" / "run_tests.sh"
        run_tests.parent.mkdir(parents=True)
        run_tests.write_text(
            'run_test "local-complete" "local_v.sol" "local"\n'
            'run_clean_test "local-complete" "local_c.sol" "local clean"\n',
            encoding="utf-8",
        )
        audits = root / "audits"
        (audits / "polymarket").mkdir(parents=True)
        archives = root / "archives"
        archives.mkdir()
        (archives / "kelp-rseth-2024.txt").write_text("postmortem", encoding="utf-8")
        return {"dsl": dsl, "run_tests": run_tests, "audits": audits, "archives": archives}

    def test_groups_fixtureless_sources_and_finds_archives(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._fixture_tree(Path(tmp))
            records = tool.load_patterns(paths["dsl"], paths["run_tests"])
            groups = tool.build_groups(
                records,
                audits_dir=paths["audits"],
                search_roots=[paths["archives"]],
                max_depth=2,
                match_limit=5,
                only_fixtureless=True,
            )
            by_source = {group.source: group for group in groups}
            self.assertNotIn("polymarket", by_source)
            self.assertEqual(by_source["economic-mining-R61"].status, "missing")
            self.assertEqual(by_source["kelp-rseth-exploit-2026-04-18-banteg-postmortem"].status, "archive-found")
            self.assertTrue(by_source["kelp-rseth-exploit-2026-04-18-banteg-postmortem"].matches)
            queue = tool.extraction_queue(groups, max_patterns_per_group=1)
            actionable = [i for i in queue if i.get("shell_command")]
            deferred = [i for i in queue if not i.get("shell_command")]
            # archive-found group produces one actionable row
            self.assertEqual(len(actionable), 1)
            self.assertEqual(actionable[0]["pattern"], "archive-fixture")
            self.assertIn("--source-file", actionable[0]["argv"])
            self.assertIn("p1-fixture-extractor.py", actionable[0]["shell_command"])
            # missing group produces one deferred row with explicit evidence
            self.assertEqual(len(deferred), 1)
            self.assertEqual(deferred[0]["source_status"], "missing")
            self.assertIsNotNone(deferred[0].get("missing_reason"))
            self.assertIsInstance(deferred[0]["searched_roots"], list)
            # missing group carries searched_roots evidence
            missing_group = by_source["economic-mining-R61"]
            self.assertIsInstance(missing_group.searched_roots, list)
            self.assertTrue(len(missing_group.searched_roots) > 0)

    def test_search_prunes_excluded_directories_and_depth(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archives = root / "archives"
            hidden = archives / "node_modules" / "kelp-rseth"
            hidden.mkdir(parents=True)
            (hidden / "kelp-rseth-2024.txt").write_text("ignored", encoding="utf-8")
            too_deep = archives / "a" / "b" / "kelp-rseth"
            too_deep.mkdir(parents=True)
            (too_deep / "kelp-rseth-2024.txt").write_text("too deep", encoding="utf-8")
            visible = archives / "kelp-rseth"
            visible.mkdir(parents=True)
            (visible / "kelp-rseth-2024.txt").write_text("matched", encoding="utf-8")

            matches = tool.find_archive_matches(
                "kelp-rseth-exploit-2026-04-18-banteg-postmortem",
                [archives],
                max_depth=2,
                limit=10,
            )

            self.assertTrue(any("archives/kelp-rseth" in item for item in matches), matches)
            self.assertFalse(any("node_modules" in item for item in matches), matches)
            self.assertFalse(any("/a/b/" in item for item in matches), matches)

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = self._fixture_tree(root)
            out_json = root / "out" / "map.json"
            out_md = root / "out" / "map.md"
            out_queue_json = root / "out" / "queue.json"
            out_queue_md = root / "out" / "queue.md"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--dsl-dir",
                    str(paths["dsl"]),
                    "--run-tests",
                    str(paths["run_tests"]),
                    "--audits-dir",
                    str(paths["audits"]),
                    "--search-root",
                    str(paths["archives"]),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--out-queue-json",
                    str(out_queue_json),
                    "--out-queue-md",
                    str(out_queue_md),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["fixtureless_patterns"], 2)
            self.assertIn("node_modules", payload["exclude_dirs"])
            # queue now includes 1 actionable + 1 deferred (missing with evidence)
            self.assertEqual(payload["extraction_queue_count"], 2)
            self.assertEqual(payload["missing_group_count"], 1)
            self.assertEqual(payload["missing_with_evidence_count"], 1)
            queue = json.loads(out_queue_json.read_text(encoding="utf-8"))
            actionable = [i for i in queue if i.get("shell_command")]
            deferred = [i for i in queue if not i.get("shell_command")]
            self.assertEqual(actionable[0]["pattern"], "archive-fixture")
            self.assertEqual(len(deferred), 1)
            self.assertEqual(deferred[0]["source_status"], "missing")
            self.assertIn("searched_roots", deferred[0])
            md_text = out_md.read_text(encoding="utf-8")
            self.assertIn("P1 Source Archive Map", md_text)
            self.assertIn("searched:", md_text)  # missing group shows searched roots
            queue_md_text = out_queue_md.read_text(encoding="utf-8")
            self.assertIn("P1 Fixture Extraction Queue", queue_md_text)
            self.assertIn("Deferred", queue_md_text)


if __name__ == "__main__":
    unittest.main()
