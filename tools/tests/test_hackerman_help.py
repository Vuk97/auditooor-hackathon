"""Tests for ``tools/hackerman-help.py``.

The tool scans a Makefile for ``hackerman-*`` targets and emits a human /
JSON index. These tests synthesise minimal Makefile fixtures so we can
assert the parser/renderer behaviour deterministically, and also smoke
the live repo Makefile to confirm the index is non-empty.

Coverage (>=8 cases):

1. ``parse_makefile`` returns one record per top-level target and excludes
   ``-test`` companions from the top-level list.
2. Companion ``-test`` targets are linked back to their parent via
   ``test_target``.
3. ``_leading_comment_block`` extracts a contiguous ``#`` comment block
   immediately above the target (skipping ``.PHONY:`` lines).
4. Knob extraction picks up ``$(NAME)``, ``$${NAME}``, and inline
   ``NAME=...`` references; Make built-ins are blacklisted.
5. Targets without a preceding comment surface ``""`` as purpose (and
   the renderer falls back to "(no purpose comment)").
6. JSON envelope matches schema ``auditooor.hackerman_help.v1`` and the
   ``targets`` array length matches ``target_count``.
7. Human renderer includes a header with target count + Makefile path
   and lists every parsed target name.
8. Output is deterministic across two consecutive runs over the same
   fixture (byte-identical for both human and JSON formats).
9. Live repo Makefile: ``parse_makefile`` returns >=20 top-level targets
   (sanity floor; the repo ships ~30+ hackerman targets).
10. CLI entry point exits 0 and writes to ``--out`` when given.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-help.py"


def _load_tool() -> Any:
    name = "_hackerman_help_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


FIXTURE_MAKEFILE = """\
# Unrelated top-of-file comment block.

.PHONY: some-other-target
some-other-target:
\t@echo "not a hackerman target"

# Compute the corpus stats. Knobs: TAGS_DIR, JSON.
.PHONY: hackerman-corpus-stats hackerman-corpus-stats-test
hackerman-corpus-stats:
\t@python3 tools/hackerman-corpus-stats.py \\
\t  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)") \\
\t  $(if $(JSON),--json)

hackerman-corpus-stats-test:
\t@python3 -m unittest tools.tests.test_hackerman_corpus_stats -v

# Aggregate gate verdicts. Pass STRICT=1 to exit non-zero on failure.
hackerman-gates-status:
\t@python3 tools/hackerman-gates-status.py \\
\t  $(if $(STRICT),--strict) \\
\t  GENERATED_AT="$${GENERATED_AT}" \\
\t  $(if $(TAGS_DIR),--tags-dir "$(TAGS_DIR)")

hackerman-no-comment:
\t@echo "no leading comment block"
"""


class ParseMakefileTests(unittest.TestCase):
    """Synthetic-fixture tests for parse_makefile + renderers."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.mk_path = self.tmp / "Makefile"
        self.mk_path.write_text(FIXTURE_MAKEFILE, encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_top_level_targets_excludes_test_companions(self) -> None:
        records = tool.parse_makefile(self.mk_path)
        names = [r["target"] for r in records]
        self.assertIn("hackerman-corpus-stats", names)
        self.assertIn("hackerman-gates-status", names)
        self.assertIn("hackerman-no-comment", names)
        # The -test companion must not appear as a top-level entry.
        self.assertNotIn("hackerman-corpus-stats-test", names)
        # Sorted asc.
        self.assertEqual(names, sorted(names))

    def test_companion_test_target_linked(self) -> None:
        records = tool.parse_makefile(self.mk_path)
        by_name = {r["target"]: r for r in records}
        self.assertEqual(
            by_name["hackerman-corpus-stats"]["test_target"],
            "hackerman-corpus-stats-test",
        )
        self.assertIsNone(by_name["hackerman-gates-status"]["test_target"])
        self.assertIsNone(by_name["hackerman-no-comment"]["test_target"])

    def test_leading_comment_block_extracted(self) -> None:
        records = tool.parse_makefile(self.mk_path)
        by_name = {r["target"]: r for r in records}
        self.assertIn(
            "Compute the corpus stats.",
            by_name["hackerman-corpus-stats"]["purpose"],
        )
        self.assertIn(
            "Aggregate gate verdicts.",
            by_name["hackerman-gates-status"]["purpose"],
        )

    def test_target_without_comment_has_empty_purpose(self) -> None:
        records = tool.parse_makefile(self.mk_path)
        by_name = {r["target"]: r for r in records}
        self.assertEqual(by_name["hackerman-no-comment"]["purpose"], "")
        # The human renderer should fall back gracefully.
        rendered = tool.render_human(records, self.mk_path)
        self.assertIn("(no purpose comment)", rendered)

    def test_knob_extraction(self) -> None:
        records = tool.parse_makefile(self.mk_path)
        by_name = {r["target"]: r for r in records}
        stats_knobs = by_name["hackerman-corpus-stats"]["knobs"]
        self.assertIn("TAGS_DIR", stats_knobs)
        self.assertIn("JSON", stats_knobs)
        gates_knobs = by_name["hackerman-gates-status"]["knobs"]
        # All three reference forms (paren / brace / inline NAME=) must
        # be detected.
        self.assertIn("STRICT", gates_knobs)
        self.assertIn("GENERATED_AT", gates_knobs)
        self.assertIn("TAGS_DIR", gates_knobs)
        # Make built-ins must NOT leak in.
        self.assertNotIn("MAKE", stats_knobs)
        self.assertNotIn("PATH", gates_knobs)

    def test_json_envelope_shape(self) -> None:
        records = tool.parse_makefile(self.mk_path)
        text = tool.render_json(records, self.mk_path)
        envelope = json.loads(text)
        self.assertEqual(envelope["schema"], "auditooor.hackerman_help.v1")
        self.assertEqual(envelope["target_count"], len(records))
        self.assertEqual(len(envelope["targets"]), envelope["target_count"])
        self.assertEqual(envelope["makefile"], str(self.mk_path))

    def test_human_renderer_lists_every_target(self) -> None:
        records = tool.parse_makefile(self.mk_path)
        text = tool.render_human(records, self.mk_path)
        self.assertIn(f"Targets:  {len(records)}", text)
        for rec in records:
            self.assertIn(rec["target"], text)

    def test_output_is_deterministic(self) -> None:
        records_a = tool.parse_makefile(self.mk_path)
        records_b = tool.parse_makefile(self.mk_path)
        self.assertEqual(records_a, records_b)
        self.assertEqual(
            tool.render_human(records_a, self.mk_path),
            tool.render_human(records_b, self.mk_path),
        )
        self.assertEqual(
            tool.render_json(records_a, self.mk_path),
            tool.render_json(records_b, self.mk_path),
        )


class LiveRepoMakefileTests(unittest.TestCase):
    """Smoke the live Makefile to confirm we discover the real corpus."""

    def test_live_makefile_has_many_targets(self) -> None:
        records = tool.parse_makefile(REPO_ROOT / "Makefile")
        # The repo ships ~30+ hackerman-* top-level targets at PR #726 time.
        self.assertGreaterEqual(
            len(records),
            20,
            f"expected >=20 hackerman-* targets, got {len(records)}",
        )
        names = [r["target"] for r in records]
        # Spot-check a few known ones.
        self.assertIn("hackerman-corpus-stats", names)
        self.assertIn("hackerman-gates-status", names)
        self.assertIn("hackerman-all", names)


class CliEntryPointTests(unittest.TestCase):
    """End-to-end CLI smoke (subprocess invocation)."""

    def test_cli_writes_to_out_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            mk = tmp / "Makefile"
            mk.write_text(FIXTURE_MAKEFILE, encoding="utf-8")
            out = tmp / "index.txt"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--makefile",
                    str(mk),
                    "--out",
                    str(out),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(out.is_file())
            text = out.read_text(encoding="utf-8")
            self.assertIn("hackerman-corpus-stats", text)
            self.assertIn("hackerman-gates-status", text)

    def test_cli_json_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            mk = tmp / "Makefile"
            mk.write_text(FIXTURE_MAKEFILE, encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--makefile",
                    str(mk),
                    "--json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            envelope = json.loads(result.stdout)
            self.assertEqual(envelope["schema"], "auditooor.hackerman_help.v1")
            self.assertGreaterEqual(envelope["target_count"], 3)


if __name__ == "__main__":
    unittest.main()
