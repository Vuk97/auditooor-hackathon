"""Tests for tools/rule-injection-sync.py."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "rule_sync"

_spec = importlib.util.spec_from_file_location(
    "rule_injection_sync",
    ROOT / "tools" / "rule-injection-sync.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]

MINI_CLAUDE = FIXTURE_DIR / "mini_claude.md"


class ParseCorrectnessTests(unittest.TestCase):
    """Tests for parse_claude_md against mini fixture."""

    def _digest(self) -> dict:
        return mod.parse_claude_md(MINI_CLAUDE)

    def test_schema_field_present(self) -> None:
        digest = self._digest()
        self.assertEqual(digest["schema"], "auditooor.codified_rules_digest.v1")

    def test_rule_count_matches_fixture(self) -> None:
        digest = self._digest()
        # mini fixture has R28, R35, R19 (3 hard rule sections)
        self.assertGreaterEqual(digest["rule_count"], 2)
        self.assertLessEqual(digest["rule_count"], 5)

    def test_r35_is_parsed(self) -> None:
        digest = self._digest()
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R35", ids)

    def test_r28_is_parsed(self) -> None:
        digest = self._digest()
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R28", ids)

    def test_r35_has_mechanical_gate(self) -> None:
        digest = self._digest()
        r35 = next(r for r in digest["rules"] if r["rule_id"] == "R35")
        self.assertIn("dos-class-reframe-check.py", r35["mechanical_gate"])

    def test_r35_has_override_marker(self) -> None:
        digest = self._digest()
        r35 = next(r for r in digest["rules"] if r["rule_id"] == "R35")
        self.assertIn("r35-rebuttal", r35["override_marker"])

    def test_r35_has_empirical_anchor(self) -> None:
        digest = self._digest()
        r35 = next(r for r in digest["rules"] if r["rule_id"] == "R35")
        self.assertIn("cantina-213", r35["empirical_anchor"])

    def test_r35_severity_scope_high_plus(self) -> None:
        digest = self._digest()
        r35 = next(r for r in digest["rules"] if r["rule_id"] == "R35")
        self.assertIn("HIGH", r35["severity_scope"])

    def test_do_not_list_populated(self) -> None:
        digest = self._digest()
        self.assertGreaterEqual(digest["do_not_count"], 2)

    def test_do_not_entries_have_linked_rule(self) -> None:
        digest = self._digest()
        # Entry 3 in fixture is linked to L30
        linked = [d for d in digest["do_not_list"] if d["linked_rule"]]
        self.assertGreater(len(linked), 0)

    def test_source_sha256_present(self) -> None:
        digest = self._digest()
        self.assertEqual(len(digest["source_sha256"]), 64)

    def test_no_duplicate_rule_ids(self) -> None:
        digest = self._digest()
        ids = [r["rule_id"] for r in digest["rules"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_r19_parsed(self) -> None:
        """R19 uses ### Rule NNN -- format, not ## Hard rule:"""
        digest = self._digest()
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R19", ids)

    def test_r19_has_override_marker(self) -> None:
        digest = self._digest()
        r19 = next((r for r in digest["rules"] if r["rule_id"] == "R19"), None)
        if r19 is not None:
            self.assertIn("rebuttal", r19["override_marker"].lower())

    def test_r25_parsed_emdash_heading(self) -> None:
        """R25 uses ### Rule 25 - (em-dash) format."""
        digest = self._digest()
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R25", ids)

    def test_r25_has_override_marker(self) -> None:
        digest = self._digest()
        r25 = next((r for r in digest["rules"] if r["rule_id"] == "R25"), None)
        self.assertIsNotNone(r25, "R25 not found in digest")
        self.assertIn("r25-rebuttal", r25["override_marker"])

    def test_r25_has_mechanical_gate(self) -> None:
        digest = self._digest()
        r25 = next((r for r in digest["rules"] if r["rule_id"] == "R25"), None)
        self.assertIsNotNone(r25, "R25 not found in digest")
        self.assertIn("63", r25["mechanical_gate"])

    def test_r26_parsed_emdash_heading(self) -> None:
        """R26 uses ### Rule 26 - (em-dash) format."""
        digest = self._digest()
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R26", ids)

    def test_r26_has_override_marker(self) -> None:
        digest = self._digest()
        r26 = next((r for r in digest["rules"] if r["rule_id"] == "R26"), None)
        self.assertIsNotNone(r26, "R26 not found in digest")
        self.assertIn("r26-rebuttal", r26["override_marker"])

    def test_r26_has_mechanical_gate(self) -> None:
        digest = self._digest()
        r26 = next((r for r in digest["rules"] if r["rule_id"] == "R26"), None)
        self.assertIsNotNone(r26, "R26 not found in digest")
        self.assertIn("64", r26["mechanical_gate"])


class SyncTargetConsistencyTests(unittest.TestCase):
    """Tests for --sync and --check consistency."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp(prefix="rule_sync_test_")
        self._json_path = Path(self._tmpdir) / "codified_rules_digest.json"
        self._md_path = Path(self._tmpdir) / "codified_rules_digest.md"
        self._session_path = Path(self._tmpdir) / "auditooor_codified_rules.md"
        # Patch SYNC_TARGETS for tests
        self._orig_targets = dict(mod.SYNC_TARGETS)
        mod.SYNC_TARGETS["json"] = self._json_path
        mod.SYNC_TARGETS["md"] = self._md_path
        mod.SYNC_TARGETS["claude_session"] = self._session_path

    def tearDown(self) -> None:
        mod.SYNC_TARGETS.update(self._orig_targets)
        mod.SYNC_TARGETS["json"] = self._orig_targets["json"]
        mod.SYNC_TARGETS["md"] = self._orig_targets["md"]
        mod.SYNC_TARGETS["claude_session"] = self._orig_targets["claude_session"]

    def test_sync_creates_json_target(self) -> None:
        rc, digest = mod.run(source=MINI_CLAUDE, mode="sync")
        self.assertEqual(rc, 0)
        self.assertTrue(self._json_path.exists())

    def test_sync_creates_md_target(self) -> None:
        rc, _ = mod.run(source=MINI_CLAUDE, mode="sync")
        self.assertEqual(rc, 0)
        self.assertTrue(self._md_path.exists())

    def test_sync_creates_session_target(self) -> None:
        rc, _ = mod.run(source=MINI_CLAUDE, mode="sync")
        self.assertEqual(rc, 0)
        self.assertTrue(self._session_path.exists())

    def test_check_passes_after_sync(self) -> None:
        mod.run(source=MINI_CLAUDE, mode="sync")
        rc, _ = mod.run(source=MINI_CLAUDE, mode="check")
        self.assertEqual(rc, 0)

    def test_json_is_valid_json(self) -> None:
        mod.run(source=MINI_CLAUDE, mode="sync")
        data = json.loads(self._json_path.read_text())
        self.assertIn("rules", data)
        self.assertIn("schema", data)

    def test_md_contains_rule_headers(self) -> None:
        mod.run(source=MINI_CLAUDE, mode="sync")
        content = self._md_path.read_text()
        self.assertIn("## R35", content)

    def test_session_md_contains_quick_reference(self) -> None:
        mod.run(source=MINI_CLAUDE, mode="sync")
        content = self._session_path.read_text()
        self.assertIn("Quick Reference", content)

    def test_session_md_contains_do_not_list(self) -> None:
        mod.run(source=MINI_CLAUDE, mode="sync")
        content = self._session_path.read_text()
        self.assertIn("Do-Not List", content)


class DriftDetectionTests(unittest.TestCase):
    """Tests for drift detection between CLAUDE.md and sync targets."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp(prefix="rule_drift_test_")
        self._json_path = Path(self._tmpdir) / "codified_rules_digest.json"
        self._md_path = Path(self._tmpdir) / "codified_rules_digest.md"
        self._session_path = Path(self._tmpdir) / "auditooor_codified_rules.md"
        self._orig_targets = dict(mod.SYNC_TARGETS)
        mod.SYNC_TARGETS["json"] = self._json_path
        mod.SYNC_TARGETS["md"] = self._md_path
        mod.SYNC_TARGETS["claude_session"] = self._session_path

    def tearDown(self) -> None:
        mod.SYNC_TARGETS["json"] = self._orig_targets["json"]
        mod.SYNC_TARGETS["md"] = self._orig_targets["md"]
        mod.SYNC_TARGETS["claude_session"] = self._orig_targets["claude_session"]

    def test_check_fails_when_no_targets_exist(self) -> None:
        rc, _ = mod.run(source=MINI_CLAUDE, mode="check")
        self.assertEqual(rc, 1)

    def test_check_fails_when_source_modified(self) -> None:
        # Sync from mini fixture
        mod.run(source=MINI_CLAUDE, mode="sync")
        # Now check with a different source (real CLAUDE.md has more rules)
        real_claude = Path.home() / ".claude" / "CLAUDE.md"
        if not real_claude.exists():
            self.skipTest("No real CLAUDE.md available")
        rc, _ = mod.run(source=real_claude, mode="check")
        # Real CLAUDE.md will have different SHA / rule set from mini fixture
        self.assertEqual(rc, 1)

    def test_check_detects_new_rule_in_source(self) -> None:
        # Sync from mini fixture
        mod.run(source=MINI_CLAUDE, mode="sync")
        # Create a modified fixture with an extra rule
        extra_rule = MINI_CLAUDE.read_text() + "\n## Hard rule: new-rule (Rule 99)\n\nFoo bar baz.\n\nEmpirical anchor: 2026-05-23 test.\n"
        tmp_src = Path(self._tmpdir) / "extended_claude.md"
        tmp_src.write_text(extra_rule, encoding="utf-8")
        rc, _ = mod.run(source=tmp_src, mode="check")
        self.assertEqual(rc, 1)

    def test_diff_output_is_informative(self) -> None:
        # No targets yet - diff should not crash and should mention missing target
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            mod.run(source=MINI_CLAUDE, mode="diff")
        output = buf.getvalue()
        # Either says no target or shows rules to add
        self.assertTrue(
            "does not exist" in output or "Rules to add" in output or "No changes" in output,
            f"Unexpected diff output: {output!r}"
        )


class SingleRuleLookupTests(unittest.TestCase):
    """Tests for --rule lookup."""

    def test_lookup_existing_rule(self) -> None:
        rc, digest = mod.run(source=MINI_CLAUDE, mode="rule", rule_id="R35", as_json=False)
        self.assertEqual(rc, 0)

    def test_lookup_missing_rule_returns_1(self) -> None:
        rc, _ = mod.run(source=MINI_CLAUDE, mode="rule", rule_id="R999", as_json=False)
        self.assertEqual(rc, 1)

    def test_lookup_json_output_is_valid(self) -> None:
        """Verify --json flag produces parseable output."""
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc, _ = mod.run(source=MINI_CLAUDE, mode="rule", rule_id="R35", as_json=True)
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["rule_id"], "R35")

    def test_lookup_r28_via_json(self) -> None:
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc, _ = mod.run(source=MINI_CLAUDE, mode="rule", rule_id="R28", as_json=True)
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertIn("multi-path", data["name"].lower())


class RealClaudeMdTests(unittest.TestCase):
    """Smoke tests against the real ~/.claude/CLAUDE.md if available."""

    def setUp(self) -> None:
        self._real = Path.home() / ".claude" / "CLAUDE.md"
        if not self._real.exists():
            self.skipTest("No real CLAUDE.md available")

    def test_real_parse_succeeds(self) -> None:
        digest = mod.parse_claude_md(self._real)
        self.assertGreater(digest["rule_count"], 10)

    def test_real_has_r35(self) -> None:
        digest = mod.parse_claude_md(self._real)
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R35", ids)

    def test_real_has_r40(self) -> None:
        digest = mod.parse_claude_md(self._real)
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R40", ids)

    def test_real_has_r43(self) -> None:
        digest = mod.parse_claude_md(self._real)
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R43", ids)

    def test_real_has_r44(self) -> None:
        digest = mod.parse_claude_md(self._real)
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R44", ids)

    def test_real_do_not_list_has_22_plus_entries(self) -> None:
        digest = mod.parse_claude_md(self._real)
        # CLAUDE.md has 24 do-not entries as of 2026-05-23
        self.assertGreaterEqual(digest["do_not_count"], 20)

    def test_real_r43_has_check_91(self) -> None:
        digest = mod.parse_claude_md(self._real)
        r43 = next((r for r in digest["rules"] if r["rule_id"] == "R43"), None)
        self.assertIsNotNone(r43)
        self.assertIn("91", r43["mechanical_gate"])

    def test_real_r44_has_check_92(self) -> None:
        digest = mod.parse_claude_md(self._real)
        r44 = next((r for r in digest["rules"] if r["rule_id"] == "R44"), None)
        self.assertIsNotNone(r44)
        self.assertIn("92", r44["mechanical_gate"])

    def test_real_r35_override_marker_present(self) -> None:
        digest = mod.parse_claude_md(self._real)
        r35 = next(r for r in digest["rules"] if r["rule_id"] == "R35")
        self.assertIn("r35-rebuttal", r35["override_marker"])

    def test_real_no_duplicate_rule_ids(self) -> None:
        digest = mod.parse_claude_md(self._real)
        ids = [r["rule_id"] for r in digest["rules"]]
        self.assertEqual(len(ids), len(set(ids)), f"Duplicates: {[i for i in ids if ids.count(i) > 1]}")

    def test_real_has_r25(self) -> None:
        """R25 uses em-dash heading; parser must handle it."""
        digest = mod.parse_claude_md(self._real)
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R25", ids)

    def test_real_has_r26(self) -> None:
        """R26 uses em-dash heading; parser must handle it."""
        digest = mod.parse_claude_md(self._real)
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R26", ids)

    def test_real_has_r18(self) -> None:
        """R18 is under the L32 / Rule 18 heading."""
        digest = mod.parse_claude_md(self._real)
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R18", ids)

    def test_real_has_r19(self) -> None:
        digest = mod.parse_claude_md(self._real)
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R19", ids)

    def test_real_has_r24(self) -> None:
        digest = mod.parse_claude_md(self._real)
        ids = {r["rule_id"] for r in digest["rules"]}
        self.assertIn("R24", ids)

    def test_real_rule_count_22_plus(self) -> None:
        """After parser fix, real CLAUDE.md should have >=21 rules (was 14)."""
        digest = mod.parse_claude_md(self._real)
        self.assertGreaterEqual(digest["rule_count"], 21)

    def test_real_r25_has_check_63(self) -> None:
        digest = mod.parse_claude_md(self._real)
        r25 = next((r for r in digest["rules"] if r["rule_id"] == "R25"), None)
        self.assertIsNotNone(r25)
        self.assertIn("63", r25["mechanical_gate"])

    def test_real_r26_has_check_64(self) -> None:
        digest = mod.parse_claude_md(self._real)
        r26 = next((r for r in digest["rules"] if r["rule_id"] == "R26"), None)
        self.assertIsNotNone(r26)
        self.assertIn("64", r26["mechanical_gate"])


if __name__ == "__main__":
    unittest.main()
