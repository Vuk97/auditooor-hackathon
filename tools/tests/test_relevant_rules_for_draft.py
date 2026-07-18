"""Tests for relevant-rules-for-draft.py + 7 bootstrap attacker frames (PR #658 commit 4).

Iter-3 Lane Q additions (dynamic-digest refactor):
  - TestDigestDrivenRuleTriggers: digest-loaded, digest-missing fallback, rule-id-as-trigger
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "relevant-rules-for-draft.py"
FRAMES_DIR = REPO / "reference" / "attacker_frames"
DIGEST_PATH = REPO / "reference" / "codified_rules_digest.json"


def _run(stdin_text, *args):
    proc = subprocess.run(
        ["python3", str(TOOL), "-", *args],
        input=stdin_text,
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestAttackerFramesBootstrap(unittest.TestCase):
    """Ensure the 7 bootstrap frames exist + are valid YAML + have required fields."""

    def test_seven_bootstrap_frames_present(self):
        frames = sorted(FRAMES_DIR.glob("AMF-*.yaml"))
        # Allow more than 7 in future, but require at least the 7 from Phase 3
        self.assertGreaterEqual(len(frames), 7, f"expected >= 7 bootstrap frames, found {len(frames)}")
        ids = [f.stem for f in frames]
        for expected in ["AMF-001", "AMF-002", "AMF-003", "AMF-004", "AMF-005", "AMF-006", "AMF-007"]:
            self.assertIn(expected, ids, f"bootstrap frame {expected} missing")

    def test_each_frame_has_required_fields(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not available")
        required = ["frame_id", "title", "version", "status", "bug_class",
                    "attacker_question", "mental_steps", "existing_corpus_anchors",
                    "trigger_keywords"]
        for path in FRAMES_DIR.glob("AMF-*.yaml"):
            with path.open() as fh:
                frame = yaml.safe_load(fh)
            for field in required:
                self.assertIn(field, frame, f"{path.name} missing required field: {field}")

    def test_each_frame_has_min_3_mental_steps(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not available")
        for path in FRAMES_DIR.glob("AMF-*.yaml"):
            with path.open() as fh:
                frame = yaml.safe_load(fh)
            steps = frame.get("mental_steps", [])
            self.assertGreaterEqual(len(steps), 3, f"{path.name} mental_steps < 3")

    def test_each_frame_has_min_1_corpus_anchor(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not available")
        for path in FRAMES_DIR.glob("AMF-*.yaml"):
            with path.open() as fh:
                frame = yaml.safe_load(fh)
            anchors = frame.get("existing_corpus_anchors", [])
            self.assertGreaterEqual(len(anchors), 1, f"{path.name} no corpus anchors")

    def test_frame_id_format(self):
        import re
        for path in FRAMES_DIR.glob("AMF-*.yaml"):
            self.assertRegex(path.stem, r"^AMF-\d{3}$")


class TestRelevantRulesForDraft(unittest.TestCase):
    def test_l32_fires_on_panic_keywords(self):
        rc, stdout, _ = _run("validator-crash panic halts-block-production defer-recover")
        self.assertEqual(rc, 0)
        self.assertIn("L32", stdout)

    def test_l30_fires_on_missing_guard(self):
        rc, stdout, _ = _run("missing-guard asymmetric receiver-side")
        self.assertEqual(rc, 0)
        self.assertIn("L30", stdout)

    def test_l28e_fires_on_fork_lag(self):
        rc, stdout, _ = _run("fork-lag upstream-divergence go.mod replace-directive")
        self.assertEqual(rc, 0)
        self.assertIn("L28-E", stdout)

    def test_amf001_fires_on_asymmetric(self):
        rc, stdout, _ = _run("missing-guard asymmetric claim-finalize")
        self.assertEqual(rc, 0)
        self.assertIn("AMF-001", stdout)
        self.assertIn("Asymmetric guard enumeration", stdout)

    def test_amf007_fires_on_fork_lag(self):
        rc, stdout, _ = _run("fork-lag go.mod cherry-pick")
        self.assertEqual(rc, 0)
        self.assertIn("AMF-007", stdout)

    def test_amf003_fires_on_permissionless(self):
        rc, stdout, _ = _run("permissionless precondition")
        self.assertEqual(rc, 0)
        self.assertIn("AMF-003", stdout)

    def test_max_frames_cap(self):
        rc, stdout, _ = _run(
            "missing-guard asymmetric fork-lag go.mod permissionless revert tier-6 ack acknowledged off-chain",
            "--max-frames", "1",
        )
        self.assertEqual(rc, 0)
        # Count "### AMF-" headers
        self.assertEqual(stdout.count("### AMF-"), 1, f"expected 1 frame, got {stdout.count('### AMF-')}")

    def test_frames_only_suppresses_rules(self):
        rc, stdout, _ = _run("panic validator-crash missing-guard", "--frames-only")
        self.assertEqual(rc, 0)
        self.assertNotIn("Relevant L-rules", stdout)

    def test_rules_only_suppresses_frames(self):
        rc, stdout, _ = _run("panic validator-crash missing-guard", "--rules-only")
        self.assertEqual(rc, 0)
        self.assertNotIn("attacker mental frames", stdout)

    def test_json_output(self):
        rc, stdout, _ = _run("missing-guard asymmetric fork-lag", "--json")
        self.assertEqual(rc, 0)
        data = json.loads(stdout)
        self.assertEqual(data["schema"], "auditooor.relevant_rules_for_draft.v1")
        self.assertIn("rules_matched", data)
        self.assertIn("frames_matched", data)

    def test_no_triggers_emits_nothing(self):
        rc, stdout, stderr = _run("This text has no relevant trigger keywords whatsoever.", "--quiet")
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.strip(), "")

    def test_counter_examples_surfaced(self):
        """Counter-examples are the highest-value field at draft time."""
        rc, stdout, _ = _run("missing-guard asymmetric")
        self.assertEqual(rc, 0)
        self.assertIn("Counter-examples", stdout)
        self.assertIn("address-or-rebut", stdout)


class TestDigestDrivenRuleTriggers(unittest.TestCase):
    """Iter-3 Lane Q: verify digest-driven RULE_TRIGGERS refactor."""

    def _import_tool(self):
        """Import the tool module, reloading to pick up any env changes."""
        import importlib
        import sys as _sys
        # Insert tools dir if needed
        tools_dir = str(REPO / "tools")
        if tools_dir not in _sys.path:
            _sys.path.insert(0, tools_dir)
        mod_name = "relevant-rules-for-draft"
        # Use importlib to load file directly (hyphen in name)
        import importlib.util
        spec = importlib.util.spec_from_file_location(mod_name, TOOL)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_digest_loaded_adds_new_rules(self):
        """When digest exists, RULE_TRIGGERS must contain rules not in hard-coded dict."""
        if not DIGEST_PATH.is_file():
            self.skipTest("digest not present")
        mod = self._import_tool()
        # R43/R44/R45 are in the digest but NOT in _RULE_TRIGGERS_HARDCODED
        for rule_id in ("R43", "R44", "R45"):
            self.assertIn(rule_id, mod.RULE_TRIGGERS,
                          f"{rule_id} not in RULE_TRIGGERS after digest load")

    def test_rule_id_is_a_trigger_keyword(self):
        """Each digest-derived rule must trigger on its own lowercase rule_id."""
        if not DIGEST_PATH.is_file():
            self.skipTest("digest not present")
        mod = self._import_tool()
        digest = json.loads(DIGEST_PATH.read_text())
        for rec in digest.get("rules", []):
            rid = rec.get("rule_id", "")
            if not rid or rid not in mod.RULE_TRIGGERS:
                continue
            kws_lower = [k.lower() for k in mod.RULE_TRIGGERS[rid]]
            self.assertIn(rid.lower(), kws_lower,
                          f"{rid} does not have its own id as a trigger keyword")

    def test_r43_fires_on_rule_id_keyword(self):
        """Draft containing literal 'R43' should surface R43 in JSON output."""
        if not DIGEST_PATH.is_file():
            self.skipTest("digest not present")
        rc, stdout, _ = _run("This draft violates R43 load-bearing-bytes-attribution", "--json")
        self.assertEqual(rc, 0)
        data = json.loads(stdout)
        matched_ids = [r["rule_id"] for r in data["rules_matched"]]
        self.assertIn("R43", matched_ids, f"R43 not in rules_matched; got {matched_ids}")

    def test_r35_fires_on_dos_keywords(self):
        """R35 (dos-class-reframe) should fire on 'dos' keyword."""
        if not DIGEST_PATH.is_file():
            self.skipTest("digest not present")
        rc, stdout, _ = _run("This is a dos-class finding without non-dos impact", "--json")
        self.assertEqual(rc, 0)
        data = json.loads(stdout)
        matched_ids = [r["rule_id"] for r in data["rules_matched"]]
        self.assertIn("R35", matched_ids, f"R35 not in rules_matched; got {matched_ids}")

    def test_digest_missing_fallback_no_error(self):
        """With DIGEST_PATH monkeypatched to a missing path, tool must still return 0."""
        import importlib.util
        import types

        # Load module with a fake DIGEST_PATH that does not exist
        source = TOOL.read_text(encoding="utf-8").replace(
            'DIGEST_PATH = REPO / "reference" / "codified_rules_digest.json"',
            'DIGEST_PATH = REPO / "reference" / "NONEXISTENT_digest_MISSING.json"',
        )
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False,
                                        encoding="utf-8") as tmp:
            tmp.write(source)
            tmp_path = tmp.name

        try:
            proc = subprocess.run(
                ["python3", tmp_path, "-"],
                input="panic validator-crash",
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0,
                             f"tool crashed without digest: {proc.stderr}")
            # Hard-coded L32 entry must still fire
            self.assertIn("L32", proc.stdout, "L32 should fire from hard-coded fallback")
            # Digest-missing warning on stderr
            self.assertIn("digest not found", proc.stderr)
        finally:
            pathlib.Path(tmp_path).unlink(missing_ok=True)

    def test_rule_triggers_count_increased(self):
        """RULE_TRIGGERS must have more entries than the 12 hard-coded ones."""
        if not DIGEST_PATH.is_file():
            self.skipTest("digest not present")
        mod = self._import_tool()
        # Hard-coded has 12 entries (L17,L25,L26,L27,L28-E,L29-Disc-3/4/5/6,L30,L31,L32)
        # + 6 more (R18,R19,R20,R24,R25,R26) = 18; digest adds 14 rules.
        # After merge expect at least 20 unique rule IDs.
        self.assertGreaterEqual(len(mod.RULE_TRIGGERS), 20,
                                f"Expected >=20 rules after digest merge, got {len(mod.RULE_TRIGGERS)}")


if __name__ == "__main__":
    unittest.main()
