"""
test_hackenproof_plain_export.py
Unit tests for tools/hackenproof-plain-export.py

Run:  python3 -m unittest tools.tests.test_hackenproof_plain_export -v
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure tools/ is importable as a module root
_TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

# Import the module under test via importlib to handle hyphenated filename
import importlib.util

_TOOL_PATH = os.path.join(_TOOLS_DIR, "hackenproof-plain-export.py")
_spec = importlib.util.spec_from_file_location("hackenproof_plain_export", _TOOL_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

parse_draft = _mod.parse_draft
clean_text = _mod.clean_text
check_limits = _mod.check_limits
check_residue = _mod.check_residue
build_plain_text = _mod.build_plain_text
build_json = _mod.build_json
validate_plain_text = _mod.validate_plain_text
SCHEMA = _mod.SCHEMA
SECTION_LIMIT = _mod.SECTION_LIMIT


def _write_tmp(content):
    fd, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    return path


_GOOD_TXT = (
    "1. Title\n\nA real bug leads to loss of funds\n\n"
    "2. Vulnerability details\n\n" + ("detail line. " * 40) + "\n\n"
    "3. Validation steps\n\n" + ("run the poc. " * 40) + "\n\n"
    "4. Supporting files / PoC\n\n- poc.zip\n"
)


# ---------------------------------------------------------------------------
# Synthetic MD draft fixture
# ---------------------------------------------------------------------------

SYNTHETIC_DRAFT = """\
# Missing guard in Foo protocol leads to direct loss of user funds

- Severity: High
- attack_class: theft
- rubric_row: High impact covers serious incorrect behavior.

## V3 Gate Rebuttals

- r38-rebuttal: theft class is correct.
<!-- r25-rebuttal: defense traversal covered below -->

## Verbatim rubric row (SEVERITY.md)

High: "High impact covers serious incorrect behavior..."

## Impact Contract

- selected_impact: Transaction manipulation - forged state accepted
- severity_tier: High
- listed_impact_proven: yes
- evidence_class: source-proof + harness
- oos_traps: not special-role
- stop_condition: stop if no adversarial staker

## Summary

The Foo protocol accepts an **unconfirmed** node as finalized.

## Root Cause

The vulnerable function `verify_foo_payload` in `src/lib.rs:42` never reads
`latestConfirmed`. Any node in `_nodes` is accepted including nodes inside
the challenge window.

## Impact

A bonded staker can create a forged `GlobalState`, submit the proof, and
Hyperbridge finalizes an attacker-chosen L2 state root. Downstream asset
transfers routed through the affected chain are exposed.

## Defenses considered

- The staker bond does not prevent finalization during the window.
- `ArbitrumConsensusClient::verify_fraud_proof` returns `FraudProofUnimplemented`.

## Proof of Concept

1. Check out commit `abc123def456`.
2. Run `cargo test --locked --test poc_foo -- --nocapture`.
3. Expected output:

```
running 3 tests
test poc_forged_node_accepted ... ok
test result: ok. 3 passed; 0 failed
```

## Recommended Fix

Add a `node_number <= latestConfirmed` check before returning `IntermediateState`.

## Supporting files

- poc-tests/foo_exploit.zip
"""


class TestTitleExtraction(unittest.TestCase):
    """Case 1: title extracted from H1."""

    def test_title_from_h1(self):
        parsed = parse_draft(SYNTHETIC_DRAFT)
        title = clean_text(parsed["title"])
        self.assertIn("Missing guard in Foo protocol", title)
        self.assertIn("loss of user funds", title)


class TestSectionMapping(unittest.TestCase):
    """Case 2: synthetic draft exports to 4-section format."""

    def setUp(self):
        parsed = parse_draft(SYNTHETIC_DRAFT)
        self.title = clean_text(parsed["title"])
        self.s2 = clean_text(parsed["vuln_details_raw"])
        self.s3 = clean_text(parsed["validation_raw"])
        self.plain = build_plain_text(self.title, self.s2, self.s3, parsed["poc_files"])

    def test_four_sections_present(self):
        self.assertIn("1. Title", self.plain)
        self.assertIn("2. Vulnerability details", self.plain)
        self.assertIn("3. Validation steps", self.plain)
        self.assertIn("4. Supporting files / PoC", self.plain)

    def test_vuln_details_has_content(self):
        self.assertGreater(len(self.s2), 50, "Section 2 should have substantial content")

    def test_validation_steps_has_content(self):
        self.assertGreater(len(self.s3), 20, "Section 3 should have PoC content")


class TestCharCounts(unittest.TestCase):
    """Case 3: section char counts are computed correctly."""

    def test_char_counts_correct(self):
        s2 = "A" * 500
        s3 = "B" * 300
        limits = check_limits(s2, s3)
        self.assertEqual(limits["section2_chars"], 500)
        self.assertEqual(limits["section3_chars"], 300)
        self.assertFalse(limits["section2_over_limit"])
        self.assertFalse(limits["section3_over_limit"])
        self.assertEqual(limits["section2_overage"], 0)
        self.assertEqual(limits["section3_overage"], 0)


class TestOverLimitFlagging(unittest.TestCase):
    """Case 4: over-10000-char section is flagged."""

    def test_section_over_limit_flagged(self):
        s2 = "X" * (SECTION_LIMIT + 100)
        s3 = "Y" * 200
        limits = check_limits(s2, s3)
        self.assertTrue(limits["section2_over_limit"])
        self.assertEqual(limits["section2_overage"], 100)
        self.assertFalse(limits["section3_over_limit"])

    def test_section3_over_limit_flagged(self):
        s2 = "A" * 200
        s3 = "Z" * (SECTION_LIMIT + 500)
        limits = check_limits(s2, s3)
        self.assertFalse(limits["section2_over_limit"])
        self.assertTrue(limits["section3_over_limit"])
        self.assertEqual(limits["section3_overage"], 500)


class TestMarkdownStripping(unittest.TestCase):
    """Case 5: markdown stripped - no # * ` in output."""

    def test_no_markdown_in_output(self):
        parsed = parse_draft(SYNTHETIC_DRAFT)
        s2 = clean_text(parsed["vuln_details_raw"])
        s3 = clean_text(parsed["validation_raw"])
        combined = s2 + "\n" + s3
        self.assertNotIn("#", combined, "# (heading marker) must not appear in plain output")
        # Asterisks used for bold/italic should be gone; allow * only if embedded in content
        # Check no standalone bold markers remain
        self.assertNotIn("**", combined, "** bold markers must be stripped")
        self.assertNotIn("`", combined, "Backticks must be stripped")

    def test_code_block_content_preserved(self):
        """Content inside code blocks should survive (just the fences removed)."""
        parsed = parse_draft(SYNTHETIC_DRAFT)
        s3 = clean_text(parsed["validation_raw"])
        self.assertIn("poc_forged_node_accepted", s3)

    def test_arithmetic_asterisks_preserved_gap_19(self):
        """Gap 19 regression (2026-05-25, DRILL-6 anchor): asterisk-as-multiplication
        in code/arithmetic expressions must not be eaten by the italic-emphasis regex.
        Found in HackenProof export of pallet-relayer-u256-truncation Medium draft.
        """
        # The exact failing pattern from DRILL-6 hackenproof-plain.txt lines 13 + 155
        text = (
            "accrued = u128::MAX * 5 + 7 -> dispatched amount = 2 "
            "(the bottom-128 bits, ~u128::MAX * 0 of useful payload)"
        )
        cleaned = clean_text(text)
        self.assertIn("u128::MAX * 5 + 7", cleaned, "* multiplication operator must survive")
        self.assertIn("~u128::MAX * 0", cleaned, "second * multiplication must survive")
        # Also test the second failing line pattern
        text2 = "The upper-128 bits (5 * 2^128 fee units) are gone"
        self.assertIn("5 * 2^128", clean_text(text2), "5 * 2^128 must survive")

    def test_proper_italic_emphasis_still_stripped(self):
        """Gap 19 fix must NOT break legitimate *italic* emphasis stripping."""
        text = "This is *important* and very *good*."
        cleaned = clean_text(text)
        self.assertEqual(cleaned, "This is important and very good.")
        # snake_case must still survive (no false-positive emphasis)
        self.assertEqual(clean_text("my_var_name and another_thing"), "my_var_name and another_thing")


class TestAsciiEnforcement(unittest.TestCase):
    """Case 6: ASCII-only enforced - smart quotes and em-dashes become plain."""

    def test_smart_quotes_replaced(self):
        text_with_smart = "The ‘protocol’ accepts “forged” state."
        result = clean_text(text_with_smart)
        self.assertNotIn("‘", result)
        self.assertNotIn("’", result)
        self.assertNotIn("“", result)
        self.assertNotIn("”", result)
        self.assertIn("protocol", result)
        self.assertIn("forged", result)

    def test_em_dash_replaced(self):
        text_with_em = "The attacker—who holds a bond—submits a forged proof."
        result = clean_text(text_with_em)
        self.assertNotIn("—", result)
        self.assertIn("-", result)

    def test_en_dash_replaced(self):
        text_with_en = "Range: 1–5."
        result = clean_text(text_with_en)
        self.assertNotIn("–", result)

    def test_output_is_ascii(self):
        parsed = parse_draft(SYNTHETIC_DRAFT)
        for text in [clean_text(parsed["title"]),
                     clean_text(parsed["vuln_details_raw"]),
                     clean_text(parsed["validation_raw"])]:
            self.assertTrue(all(ord(c) < 128 for c in text),
                            f"Non-ASCII character found in output: {[c for c in text if ord(c) >= 128]}")


class TestInternalLabelScrubbing(unittest.TestCase):
    """Case 7: internal labels are scrubbed from output."""

    def test_internal_labels_absent(self):
        parsed = parse_draft(SYNTHETIC_DRAFT)
        s2 = clean_text(parsed["vuln_details_raw"])
        s3 = clean_text(parsed["validation_raw"])
        combined = s2 + "\n" + s3 + "\n" + clean_text(parsed["title"])
        # Gate rebuttal markers
        self.assertNotIn("r38-rebuttal", combined)
        self.assertNotIn("r25-rebuttal", combined)
        # Impact Contract fields
        self.assertNotIn("selected_impact", combined)
        self.assertNotIn("severity_tier", combined)
        self.assertNotIn("listed_impact_proven", combined)
        self.assertNotIn("oos_traps", combined)
        self.assertNotIn("stop_condition", combined)
        # Section headers that are internal
        self.assertNotIn("V3 Gate Rebuttals", combined)
        self.assertNotIn("Impact Contract", combined)
        self.assertNotIn("Verbatim rubric row", combined)
        # attack_class field
        self.assertNotIn("attack_class", combined)

    def test_public_refs_preserved(self):
        """Commit SHAs and file:line refs in the audited codebase must survive."""
        parsed = parse_draft(SYNTHETIC_DRAFT)
        s2 = clean_text(parsed["vuln_details_raw"])
        s3 = clean_text(parsed["validation_raw"])
        combined = s2 + s3
        self.assertIn("abc123def456", combined, "Commit SHA must survive scrubbing")
        self.assertIn("src/lib.rs:42", combined, "File:line ref must survive scrubbing")

    def test_gap20_21_internal_vocabulary_scrubbed(self):
        text = (
            "V3-grade tracker marked L29 and R47 and R53.\n"
            "MCP routing used vault_export_bucket with context_pack_id and context_pack_hash.\n"
            "lane_name: lane-g\n"
            "agent_output: trace and internal-workflow marker remain."
        )
        cleaned = clean_text(text)
        self.assertNotIn("V3-grade", cleaned)
        self.assertNotIn("L29", cleaned)
        self.assertNotIn("R47", cleaned)
        self.assertNotIn("R53", cleaned)
        self.assertNotIn("MCP", cleaned)
        self.assertNotIn("vault_export_bucket", cleaned)
        self.assertNotIn("context_pack_id", cleaned)
        self.assertNotIn("context_pack_hash", cleaned)
        self.assertNotIn("lane_name", cleaned)
        self.assertNotIn("lane-g", cleaned)
        self.assertNotIn("agent_output", cleaned)
        self.assertNotIn("internal-workflow", cleaned)

    def test_gap20_legitimate_prose_survives_scrubber(self):
        text = (
            "Investigated lane-rebalancing edge case in protocol code.\n"
            "This MCP proof verifies the public component behavior.\n"
            "Observed L29 and R47 identifiers in an external audit appendix."
        )
        cleaned = clean_text(text)
        self.assertIn("lane-rebalancing", cleaned)
        self.assertIn("MCP proof", cleaned)
        self.assertIn("L29", cleaned)
        self.assertIn("R47", cleaned)


class TestHackenproofPlatformMode(unittest.TestCase):
    """Case 11: platform-specific source-block stripping for HackenProof."""

    def test_hackenproof_mode_strips_inline_source_keeps_transcript(self):
        text = """\
Description before PoC.

```solidity
contract Exploit {
    function pwn() external {}
}
```

Run:
```bash
$ forge test -vv
running 2 tests
test result: ok. 2 passed; 0 failed
```
"""
        generic = clean_text(text)
        hp = clean_text(text, platform="hackenproof")
        self.assertIn("contract Exploit", generic, "Generic mode should keep source blocks")
        self.assertNotIn("contract Exploit", hp, "HackenProof mode should strip source blocks")
        self.assertIn("forge test -vv", hp, "Transcript commands must be preserved")
        self.assertIn("running 2 tests", hp, "Transcript output must be preserved")

    def test_hackenproof_cli_platform_strips_source(self):
        with tempfile.TemporaryDirectory() as td:
            draft = Path(td) / "draft.md"
            out = Path(td) / "out.txt"
            draft.write_text(
                "# Source Strip\n\n"
                "## Summary\n"
                "Source block should be stripped for HackenProof.\n\n"
                "```rust\n"
                "fn exploit() { assert!(true); }\n"
                "```\n\n"
                "## Vulnerability Details\n"
                "Details stay.\n\n"
                "## Proof of Concept\n"
                "Run transcript:\n"
                "```bash\n"
                "cargo test exploit -- --nocapture\n"
                "test result: ok. 1 passed; 0 failed\n"
                "```\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    _TOOL_PATH,
                    "--draft",
                    str(draft),
                    "--out",
                    str(out),
                    "--platform",
                    "hackenproof",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            body = out.read_text(encoding="utf-8")
            self.assertNotIn("fn exploit", body)
            self.assertIn("cargo test exploit", body)

    def test_unlabeled_transcript_fence_survives_hackenproof_mode(self):
        text = """\
```
cargo test exploit -- --nocapture
running 1 test
test result: ok. 1 passed; 0 failed
```
"""
        hp = clean_text(text, platform="hackenproof")
        self.assertIn("cargo test exploit", hp)
        self.assertIn("test result: ok", hp)

    def test_validate_rejects_new_internal_label_set(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.txt"
            p.write_text(
                "1. Title\n\n"
                "Bad\n\n"
                "2. Vulnerability details\n\n"
                "V3-grade internal note\n\n"
                "3. Validation steps\n\n"
                "MCP routing used vault_export_bucket\n\n"
                "4. Supporting files / PoC\n\n"
                "- poc.txt\n",
                encoding="utf-8",
            )
            result = validate_plain_text(str(p))
            self.assertFalse(result["ok"])
            self.assertTrue(any("internal-label leak" in f for f in result["failures"]))


class TestJsonSchema(unittest.TestCase):
    """Case 8: JSON sidecar has required schema fields."""

    def test_json_schema_fields(self):
        parsed = parse_draft(SYNTHETIC_DRAFT)
        s2 = clean_text(parsed["vuln_details_raw"])
        s3 = clean_text(parsed["validation_raw"])
        limits = check_limits(s2, s3)
        residue = check_residue(s2 + s3)
        sidecar = build_json(parsed["title"], s2, s3, parsed["poc_files"], limits, residue)

        required_fields = [
            "schema", "title",
            "section2_chars", "section3_chars",
            "section2_over_limit", "section3_over_limit",
            "section2_overage", "section3_overage",
            "has_markdown_residue", "non_ascii_count",
            "poc_files",
        ]
        for field in required_fields:
            self.assertIn(field, sidecar, f"Missing field: {field}")
        self.assertEqual(sidecar["schema"], SCHEMA)
        self.assertEqual(sidecar["schema"], "auditooor.hackenproof_plain_export.v1")
        self.assertIsInstance(sidecar["poc_files"], list)

    def test_json_is_serialisable(self):
        parsed = parse_draft(SYNTHETIC_DRAFT)
        s2 = clean_text(parsed["vuln_details_raw"])
        s3 = clean_text(parsed["validation_raw"])
        limits = check_limits(s2, s3)
        residue = check_residue(s2 + s3)
        sidecar = build_json(parsed["title"], s2, s3, parsed["poc_files"], limits, residue)
        serialised = json.dumps(sidecar)
        self.assertIsInstance(serialised, str)
        reloaded = json.loads(serialised)
        self.assertEqual(reloaded["schema"], SCHEMA)


class TestCliRoundTrip(unittest.TestCase):
    """Case 9: CLI round-trip via tempfile - output file created, sections bounded."""

    def test_cli_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            draft_path = os.path.join(tmpdir, "test_draft.md")
            out_path = os.path.join(tmpdir, "output.hackenproof-plain.txt")
            with open(draft_path, "w", encoding="utf-8") as f:
                f.write(SYNTHETIC_DRAFT)

            # Simulate CLI by calling main internals directly
            with open(draft_path, "r", encoding="utf-8") as f:
                md = f.read()
            parsed = parse_draft(md)
            s2 = clean_text(parsed["vuln_details_raw"])
            s3 = clean_text(parsed["validation_raw"])
            title = clean_text(parsed["title"])
            plain = build_plain_text(title, s2, s3, parsed["poc_files"])
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(plain)

            self.assertTrue(os.path.exists(out_path))
            with open(out_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("1. Title", content)
            self.assertIn("2. Vulnerability details", content)
            self.assertIn("3. Validation steps", content)
            self.assertIn("4. Supporting files / PoC", content)
            limits = check_limits(s2, s3)
            self.assertFalse(limits["section2_over_limit"])
            self.assertFalse(limits["section3_over_limit"])


class TestPocFileExtraction(unittest.TestCase):
    """Case 10: PoC file references extracted."""

    def test_poc_zip_extracted(self):
        parsed = parse_draft(SYNTHETIC_DRAFT)
        # The synthetic draft has "poc-tests/foo_exploit.zip"
        self.assertTrue(len(parsed["poc_files"]) >= 1)
        joined = " ".join(parsed["poc_files"])
        self.assertIn(".zip", joined)


class TestValidateMode(unittest.TestCase):
    """Validate-mode checks on a finished .txt file."""

    def setUp(self):
        self._tmp = []

    def tearDown(self):
        for p in self._tmp:
            try:
                os.unlink(p)
            except OSError:
                pass

    def _v(self, content):
        p = _write_tmp(content)
        self._tmp.append(p)
        return validate_plain_text(p)

    def test_good_file_passes(self):
        r = self._v(_GOOD_TXT)
        self.assertTrue(r["ok"], r["failures"])
        self.assertEqual(r["failures"], [])

    def test_missing_section_header_fails(self):
        bad = _GOOD_TXT.replace("3. Validation steps", "3. Repro steps")
        r = self._v(bad)
        self.assertFalse(r["ok"])
        self.assertTrue(any("missing section header" in f for f in r["failures"]))

    def test_section_over_limit_fails(self):
        bad = _GOOD_TXT.replace("detail line. " * 40, "x" * 10500)
        r = self._v(bad)
        self.assertFalse(r["ok"])
        self.assertTrue(any("over the 10000 limit" in f for f in r["failures"]))

    def test_non_ascii_fails(self):
        bad = _GOOD_TXT.replace("A real bug", "A real bug — dash")
        r = self._v(bad)
        self.assertFalse(r["ok"])
        self.assertTrue(any("non-ASCII" in f for f in r["failures"]))

    def test_markdown_heading_residue_fails(self):
        bad = _GOOD_TXT.replace("detail line. " * 40,
                                "## a heading\n" + "detail line. " * 20)
        r = self._v(bad)
        self.assertFalse(r["ok"])
        self.assertTrue(any("markdown heading" in f for f in r["failures"]))

    def test_code_fence_residue_fails(self):
        bad = _GOOD_TXT.replace("run the poc. " * 40,
                                "```rust\ncode\n```\n" + "run the poc. " * 20)
        r = self._v(bad)
        self.assertFalse(r["ok"])
        self.assertTrue(any("code-fence" in f for f in r["failures"]))

    def test_internal_label_leak_fails(self):
        bad = _GOOD_TXT.replace("- poc.zip",
                                "- /Users/wolf/audits/x/poc.zip")
        r = self._v(bad)
        self.assertFalse(r["ok"])
        self.assertTrue(any("internal-label leak" in f for f in r["failures"]))

    def test_html_comment_leak_fails(self):
        bad = _GOOD_TXT.replace("A real bug",
                                "<!-- r40-rebuttal: x -->\nA real bug")
        r = self._v(bad)
        self.assertFalse(r["ok"])

    def test_near_limit_warning(self):
        body = "y" * (SECTION_LIMIT - 100)
        near = (
            "1. Title\n\nT\n\n"
            "2. Vulnerability details\n\n" + body + "\n\n"
            "3. Validation steps\n\nshort\n\n"
            "4. Supporting files / PoC\n\n- poc.zip\n"
        )
        r = self._v(near)
        self.assertTrue(r["ok"])
        self.assertTrue(any("within 300 chars" in w for w in r["warnings"]))


if __name__ == "__main__":
    unittest.main()
