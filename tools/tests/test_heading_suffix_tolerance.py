#!/usr/bin/env python3
"""Rank-2 fix: exact-header brittleness (trailing `(Rule NN)` / bold suffix).

The section-header regexes used to anchor on ``\\s*$`` immediately after the
heading text, so a heading carrying a rule tag or bold close silently failed
to match and the WHOLE section was dropped (the 43-fail cliff). This fixes
BOTH `production_path.py` heading regexes and the
`impact-contract-preflight.py` `_extract_markdown_section` regex to tolerate a
trailing bold close and/or a parenthesised suffix.

Each fix has TWO assertions:

  * SUPPRESSION - a rule-tagged / bold-suffixed heading now extracts the
    section (the false negative is gone).
  * CONTROL (true-positive still fires) - the parser still extracts the same
    substantive content, so the downstream gate still SEES the reliance /
    violation it must flag. A bogus heading still does NOT match.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_PATH_LIB = ROOT / "tools" / "lib" / "production_path.py"
IMPACT_PREFLIGHT = ROOT / "tools" / "impact-contract-preflight.py"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PP = _load("_pp_lib_rank2", PRODUCTION_PATH_LIB)
ICP = _load("_icp_rank2", IMPACT_PREFLIGHT)


PP_BODY = (
    "1. In-scope asset: NuvaVault\n"
    "2. Affected contract / function: swapOut()\n"
    "7. Mock components used in PoC: MockOracle\n"
    "8. Real component replacement for each mock: Chainlink feed\n"
    "9. OOS clauses checked: OOS-3\n"
)


class ProductionPathHeadingSuffix(unittest.TestCase):
    def test_rule_tag_suffix_matches(self):
        """SUPPRESSION: `## Production Path (Rule 40)` now matches."""
        self.assertTrue(
            PP.PRODUCTION_PATH_HEADING_RE.match("## Production Path (Rule 40)")
        )
        self.assertTrue(
            PP.PRODUCTION_PATH_HEADING_RE.match("## **Production Path** (R40)")
        )

    def test_rule_tag_suffix_extracts_full_section(self):
        """SUPPRESSION: the whole section is captured, not dropped."""
        draft = "## Production Path (Rule 40)\n" + PP_BODY + "\n## Next\nbody\n"
        section = PP.extract_production_path_section(draft)
        self.assertTrue(section.present)
        self.assertEqual(section.item(7), "MockOracle")
        self.assertEqual(section.item(8), "Chainlink feed")

    def test_plain_heading_still_matches_control(self):
        """CONTROL: a plain heading with no suffix still matches + parses."""
        self.assertTrue(PP.PRODUCTION_PATH_HEADING_RE.match("## Production Path"))
        self.assertTrue(PP.PRODUCTION_PATH_HEADING_RE.match("## **Production Path**"))
        draft = "## Production Path\n" + PP_BODY
        section = PP.extract_production_path_section(draft)
        self.assertEqual(section.item(9), "OOS-3")

    def test_true_positive_violation_still_fires_control(self):
        """CONTROL: a real mock-without-replacement violation STILL FAILs,
        even when the heading carries a rule tag (proves suppression did not
        blind the substantive gate)."""
        draft = (
            "## Production Path (Rule 40)\n"
            "1. In-scope asset: NuvaVault\n"
            "7. Mock components used in PoC: MockOracle\n"
        )  # item 8 (real replacement) deliberately absent -> must FAIL
        result = PP.evaluate_gate(draft, "HIGH")
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any("mock trigger" in r for r in result.reasons))

    def test_bogus_heading_still_rejected(self):
        """A heading that is not Production Path must NOT match."""
        self.assertIsNone(
            PP.PRODUCTION_PATH_HEADING_RE.match("## Production Pathway (Rule 40)")
        )
        self.assertIsNone(PP.PRODUCTION_PATH_HEADING_RE.match("## Impact Contract"))


PRECOND_BODY = (
    "The swapOut() entrypoint is permissionless and in-scope; any attacker "
    "can call it directly. Scope verdict: in.\n"
)


class PreconditionHeadingSuffix(unittest.TestCase):
    def test_rule_tag_suffix_matches(self):
        """SUPPRESSION."""
        self.assertTrue(
            PP.PRECONDITION_HEADING_RE.match("## Precondition-Reachability (Rule 40)")
        )
        self.assertTrue(
            PP.PRECONDITION_HEADING_RE.match("## **Precondition Reachability**")
        )

    def test_rule_tag_suffix_extracts_full_section(self):
        """SUPPRESSION: section body captured despite the rule tag."""
        draft = "## Precondition-Reachability (Rule 40)\n" + PRECOND_BODY + "\n## Next\nx\n"
        body = PP.extract_precondition_reachability_section(draft)
        self.assertIn("permissionless", body)
        self.assertTrue(PP.precondition_section_has_external_in_scope_path(body))

    def test_plain_heading_still_matches_control(self):
        """CONTROL."""
        self.assertTrue(
            PP.PRECONDITION_HEADING_RE.match("## Precondition-Reachability")
        )
        draft = "## Precondition-Reachability\n" + PRECOND_BODY
        body = PP.extract_precondition_reachability_section(draft)
        self.assertIn("permissionless", body)

    def test_oos_only_reliance_still_flagged_control(self):
        """CONTROL: a Precondition-Reachability section that lists ONLY an
        admin/OOS path is still detected as OOS-only even under a rule tag."""
        draft = (
            "## Precondition-Reachability (Rule 40)\n"
            "Only the guardian (admin) can set this state; requires governance "
            "multisig action.\n"
        )
        body = PP.extract_precondition_reachability_section(draft)
        self.assertTrue(PP.precondition_section_is_oos_only(body))


class ImpactContractHeadingSuffix(unittest.TestCase):
    IC_BODY = (
        "- victim: NuvaVault depositors\n"
        "- source-proof: src/NuvaVault.sol:120\n"
        "- selected-impact: fund loss\n"
        "- severity-tier: HIGH\n"
        "- listed-impact-proven: yes\n"
        "- evidence-class: source-proof\n"
        "- oos-traps: none\n"
        "- stop-condition: PoC PASS\n"
    )

    def test_rule_tag_suffix_extracts_section(self):
        """SUPPRESSION: `## Impact Contract (Rule 27)` still extracts."""
        draft = "## Impact Contract (Rule 27)\n" + self.IC_BODY + "\n## Next\nx\n"
        section = ICP._extract_markdown_section(draft, "Impact Contract")
        self.assertIn("victim:", section)
        self.assertIn("source-proof:", section)

    def test_bold_suffix_extracts_section(self):
        """SUPPRESSION: `## **Impact Contract**` still extracts."""
        draft = "## **Impact Contract**\n" + self.IC_BODY
        section = ICP._extract_markdown_section(draft, "Impact Contract")
        self.assertIn("selected-impact:", section)

    def test_plain_heading_still_extracts_control(self):
        """CONTROL: the plain heading still extracts the same substance, so
        the downstream contract-completeness check still fires."""
        draft = "## Impact Contract\n" + self.IC_BODY
        section = ICP._extract_markdown_section(draft, "Impact Contract")
        fields = ICP._parse_markdown_fields(section)
        self.assertEqual(fields.get("victim"), "NuvaVault depositors")
        self.assertEqual(fields.get("source-proof"), "src/NuvaVault.sol:120")

    def test_bogus_heading_still_rejected(self):
        """A non-matching heading name yields no section."""
        draft = "## Impact Contracts Overview (Rule 27)\n" + self.IC_BODY
        section = ICP._extract_markdown_section(draft, "Impact Contract")
        self.assertEqual(section, "")


if __name__ == "__main__":
    unittest.main()
