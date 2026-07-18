#!/usr/bin/env python3
# r36-rebuttal: lane ZEBRA-GHSA-EXPORT registered in .auditooor/agent_pathspec.json
"""Tests for tools/ghsa-advisory-export.py."""

import importlib.util
import json
import os
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOL = os.path.join(_HERE, "..", "ghsa-advisory-export.py")

_spec = importlib.util.spec_from_file_location("ghsa_advisory_export", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


GOOD_DRAFT = """<!-- l34-rebuttal: authorized new draft -->
<!-- escalation-rebuttal: structural ceiling -->

# Mempool leak in zebrad allows an unauthenticated peer to grow memory

## Advisory Details

**Title:** Mempool per-peer slot leak in zebrad allows an unauthenticated peer to disable the cap.

### Summary
A per-peer counter leaks on the verify-timeout arm. Affects zebrad <= 4.5.0.

### Details
Root cause at downloads.rs:261 - the timeout arm removes cancel_handles but
never calls release_peer_slot, so pending_per_peer is never decremented.

### PoC
Run `cargo test -p zebrad --lib mempool::downloads_poc_tests`. Transcript shows
`test result: ok. 2 passed`. Negative control included.

### Impact
CWE-400 resource consumption. Node operators impacted by an unauthenticated peer.

## Affected products
- **Ecosystem:** crates.io (Rust)
- **Package name:** zebrad
- **Affected versions:** `<= 4.5.0`
- **Patched versions:** none

## Severity
- **Severity band:** Medium
- **CVSS:3.1 vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` (base 5.3)

## Weaknesses
- CWE-400 Uncontrolled Resource Consumption
- CWE-459 Incomplete Cleanup

## Originality (R47 / R53)
Distinct from GHSA-65jj. Internal section - must NOT leak into body.

## Escalate-First Attempt (Check #127)
Higher tier infeasible. Internal section - must NOT leak into body.
"""


class TestParse(unittest.TestCase):
    def setUp(self):
        self.parsed = mod.parse_draft(GOOD_DRAFT)

    def test_title_prefers_explicit(self):
        self.assertIn("Mempool per-peer slot leak", self.parsed["title"])

    def test_four_sections_extracted(self):
        for k in ("summary", "details", "poc", "impact"):
            self.assertTrue(self.parsed["sections"][k], f"section {k} empty")
        self.assertIn("downloads.rs:261", self.parsed["sections"]["details"])

    def test_affected_products(self):
        aff = self.parsed["affected"]
        self.assertIn("crates.io", aff["ecosystem"])
        self.assertEqual(aff["package"], "zebrad")
        self.assertIn("4.5.0", aff["affected_versions"])
        self.assertIn("none", aff["patched_versions"])

    def test_cvss_vector(self):
        self.assertEqual(self.parsed["cvss"],
                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L")

    def test_severity_band(self):
        self.assertEqual(self.parsed["severity_band"], "Medium")

    def test_cwes(self):
        self.assertEqual(self.parsed["cwes"], ["CWE-400", "CWE-459"])


class TestRender(unittest.TestCase):
    def setUp(self):
        self.parsed = mod.parse_draft(GOOD_DRAFT)
        self.body = mod.build_advisory_body(self.parsed)

    def test_body_has_four_section_headers(self):
        for h in ("### Summary", "### Details", "### PoC", "### Impact"):
            self.assertIn(h, self.body)

    def test_body_strips_html_comments(self):
        self.assertNotIn("l34-rebuttal", self.body)
        self.assertNotIn("escalation-rebuttal", self.body)
        self.assertNotIn("<!--", self.body)

    def test_body_excludes_internal_sections(self):
        # Originality / Escalate-First are NOT among the 4 rendered sections.
        self.assertNotIn("Originality", self.body)
        self.assertNotIn("Escalate-First", self.body)
        self.assertNotIn("must NOT leak", self.body)

    def test_json_sidecar_shape(self):
        j = mod.build_json(self.parsed)
        self.assertEqual(j["schema"], "auditooor.ghsa_advisory_export.v1")
        self.assertEqual(j["affected_products"]["package"], "zebrad")
        self.assertEqual(j["severity"]["band"], "Medium")
        self.assertIn("CVSS:3.1", j["severity"]["cvss_v3_vector"])
        self.assertEqual(j["weaknesses"], ["CWE-400", "CWE-459"])


class TestValidate(unittest.TestCase):
    def test_good_draft_passes(self):
        parsed = mod.parse_draft(GOOD_DRAFT)
        body = mod.build_advisory_body(parsed)
        res = mod.validate_advisory(parsed, body)
        self.assertTrue(res["ok"], res["failures"])

    def test_missing_cvss_fails(self):
        bad = GOOD_DRAFT.replace(
            "`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` (base 5.3)", "(tbd)")
        parsed = mod.parse_draft(bad)
        body = mod.build_advisory_body(parsed)
        res = mod.validate_advisory(parsed, body)
        self.assertFalse(res["ok"])
        self.assertTrue(any("CVSS" in f for f in res["failures"]))

    def test_missing_cwe_fails(self):
        bad = GOOD_DRAFT.replace("CWE-400", "weakness").replace("CWE-459", "cleanup")
        parsed = mod.parse_draft(bad)
        body = mod.build_advisory_body(parsed)
        res = mod.validate_advisory(parsed, body)
        self.assertFalse(res["ok"])
        self.assertTrue(any("CWE" in f for f in res["failures"]))

    def test_missing_section_fails(self):
        bad = GOOD_DRAFT.replace("### Impact\n", "### NotImpact\n")
        parsed = mod.parse_draft(bad)
        body = mod.build_advisory_body(parsed)
        res = mod.validate_advisory(parsed, body)
        self.assertFalse(res["ok"])
        self.assertTrue(any("impact" in f for f in res["failures"]))


class TestCLI(unittest.TestCase):
    def test_export_writes_files(self):
        with tempfile.TemporaryDirectory() as d:
            draft = os.path.join(d, "finding.md")
            with open(draft, "w") as f:
                f.write(GOOD_DRAFT)
            rc = mod.main(["--draft", draft, "--json", "--strict"])
            self.assertEqual(rc, 0)
            txt = draft[:-3] + ".advisory.txt"
            js = draft[:-3] + ".advisory.json"
            self.assertTrue(os.path.isfile(txt))
            self.assertTrue(os.path.isfile(js))
            with open(js) as f:
                data = json.load(f)
            self.assertEqual(data["affected_products"]["package"], "zebrad")
            with open(txt) as f:
                body = f.read()
            self.assertNotIn("<!--", body)
            self.assertIn("### Summary", body)

    def test_export_then_validate_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            draft = os.path.join(d, "finding.md")
            with open(draft, "w") as f:
                f.write(GOOD_DRAFT)
            out = os.path.join(d, "out.advisory.txt")
            self.assertEqual(mod.main(["--draft", draft, "--out", out, "--strict"]), 0)
            # Re-parse the emitted body: it must still validate. The body has the
            # 4 sections but not the structured Severity/Weaknesses fields, so
            # validation of the BODY alone for CVSS/CWE is informational; we
            # validate the original draft path roundtrips structurally.
            self.assertEqual(mod.main(["--validate", draft, "--strict"]), 0)

    def test_strict_export_missing_cvss_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            draft = os.path.join(d, "finding.md")
            with open(draft, "w") as f:
                f.write(GOOD_DRAFT.replace(
                    "`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` (base 5.3)", "(tbd)"))
            rc = mod.main(["--draft", draft, "--strict"])
            self.assertEqual(rc, 2)


class TestAdvisoryMd(unittest.TestCase):
    """The pure-markdown GHSA paste (PoC inline, filtered passthrough)."""

    def setUp(self):
        self.md = mod.build_advisory_md(GOOD_DRAFT)

    def test_starts_with_title_h1(self):
        self.assertTrue(self.md.lstrip().startswith("# Mempool leak in zebrad"))

    def test_keeps_advisory_details_wrapper_and_form_sections(self):
        for h in ("## Advisory Details", "### Summary", "### Details",
                  "### PoC", "### Impact", "## Affected products",
                  "## Severity", "## Weaknesses"):
            self.assertIn(h, self.md, f"missing header {h}")

    def test_strips_all_html_comments(self):
        self.assertNotIn("<!--", self.md)
        self.assertNotIn("l34-rebuttal", self.md)
        self.assertNotIn("escalation-rebuttal", self.md)

    def test_drops_internal_gate_sections(self):
        self.assertNotIn("## Originality", self.md)
        self.assertNotIn("## Escalate-First Attempt", self.md)
        self.assertNotIn("must NOT leak", self.md)
        self.assertNotIn("Check #127", self.md)

    def test_poc_kept_inline(self):
        # the cargo invocation stays in the PoC body (inline, NOT zipped)
        self.assertIn("cargo test -p zebrad", self.md)
        self.assertIn("test result: ok", self.md)
        self.assertNotIn("-poc.zip", self.md)
        self.assertNotIn("see attached", self.md.lower())

    def test_no_internal_leaks(self):
        low = self.md.lower()
        self.assertNotIn("/users/wolf", low)
        self.assertNotIn("auditooor", low)
        self.assertNotIn("worker-", low)

    def test_html_comment_inside_code_fence_preserved(self):
        draft = GOOD_DRAFT.replace(
            "### PoC\n",
            "### PoC\nExample HTML payload:\n```html\n<!-- payload comment -->\n```\n",
            1,
        )
        out = mod.build_advisory_md(draft)
        # the comment inside the ```html fence is preserved; the leading
        # rebuttal markers are still stripped
        self.assertIn("<!-- payload comment -->", out)
        self.assertNotIn("l34-rebuttal", out)

    def test_cli_emits_advisory_md_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            draft = os.path.join(d, "finding.md")
            with open(draft, "w") as f:
                f.write(GOOD_DRAFT)
            rc = mod.main(["--draft", draft, "--strict"])
            self.assertEqual(rc, 0)
            md_path = draft[:-3] + ".advisory.md"
            self.assertTrue(os.path.isfile(md_path))
            with open(md_path) as f:
                body = f.read()
            self.assertIn("## Advisory Details", body)
            self.assertIn("cargo test -p zebrad", body)
            self.assertNotIn("<!--", body)
            self.assertNotIn("## Originality", body)

    def test_cli_no_md_suppresses(self):
        with tempfile.TemporaryDirectory() as d:
            draft = os.path.join(d, "finding.md")
            with open(draft, "w") as f:
                f.write(GOOD_DRAFT)
            rc = mod.main(["--draft", draft, "--no-md", "--strict"])
            self.assertEqual(rc, 0)
            md_path = draft[:-3] + ".advisory.md"
            self.assertFalse(os.path.isfile(md_path))



if __name__ == "__main__":
    unittest.main()
