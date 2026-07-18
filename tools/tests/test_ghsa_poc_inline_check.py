#!/usr/bin/env python3
# r36-rebuttal: lane ZEBRA-GHSA-MD-EXPORT registered in .auditooor/agent_pathspec.json
"""Tests for tools/ghsa-poc-inline-check.py."""

import importlib.util
import os
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOL = os.path.join(_HERE, "..", "ghsa-poc-inline-check.py")

_spec = importlib.util.spec_from_file_location("ghsa_poc_inline_check", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


GOOD_MD = """# Mempool leak in zebrad allows an unauthenticated peer to grow memory

## Advisory Details

**Title:** Mempool per-peer slot leak in zebrad.

### Summary
A per-peer counter leaks on the verify-timeout arm. Affects zebrad <= 4.5.0.

### Details
Root cause at downloads.rs:261 - the timeout arm never calls release_peer_slot.

```rust
// downloads.rs:261
this.cancel_handles.remove(&txid);
```

### PoC
Install the harness and run:

```
cargo test -p zebrad --lib mempool::downloads_poc_tests -- --nocapture
```

PASS transcript:

```
test result: ok. 2 passed; 0 failed; 0 ignored
```

Negative control included.

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
"""


def _check(md):
    return mod.check(md)


class TestPass(unittest.TestCase):
    def test_clean_md_passes(self):
        res = _check(GOOD_MD)
        self.assertEqual(res["verdict"], "pass-ghsa-md-inline-poc", res["failures"])
        self.assertTrue(res["ok"])
        self.assertEqual(res["evidence"]["cwes"], ["CWE-400", "CWE-459"])
        self.assertTrue(res["evidence"]["poc_inline_fence"])

    def test_real_fixture_passes_if_present(self):
        fixture = ("/Users/wolf/audits/zebra/submissions/filed/"
                   "zebra-mempool-per-peer-slot-leak-on-verify-timeout-MEDIUM/"
                   "zebra-mempool-per-peer-slot-leak-on-verify-timeout-MEDIUM.advisory.md")
        if not os.path.isfile(fixture):
            self.skipTest("zebra fixture not present in this checkout")
        with open(fixture) as f:
            res = _check(f.read())
        self.assertEqual(res["verdict"], "pass-ghsa-md-inline-poc", res["failures"])


class TestFailHtmlComments(unittest.TestCase):
    def test_leading_comment_fails(self):
        md = "<!-- r36-rebuttal: foo -->\n" + GOOD_MD
        res = _check(md)
        self.assertEqual(res["verdict"], "fail-html-comments")
        self.assertFalse(res["ok"])

    def test_comment_inside_fence_does_not_fail(self):
        md = GOOD_MD.replace(
            "### Impact\n",
            "### Impact\nExample:\n```html\n<!-- benign in-fence comment -->\n```\n",
            1,
        )
        res = _check(md)
        self.assertEqual(res["verdict"], "pass-ghsa-md-inline-poc", res["failures"])


class TestFailMissingSection(unittest.TestCase):
    def test_missing_poc_section_fails_missing(self):
        md = GOOD_MD.replace("### PoC\n", "### NotPoC\n")
        res = _check(md)
        self.assertEqual(res["verdict"], "fail-missing-section")

    def test_missing_cvss_fails(self):
        md = GOOD_MD.replace(
            "`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` (base 5.3)", "(tbd)")
        res = _check(md)
        self.assertEqual(res["verdict"], "fail-missing-section")
        self.assertTrue(any("CVSS" in f for f in res["failures"]))

    def test_missing_cwe_fails(self):
        md = GOOD_MD.replace("CWE-400", "weakness").replace("CWE-459", "cleanup")
        res = _check(md)
        self.assertEqual(res["verdict"], "fail-missing-section")
        self.assertTrue(any("CWE" in f for f in res["failures"]))

    def test_missing_form_section_fails(self):
        md = GOOD_MD.replace("## Weaknesses\n", "## NotWeaknesses\n")
        res = _check(md)
        self.assertEqual(res["verdict"], "fail-missing-section")
        self.assertTrue(any("weaknesses" in f for f in res["failures"]))

    def test_out_of_order_subsections_fails(self):
        # swap Summary and Details headers -> order Details/Summary/PoC/Impact
        md = GOOD_MD.replace("### Summary", "<<S>>").replace(
            "### Details", "### Summary").replace("<<S>>", "### Details")
        res = _check(md)
        self.assertEqual(res["verdict"], "fail-missing-section")


class TestFailNoInlinePoc(unittest.TestCase):
    def test_pointer_to_zip_fails(self):
        md = GOOD_MD.replace(
            "Install the harness and run:\n\n"
            "```\ncargo test -p zebrad --lib mempool::downloads_poc_tests -- --nocapture\n```\n\n"
            "PASS transcript:\n\n"
            "```\ntest result: ok. 2 passed; 0 failed; 0 ignored\n```\n\n"
            "Negative control included.",
            "See the attached finding-poc.zip for the full harness and transcript.",
        )
        res = _check(md)
        self.assertEqual(res["verdict"], "fail-no-inline-poc")
        self.assertFalse(res["evidence"]["poc_inline_fence"])

    def test_prose_only_poc_no_fence_fails(self):
        md = GOOD_MD.replace(
            "Install the harness and run:\n\n"
            "```\ncargo test -p zebrad --lib mempool::downloads_poc_tests -- --nocapture\n```\n\n"
            "PASS transcript:\n\n"
            "```\ntest result: ok. 2 passed; 0 failed; 0 ignored\n```\n\n"
            "Negative control included.",
            "We ran cargo test and it passed. Trust us.",
        )
        res = _check(md)
        self.assertEqual(res["verdict"], "fail-no-inline-poc")


class TestFailInternalLeak(unittest.TestCase):
    def test_internal_section_leak_fails(self):
        md = GOOD_MD + "\n## Originality (R47 / R53)\nDistinct from GHSA-65jj.\n"
        res = _check(md)
        self.assertEqual(res["verdict"], "fail-internal-leak")

    def test_internal_path_leak_fails(self):
        md = GOOD_MD.replace(
            "Negative control included.",
            "Negative control included. See /Users/wolf/audits/zebra/poc.",
        )
        res = _check(md)
        self.assertEqual(res["verdict"], "fail-internal-leak")

    def test_html_comment_takes_precedence_over_leak(self):
        md = "<!-- x -->\n" + GOOD_MD + "\n## Originality\nfoo\n"
        res = _check(md)
        self.assertEqual(res["verdict"], "fail-html-comments")


class TestCLI(unittest.TestCase):
    def test_cli_pass_rc0(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.advisory.md")
            with open(p, "w") as f:
                f.write(GOOD_MD)
            self.assertEqual(mod.main([p]), 0)

    def test_cli_fail_rc1(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.advisory.md")
            with open(p, "w") as f:
                f.write("<!-- leak -->\n" + GOOD_MD)
            self.assertEqual(mod.main([p]), 1)

    def test_cli_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.advisory.md")
            with open(p, "w") as f:
                f.write(GOOD_MD)
            self.assertEqual(mod.main([p, "--json"]), 0)


if __name__ == "__main__":
    unittest.main()
