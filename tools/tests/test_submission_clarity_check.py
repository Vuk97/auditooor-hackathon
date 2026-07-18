"""Golden tests for tools/submission-clarity-check.py - the readability gate.

Guards the three clarity signals (C1 lead-summary, C2 what-the-PoC-proves, C3
lead-readability) + never-false-pass on empty/missing. Advisory-first: a correct
finding with all three present must PASS; a finding missing them must WARN (not
silently pass).
"""
import importlib.util
import os
import sys
import unittest

_P = os.path.join(os.path.dirname(__file__), "..", "submission-clarity-check.py")
_spec = importlib.util.spec_from_file_location("submission_clarity_check", _P)
scc = importlib.util.module_from_spec(_spec)
sys.modules["submission_clarity_check"] = scc
_spec.loader.exec_module(scc)


GOOD = """# Unbounded X leads to OOM crash

## Summary

`Foo.NewThing` at `src/foo.go:397` inserts into an unbounded map with no cap, and the
only reaper evicts by staleness. An unauthenticated remote caller can flood `newThing`
until the node OOM-crashes. This affects any default-config RPC node (`config.go:213`).

## Severity
Medium

## Impact Contract
- victim: operators

## Proof of concept
```go
func TestUnbounded(t *testing.T) {}
```

## What the PoC proves
Test A proves creation never caps (len==N, zero rejections); test B proves the reaper
evicts only by staleness, at `src/foo.go:345`.

## Recommended fix
Add a cap.
"""

# Our real SEI shape: opens with rebuttal comments, no ## Summary, proof-claim only inline.
BAD_LIKE_SEI = """# Unbounded filter allocation leads to crash

<!-- r40-rebuttal: DoS availability finding. -->
<!-- r64-rebuttal: make target is real. -->
<!-- r82-rebuttal: recoverable by restart. -->

## Severity
Medium

## Impact Contract
- victim: operators of RPC nodes

## Root cause
`FilterAPI.NewFilter` at `filter.go:397` inserts without a cap.

## Proof of concept
It proves the two mechanism claims via a Go test.
```go
func TestUnbounded(t *testing.T) {}
```

## Recommended fix
Add a cap.
"""


class TestClarity(unittest.TestCase):
    def test_good_finding_passes(self):
        r = scc.evaluate(GOOD)
        self.assertEqual(r["verdict"], "pass-clarity", r["warnings"])
        self.assertEqual(r["signals"]["lead_summary"], "ok")
        self.assertEqual(r["signals"]["what_poc_proves"], "ok-section")
        self.assertEqual(r["signals"]["lead_readability"], "ok")

    def test_sei_shape_warns_on_all_three(self):
        r = scc.evaluate(BAD_LIKE_SEI)
        self.assertEqual(r["verdict"], "warn-clarity-issues")
        # C1: no ## Summary heading at all
        self.assertEqual(r["signals"]["lead_summary"], "absent")
        # C2: PoC present, proof-claim only inline ("It proves ...") -> nudge to section
        self.assertEqual(r["signals"]["what_poc_proves"], "inline-only")
        # C3: three rebuttal comments before the first prose
        self.assertEqual(r["signals"]["lead_readability"], "comment-wall")

    def test_summary_after_machinery_is_late(self):
        md = ("# T\n\n## Impact Contract\n- victim: x\n\n## Summary\n"
              "This bug at `a.go:5` lets anyone crash the node. It is unauthenticated.\n")
        r = scc.evaluate(md)
        self.assertEqual(r["signals"]["lead_summary"], "present-but-late")

    def test_summary_without_cite_flagged(self):
        md = ("# T\n\n## Summary\nThis is a serious bug. Anyone can trigger it remotely.\n\n"
              "## Impact Contract\n- v: x\n")
        r = scc.evaluate(md)
        self.assertEqual(r["signals"]["lead_summary"], "no-cite")

    def test_no_poc_makes_c2_na(self):
        md = ("# T\n\n## Summary\nBug at `a.go:9` allows fund theft by anyone. Unauthenticated.\n\n"
              "## Recommendation\nfix\n")
        r = scc.evaluate(md)
        self.assertEqual(r["signals"]["what_poc_proves"], "n/a-no-poc")

    def test_empty_is_fail_not_pass(self):
        r = scc.evaluate("   \n\n")
        self.assertEqual(r["verdict"], "fail-empty")

    def test_poc_with_named_proves_section_ok(self):
        md = ("# T\n\n## Summary\nBug at `a.go:1` crashes the node, unauthenticated remote.\n"
              "It is reachable by default.\n\n## Proof of concept\n```\nx\n```\n\n"
              "## What the test proves\nProves the map grows unbounded.\n")
        r = scc.evaluate(md)
        self.assertEqual(r["signals"]["what_poc_proves"], "ok-section")


if __name__ == "__main__":
    unittest.main()
