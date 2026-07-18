"""Guard: the UNBOUNDED advisory tail of `make audit` carries a wall-clock cap.

Root cause (NUVA, 2026-07-02): `make audit` hung for 1h07m though the CORE audit +
completion marker finished long before - `make hunt-starter` (an advisory Step-1 sub-target)
sat at 0% CPU for 41+ min blocked on an MCP/network call with NO wall-clock cap, so the
recipe never returned. G9 says advisory Step-1 stages must not block, but with no timeout one
hung call blocks forever.

Fix: an env-configurable `AUDITOOOR_ADVISORY_TAIL_TIMEOUT` (default 300s) wraps every
unbounded advisory sub-target via a `$$_ADV_TO` prefix (gtimeout||timeout, unwrapped if
neither exists). A timeout DROPS the advisory pack + continues (exit 0 preserved), exactly
like the existing advisory-warn failure branches.

This structural test asserts:
  1. every named advisory sub-target in the `audit:` recipe carries the `$$_ADV_TO` prefix,
  2. the timeout-binary detection + AUDITOOOR_ADVISORY_TAIL_TIMEOUT default(300) block exists,
  3. CONTROL: provider-fanout-discipline-check is NOT wrapped (it is blocking-by-design and
     must stay exit-non-zero, not silently timed out and dropped).
"""
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"

# The unbounded advisory sub-targets that must be timeout-wrapped.
WRAPPED_TARGETS = [
    "cross-seed",
    "hacker-brief",
    "phase-b-e-measurement-report",
    "audit-hacker-logic-bridge",
    "mined-findings-hunter-bridge",
    "v3-worker-packet",
    "prior-disclosure-index",
    "exploit-queue",
    "prove-top-leads",
    "queue-proof-hard-close",
    "field-validation-report",
    "v3-roadmap-sidecars",
    "live-target-intel",
    "hunt-starter",
    "auto-coverage-close",
]


class AdvisoryTailBoundedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = MAKEFILE.read_text()
        # Wrapped-invocation lines look like: `$$_ADV_TO $(MAKE) --no-print-directory <tgt>`
        cls.wrapped = set(
            re.findall(
                r"\$\$_ADV_TO \$\(MAKE\) --no-print-directory ([a-z0-9-]+)", cls.text
            )
        )

    def test_env_var_and_default_present(self):
        self.assertIn(
            "AUDITOOOR_ADVISORY_TAIL_TIMEOUT",
            self.text,
            "advisory-tail cap env var must be referenced",
        )
        self.assertRegex(
            self.text,
            r"AUDITOOOR_ADVISORY_TAIL_TIMEOUT:-300",
            "advisory-tail cap must default to 300s",
        )

    def test_timeout_binary_detection_present(self):
        # gtimeout preferred, timeout fallback, unwrapped if neither (never break a box).
        self.assertIn("command -v gtimeout", self.text)
        self.assertIn("command -v timeout", self.text)
        self.assertIn(
            '_ADV_TO=""',
            self.text,
            "must fall back to UNWRAPPED (empty prefix) when no timeout binary exists",
        )

    def test_all_advisory_targets_wrapped(self):
        for tgt in WRAPPED_TARGETS:
            self.assertIn(
                tgt,
                self.wrapped,
                f"advisory sub-target {tgt!r} must carry the $$_ADV_TO wall-clock cap",
            )

    def test_provider_fanout_discipline_check_not_wrapped(self):
        # CONTROL: provider-fanout-discipline-check is blocking-by-design (exit-non-zero on
        # failure). It must NOT be timeout-wrapped, or a hung call would be silently dropped.
        self.assertNotIn(
            "provider-fanout-discipline-check",
            self.wrapped,
            "provider-fanout-discipline-check must stay UNWRAPPED (blocking-by-design)",
        )
        self.assertRegex(
            self.text,
            r"provider-fanout-discipline-check[^\n]*\|\| pfd_rc=\$\$\?",
            "provider-fanout-discipline-check must remain exit-non-zero-by-design",
        )


if __name__ == "__main__":
    unittest.main()
