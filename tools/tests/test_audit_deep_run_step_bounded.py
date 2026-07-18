"""Regression: the solidity-deep-audit run_step() helper MUST wall-clock-bound each
deep-engine step (echidna-campaign / medusa-fuzz / halmos-runner / chimera-echidna-emit
/ foundry-invariant-runner). Before the fix it ran the engine via bare `"$@"` with no
timeout, so a hung engine (0% CPU, waiting on a dead child) stalled the ENTIRE audit-deep
run indefinitely (observed NUVA 2026-07-06, ~5min frozen at 0% CPU). This guards that the
gtimeout/timeout wrapper + AUDITOOOR_DEEP_STEP_TIMEOUT env stay wired into run_step.
"""
import os
import re
import unittest

_MAKEFILE = os.path.join(os.path.dirname(__file__), "..", "..", "Makefile")


class TestRunStepBounded(unittest.TestCase):
    def setUp(self):
        with open(_MAKEFILE, encoding="utf-8") as fh:
            self.mk = fh.read()

    def _run_step_body(self) -> str:
        # Extract the run_step() { ... } recipe body (a single backslash-continued line block).
        m = re.search(r"run_step\(\)\s*\{.*?write_artifact.*?\}", self.mk, re.DOTALL)
        self.assertIsNotNone(m, "run_step() helper not found in Makefile")
        return m.group(0)

    def test_run_step_wraps_engine_in_a_timeout(self):
        body = self._run_step_body()
        self.assertIn("AUDITOOOR_DEEP_STEP_TIMEOUT", body,
                      "run_step must expose an env-overridable per-step wall-clock cap")
        self.assertTrue(re.search(r"\bgtimeout\b", body) and re.search(r"\btimeout\b", body),
                        "run_step must resolve gtimeout (or timeout) to bound each deep-engine step")
        # the resolved timeout binary must actually prefix the engine invocation ($_step_to "$@")
        self.assertRegex(body, r"\$\$_step_to\s+\"\$\$@\"",
                         "the resolved timeout must prefix the engine command, else the cap is dead")

    def test_run_step_records_timeout_status_not_phantom_ok(self):
        body = self._run_step_body()
        # a timed-out step must be recorded as timeout (rc 124/137), never silently ok.
        self.assertIn('status="timeout"', body)
        self.assertTrue("124" in body and "137" in body,
                        "run_step must detect the gtimeout exit codes (124 TERM / 137 KILL)")


class TestPerlangProducerBounded(unittest.TestCase):
    """Regression: the _audit-deep-perlang-genuine-coverage recipe must wall-clock-bound
    the cross-function-harness-producer (mutation-verify aggregation). Before the fix it
    ran the producer via a bare `python3 ... || echo WARN` - the `||` only catches a
    non-zero EXIT, not a HANG. Over a broken/oversized forge harness tree (NUVA:
    40 uncheckable harnesses) the producer ground forever at 0% CPU, stalling audit-deep
    before the Go engine (gate A) could run. This guards the gtimeout wrapper stays wired.
    """

    def setUp(self):
        with open(_MAKEFILE, encoding="utf-8") as fh:
            self.mk = fh.read()

    def _recipe(self) -> str:
        m = re.search(r"_audit-deep-perlang-genuine-coverage:.*?(?=\n[A-Za-z0-9_.\-]+:|\n# ---)",
                      self.mk, re.DOTALL)
        self.assertIsNotNone(m, "_audit-deep-perlang-genuine-coverage recipe not found")
        return m.group(0)

    def test_producer_call_is_timeout_bounded(self):
        r = self._recipe()
        self.assertIn("AUDITOOOR_PERLANG_PRODUCER_TIMEOUT", r,
                      "the producer call must expose an env-overridable wall-clock cap")
        self.assertTrue(re.search(r"\bgtimeout\b", r) and re.search(r"\btimeout\b", r),
                        "recipe must resolve gtimeout/timeout to bound the producer")
        self.assertRegex(r, r"\$\$_plc_to\s+python3",
                         "the resolved timeout must prefix the producer python3 call")

    def test_producer_records_timeout_not_silent(self):
        r = self._recipe()
        self.assertTrue("124" in r and "137" in r,
                        "recipe must detect the gtimeout exit codes (124 TERM / 137 KILL)")
        self.assertIn("wall-clock cap", r)

    def test_strict_producer_failure_is_fail_closed(self):
        r = self._recipe()
        self.assertIn("STRICT=1: refusing to continue with partial mutation evidence", r)
        self.assertIn("STRICT=1: refusing to continue with incomplete mutation evidence", r)
        self.assertIn("STRICT=1: required producer is absent; refusing to continue", r)

    def test_strict_is_propagated_from_deep_callers(self):
        # A strict parent must pass STRICT=1 into the nested producer. Otherwise
        # the producer's fail-closed branch is never selected.
        self.assertIn(
            'LANG_HINT=solidity PROJECT_ROOT="$$project_root" $(if $(STRICT),STRICT=1)',
            self.mk,
        )
        self.assertIn(
            'LANG_HINT=go $(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)") $(if $(STRICT),STRICT=1)',
            self.mk,
        )


class TestGoProdHarnessBounded(unittest.TestCase):
    """Regression: the go-dynamic-engine-runner prod-harness `go test ./...` must be
    bounded by its OWN tighter cap, not run_with_budget's full remaining wall-clock.
    On a large cosmos vault the production-harness go test runs 10-20min and holds the
    fuzz_runs manifest (the live-engines gate-A evidence) hostage far behind the
    already-completed fuzz step (NUVA 2026-07-06: fuzz held <1min, manifest unwritten
    11min later stuck in prod-harness). A separate ABCI-surface signal must never delay
    the gate-A fuzz evidence."""

    def setUp(self):
        p = os.path.join(os.path.dirname(__file__), "..", "go-dynamic-engine-runner.sh")
        with open(p, encoding="utf-8") as fh:
            self.sh = fh.read()

    def test_prod_harness_go_test_is_capped(self):
        m = re.search(r"ph_fail=0; ph_pass=0.*?PROD_HARNESS_STATUS=\"pass", self.sh, re.DOTALL)
        self.assertIsNotNone(m, "prod-harness block not found")
        b = m.group(0)
        self.assertIn("AUDITOOOR_PROD_HARNESS_TIMEOUT", b,
                      "prod-harness needs an env-overridable cap separate from the run budget")
        self.assertRegex(b, r'"\$TIMEOUT_BIN"\s+--kill-after=\d+\s+-s\s+TERM\s+"\$_ph_cap"\s+go\s+test',
                         "the prod-harness go test must run under the bounded timeout")
        self.assertTrue("ph_timeout" in b and "timeout(" in b,
                        "a timed-out prod-harness must be recorded distinctly, not treated as a hang")


if __name__ == "__main__":
    unittest.main()
