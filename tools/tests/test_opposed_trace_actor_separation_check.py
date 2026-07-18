"""Unit tests for Rule 44 Opposed-Trace Actor Separation preflight."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "r44"

_spec = importlib.util.spec_from_file_location(
    "opposed_trace_actor_separation_check",
    ROOT / "tools" / "opposed-trace-actor-separation-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


class OpposedTraceActorSeparationCheckTests(unittest.TestCase):
    # ------------------------------------------------------------------
    # 1. Spark v8 pass fixture - should PASS with pass-actor-separation-with-assertions
    # ------------------------------------------------------------------
    def test_spark_v8_pass(self) -> None:
        target = FIXTURES / "spark_v8_pass"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 0, f"expected pass, got: {payload}")
        self.assertEqual(
            payload["verdict"],
            "pass-actor-separation-with-assertions",
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 2. Spark v7 fail fixture - single wallet multi-role anti-pattern
    # ------------------------------------------------------------------
    def test_spark_v7_fail_single_wallet(self) -> None:
        target = FIXTURES / "spark_v7_fail"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 1, f"expected fail, got rc={rc}: {payload}")
        self.assertEqual(
            payload["verdict"],
            "fail-single-wallet-multi-role",
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 3. EVM Foundry pass fixture - distinct vm.startPrank actors
    # ------------------------------------------------------------------
    def test_evm_foundry_pass(self) -> None:
        target = FIXTURES / "evm_foundry_pass"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 0, f"expected pass, got: {payload}")
        self.assertEqual(
            payload["verdict"],
            "pass-actor-separation-with-assertions",
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 4. EVM Foundry fail - no role separation (single deployer)
    # ------------------------------------------------------------------
    def test_evm_foundry_fail_no_separation(self) -> None:
        target = FIXTURES / "evm_foundry_fail_no_separation"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 1, f"expected fail, got rc={rc}: {payload}")
        self.assertIn(
            payload["verdict"],
            ("fail-no-role-separation", "fail-no-withheld-artifact-assertion"),
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 5. Cooperative-case labeled - should PASS with pass-cooperative-case-labeled
    # ------------------------------------------------------------------
    def test_cooperative_labeled_pass(self) -> None:
        target = FIXTURES / "cooperative_labeled_pass"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 0, f"expected pass, got: {payload}")
        self.assertEqual(
            payload["verdict"],
            "pass-cooperative-case-labeled",
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 6. Cosmos pass - separated signers + withheld loop + causality
    # ------------------------------------------------------------------
    def test_cosmos_pass(self) -> None:
        target = FIXTURES / "cosmos_pass"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 0, f"expected pass, got: {payload}")
        self.assertEqual(
            payload["verdict"],
            "pass-actor-separation-with-assertions",
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 7. Solana pass - separate Keypair per role
    # ------------------------------------------------------------------
    def test_solana_pass(self) -> None:
        target = FIXTURES / "solana_pass"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 0, f"expected pass, got: {payload}")
        self.assertEqual(
            payload["verdict"],
            "pass-actor-separation-with-assertions",
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 8. Rebuttal override - should PASS with ok-rebuttal
    # ------------------------------------------------------------------
    def test_rebuttal_override(self) -> None:
        target = FIXTURES / "r44_rebuttal_override"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 0, f"expected pass, got: {payload}")
        self.assertEqual(
            payload["verdict"],
            "ok-rebuttal",
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 9. Cosmos fail - no withheld-artifact assertion
    # ------------------------------------------------------------------
    def test_cosmos_fail_no_withheld(self) -> None:
        target = FIXTURES / "cosmos_fail_no_withheld"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 1, f"expected fail, got rc={rc}: {payload}")
        self.assertEqual(
            payload["verdict"],
            "fail-no-withheld-artifact-assertion",
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 10. Substrate pass - separate OriginFor actors
    # ------------------------------------------------------------------
    def test_substrate_pass(self) -> None:
        target = FIXTURES / "substrate_pass"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 0, f"expected pass, got: {payload}")
        self.assertEqual(
            payload["verdict"],
            "pass-actor-separation-with-assertions",
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 11. EVM fail - no attack-causality assertion
    # ------------------------------------------------------------------
    def test_evm_fail_no_causality(self) -> None:
        target = FIXTURES / "evm_fail_no_causality"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 1, f"expected fail, got rc={rc}: {payload}")
        self.assertEqual(
            payload["verdict"],
            "fail-no-attack-causality-assertion",
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 12. Move fail - single signer for both roles
    # ------------------------------------------------------------------
    def test_move_fail_single_signer(self) -> None:
        target = FIXTURES / "move_fail_single_signer"
        self.assertTrue(target.exists(), f"fixture missing: {target}")
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 1, f"expected fail, got rc={rc}: {payload}")
        self.assertIn(
            payload["verdict"],
            ("fail-no-role-separation", "fail-single-wallet-multi-role",
             "fail-no-withheld-artifact-assertion"),
            f"wrong verdict: {payload}",
        )

    # ------------------------------------------------------------------
    # 13. Below-HIGH severity - out of scope (pass)
    # ------------------------------------------------------------------
    def test_below_high_out_of_scope(self) -> None:
        target = FIXTURES / "spark_v8_pass"
        rc, payload = mod.run(target, severity_override="low")
        self.assertEqual(rc, 0, f"expected pass (out-of-scope): {payload}")
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_medium_out_of_scope(self) -> None:
        target = FIXTURES / "spark_v8_pass"
        rc, payload = mod.run(target, severity_override="medium")
        self.assertEqual(rc, 0, f"expected pass (out-of-scope): {payload}")
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    # ------------------------------------------------------------------
    # 14. Non-existent target - error
    # ------------------------------------------------------------------
    def test_error_missing_target(self) -> None:
        target = FIXTURES / "does_not_exist_zzz"
        rc, payload = mod.run(target, severity_override="high")
        self.assertEqual(rc, 2, f"expected error rc=2: {payload}")
        self.assertEqual(payload["verdict"], "error")

    # ------------------------------------------------------------------
    # 15. CRITICAL severity - same logic applies (fires on HIGH+)
    # ------------------------------------------------------------------
    def test_critical_fires(self) -> None:
        target = FIXTURES / "spark_v8_pass"
        rc, payload = mod.run(target, severity_override="critical")
        self.assertEqual(rc, 0, f"expected pass: {payload}")
        self.assertEqual(
            payload["verdict"],
            "pass-actor-separation-with-assertions",
        )

    # ------------------------------------------------------------------
    # 16. Non-opposed-trace harness - pass-out-of-scope
    # ------------------------------------------------------------------
    def test_non_opposed_trace_pass_out_of_scope(self) -> None:
        """A harness with no opposed-trace signals passes out-of-scope."""
        import tempfile
        from pathlib import Path as P

        with tempfile.TemporaryDirectory() as d:
            f = P(d) / "plain_test.go"
            f.write_text(
                "// plain unit test, standalone integration check\n"
                "func TestFoo(t *testing.T) { t.Log(\"hello\") }\n",
                encoding="utf-8",
            )
            rc, payload = mod.run(P(d), severity_override="high")
        self.assertEqual(rc, 0, f"expected pass: {payload}")
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    # ------------------------------------------------------------------
    # 17. HTML-comment rebuttal form
    # ------------------------------------------------------------------
    def test_html_comment_rebuttal(self) -> None:
        import tempfile
        from pathlib import Path as P

        body = (
            "# Opposed-trace harness\n"
            "## Severity: High\n"
            "Attacker withholds tx-real in this run.\n"
            "<!-- r44-rebuttal: single-party-regtest; victim not present in this harness -->\n"
        )
        with tempfile.TemporaryDirectory() as d:
            f = P(d) / "run.sh"
            f.write_text(body, encoding="utf-8")
            rc, payload = mod.run(P(d), severity_override="high")
        self.assertEqual(rc, 0, f"expected ok-rebuttal: {payload}")
        self.assertEqual(payload["verdict"], "ok-rebuttal")


if __name__ == "__main__":
    unittest.main()
