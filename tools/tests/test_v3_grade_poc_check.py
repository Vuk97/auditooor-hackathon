"""Unit tests for Rule 40 V3-grade-PoC preflight."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "v3_grade_poc_check",
    ROOT / "tools" / "v3-grade-poc-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]

HB_STAGING = Path("/Users/wolf/audits/hyperbridge/submissions/staging")


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r40_v3poc_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests" / "case").mkdir(parents=True)
    return root


def _write(body: str, source: str | None = None, filename: str = "draft-HIGH.md") -> Path:
    root = _workspace()
    if source is not None:
        (root / "poc-tests" / "case" / "poc_test.go").write_text(source, encoding="utf-8")
        body += "\nPoC: `poc-tests/case`\n"
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body, encoding="utf-8")
    return draft


# A draft body that satisfies all six V3-grade points.
_V3_GRADE_BODY = """# Loss of bridged funds via a forged commitment

- Severity: High

## Proof of Concept

The PoC drives the real, unmodified verify_payload entrypoint - the real
vulnerable code - and exercises the real impact surface (the commitment
store). It is live production code, not a mock.

## Opposed-trace (every guard between bug and impact)

Every protocol-owned defense is enumerated: the refund path is executed, the
finalizer is executed, the challenge guard is ruled out with source evidence
at lib.rs:352. all_defenses_enumerated.

## Mock assumptions

Mocked components are external dependencies only: the external RPC client is
mocked. Each mock assumption is stated: the mock RPC returns a fixed header.

## Negative control

Negative control: the patched code path rejects the forged commitment; the
canonical upstream behavior is the correct reference where the impact does
not occur.

## Balances asserted

The exact victim and attacker balances are asserted before and after:
balBefore and balAfter are compared with assertEq on the victim escrow
balance.
"""


class V3GradePoCCheckTests(unittest.TestCase):
    # 1. full V3-grade pass
    def test_v3_grade_pass(self) -> None:
        draft = _write(_V3_GRADE_BODY)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-v3-grade")

    # 2. claim-narrowed pass
    def test_claim_narrowed_pass(self) -> None:
        body = (
            "Severity: High\nThis finding causes loss of funds.\n"
            "Honest scope of the PoC: the downstream loss is reasoned not "
            "executed; the claim is narrowed to the source-level gap.\n"
        )
        draft = _write(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-claim-narrowed")

    # 3. below-Medium skip
    def test_below_medium_out_of_scope(self) -> None:
        draft = _write("Severity: Low\nloss of funds claim.")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    # 4. no trigger keyword -> out of scope
    def test_no_trigger_out_of_scope(self) -> None:
        draft = _write("Severity: High\nA cosmetic event-emission mismatch.")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    # 5. fail-mock-replaces-protocol-path
    def test_fail_mock_replaces_protocol_path(self) -> None:
        body = (
            "Severity: High\nLoss of funds via a forged root.\n"
            "The PoC uses a placeOrder simulator that re-implements the "
            "vulnerable path instead of driving the real entrypoint.\n"
        )
        draft = _write(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-mock-replaces-protocol-path")

    # 6. fail-no-negative-control
    def test_fail_no_negative_control(self) -> None:
        body = (
            "Severity: High\nState corruption via a forged commitment.\n"
            "The PoC drives the real, unmodified verify_payload entrypoint.\n"
            "Opposed-trace: every protocol-owned defense is enumerated and the "
            "finalizer is executed.\n"
            "The victim balance is asserted before and after with assertEq.\n"
        )
        draft = _write(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-negative-control")

    # 7. fail-no-before-after-assertions
    def test_fail_no_before_after_assertions(self) -> None:
        body = (
            "Severity: High\nLoss of bridged funds via a forged root.\n"
            "The PoC drives the real, unmodified verify_payload entrypoint.\n"
            "Opposed-trace: every protocol-owned defense is enumerated.\n"
            "Negative control: the patched code rejects the forged root.\n"
        )
        draft = _write(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-before-after-assertions")

    # 8. fail-defense-not-traversed
    def test_fail_defense_not_traversed(self) -> None:
        body = (
            "Severity: Critical\nPermanent freezing of funds.\n"
            "The PoC drives the real, unmodified entrypoint.\n"
            "Negative control: the canonical upstream behavior is the clean "
            "path where the impact does not occur.\n"
            "The attacker balance is asserted before and after with assertEq "
            "on the escrow balance.\n"
        )
        draft = _write(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-defense-not-traversed")

    # 9. fail-variant-unproven
    def test_fail_variant_unproven(self) -> None:
        body = (
            "Severity: High\nLoss of funds.\n"
            "The report names two variants of the attack but only the first "
            "has an executed PoC; the second attack variant is not run.\n"
            "The PoC drives the real unmodified entrypoint, opposed-trace "
            "enumerates every defense, a negative control patched path exists, "
            "and balances are asserted before and after with assertEq.\n"
        )
        draft = _write(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-variant-unproven")

    # 10. visible-rebuttal-line pass
    def test_visible_rebuttal_line_pass(self) -> None:
        body = (
            "Severity: High\nLoss of funds via a forged root.\n"
            "r40-rebuttal: external dependency only is mocked; protocol path "
            "is real and the downstream step is bounded by source evidence.\n"
        )
        draft = _write(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    # 11. HTML-comment-rebuttal pass
    def test_html_comment_rebuttal_pass(self) -> None:
        body = (
            "Severity: Critical\nState corruption claim.\n"
            "<!-- r40-rebuttal: bounded source-backed exception; the real "
            "protocol path is exercised end-to-end. -->\n"
        )
        draft = _write(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    # 12. oversized rebuttal is ignored, original fail stands
    def test_oversized_rebuttal_ignored(self) -> None:
        body = (
            "Severity: High\nLoss of funds via a forged root.\n"
            "r40-rebuttal: " + ("x" * 240) + "\n"
        )
        draft = _write(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertNotEqual(payload["verdict"], "ok-rebuttal")

    # 13. error on unreadable draft
    def test_error_on_missing_draft(self) -> None:
        rc, payload = mod.run(Path("/nonexistent/r40/draft-HIGH.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    # 14. Medium severity is in scope (not skipped like below-Medium)
    def test_medium_severity_in_scope(self) -> None:
        body = "Severity: Medium\nLoss of user funds via a misrouted refund.\n"
        draft = _write(body, filename="draft-MEDIUM.md")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertTrue(payload["verdict"].startswith("fail"))

    # 15. real Hyperbridge Arbitrum draft should pass (narrowed claim)
    def test_hyperbridge_arbitrum_draft_passes(self) -> None:
        fixture = HB_STAGING / "hb-arbitrum-orbit-unconfirmed-node-HIGH.md"
        if not fixture.exists():
            self.skipTest("Hyperbridge Arbitrum fixture not present")
        rc, payload = mod.run(fixture, severity_override="High")
        self.assertEqual(rc, 0)
        self.assertIn(payload["verdict"], {"pass-v3-grade", "pass-claim-narrowed"})

    # 16. real Hyperbridge UniV3/V4 Medium draft should pass
    def test_hyperbridge_univ3_draft_passes(self) -> None:
        fixture = HB_STAGING / "hb-univ3-univ4-wrapper-refund-deployer-MEDIUM.md"
        if not fixture.exists():
            self.skipTest("Hyperbridge UniV3 fixture not present")
        rc, payload = mod.run(fixture, severity_override="Medium")
        self.assertEqual(rc, 0)
        self.assertIn(payload["verdict"], {"pass-v3-grade", "pass-claim-narrowed"})

    # 17b. an unrelated function literally named `placeOrder` must NOT
    # false-positive as a mock-over-protocol smell. The generic default fires
    # only on simulate/mock/stub/re-implement near a protocol surface noun.
    def test_unrelated_place_order_no_false_positive(self) -> None:
        body = (
            "Severity: High\nLoss of funds via a forged commitment.\n"
            "The PoC drives the real, unmodified placeOrder entrypoint - the "
            "real vulnerable code - and exercises the real impact surface.\n"
            "Opposed-trace: every protocol-owned defense is enumerated and the "
            "finalizer is executed.\n"
            "Mock assumptions: only the external RPC dependency is mocked.\n"
            "Negative control: the patched code path rejects the forged "
            "commitment - the canonical upstream behavior where the impact "
            "does not occur.\n"
            "The exact victim escrow balance is asserted before and after with "
            "assertEq on balBefore and balAfter.\n"
        )
        draft = _write(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-v3-grade")
        self.assertEqual(payload["evidence"]["mock_replaces_protocol_hits"], [])

    # 17c. the formerly-hard-coded Hyperbridge literal still fires via the env
    # extension default - generalizing must not regress the original anchor.
    def test_gateway_simulator_literal_still_fires(self) -> None:
        body = (
            "Severity: High\nLoss of funds via a forged root.\n"
            "The PoC uses a gateway-simulator that stands in for the real "
            "in-scope code instead of driving the real entrypoint.\n"
        )
        draft = _write(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-mock-replaces-protocol-path")

    # 17. real Hyperbridge Optimism draft is in scope (source-vs-end-to-end gap)
    def test_hyperbridge_optimism_draft_in_scope(self) -> None:
        fixture = HB_STAGING / "hb-optimism-l2oracle-unfinalized-output-HIGH.md"
        if not fixture.exists():
            self.skipTest("Hyperbridge Optimism fixture not present")
        rc, payload = mod.run(fixture, severity_override="High")
        # Optimism PoC is the source-vs-end-to-end case the rule targets; the
        # gate must produce a definite verdict (pass-narrowed or a fail) - not
        # silently treat it as out-of-scope.
        self.assertNotEqual(payload["verdict"], "pass-out-of-scope")
        self.assertIn(rc, (0, 1))


if __name__ == "__main__":
    unittest.main()
