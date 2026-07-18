"""Tests for tools/load-bearing-bytes-attribution-check.py (Rule 43)."""
from __future__ import annotations

import importlib.util
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "load_bearing_bytes_attribution_check",
    ROOT / "tools" / "load-bearing-bytes-attribution-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]

FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "r43"

PASS_VERDICTS = {
    "pass-out-of-scope",
    "pass-no-defender-narrative",
    "pass-attribution-complete-defense-unreachable",
    "pass-attribution-complete-defense-reachable",
    "pass-walk-back-justified",
    "ok-rebuttal",
}

FAIL_VERDICTS = {
    "fail-no-bytes-enumerated",
    "fail-no-production-site",
    "fail-no-signer-set",
    "fail-no-attacker-intersect",
    "fail-no-withholding-analysis",
    "fail-no-attribution-section",
}


def _write(tmp: Path, name: str, body: str) -> Path:
    path = tmp / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


class TestLoadBearingBytesAttributionCheck(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    # -----------------------------------------------------------------------
    # Fixture-file based tests
    # -----------------------------------------------------------------------

    def test_fixture_spark_lead1_v8_pass(self) -> None:
        """spark_lead1_v8_pass.md -> pass-attribution-complete-defense-unreachable"""
        f = FIXTURES / "spark_lead1_v8_pass.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-attribution-complete-defense-unreachable")

    def test_fixture_spark_lead1_v7_walkback_fail(self) -> None:
        """spark_lead1_v7_walkback_fail.md -> fail-no-attribution-section"""
        f = FIXTURES / "spark_lead1_v7_walkback_fail.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertIn(payload["verdict"], FAIL_VERDICTS)
        self.assertEqual(payload["verdict"], "fail-no-attribution-section")

    def test_fixture_evm_oracle_walkback_pass_reachable(self) -> None:
        """evm_oracle_walkback_pass_reachable.md -> pass-walk-back-justified"""
        f = FIXTURES / "evm_oracle_walkback_pass_reachable.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertEqual(rc, 0)
        self.assertIn(payload["verdict"], {"pass-walk-back-justified", "pass-attribution-complete-defense-reachable"})

    def test_fixture_cosmos_msg_no_defender_narrative(self) -> None:
        """cosmos_msg_no_defender_narrative.md -> pass-no-defender-narrative"""
        f = FIXTURES / "cosmos_msg_no_defender_narrative.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-defender-narrative")

    def test_fixture_low_severity_out_of_scope(self) -> None:
        """low_severity_out_of_scope.md -> pass-out-of-scope"""
        f = FIXTURES / "low_severity_out_of_scope.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_fixture_rebuttal_override(self) -> None:
        """r43_rebuttal_override.md -> ok-rebuttal"""
        f = FIXTURES / "r43_rebuttal_override.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_fixture_fail_no_bytes_enumerated(self) -> None:
        """fail_no_bytes_enumerated.md -> fail-no-bytes-enumerated"""
        f = FIXTURES / "fail_no_bytes_enumerated.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertEqual(payload["verdict"], "fail-no-bytes-enumerated")

    def test_fixture_fail_no_production_site(self) -> None:
        """fail_no_production_site.md -> fail-no-production-site"""
        f = FIXTURES / "fail_no_production_site.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertEqual(payload["verdict"], "fail-no-production-site")

    def test_fixture_fail_no_signer_set(self) -> None:
        """fail_no_signer_set.md -> fail-no-signer-set"""
        f = FIXTURES / "fail_no_signer_set.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertEqual(payload["verdict"], "fail-no-signer-set")

    def test_fixture_fail_no_attacker_intersect(self) -> None:
        """fail_no_attacker_intersect.md -> fail-no-attacker-intersect"""
        f = FIXTURES / "fail_no_attacker_intersect.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertEqual(payload["verdict"], "fail-no-attacker-intersect")

    def test_fixture_fail_no_withholding_analysis(self) -> None:
        """fail_no_withholding_analysis.md -> fail-no-withholding-analysis"""
        f = FIXTURES / "fail_no_withholding_analysis.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertEqual(payload["verdict"], "fail-no-withholding-analysis")

    def test_fixture_fail_no_attribution_section(self) -> None:
        """fail_no_attribution_section.md -> fail-no-attribution-section"""
        f = FIXTURES / "fail_no_attribution_section.md"
        if not f.is_file():
            self.skipTest(f"fixture missing: {f}")
        rc, payload = mod.run(f)
        self.assertEqual(payload["verdict"], "fail-no-attribution-section")

    # -----------------------------------------------------------------------
    # Synthetic tests
    # -----------------------------------------------------------------------

    def test_severity_cli_override_low_passes_out_of_scope(self) -> None:
        """--severity Low forces pass-out-of-scope regardless of content."""
        draft = _write(
            self.tmp,
            "override-LOW.md",
            """
            # Dispute

            **Severity**: Critical

            The SSP broadcasts the tx. We agree.
            """,
        )
        rc, payload = mod.run(draft, severity_override="low")
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_rebuttal_line_form_passes(self) -> None:
        """Visible r43-rebuttal: line triggers ok-rebuttal."""
        draft = _write(
            self.tmp,
            "rebuttal-line-HIGH.md",
            """
            # Dispute

            **Severity**: High

            The validator signs the block. We walk back.

            r43-rebuttal: L2 spec verbatim; adding attribution adds no new analysis
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_rebuttal_too_long_is_ignored(self) -> None:
        """Rebuttal reason > 200 chars is ignored; original fail verdict stands."""
        reason = "x" * 201
        draft = _write(
            self.tmp,
            "rebuttal-too-long-HIGH.md",
            f"""
            # Dispute

            **Severity**: High

            The sequencer commits the batch. We accept.

            r43-rebuttal: {reason}
            """,
        )
        rc, payload = mod.run(draft)
        self.assertNotEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn(payload["verdict"], FAIL_VERDICTS)

    def test_no_defender_narrative_passes(self) -> None:
        """Draft with no defender-narrative phrasing passes."""
        draft = _write(
            self.tmp,
            "no-narrative-HIGH.md",
            """
            # Missing slippage check

            **Severity**: High

            The order handler skips the slippage validation. An attacker
            can drain funds by submitting orders at extreme prices.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-defender-narrative")

    def test_full_section_unreachable_passes(self) -> None:
        """Complete attribution section with defense-unreachable verdict passes."""
        draft = _write(
            self.tmp,
            "full-unreachable-CRITICAL.md",
            """
            # Dispute response

            **Severity**: Critical

            The SSP broadcasts the cooperative exit tx.

            ## Load-Bearing Bytes Attribution

            - Defender narrative (verbatim): "the SSP broadcasts tx-real"
            - Load-bearing artifact (verbatim name): tx-real (2-of-2 FROST exit tx)
            - Production site (file:line or off-chain component + in-scope hand-off): watch_chain.go:842 txid check; off-chain FROST share aggregation; hand-off at broadcast
            - Required signers (threshold + roles): 2-of-2 FROST: (1) sender share (attacker), (2) SSP share (defender)
            - Attack-model attacker in signer set? yes - sender is attacker; controls FROST share 1
            - Withholding incentive analysis: attacker withholds share; no penalty; receiver loses funds
            - Verdict: defense-unreachable
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-attribution-complete-defense-unreachable")

    def test_full_section_reachable_passes(self) -> None:
        """Complete attribution section with defense-reachable verdict passes."""
        draft = _write(
            self.tmp,
            "full-reachable-HIGH.md",
            """
            # Dispute response

            **Severity**: High

            The oracle committee signs and submits a fresh attestation.

            ## Load-Bearing Bytes Attribution

            - Defender narrative (verbatim): "the oracle committee submits a fresh attestation"
            - Load-bearing artifact (verbatim name): oracle-attestation (BLS aggregate)
            - Production site (file:line or off-chain component + in-scope hand-off): OracleAdapter.sol:142 latestRoundData(); off-chain Chainlink node network; hand-off at AggregatorV3Interface
            - Required signers (threshold + roles): 5-of-9 Chainlink committee BLS threshold
            - Attack-model attacker in signer set? no - attacker is external MEV bot, not a committee member
            - Withholding incentive analysis: attacker cannot withhold; not a committee member; defense is reachable
            - Verdict: defense-reachable
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-attribution-complete-defense-reachable")

    def test_walk_back_justified_attacker_not_in_set(self) -> None:
        """Walk-back with explicit attacker-not-in-set passes as justified."""
        draft = _write(
            self.tmp,
            "walkback-justified-HIGH.md",
            """
            # Walk-back: oracle committee defense is sound

            **Severity**: Medium

            The defender argues the oracle committee submits fresh rounds.

            ## Load-Bearing Bytes Attribution

            - Defender narrative (verbatim): "the oracle committee signs and submits fresh rounds"
            - Load-bearing artifact (verbatim name): oracle-round (BLS aggregate)
            - Production site (file:line or off-chain component + in-scope hand-off): Registry.sol:99 submitRound(); off-chain Chainlink nodes; hand-off at AggregatorV3Interface.latestRoundData()
            - Required signers (threshold + roles): 5-of-9 Chainlink threshold
            - Attack-model attacker in signer set? no - attacker is a downstream consumer, not an oracle node
            - Withholding incentive analysis: attacker has no signing capacity; cannot withhold attestation; defense is reachable independently
            - Verdict: defense-reachable

            Walk-back: the severity downgrade to Medium is warranted given the oracle
            committee operates independently of the attacker.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertIn(
            payload["verdict"],
            {"pass-walk-back-justified", "pass-attribution-complete-defense-reachable"},
        )

    def test_error_on_missing_file(self) -> None:
        """Non-existent draft returns error verdict."""
        rc, payload = mod.run(Path("/nonexistent/draft-HIGH.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    def test_schema_version_present(self) -> None:
        """Schema version field is always present in payload."""
        draft = _write(self.tmp, "schema-LOW.md", "**Severity**: Low\nContent.")
        _, payload = mod.run(draft)
        self.assertEqual(payload["schema_version"], "auditooor.r43_load_bearing_bytes_attribution.v1")

    def test_gate_field_present(self) -> None:
        """Gate field is always present in payload."""
        draft = _write(self.tmp, "gate-LOW.md", "**Severity**: Low\nContent.")
        _, payload = mod.run(draft)
        self.assertEqual(payload["gate"], "R43-LOAD-BEARING-BYTES-ATTRIBUTION")

    def test_missing_severity_and_no_narrative_passes_out_of_scope(self) -> None:
        """Draft with no severity indicator passes out-of-scope."""
        draft = _write(self.tmp, "nosev.md", "Some text with no severity line.")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_filename_severity_critical_with_narrative_and_no_section_fails(self) -> None:
        """Filename-derived Critical severity + narrative but no section -> fail."""
        draft = _write(
            self.tmp,
            "something-CRITICAL.md",
            """
            The SSP finalizes the cooperative exit and broadcasts the tx.
            We agree that this defense is sound.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(payload["verdict"], "fail-no-attribution-section")


if __name__ == "__main__":
    unittest.main()
