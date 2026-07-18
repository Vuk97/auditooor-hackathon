"""Tests for tools/configured-impact-trace-check.py (Rule 42)."""
from __future__ import annotations

import importlib.util
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "configured_impact_trace_check",
    ROOT / "tools" / "configured-impact-trace-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]

# Real Hyperbridge fixtures used by the operator's 4 anchor cases.
HB_FILED = Path("/Users/wolf/audits/hyperbridge/submissions/filed")
HB_MEDIUM = (
    HB_FILED
    / "hb-univ3-univ4-wrapper-refund-deployer-MEDIUM"
    / "hb-univ3-univ4-wrapper-refund-deployer-MEDIUM.md"
)
HB_OPTIMISM = (
    HB_FILED
    / "hb-optimism-l2oracle-unfinalized-output-HIGH"
    / "hb-optimism-l2oracle-unfinalized-output-HIGH.md"
)
HB_ARBITRUM = (
    HB_FILED
    / "hb-arbitrum-orbit-unconfirmed-node-HIGH"
    / "hb-arbitrum-orbit-unconfirmed-node-HIGH.md"
)

PASS_VERDICTS = {
    "pass-out-of-scope",
    "pass-not-config-dependent",
    "pass-configured-impact-traced",
    "pass-claim-narrowed",
    "ok-rebuttal",
}


def _write(tmp: Path, name: str, body: str) -> Path:
    path = tmp / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


class TestConfiguredImpactTraceCheck(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    # --- operator's 4 anchor fixtures (real Hyperbridge drafts) ------------

    def test_fixture_hb_medium_univ3_univ4_passes(self) -> None:
        """MEDIUM fixture either passes or fails only on the new field-5 gate."""
        if not HB_MEDIUM.is_file():
            self.skipTest(f"fixture missing: {HB_MEDIUM}")
        rc, payload = mod.run(HB_MEDIUM)
        trace = payload.get("trace", {})
        self.assertTrue(trace.get("config_dependent"))
        self.assertTrue(trace.get("has_configuration_precondition"))
        self.assertTrue(trace.get("has_downstream_consumer_path"))
        if rc == 0:
            self.assertIn(payload["verdict"], PASS_VERDICTS)
        else:
            self.assertEqual(payload["verdict"], "fail-missing-triage-followup")

    def test_fixture_hb_optimism_verifier_acceptance_passes_narrowed(self) -> None:
        """Optimism fixture either passes or fails only on the new field-5 gate."""
        if not HB_OPTIMISM.is_file():
            self.skipTest(f"fixture missing: {HB_OPTIMISM}")
        rc, payload = mod.run(HB_OPTIMISM)
        if rc == 0:
            self.assertIn(
                payload["verdict"],
                {"pass-claim-narrowed", "pass-configured-impact-traced"},
            )
        else:
            self.assertEqual(payload["verdict"], "fail-missing-triage-followup")

    def test_fixture_hb_arbitrum_verifier_acceptance_passes_narrowed(self) -> None:
        """Arbitrum fixture either passes or fails only on the new field-5 gate."""
        if not HB_ARBITRUM.is_file():
            self.skipTest(f"fixture missing: {HB_ARBITRUM}")
        rc, payload = mod.run(HB_ARBITRUM)
        if rc == 0:
            self.assertIn(
                payload["verdict"],
                {"pass-claim-narrowed", "pass-configured-impact-traced"},
            )
        else:
            self.assertEqual(payload["verdict"], "fail-missing-triage-followup")

    def test_synthetic_loss_of_funds_no_configured_trace_fails(self) -> None:
        """FAIL: 'loss of funds' from a verifier gap, no configured chain/client/consumer."""
        draft = _write(
            self.tmp,
            "verifier-gap-loss-HIGH.md",
            """
            # Verifier gap leads to loss of funds

            **Severity**: High

            The light-client verifier omits a finalization check. A registered
            consensus client accepts an unfinalized state root. This leads to
            loss of funds for bridged assets and theft of funds from the pool.

            ## Summary

            The verifier function does not check finality. That is the whole
            finding. Drained funds result downstream somehow.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertIn(
            payload["verdict"],
            {
                "fail-no-configured-impact-trace",
                "fail-overclaimed-impact-vs-evidence",
            },
        )

    def test_synthetic_if_configured_without_evidence_fails(self) -> None:
        """FAIL: 'if configured this way' dependency, no source/live/config evidence."""
        draft = _write(
            self.tmp,
            "if-configured-HIGH.md",
            """
            # Router adapter misroutes refunds

            **Severity**: High

            If the chain is configured with our custom router adapter, the
            refund is misrouted. Assuming the deployment uses this adapter,
            funds would be drained from the pool. This would be exploitable if
            configured with the vulnerable router.

            There is no statement about whether any chain actually uses this
            configuration.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-if-configured-without-evidence")

    def test_synthetic_hypothetical_component_fails(self) -> None:
        """FAIL: the affected client is only hypothetical, no narrowed claim."""
        draft = _write(
            self.tmp,
            "hypothetical-client-HIGH.md",
            """
            # Hypothetical consensus client accepts forged root

            **Severity**: High

            A registered consensus client could accept a forged root. No such
            client is currently registered or deployed anywhere. If any such
            chain ever exists, this would cause loss of funds and fund drain
            from the bridge reserve.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-hypothetical-component")

    def test_synthetic_generic_downstream_fails(self) -> None:
        """FAIL: downstream reasoned generically, not tied to configured consumer."""
        draft = _write(
            self.tmp,
            "generic-downstream-HIGH.md",
            """
            # Registered oracle adapter accepts stale price

            **Severity**: High

            ## Configured-Impact Trace

            - Configuration precondition: the oracle adapter is registered at
              the registry mapping and is the active router for the market.
            - Downstream consumer: some downstream module would consume the
              stale price. A downstream component would then mis-price. In
              general the downstream consumer turns this into loss of funds.

            No file:line citation ties this to the actual configured consumer.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(
            payload["verdict"], "fail-downstream-generic-not-configured"
        )

    def test_synthetic_full_trace_passes(self) -> None:
        """PASS: full Configured-Impact Trace with config + downstream citations."""
        draft = _write(
            self.tmp,
            "full-trace-HIGH.md",
            """
            # Registered router accepts bad swap path leads to loss of funds

            **Severity**: High

            ## Configured-Impact Trace

            - Scope mode: deployed/configured
            - Configuration precondition: the router is registered as the
              active router via the contract constructor at
              `src/Registry.sol:42` and is the configured router for the
              gateway.
            - Evidence: deployment config at `deploy/mainnet.json:18` sets the
              router address; runtime registration confirmed in production.
            - Downstream consumer: the configured consumer `Gateway.placeOrder`
              at `src/Gateway.sol:330` reads the router and settles funds.
            - Hop-by-hop impact trace: `src/Router.sol:88` emits the bad path;
              `src/Gateway.sol:330` consumes it; `src/Gateway.sol:360` releases
              escrowed funds.
            - Executed in PoC? yes
            - If no, narrowed claim / severity cap: n/a
            - Triage-follow-up pre-answer: deployed/configured-chain assumption
              needed: the router is the configured gateway router at
              `deploy/mainnet.json:18`; downstream runtime path realizes impact:
              `src/Router.sol:88` -> `src/Gateway.sol:330` ->
              `src/Gateway.sol:360`.

            The executed PoC asserts `assertEq(gateway.balance, expected)`
            before and after; Suite result: ok.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0, payload.get("reason"))
        self.assertEqual(payload["verdict"], "pass-configured-impact-traced")

    def test_below_medium_skips(self) -> None:
        """Below-Medium drafts are out of scope."""
        draft = _write(
            self.tmp,
            "low-finding-LOW.md",
            """
            # Minor router log issue

            **Severity**: Low

            A registered router emits a noisy log. No fund impact.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_not_config_dependent_passes(self) -> None:
        """A Medium finding whose impact does not depend on configuration."""
        draft = _write(
            self.tmp,
            "arith-bug-MEDIUM.md",
            """
            # Integer overflow in the fee calculation

            **Severity**: Medium

            The fee math overflows for large orders, causing the user to be
            overcharged. This is a pure arithmetic defect in a single function
            and does not depend on any deployed or configured component.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-not-config-dependent")

    def test_visible_source_backed_rebuttal_line_passes(self) -> None:
        """A visible source-backed 'r42-rebuttal:' short-circuits."""
        draft = _write(
            self.tmp,
            "rebuttal-line-HIGH.md",
            """
            # Registered client accepts forged root leads to loss of funds

            **Severity**: High

            r42-rebuttal: configured consumer is single in-scope state machine at runtime/lib.rs:120.

            The verifier accepts a forged root; downstream drain follows.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertTrue(payload.get("rebuttal"))

    def test_html_comment_source_backed_rebuttal_passes(self) -> None:
        """The HTML-comment <!-- r42-rebuttal: --> form is accepted when sourced."""
        draft = _write(
            self.tmp,
            "rebuttal-html-HIGH.md",
            """
            # Registered router drains the bridge reserve

            **Severity**: High

            <!-- r42-rebuttal: single configured router is source-traced at src/Router.sol:88. -->

            The router misroutes funds; loss of funds results.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertTrue(payload.get("rebuttal"))

    def test_unsourced_rebuttal_does_not_bypass(self) -> None:
        """A short but unsourced rebuttal is not enough for Rule 42."""
        draft = _write(
            self.tmp,
            "unsourced-rebuttal-HIGH.md",
            """
            # Registered router drains the bridge reserve

            **Severity**: High

            r42-rebuttal: operator override says this is already covered.

            The router misroutes funds; loss of funds results.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertTrue(payload.get("rebuttal_invalid"))
        self.assertNotEqual(payload["verdict"], "ok-rebuttal")

    def test_oversized_rebuttal_ignored(self) -> None:
        """A rebuttal longer than 200 chars is ignored; the fail stands."""
        long_reason = "x" * 240
        draft = _write(
            self.tmp,
            "oversized-rebuttal-HIGH.md",
            f"""
            # Registered client accepts forged root leads to loss of funds

            **Severity**: High

            r42-rebuttal: {long_reason}

            The verifier accepts a forged root; downstream drain of funds
            follows somehow with no configured-consumer trace.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertTrue(payload["verdict"].startswith("fail"))

    def test_narrowed_claim_with_trace_passes(self) -> None:
        """Honest narrowing with a trace section passes via pass-claim-narrowed."""
        draft = _write(
            self.tmp,
            "narrowed-HIGH.md",
            """
            # Consensus client accepts an unfinalized root

            **Severity**: High

            ## Configured-Impact Trace

            - Configuration precondition: the consensus client is registered in
              the runtime at `runtime/lib.rs:120` (ConsensusClients).
            - Downstream consumer: the ISMP request handler at
              `core/handlers/request.rs:87` reads the stored commitment.
            - Triage-follow-up pre-answer: deployed/configured-chain assumption
              needed: client registration at `runtime/lib.rs:120`; downstream
              runtime path realizes impact: `core/handlers/request.rs:87`.

            This proves consensus acceptance of an unfinalized root. Downstream
            fund-loss is possible only if this client is configured for a
            value-bearing state machine; severity is capped because that
            deployment/configuration is unproven.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0, payload.get("reason"))
        self.assertEqual(payload["verdict"], "pass-claim-narrowed")

    def test_narrowed_claim_without_trace_section_fails(self) -> None:
        """Narrowing alone does not excuse a missing trace section."""
        draft = _write(
            self.tmp,
            "narrowed-notrace-HIGH.md",
            """
            # Registered client accepts an unfinalized root

            **Severity**: High

            This proves consensus acceptance of an unfinalized root; severity
            is capped because configuration is unproven. There is no
            configuration-precondition citation and no downstream-consumer
            section anywhere in the draft.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-configured-impact-trace")

    def test_error_on_missing_file(self) -> None:
        rc, payload = mod.run(self.tmp / "does-not-exist.md")
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    # --- Triage-failure-mode regression lock (Codex 2026-05-22) ------------
    # The exact failure mode: a draft that proves only UPSTREAM ACCEPTANCE
    # (verifier/consensus accepts a bad root) gets filed claiming downstream
    # fund loss while leaving the deployed/configured-chain assumption and the
    # downstream runtime path unanswered. These five tests permanently lock
    # both directions of that failure mode.

    _TRIAGE_UPSTREAM_ONLY_BODY = """
        # Light-client verifier accepts an unfinalized root leads to loss of funds

        **Severity**: High

        ## Configured-Impact Trace

        - Scope mode: source-only
        - Configuration precondition: the consensus client is registered in
          the runtime at `runtime/lib.rs:120` (ConsensusClients).
        - Evidence: registration site `runtime/lib.rs:120`.
        - Downstream consumer: the ISMP request handler at
          `core/handlers/request.rs:87` reads the stored commitment.
        - Hop-by-hop impact trace: `core/verifier.rs:54` accepts the root;
          `core/handlers/request.rs:87` reads it back.
        - Executed in PoC? yes

        The executed PoC asserts `assert_eq!(verifier.accepted, true)`;
        cargo test Suite result: ok. This proves the verifier accepts an
        unfinalized root and the report claims loss of bridged funds.
        """

    def test_triage_failure_upstream_acceptance_without_configured_chain_assumption_fails(
        self,
    ) -> None:
        """LOCK: upstream-acceptance PoC + no configured-chain assumption -> FAIL.

        Field 5 question (a) - 'what deployed/configured-chain assumption is
        needed?' - is unanswered. The draft has a config precondition citation
        but never states the deployed/configured-chain assumption that the
        fund-loss claim rests on. Codex's exact triage failure mode.
        """
        draft = _write(
            self.tmp,
            "triage-no-chain-assumption-HIGH.md",
            self._TRIAGE_UPSTREAM_ONLY_BODY,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1, payload.get("reason"))
        self.assertEqual(payload["verdict"], "fail-missing-triage-followup")
        trace = payload.get("trace", {})
        self.assertFalse(trace.get("has_triage_followup_assumption_answer"))
        self.assertFalse(trace.get("has_triage_followup_preanswer"))

    def test_triage_failure_upstream_acceptance_without_downstream_runtime_trace_fails(
        self,
    ) -> None:
        """LOCK: upstream-acceptance PoC + only the chain assumption answered,
        no downstream runtime path -> FAIL.

        Field 5 question (b) - 'what downstream runtime path realizes impact?'
        - is unanswered even though question (a) is present. The gate must
        require BOTH answers.
        """
        body = """
            # Verifier accepts an unfinalized root leads to loss of bridged funds

            **Severity**: High

            ## Configured-Impact Trace

            - Scope mode: source-only
            - Configuration precondition: the consensus client is registered
              in the runtime at `runtime/lib.rs:120`.
            - Evidence: registration site `runtime/lib.rs:120`.
            - Downstream consumer: the ISMP request handler at
              `core/handlers/request.rs:87` reads the commitment.
            - Hop-by-hop impact trace: `core/verifier.rs:54` accepts it.
            - Executed in PoC? yes
            - Triage-follow-up pre-answer: deployed/configured-chain
              assumption needed: the consensus client is registered for the
              in-scope state machine at `runtime/lib.rs:120`.

            The PoC asserts `assert_eq!(verifier.accepted, true)`; cargo test
            Suite result: ok. The report claims loss of bridged funds.
            """
        draft = _write(self.tmp, "triage-no-runtime-path-HIGH.md", body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1, payload.get("reason"))
        self.assertEqual(payload["verdict"], "fail-missing-triage-followup")
        trace = payload.get("trace", {})
        self.assertTrue(trace.get("has_triage_followup_assumption_answer"))
        self.assertFalse(trace.get("has_triage_followup_runtime_answer"))
        self.assertFalse(trace.get("has_triage_followup_preanswer"))

    def test_triage_failure_same_draft_narrowed_to_state_integrity_passes(
        self,
    ) -> None:
        """LOCK: the SAME upstream-only finding, narrowed to an accepted-bad-
        state / state-integrity claim with field 5 answered -> PASS.

        Narrowing the impact wording (no fund-loss claim) plus answering both
        field-5 questions is the correct remediation, not an over-claim.
        """
        body = """
            # Verifier accepts an unfinalized (deletable) root - state-integrity gap

            **Severity**: High

            ## Configured-Impact Trace

            - Scope mode: source-only
            - Configuration precondition: the consensus client is registered
              in the runtime at `runtime/lib.rs:120` (ConsensusClients).
            - Evidence: registration site `runtime/lib.rs:120`.
            - Downstream consumer: the ISMP request handler at
              `core/handlers/request.rs:87` reads the stored commitment.
            - Hop-by-hop impact trace: `core/verifier.rs:54` accepts the root.
            - Executed in PoC? yes
            - If no, narrowed claim / severity cap: impact is worded as
              accepted forged/unfinalized state - a state-integrity failure -
              not loss of funds.
            - Triage-follow-up pre-answer: deployed/configured-chain
              assumption needed: the consensus client is registered for the
              in-scope state machine at `runtime/lib.rs:120`; what downstream
              runtime path realizes impact: none is executed - downstream
              fund-loss is possible only if this client is configured for a
              value-bearing state machine, so severity is capped.

            This proves consensus acceptance of an unfinalized root; the claim
            is narrowed to a state-integrity failure. cargo test Suite result:
            ok.
            """
        draft = _write(self.tmp, "triage-narrowed-state-integrity-HIGH.md", body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0, payload.get("reason"))
        self.assertEqual(payload["verdict"], "pass-claim-narrowed")
        trace = payload.get("trace", {})
        self.assertTrue(trace.get("has_triage_followup_preanswer"))

    def test_triage_failure_same_draft_full_chain_and_downstream_trace_passes(
        self,
    ) -> None:
        """LOCK: the SAME finding, with the full configured-chain assumption
        AND the executed downstream runtime trace -> PASS.

        When the downstream fund path is genuinely executed and both field-5
        questions are answered, the fund-loss claim is legitimate.
        """
        body = """
            # Registered consensus client accepts a forged root leads to loss of funds

            **Severity**: High

            ## Configured-Impact Trace

            - Scope mode: deployed/configured
            - Configuration precondition: the consensus client is registered
              in the runtime at `runtime/lib.rs:120` and is the configured
              client for the deployed asset-bearing chain.
            - Evidence: runtime registration `runtime/lib.rs:120`; deployment
              config `deploy/mainnet.json:18` enables the client.
            - Downstream consumer: the configured consumer
              `pallet_tokengateway::handle` at `pallets/tokengateway/lib.rs:210`
              reads the accepted root and releases escrowed funds.
            - Hop-by-hop impact trace: `core/verifier.rs:54` accepts the forged
              root; `core/handlers/request.rs:87` dispatches it;
              `pallets/tokengateway/lib.rs:210` releases the escrow.
            - Executed in PoC? yes
            - Triage-follow-up pre-answer: deployed/configured-chain assumption
              needed: the consensus client is the configured client for the
              deployed asset-bearing chain per `deploy/mainnet.json:18`; what
              downstream runtime path realizes impact: `core/verifier.rs:54` ->
              `core/handlers/request.rs:87` -> `pallets/tokengateway/lib.rs:210`
              releases escrowed funds, executed end-to-end in the PoC.

            The executed PoC asserts `assert_eq!(gateway.balance, drained)`
            before and after; cargo test Suite result: ok.
            """
        draft = _write(self.tmp, "triage-full-trace-HIGH.md", body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0, payload.get("reason"))
        self.assertEqual(payload["verdict"], "pass-configured-impact-traced")
        trace = payload.get("trace", {})
        self.assertTrue(trace.get("has_triage_followup_preanswer"))

    def test_triage_failure_missing_field5_block_entirely_fails(self) -> None:
        """LOCK: a draft with a complete fields 1-4 trace but NO field-5
        triage-follow-up pre-answer at all -> FAIL.

        Field 5 is mandatory; a trace that is otherwise complete still fails
        if the triage-follow-up block is absent.
        """
        body = """
            # Registered router accepts a bad swap path leads to loss of funds

            **Severity**: High

            ## Configured-Impact Trace

            - Scope mode: deployed/configured
            - Configuration precondition: the router is registered as the
              active router via the constructor at `src/Registry.sol:42`.
            - Evidence: deployment config `deploy/mainnet.json:18`.
            - Downstream consumer: `Gateway.placeOrder` at `src/Gateway.sol:330`
              reads the router and settles funds.
            - Hop-by-hop impact trace: `src/Router.sol:88` emits the bad path;
              `src/Gateway.sol:330` consumes it; `src/Gateway.sol:360` releases
              escrowed funds.
            - Executed in PoC? yes

            The executed PoC asserts `assertEq(gateway.balance, expected)`;
            Suite result: ok. No triage-follow-up block is present.
            """
        draft = _write(self.tmp, "triage-no-field5-block-HIGH.md", body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1, payload.get("reason"))
        self.assertEqual(payload["verdict"], "fail-missing-triage-followup")
        trace = payload.get("trace", {})
        self.assertFalse(trace.get("has_triage_followup_preanswer"))


if __name__ == "__main__":
    unittest.main()
