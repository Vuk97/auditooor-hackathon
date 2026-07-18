"""Unit tests for Rule 46 Trusted-Infrastructure-Compromise preflight (Check #94).

Covers all 9 verdict classes with >= 12 test cases including live fixture files.
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "r46"

_spec = importlib.util.spec_from_file_location(
    "trusted_infrastructure_compromise_check",
    ROOT / "tools" / "trusted-infrastructure-compromise-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _run(
    draft: Path,
    *,
    workspace: Path | None = None,
    strict: bool = False,
    severity: str | None = None,
) -> tuple[int, dict]:
    return mod.run(draft, workspace=workspace, severity_override=severity, strict=strict)


def _workspace(
    *,
    scope_md: str | None = None,
    severity_md: str | None = None,
) -> Path:
    root = Path(tempfile.mkdtemp(prefix="r46_ws_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests").mkdir()
    if scope_md is not None:
        (root / "SCOPE.md").write_text(scope_md, encoding="utf-8")
    if severity_md is not None:
        (root / "SEVERITY.md").write_text(severity_md, encoding="utf-8")
    return root


def _write_draft(body: str, *, ws: Path | None = None, name: str = "draft-HIGH.md") -> Path:
    if ws is None:
        ws = _workspace()
    p = ws / "submissions" / "paste_ready" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Case 1: Low severity -> pass-out-of-scope (fixture)
# ---------------------------------------------------------------------------
class TestPassOutOfScope(unittest.TestCase):
    def test_low_severity_fixture(self) -> None:
        draft = FIXTURES / "low_severity_pass.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_medium_severity_oos(self) -> None:
        draft = FIXTURES / "medium_severity_oos_pass.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_override_low_is_oos(self) -> None:
        draft = FIXTURES / "dydx_slinky_dead_code_fail.md"
        rc, payload = _run(draft, strict=True, severity="Low")
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")
        self.assertEqual(payload["severity_source"], "cli")


# ---------------------------------------------------------------------------
# Case 2: pass-no-trusted-infra-dep (HIGH+ but no trigger)
# ---------------------------------------------------------------------------
class TestPassNoTrustedInfraDep(unittest.TestCase):
    def test_no_trigger_high_finding(self) -> None:
        draft = FIXTURES / "no_trusted_infra_dep_pass.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-trusted-infra-dep")

    def test_inline_no_trusted_infra(self) -> None:
        body = (
            "Severity: High\n\n"
            "## Summary\n\n"
            "An integer overflow in the fee calculation allows a user to pay zero fees.\n\n"
            "## Root Cause\n\n"
            "`contracts/FeeVault.sol:88` - missing overflow guard.\n"
        )
        draft = _write_draft(body, name="fee-overflow-HIGH.md")
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-trusted-infra-dep")


# ---------------------------------------------------------------------------
# Case 3: pass-non-trusted-trigger-also-exists (fixture)
# ---------------------------------------------------------------------------
class TestPassNonTrustedTrigger(unittest.TestCase):
    def test_non_trusted_trigger_fixture(self) -> None:
        draft = FIXTURES / "non_trusted_trigger_also_exists_pass.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-non-trusted-trigger-also-exists")

    def test_inline_non_trusted_trigger(self) -> None:
        body = (
            "Severity: High\n\n"
            "An oracle sidecar replay can serve stale data. However, this exploit "
            "also works without any trusted infrastructure compromise: a natural "
            "90-second network partition triggers the same code path. "
            "No trusted-infrastructure compromise is required - sufficient alone.\n\n"
            "## Root Cause\n\n"
            "`x/prices/keeper.go:142` - no staleness check.\n"
        )
        draft = _write_draft(body, name="staleness-HIGH.md")
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-non-trusted-trigger-also-exists")


# ---------------------------------------------------------------------------
# Case 4: fail-no-trusted-infra-tabulation (fixtures)
# ---------------------------------------------------------------------------
class TestFailNoTabulation(unittest.TestCase):
    def test_slinky_dead_code_no_tabulation(self) -> None:
        draft = FIXTURES / "dydx_slinky_dead_code_fail.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(payload["verdict"], "fail-no-trusted-infra-tabulation")

    def test_proposer_no_tabulation(self) -> None:
        draft = FIXTURES / "dydx_new_market_zero_price_fail.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(payload["verdict"], "fail-no-trusted-infra-tabulation")

    def test_mev_share_no_tabulation(self) -> None:
        draft = FIXTURES / "mev_share_trusted_infra_fail.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(payload["verdict"], "fail-no-trusted-infra-tabulation")

    def test_off_chain_dispatcher_no_tabulation(self) -> None:
        draft = FIXTURES / "off_chain_dispatcher_fail.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(payload["verdict"], "fail-no-trusted-infra-tabulation")

    def test_inline_rpc_provider_no_section(self) -> None:
        body = (
            "Severity: High\n\n"
            "An attacker who controls the RPC provider can replay old state roots "
            "to fool clients into accepting stale data.\n\n"
            "## Root Cause\n\n"
            "No RPC freshness validation.\n"
        )
        draft = _write_draft(body, name="rpc-high.md")
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-trusted-infra-tabulation")


# ---------------------------------------------------------------------------
# Case 5: fail-oos-citation-missing (fixture)
# ---------------------------------------------------------------------------
class TestFailOosCitationMissing(unittest.TestCase):
    def test_oos_citation_missing_fixture(self) -> None:
        draft = FIXTURES / "oos_citation_missing_fail.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(payload["verdict"], "fail-oos-citation-missing")

    def test_inline_oos_citation_missing(self) -> None:
        body = (
            "Severity: High\n\n"
            "A malicious sequencer can submit invalid state roots.\n\n"
            "## Trusted Infrastructure Tabulation\n\n"
            "1. **Trusted component name + protocol role**: Sequencer - batches transactions.\n"
            "2. **Program OOS clause**: The sequencer is a centralized component.\n"
            "3. **Defense layer classification**: The fraud proof mechanism is the PRIMARY defense.\n"
            "4. **Non-trusted-compromise trigger**: No.\n\n"
            "## Recommendation\n\nEnable permissionless fraud proofs.\n"
        )
        draft = _write_draft(body, name="sequencer-no-citation-HIGH.md")
        rc, payload = _run(draft, strict=True)
        self.assertEqual(payload["verdict"], "fail-oos-citation-missing")


# ---------------------------------------------------------------------------
# Case 6: fail-trusted-infra-primary-defense-no-walk-back (fixture)
# ---------------------------------------------------------------------------
class TestFailPrimaryDefenseNoWalkback(unittest.TestCase):
    def test_primary_defense_no_walkback_fixture(self) -> None:
        draft = FIXTURES / "primary_defense_no_walkback_fail.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(payload["verdict"], "fail-trusted-infra-primary-defense-no-walk-back")


# ---------------------------------------------------------------------------
# Case 7: pass-trusted-infra-tabulated-with-walk-back (fixture)
# ---------------------------------------------------------------------------
class TestPassTabulatedWithWalkback(unittest.TestCase):
    def test_clean_tabulated_walkback_fixture(self) -> None:
        draft = FIXTURES / "clean_tabulated_with_walkback_pass.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_signer_node_in_scope_pass(self) -> None:
        # Signer node is explicitly in-scope per SCOPE.md; finding has r46-rebuttal
        # stating the component is in-scope and full HIGH severity is justified.
        draft = FIXTURES / "signer_node_tabulated_pass.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_inline_full_tabulation_with_walkback(self) -> None:
        body = (
            "Severity: High\n\n"
            "A malicious relayer can delay messages in the cross-chain bridge.\n\n"
            "## Trusted Infrastructure Tabulation\n\n"
            "1. **Trusted component name + protocol role**: Cross-chain relayer - "
            "delivers messages between L1 and L2. The relayer is trusted to deliver "
            "messages promptly.\n"
            "2. **Program OOS clause (verbatim from SCOPE.md)**: "
            '"Relayer compromise and message delivery delays are acknowledged as out-of-scope by design."\n'
            "3. **Defense layer classification**: The timeout mechanism is the PRIMARY defense "
            "against relayer withholding attacks. The relayer IS the primary trusted component "
            "for liveness.\n"
            "4. **Non-trusted-compromise trigger**: No. The delay attack requires relayer "
            "compromise.\n\n"
            "## Severity Walk-back\n\n"
            "Because the exploit requires compromise of trusted relayer infrastructure, "
            "and the program explicitly designates this as out-of-scope, this finding "
            "is walked back to documentation note.\n\n"
            "## Recommendation\n\nAdd permissionless relay fallback.\n"
        )
        draft = _write_draft(body, name="relayer-high.md")
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-trusted-infra-tabulated-with-walk-back")


# ---------------------------------------------------------------------------
# Case 8: ok-rebuttal (fixture)
# ---------------------------------------------------------------------------
class TestOkRebuttal(unittest.TestCase):
    def test_rebuttal_fixture(self) -> None:
        draft = FIXTURES / "r46_rebuttal_override.md"
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn("keeper node", payload.get("rebuttal", "").lower())

    def test_html_rebuttal_form(self) -> None:
        body = (
            "Severity: High\n\n"
            "A malicious keeper malicious node can replay stale upkeep proofs.\n\n"
            "## Root Cause\n\n`contracts/Keeper.sol:44` - no nonce check.\n\n"
            "<!-- r46-rebuttal: keeper is explicitly in-scope per SCOPE.md section 3; "
            "tabulation not required -->\n"
        )
        draft = _write_draft(body, name="keeper-rebuttal-HIGH.md")
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_rebuttal_too_long_fails_and_triggers_gate(self) -> None:
        # A rebuttal > 200 chars should be ignored; the gate should then fail.
        long_reason = "x" * 201
        body = (
            "Severity: High\n\n"
            f"An oracle sidecar compromise feeds stale prices.\n\n"
            f"r46-rebuttal: {long_reason}\n"
        )
        draft = _write_draft(body, name="rebuttal-toolong-HIGH.md")
        rc, payload = _run(draft, strict=True)
        # Rebuttal is too long, should NOT be accepted
        self.assertNotEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn("fail", payload["verdict"])


# ---------------------------------------------------------------------------
# Case 9: env extension patterns
# ---------------------------------------------------------------------------
class TestEnvPatterns(unittest.TestCase):
    def test_custom_env_pattern_triggers(self) -> None:
        import os
        old = os.environ.get("AUDITOOOR_R46_TRUSTED_INFRA_PATTERNS", "")
        try:
            os.environ["AUDITOOOR_R46_TRUSTED_INFRA_PATTERNS"] = r"custom_oracle_sidecar"
            body = (
                "Severity: High\n\n"
                "A custom_oracle_sidecar compromise causes stale price acceptance.\n\n"
                "## Root Cause\n\n`x/prices/keeper.go:10` - no validation.\n"
            )
            draft = _write_draft(body, name="custom-trigger-HIGH.md")
            rc, payload = _run(draft, strict=True)
            self.assertEqual(payload["verdict"], "fail-no-trusted-infra-tabulation")
        finally:
            if old:
                os.environ["AUDITOOOR_R46_TRUSTED_INFRA_PATTERNS"] = old
            else:
                os.environ.pop("AUDITOOOR_R46_TRUSTED_INFRA_PATTERNS", None)


# ---------------------------------------------------------------------------
# Case 10: error verdict (unreadable file)
# ---------------------------------------------------------------------------
class TestErrorVerdict(unittest.TestCase):
    def test_missing_file_returns_error(self) -> None:
        rc, payload = _run(Path("/nonexistent/draft.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")
        self.assertIn("error", payload)


# ---------------------------------------------------------------------------
# FP regression cases (iter5 Lane II - iter6 Lane LL fix, 2026-05-23)
# Scenarios that previously emitted fail-no-trusted-infra-tabulation due to
# greedy regex or OOS-checklist negation context matches.
# ---------------------------------------------------------------------------
class TestFPRegressionNegationContext(unittest.TestCase):
    """malicious.*proposer must not fire when the line says 'does not require a malicious proposer'."""

    def test_oos_negation_clause_proposer(self) -> None:
        body = (
            "Severity: High\n\n"
            "## Summary\n\n"
            "This route does not require a malicious proposer or modified daemon "
            "ordering. The attacker input is ordinary account state.\n\n"
            "## Root Cause\n\n"
            "`x/clob/keeper/deleveraging.go:296` - deterministic counterparty selection.\n"
        )
        draft = _write_draft(body, name="deleveraging-negation-HIGH.md")
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-trusted-infra-dep")

    def test_oos_checklist_block_malicious_proposer(self) -> None:
        body = (
            "Severity: Critical\n\n"
            "## OOS Verification\n\n"
            "9. OOS clauses checked: no compromised privileged signer, governance attack, "
            "validator collusion, malicious proposer, modified daemon ordering, oracle "
            "manipulation by attacker is required for the attacker step.\n\n"
            "## Root Cause\n\n"
            "`x/vault/keeper/vault.go:142` - equity accounting overflow.\n"
        )
        draft = _write_draft(body, name="megavault-oos-checklist-CRITICAL.md")
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-trusted-infra-dep")


class TestFPRegressionValidatorSetNode(unittest.TestCase):
    """validator.*set.*node greedy form must not match 'validator process exits...legacy-node'."""

    def test_validator_process_exit_no_match(self) -> None:
        body = (
            "Severity: High\n\n"
            "## Attack Path\n\n"
            "7. The validator process exits while the goroutine may still be mid-write "
            "to `ndb.batch`. Depending on whether the underlying DB has flushed any of "
            "those writes, an inconsistent subset of legacy-node deletions reaches disk.\n\n"
            "## Root Cause\n\n"
            "`iavl/nodedb.go:970` - no Close() on batch before exit.\n"
        )
        draft = _write_draft(body, name="iavl-shutdown-race-HIGH.md")
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-trusted-infra-dep")

    def test_actual_validator_set_node_still_triggers(self) -> None:
        body = (
            "Severity: High\n\n"
            "## Summary\n\n"
            "A compromised validator-set node can inject crafted consensus messages.\n\n"
            "## Root Cause\n\n"
            "`consensus/state.go:44` - no verification of validator-set node authority.\n"
        )
        draft = _write_draft(body, name="valset-node-HIGH.md")
        rc, payload = _run(draft, strict=True)
        self.assertNotEqual(payload["verdict"], "pass-no-trusted-infra-dep")


class TestFPRegressionSlinkyOracle(unittest.TestCase):
    """slinky.*oracle must not fire when Slinky is mentioned only as external gate in passing."""

    def test_slinky_defense_in_depth_mention_no_match(self) -> None:
        body = (
            "Severity: High\n\n"
            "## Summary\n\n"
            "A permissionlessly triggerable weakness eliminates price-validation on the "
            "first oracle update for a new market. While Slinky VE consensus still acts "
            "as an external gate, the protocol provides no defense-in-depth for a new "
            "market's first price.\n\n"
            "## Root Cause\n\n"
            "`x/prices/keeper/msg_server.go:52` - zero initial price skips validatePriceAccuracy.\n"
        )
        draft = _write_draft(body, name="new-market-zero-price-HIGH.md")
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-trusted-infra-dep")

    def test_slinky_oracle_compromise_still_triggers(self) -> None:
        body = (
            "Severity: High\n\n"
            "## Summary\n\n"
            "A Slinky oracle sidecar compromise can push manipulated prices into "
            "the block proposer's VE injection path.\n\n"
            "## Root Cause\n\n"
            "`x/prices/keeper/grpc.go:88` - no Slinky oracle output validation.\n"
        )
        draft = _write_draft(body, name="slinky-oracle-compromise-HIGH.md")
        rc, payload = _run(draft, strict=True)
        self.assertNotEqual(payload["verdict"], "pass-no-trusted-infra-dep")


# r36-rebuttal: lane r46-source-verify-hardening-2026-05-28 — CAP-GAP-NI-10 regression tests
# Anchor: NEAR-Intents merkle-malleability paste-ready KILLED by operator + Codex review.
class TestSourceVerifyHardening(unittest.TestCase):
    def _ws_with_rust_consumer(self, *, with_gate: bool):
        root = _workspace()
        api = root / "src" / "api"
        api.mkdir(parents=True)
        lines = ["// placeholder"] * 21
        if with_gate:
            lines.append("    #[trusted_relayer]")
        else:
            lines.append("    // permissionless entry point - no gate")
        lines.append("    pub fn verify_withdraw(tx_id: String) -> Promise {")
        (api / "bridge.rs").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return root, api / "bridge.rs"

    def test_source_verify_catches_trusted_relayer_gate(self) -> None:
        root, _ = self._ws_with_rust_consumer(with_gate=True)
        body = (
            "Severity: Critical\n\n"
            "## Summary\n\n"
            "Permissionless attack on a Bitcoin merkle-proof verifier. "
            "Any caller can invoke the verifier path via cross-contract call.\n\n"
            "## Root Cause\n\n"
            "`src/api/bridge.rs:23` - verify_withdraw entry. no trusted-infra dep.\n"
        )
        draft = _write_draft(body, ws=root, name="merkle-malleability-CRITICAL.md")
        rc, payload = _run(draft, workspace=root, strict=True)
        self.assertEqual(payload["verdict"], "fail-trusted-infra-source-verify-mismatch")
        self.assertEqual(rc, 1)
        ev = payload.get("evidence", {})
        self.assertTrue(ev.get("claims_no_trusted_dep"))
        self.assertGreater(len(ev.get("trust_gate_hits", [])), 0)
        self.assertIn("trusted_relayer", ev["trust_gate_hits"][0]["matched_pattern"])

    def test_source_verify_passes_when_no_gate(self) -> None:
        root, _ = self._ws_with_rust_consumer(with_gate=False)
        body = (
            "Severity: Critical\n\n"
            "## Summary\n\n"
            "Permissionless attack. Any caller can invoke the entry point.\n\n"
            "## Root Cause\n\n"
            "`src/api/bridge.rs:23` - no trusted-infra dep.\n"
        )
        draft = _write_draft(body, ws=root, name="genuinely-permissionless-CRITICAL.md")
        rc, payload = _run(draft, workspace=root, strict=True)
        self.assertEqual(payload["verdict"], "pass-no-trusted-infra-dep")
        self.assertEqual(rc, 0)

    def test_source_verify_rebuttal_skips_check(self) -> None:
        root, _ = self._ws_with_rust_consumer(with_gate=True)
        body = (
            "Severity: Critical\n\n"
            "<!-- r46-source-verify-rebuttal: gate is on sibling path not exploit path -->\n\n"
            "## Summary\n\n"
            "Permissionless attack on cited entry. no trusted-infra dep.\n\n"
            "## Root Cause\n\n"
            "`src/api/bridge.rs:23` - target entry.\n"
        )
        draft = _write_draft(body, ws=root, name="rebuttal-CRITICAL.md")
        rc, payload = _run(draft, workspace=root, strict=True)
        self.assertEqual(payload["verdict"], "pass-no-trusted-infra-dep")
        self.assertEqual(rc, 0)
        self.assertIn("source_verify_rebuttal", payload)

    def test_source_verify_only_fires_when_draft_claims_no_dep(self) -> None:
        root, _ = self._ws_with_rust_consumer(with_gate=True)
        body = (
            "Severity: Critical\n\n"
            "## Summary\n\n"
            "An attack on the bridge withdraw entry.\n\n"
            "## Root Cause\n\n"
            "`src/api/bridge.rs:23` - exploited via gas griefing.\n"
        )
        draft = _write_draft(body, ws=root, name="no-claim-CRITICAL.md")
        rc, payload = _run(draft, workspace=root, strict=True)
        self.assertEqual(payload["verdict"], "pass-no-trusted-infra-dep")
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
