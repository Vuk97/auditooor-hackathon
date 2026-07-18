"""Unit tests for Rule 24 non-self-impact preflight."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "non_self_impact_check",
    ROOT / "tools" / "non-self-impact-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r24_nonself_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests").mkdir()
    return root


def _draft(
    *,
    severity: str = "High",
    impact: str = "Direct theft of user funds",
    body: str = "",
    poc_ref: str = "",
) -> str:
    return (
        f"Severity: {severity}\n"
        f"Selected impact: {impact}\n\n"
        f"{poc_ref}\n\n"
        f"{body}\n"
    )


def _write_case(body: str, *, filename: str = "draft-HIGH.md") -> Path:
    root = _workspace()
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _write_case_with_poc(draft_body: str, source_body: str, *, poc_dir: str = "case") -> Path:
    root = _workspace()
    directory = root / "poc-tests" / poc_dir
    directory.mkdir(parents=True)
    (directory / "poc_test.go").write_text(source_body, encoding="utf-8")
    draft = root / "submissions" / "paste_ready" / "draft-HIGH.md"
    draft.write_text(draft_body, encoding="utf-8")
    return draft


def _run(draft: Path, *, strict: bool = False, severity: str | None = None) -> tuple[int, dict]:
    return mod.run(draft, strict=strict, severity_override=severity)


class NonSelfImpactScopeTests(unittest.TestCase):
    def test_medium_severity_is_out_of_scope(self) -> None:
        draft = _write_case(_draft(severity="Medium", body="Attacker drains their own funds."))
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_high_without_fund_loss_keyword_is_out_of_scope(self) -> None:
        draft = _write_case(_draft(impact="Matching engine degradation", body="No fund-loss claim here."))
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_severity_override_triggers_gate(self) -> None:
        draft = _write_case(
            _draft(
                severity="Medium",
                body="The attacker drains only attacker-owned funds.",
            ),
            filename="draft.md",
        )
        rc, payload = _run(draft, strict=True, severity="High")
        self.assertEqual(rc, 1)
        self.assertEqual(payload["severity_source"], "cli")
        self.assertEqual(payload["verdict"], "fail-self-harm-only")

    def test_unreadable_path_returns_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/draft.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


class NonSelfImpactPositiveTests(unittest.TestCase):
    def test_explicit_non_self_prose_passes(self) -> None:
        draft = _write_case(
            _draft(
                body=(
                    "Non-self impact demonstrated: victim funds are debited, "
                    "and funds the attacker does not control are transferred."
                )
            )
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-non-self-impact")

    def test_protocol_custody_prose_passes(self) -> None:
        draft = _write_case(
            _draft(body="The exploit drains protocol-custody funds from the insurance fund module account.")
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-non-self-impact")

    def test_non_self_character_plus_go_assertion_passes(self) -> None:
        draft = _write_case_with_poc(
            _draft(poc_ref="PoC: `poc-tests/case`", body="Alice signs; Bob is the victim."),
            (
                "package poc\n"
                "func TestNonSelf(t *testing.T){\n"
                "  beforeBobBalance := balance(BobAccAddress)\n"
                "  afterBobBalance := balance(BobAccAddress)\n"
                "  require.Equal(t, beforeBobBalance-100, afterBobBalance)\n"
                "}\n"
            ),
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-non-self-impact")

    def test_poc_dir_html_comment_is_resolved(self) -> None:
        draft = _write_case_with_poc(
            _draft(
                body="<!-- poc-dir: poc-tests/case --> Alice triggers unauthorized transfer against recipientAddr.",
            ),
            (
                "package poc\n"
                "func TestRecipient(t *testing.T){\n"
                "  beforeRecipientBalance := balance(recipientAddr)\n"
                "  afterRecipientBalance := balance(recipientAddr)\n"
                "  assert.Equal(t, beforeRecipientBalance+1, afterRecipientBalance)\n"
                "}\n"
            ),
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertTrue(payload["poc_paths"])

    def test_env_victim_pattern_is_honored(self) -> None:
        draft = _write_case_with_poc(
            _draft(poc_ref="PoC: `poc-tests/case`", body="Alice drains funds from customerSeat."),
            (
                "package poc\n"
                "func TestSeat(t *testing.T){\n"
                "  beforeSeatBalance := balance(customerSeat)\n"
                "  afterSeatBalance := balance(customerSeat)\n"
                "  require.Equal(t, beforeSeatBalance-1, afterSeatBalance)\n"
                "}\n"
            ),
        )
        old_value = os.environ.get("AUDITOOOR_R24_VICTIM_PATTERNS")
        os.environ["AUDITOOOR_R24_VICTIM_PATTERNS"] = r"\bcustomerSeat\b"
        try:
            rc, payload = _run(draft, strict=True)
        finally:
            if old_value is None:
                os.environ.pop("AUDITOOOR_R24_VICTIM_PATTERNS", None)
            else:
                os.environ["AUDITOOOR_R24_VICTIM_PATTERNS"] = old_value
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-non-self-impact")


class NonSelfImpactNegativeTests(unittest.TestCase):
    def test_non_self_character_without_assertion_fails_strict(self) -> None:
        draft = _write_case(_draft(body="Alice causes Bob to lose funds, but no PoC assertion is cited."))
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-strict-no-assertion")

    def test_attacker_only_fails_self_harm(self) -> None:
        draft = _write_case(_draft(body="The attacker drains only attacker-owned funds from attackerAddr."))
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-self-harm-only")

    def test_self_harm_disclosed_without_walkback_fails(self) -> None:
        draft = _write_case(_draft(body="Self-harm only: attacker burns their own funds."))
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-self-harm-only")

    def test_self_harm_disclosed_with_walkback_passes(self) -> None:
        draft = _write_case(
            _draft(body="Self-harm only: attacker burns their own funds. Walk back to Medium.")
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-self-harm-disclosed")

    def test_rebuttal_passes(self) -> None:
        draft = _write_case(
            _draft(body="<!-- r24-rebuttal: protocol-native burn has no attacker-controlled fund owner -->")
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_overlong_rebuttal_is_ignored(self) -> None:
        draft = _write_case(_draft(body=f"<!-- r24-rebuttal: {'x' * 220} -->"))
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertNotEqual(payload["verdict"], "ok-rebuttal")


class NonSelfImpactEcosystemCoverageTests(unittest.TestCase):
    """Rule-generality: the built-in victim/protocol actor patterns must
    recognise non-EVM/cosmos ecosystems out-of-the-box (Substrate, Move,
    Solana), not only via the AUDITOOOR_R24_VICTIM_PATTERNS env hook.
    """

    def test_substrate_treasury_account_victim_passes(self) -> None:
        draft = _write_case_with_poc(
            _draft(
                poc_ref="PoC: `poc-tests/case`",
                body="Alice drains funds from the Substrate Treasury pallet account.",
            ),
            (
                "package poc\n"
                "func TestTreasuryDrain(t *testing.T){\n"
                "  // Substrate Treasury pallet account balance.\n"
                "  beforeTreasuryBalance := balance(TreasuryAccount)\n"
                "  afterTreasuryBalance := balance(TreasuryAccount)\n"
                "  require.Equal(t, beforeTreasuryBalance-100, afterTreasuryBalance)\n"
                "}\n"
            ),
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-non-self-impact")

    def test_substrate_reserve_balance_victim_passes(self) -> None:
        draft = _write_case_with_poc(
            _draft(
                poc_ref="PoC: `poc-tests/case`",
                body="Alice causes loss of funds from a victim's reserved balance.",
            ),
            (
                "package poc\n"
                "func TestReserveDrain(t *testing.T){\n"
                "  // pallet_balances reserved balance of the victim.\n"
                "  beforeReservedBalance := pallet_balances_reserved(victimAccount)\n"
                "  afterReservedBalance := pallet_balances_reserved(victimAccount)\n"
                "  require.NotEqual(t, beforeReservedBalance, afterReservedBalance)\n"
                "}\n"
            ),
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-non-self-impact")

    def test_move_treasury_resource_account_victim_passes(self) -> None:
        draft = _write_case_with_poc(
            _draft(
                poc_ref="PoC: `poc-tests/case`",
                body="Attacker drains the @treasury resource_account in a Move module.",
            ),
            (
                "package poc\n"
                "func TestMoveTreasury(t *testing.T){\n"
                "  // Move @treasury resource_account balance.\n"
                "  beforeTreasuryBalance := balance(addr(\"@treasury\"))\n"
                "  afterTreasuryBalance := balance(addr(\"@treasury\"))\n"
                "  require.Equal(t, beforeTreasuryBalance-1, afterTreasuryBalance)\n"
                "}\n"
            ),
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-non-self-impact")

    def test_solana_vault_pda_victim_passes(self) -> None:
        draft = _write_case_with_poc(
            _draft(
                poc_ref="PoC: `poc-tests/case`",
                body="Attacker drains the protocol-owned vault PDA in a Solana program.",
            ),
            (
                "package poc\n"
                "func TestVaultPDA(t *testing.T){\n"
                "  // Solana protocol-owned vault PDA balance.\n"
                "  beforeVaultBalance := balance(vault_pda)\n"
                "  afterVaultBalance := balance(vault_pda)\n"
                "  require.Equal(t, beforeVaultBalance-100, afterVaultBalance)\n"
                "}\n"
            ),
        )
        rc, payload = _run(draft, strict=True)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-non-self-impact")


if __name__ == "__main__":
    unittest.main(verbosity=2)
