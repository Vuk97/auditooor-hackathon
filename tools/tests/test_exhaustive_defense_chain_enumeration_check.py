"""Unit tests for Rule 57 exhaustive-defense-chain-enumeration preflight."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "exhaustive_defense_chain_enumeration_check",
    ROOT / "tools" / "exhaustive-defense-chain-enumeration-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _make_workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r57_defense_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests").mkdir(parents=True)
    return root


def _write_draft(body: str, *, filename: str = "draft-HIGH.md") -> Path:
    root = _make_workspace()
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _write_draft_with_modules(
    body: str,
    *,
    filename: str = "draft-HIGH.md",
    modules: dict[str, str] | None = None,
    register_modules: list[str] | None = None,
) -> tuple[Path, Path]:
    """Write a draft and optionally populate defender-codebase modules.

    `modules` maps repo-relative paths -> file contents.
    `register_modules` is a list of repo-relative directory paths to register
    in .auditooor/r57_protection_modules.json.
    """
    root = _make_workspace()
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body, encoding="utf-8")
    if modules:
        for relpath, content in modules.items():
            p = root / relpath
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
    if register_modules:
        import json as _json
        cfg = root / ".auditooor" / "r57_protection_modules.json"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(_json.dumps({"modules": register_modules}), encoding="utf-8")
    return draft, root


# ---------------------------------------------------------------------------
# Severity / scope
# ---------------------------------------------------------------------------

class SeverityScopeTests(unittest.TestCase):
    def test_medium_severity_out_of_scope(self) -> None:
        draft = _write_draft("Severity: MEDIUM\nthe defender cannot stop the attack.\n")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_low_severity_out_of_scope(self) -> None:
        draft = _write_draft("Severity: LOW\nthe defense does not apply.\n")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_unknown_severity_out_of_scope(self) -> None:
        # Pass filename without severity hint to avoid filename-fallback HIGH detection.
        draft = _write_draft(
            "# Some draft\nno severity declared at all.\n",
            filename="plain-draft.md",
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


# ---------------------------------------------------------------------------
# Defender-narrative trigger
# ---------------------------------------------------------------------------

class DefenderNarrativeTriggerTests(unittest.TestCase):
    def test_pass_no_defender_narrative(self) -> None:
        # Pure source-only finding - no defender language at all.
        draft = _write_draft(
            "Severity: HIGH\n## Summary\nThe function at X.go:120 has an "
            "unchecked subtraction leading to underflow when amount > balance.\n"
            "## Impact\nDirect loss of funds.\n"
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-defense-narrative")

    def test_high_with_ssp_cannot_broadcast_fires(self) -> None:
        # SSP defender narrative; no enumeration section -> Layer 1 fails
        draft = _write_draft(
            "Severity: HIGH\nThe SSP has no capacity to broadcast a defensive "
            "transaction against P; every defensive watchtower path is gated "
            "on NodeConfirmationHeight.\n"
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-enumeration-section")


# ---------------------------------------------------------------------------
# Layer 1: section + table + citation
# ---------------------------------------------------------------------------

class LayerOneTableTests(unittest.TestCase):
    SECTION_HEADER = "## Exhaustive Defense Chain Enumeration\n"

    def test_fail_no_enumeration_section(self) -> None:
        draft = _write_draft(
            "Severity: HIGH\nthe defender cannot stop the attack; SSP has no capacity.\n"
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-enumeration-section")

    def test_fail_table_missing(self) -> None:
        body = (
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            f"{self.SECTION_HEADER}\n"
            "Just prose with no table at all. Defense 1 is gated on NodeConfirmationHeight.\n"
        )
        draft = _write_draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-table-missing")

    def test_fail_table_only_one_row(self) -> None:
        body = (
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| so/watchtower | watchtower.go:82 | ruled-out | NodeConfirmationHeight=0 |\n"
        )
        draft = _write_draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-table-missing")

    def test_fail_row_without_citation(self) -> None:
        body = (
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| so/watchtower | watchtower.go:82 | ruled-out | NodeConfirmationHeight=0 |\n"
            "| so/handler | unknown row no path cited | ruled-out | reason |\n"
        )
        draft = _write_draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-row-without-citation")

    def test_pass_layer1_with_no_registry_warns(self) -> None:
        body = (
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| so/watchtower | watchtower.go:82 | ruled-out | NodeConfirmationHeight=0 |\n"
            "| so/handler | transfer_handler.go:4523 | ruled-out | gated by tx-real confirm |\n"
        )
        draft = _write_draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-all-defense-paths-enumerated")
        self.assertIn("warn", payload)


# ---------------------------------------------------------------------------
# Rebuttal
# ---------------------------------------------------------------------------

class RebuttalTests(unittest.TestCase):
    def test_rebuttal_html_comment_passes(self) -> None:
        draft = _write_draft(
            "Severity: HIGH\nthe defense does not apply because attacker withholds.\n"
            "<!-- r57-rebuttal: single-defense protocol; no other broadcast call sites exist in defender codebase -->\n"
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_rebuttal_inline_line_passes(self) -> None:
        draft = _write_draft(
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            "r57-rebuttal: defense path is in OOS sibling repo per SCOPE.md citation\n"
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_rebuttal_empty_ignored(self) -> None:
        draft = _write_draft(
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            "<!-- r57-rebuttal:   -->\n"
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-enumeration-section")

    def test_rebuttal_oversized_ignored(self) -> None:
        # 201-char reason; HTML matcher caps the inner group at 300 but
        # the post-strip length check rejects >200.
        reason = "x" * 201
        draft = _write_draft(
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            f"<!-- r57-rebuttal: {reason} -->\n"
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-enumeration-section")


# ---------------------------------------------------------------------------
# Layer 2: grep-derived count vs table count
# ---------------------------------------------------------------------------

def _make_mock_watchtower_go() -> str:
    """Generate a mock watchtower.go with call sites at known line numbers
    near typical Spark watchtower line ranges."""
    lines: list[str] = []
    lines.append("package watchtower")
    lines.append("")
    # Pad to line 80
    while len(lines) < 80:
        lines.append("// padding")
    # Defense call site at line 82
    lines.append("// ScanLoop:")
    lines.append("client.SendRawTransaction(node.tx)  // ScanLoop line 82")
    # Pad to line 246
    while len(lines) < 246:
        lines.append("// padding")
    # Defense call site at line 247
    lines.append("// checkAndBroadcastNodeTx: parent gate")
    # Pad to line 249
    while len(lines) < 249:
        lines.append("// padding")
    # Defense call site at line 250
    lines.append("client.SendRawTransaction(node.tx)  // checkAndBroadcastNodeTx line 250")
    # Pad to line 369
    while len(lines) < 369:
        lines.append("// padding")
    # Defense call site at line 370
    lines.append("BroadcastTransferLeafRefund(leaf)  // line 370")
    # Pad to line 371
    while len(lines) < 371:
        lines.append("// padding")
    # Defense call site at line 372
    lines.append("client.SendRawTransaction(leaf.refundTx)  // line 372")
    # Pad to line 500
    while len(lines) < 500:
        lines.append("// padding")
    return "\n".join(lines) + "\n"


def _make_mock_handler_go() -> str:
    """Generate a mock transfer_handler.go with call sites at lines 4410 and 4523."""
    lines: list[str] = ["package handler", ""]
    while len(lines) < 4409:
        lines.append("// padding")
    lines.append("func (h *Handler) ClaimTransferSignRefunds(ctx context.Context) error {  // line 4410")
    while len(lines) < 4522:
        lines.append("// padding")
    lines.append('SetStatus("RECEIVER_INSTALLED")  // line 4523')
    while len(lines) < 4600:
        lines.append("// padding")
    return "\n".join(lines) + "\n"


MOCK_WATCHTOWER_GO = _make_mock_watchtower_go()
MOCK_HANDLER_GO = _make_mock_handler_go()


class LayerTwoGrepCountTests(unittest.TestCase):
    SECTION_HEADER = "## Exhaustive Defense Chain Enumeration\n"

    def test_pass_all_defense_paths_enumerated_complete(self) -> None:
        """Fixture 1: complete enumeration matches every grep hit."""
        body = (
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            f"{self.SECTION_HEADER}\n"
            "Protection modules considered:\n"
            "- so/watchtower: defensive broadcast layer\n"
            "- so/handler: claim-path handler\n\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| watchtower | watchtower.go:82 | ruled-out | NodeConfirmationHeight=0 |\n"
            "| watchtower | watchtower.go:247 | ruled-out | parent NCH=0 |\n"
            "| watchtower | watchtower.go:250 | ruled-out | early return |\n"
            "| watchtower | watchtower.go:370 | ruled-out | early return |\n"
            "| watchtower | watchtower.go:372 | ruled-out | unreachable |\n"
            "| handler | transfer_handler.go:4410 | ruled-out | tx-real never confirms |\n"
            "| handler | transfer_handler.go:4523 | ruled-out | install gated |\n"
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={
                "external/spark/so/watchtower/watchtower.go": MOCK_WATCHTOWER_GO,
                "external/spark/so/handler/transfer_handler.go": MOCK_HANDLER_GO,
            },
            register_modules=[
                "external/spark/so/watchtower",
                "external/spark/so/handler",
            ],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-all-defense-paths-enumerated")

    def test_fail_defense_paths_missing_from_enumeration(self) -> None:
        """Fixture 2: mirrors Spark LEAD 1 v8 miss - 2 of 3 defense families enumerated."""
        body = (
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| watchtower | watchtower.go:82 | ruled-out | NodeConfirmationHeight=0 |\n"
            "| watchtower | watchtower.go:247 | ruled-out | parent NCH=0 |\n"
            # MISSING: watchtower.go:370/372, transfer_handler.go:4410/4523
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={
                "external/spark/so/watchtower/watchtower.go": MOCK_WATCHTOWER_GO,
                "external/spark/so/handler/transfer_handler.go": MOCK_HANDLER_GO,
            },
            register_modules=[
                "external/spark/so/watchtower",
                "external/spark/so/handler",
            ],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-defense-paths-missing-from-enumeration")
        # Confirm transfer_handler.go is in the unaccounted list
        unaccounted_files = {h["file"] for h in payload["evidence"]["unaccounted_call_sites"]}
        self.assertTrue(any("transfer_handler.go" in f for f in unaccounted_files))

    def test_pass_via_rebuttal_when_missing(self) -> None:
        """Fixture 3: same shape as fixture 2 but with rebuttal."""
        body = (
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            "<!-- r57-rebuttal: Defense 3 path post-claim direct-from-CPFP is structurally unreachable -->\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| watchtower | watchtower.go:82 | ruled-out | NodeConfirmationHeight=0 |\n"
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={
                "external/spark/so/watchtower/watchtower.go": MOCK_WATCHTOWER_GO,
                "external/spark/so/handler/transfer_handler.go": MOCK_HANDLER_GO,
            },
            register_modules=[
                "external/spark/so/watchtower",
                "external/spark/so/handler",
            ],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "ok-rebuttal")


# ---------------------------------------------------------------------------
# Layer 3: --strict per-row citation existence
# ---------------------------------------------------------------------------

class LayerThreeStrictTests(unittest.TestCase):
    SECTION_HEADER = "## Exhaustive Defense Chain Enumeration\n"

    def test_strict_passes_when_citations_resolve(self) -> None:
        body = (
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| watchtower | watchtower.go:82 | ruled-out | NodeConfirmationHeight=0 |\n"
            "| watchtower | watchtower.go:247 | ruled-out | parent NCH=0 |\n"
            "| watchtower | watchtower.go:250 | ruled-out | early return |\n"
            "| watchtower | watchtower.go:370 | ruled-out | early return |\n"
            "| watchtower | watchtower.go:372 | ruled-out | unreachable |\n"
            "| handler | transfer_handler.go:4410 | ruled-out | tx-real never confirms |\n"
            "| handler | transfer_handler.go:4523 | ruled-out | install gated |\n"
        )
        # MOCK_*_GO now generate realistic line ranges (watchtower up to ~500,
        # handler up to ~4600), so cited lines 82/247/370/372/4410/4523 resolve.
        draft, root = _write_draft_with_modules(
            body,
            modules={
                "external/spark/so/watchtower/watchtower.go": MOCK_WATCHTOWER_GO,
                "external/spark/so/handler/transfer_handler.go": MOCK_HANDLER_GO,
            },
            register_modules=[
                "external/spark/so/watchtower",
                "external/spark/so/handler",
            ],
        )
        rc, payload = mod.run(draft, workspace=root, strict=True)
        # Should pass — all citations resolve, and Layer 2 grep accounted for
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-all-defense-paths-enumerated")

    def test_strict_fails_on_unresolved_citation(self) -> None:
        body = (
            "Severity: HIGH\nthe SSP cannot broadcast.\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| watchtower | nonexistent_file.go:999 | ruled-out | fake citation |\n"
            "| watchtower | another_fake.go:1234 | ruled-out | fake citation |\n"
        )
        draft = _write_draft(body)
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-ruling-without-source-citation")


# ---------------------------------------------------------------------------
# Real-world fixture: dydx filed paste-ready (should pass-no-defense-narrative)
# ---------------------------------------------------------------------------

class RealWorldFixtureTests(unittest.TestCase):
    def test_pure_source_only_dydx_style_passes_no_defense_narrative(self) -> None:
        # Mirrors a typical dydx filed paste-ready that doesn't contest a defender.
        body = (
            "Severity: HIGH\n"
            "## Summary\n"
            "Integer overflow in PerpetualLiquidation accounting at "
            "x/clob/keeper/liquidations.go:435 causes attacker subaccount to "
            "receive 2^64 USDC when liquidation triggers near MaxUint64.\n"
            "## Impact\nDirect loss of funds from insurance fund.\n"
            "## PoC\nSee poc-tests/liquidation_overflow/test.go\n"
        )
        draft = _write_draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-no-defense-narrative")


# ---------------------------------------------------------------------------
# Severity override
# ---------------------------------------------------------------------------

class SeverityOverrideTests(unittest.TestCase):
    def test_explicit_high_override_promotes_unknown_draft(self) -> None:
        draft = _write_draft("the SSP cannot broadcast.\n")
        rc, payload = mod.run(draft, severity_override="HIGH")
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-enumeration-section")

    def test_explicit_low_override_drops_to_oos(self) -> None:
        draft = _write_draft("Severity: CRITICAL\nthe SSP cannot broadcast.\n")
        rc, payload = mod.run(draft, severity_override="LOW")
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


# ---------------------------------------------------------------------------
# Error path
# ---------------------------------------------------------------------------

class ErrorPathTests(unittest.TestCase):
    def test_missing_file_returns_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/path/draft.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


# ---------------------------------------------------------------------------
# Schema invariants
# ---------------------------------------------------------------------------

class SchemaInvariantTests(unittest.TestCase):
    def test_schema_version_is_set(self) -> None:
        self.assertEqual(
            mod.SCHEMA_VERSION,
            "auditooor.r57_exhaustive_defense_chain_enumeration.v1",
        )

    def test_gate_constant_is_set(self) -> None:
        self.assertEqual(mod.GATE, "R57-EXHAUSTIVE-DEFENSE-CHAIN-ENUMERATION")


# ---------------------------------------------------------------------------
# Multi-target fixture expansion (R57 generalization validation)
#
# R57 ships a 6-target defense-action pattern library. The Bitcoin/Lightning/
# Spark target had a real-world hit (Spark v9 dispute). This block adds PASS
# + FAIL fixtures for the other 5 target families to validate that the
# pattern library generalizes mechanically:
#   1. Cosmos-SDK   (ante decorators + ProcessProposal + EndBlocker)
#   2. EVM          (modifier + AccessControl + reentrancy guard + circuit breaker)
#   3. Substrate    (SignedExtension + on_initialize + pallet::weight)
#   4. L2 rollup    (sequencer + prover + dispute game + L1 challenger)
#   5. Solana       (PDA owner check + CPI invoke + anchor require_keys_eq)
#
# Each block ships a synthetic codebase generator + two test cases:
# a PASS-path (table cites every grep hit) and a FAIL-path (table omits one
# defense call site -> fail-defense-paths-missing-from-enumeration).
#
# The mock-codebase generators pad to specific line numbers and place
# defense-action tokens at those lines so the draft table can cite the
# matching file:line and Layer 2's _hit_accounted_for() line-tolerance
# (+/-60 lines) accepts the citation.
# ---------------------------------------------------------------------------


def _pad_to(lines: list[str], target_line: int) -> None:
    """In-place pad `lines` with comment placeholders to reach line index `target_line - 1`
    (so the NEXT appended line sits at `target_line`).
    """
    while len(lines) < target_line - 1:
        lines.append("// padding")


# ---- 1. Cosmos-SDK ---------------------------------------------------------

def _make_mock_cosmos_app_go() -> str:
    """Cosmos-SDK app.go with ante decorator wiring + ProcessProposal + EndBlocker.

    Defense call sites spaced >120 lines apart so missing rows produce
    grep hits more than `_hit_accounted_for`'s line_tolerance (+/-60) away
    from any cited line.

    Line layout:
      line 200:  ante.NewMempoolFeeDecorator (matches `ante\\.[A-Z][a-zA-Z]+Decorator`)
      line 500:  NewAnteHandler
      line 800:  ProcessProposal
      line 1100: EndBlocker
    """
    lines: list[str] = ["package app", ""]
    _pad_to(lines, 200)
    lines.append("anteDecorators := ante.NewMempoolFeeDecorator(ctx)  // line 200")
    _pad_to(lines, 500)
    lines.append("handler := NewAnteHandler(opts)  // line 500")
    _pad_to(lines, 800)
    lines.append("func (app *App) ProcessProposal(req abci.RequestProcessProposal) abci.ResponseProcessProposal {  // line 800")
    _pad_to(lines, 1100)
    lines.append("func (app *App) EndBlocker(ctx sdk.Context) []abci.ValidatorUpdate {  // line 1100")
    _pad_to(lines, 1200)
    return "\n".join(lines) + "\n"


MOCK_COSMOS_APP_GO = _make_mock_cosmos_app_go()


class CosmosSdkFixtureTests(unittest.TestCase):
    """R57 fixtures for the cosmos_sdk target family."""

    SECTION_HEADER = "## Exhaustive Defense Chain Enumeration\n"

    def test_cosmos_pass_all_defenses_enumerated(self) -> None:
        """PASS: table cites all 4 cosmos defense call sites (ante + handler + ProcessProposal + EndBlocker)."""
        body = (
            "Severity: HIGH\nthe ante decorator does not fire on this MsgExec path.\n"
            f"{self.SECTION_HEADER}\n"
            "Protection modules considered:\n"
            "- app: ante decorator chain + ProcessProposal + EndBlocker\n\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| app | app.go:200 | ruled-out | MempoolFeeDecorator irrelevant to nested-msg path |\n"
            "| app | app.go:500 | ruled-out | NewAnteHandler chain does not include ValidateNestedMsg |\n"
            "| app | app.go:800 | ruled-out | ProcessProposal does not re-run ante decorators |\n"
            "| app | app.go:1100 | ruled-out | EndBlocker has no nested-msg sanitizer |\n"
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={"app/app.go": MOCK_COSMOS_APP_GO},
            register_modules=["app"],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-all-defense-paths-enumerated")

    def test_cosmos_fail_missing_endblocker_enumeration(self) -> None:
        """FAIL: table enumerates ante + handler + ProcessProposal but omits EndBlocker."""
        body = (
            "Severity: HIGH\nthe ante decorator does not fire on this MsgExec path.\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| app | app.go:200 | ruled-out | MempoolFeeDecorator irrelevant |\n"
            "| app | app.go:500 | ruled-out | NewAnteHandler chain |\n"
            "| app | app.go:800 | ruled-out | ProcessProposal does not re-run ante |\n"
            # MISSING: EndBlocker at line 1100
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={"app/app.go": MOCK_COSMOS_APP_GO},
            register_modules=["app"],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-defense-paths-missing-from-enumeration")
        # The unaccounted call site should include EndBlocker at line 1100
        unaccounted_lines = {h["line"] for h in payload["evidence"]["unaccounted_call_sites"]}
        self.assertIn(1100, unaccounted_lines)


# ---- 2. EVM / Solidity -----------------------------------------------------

def _make_mock_evm_vault_sol() -> str:
    """Solidity Vault contract with modifier + onlyOwner + nonReentrant + pause + emit.

    Defense call sites spaced >120 lines apart so each missing row produces
    a grep hit outside `_hit_accounted_for`'s line_tolerance (+/-60).
    The whenNotPaused modifier definition deliberately contains the only
    `require(` token on line 200 so the `require(` pattern fires once at
    the cited line; the second require on line 1400 fires the 5th defense
    site for the missing-reentrancy FAIL fixture.

    Line layout:
      line 200:  modifier whenNotPaused() { ... }  (matches `modifier [a-z]`)
      line 500:  function withdraw(...) nonReentrant  (matches `nonReentrant`)
      line 800:  function setOwner(...) onlyOwner    (matches `onlyOwner`)
      line 1100: emit EmergencyPause(msg.sender);   (matches `emit [A-Z]`)
      line 1400: require(msg.sender != address(0)); (matches `require\\(`)
    """
    lines: list[str] = ["// SPDX-License-Identifier: MIT", "pragma solidity ^0.8.0;", "", "contract Vault {"]
    _pad_to(lines, 200)
    lines.append("    modifier whenNotPaused() { _; }  // line 200")
    _pad_to(lines, 500)
    lines.append("    function withdraw(uint amt) external nonReentrant {  // line 500")
    _pad_to(lines, 800)
    lines.append("    function setOwner(address o) external onlyOwner {  // line 800")
    _pad_to(lines, 1100)
    lines.append("        emit EmergencyPause(msg.sender);  // line 1100")
    _pad_to(lines, 1400)
    lines.append("        require(msg.sender != address(0));  // line 1400")
    _pad_to(lines, 1500)
    lines.append("}")
    return "\n".join(lines) + "\n"


MOCK_EVM_VAULT_SOL = _make_mock_evm_vault_sol()


class EvmFixtureTests(unittest.TestCase):
    """R57 fixtures for the evm target family."""

    SECTION_HEADER = "## Exhaustive Defense Chain Enumeration\n"

    def test_evm_pass_all_defenses_enumerated(self) -> None:
        """PASS: table cites every modifier + reentrancy + access-control + circuit-breaker site."""
        body = (
            "Severity: HIGH\nthe modifier does not block this reentrant withdraw path.\n"
            f"{self.SECTION_HEADER}\n"
            "Protection modules considered:\n"
            "- contracts/Vault.sol: pause guard + reentrancy guard + owner-only + event emission\n\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| Vault | Vault.sol:200 | ruled-out | whenNotPaused not applied to vulnerable selector |\n"
            "| Vault | Vault.sol:500 | ruled-out | nonReentrant bypassed via delegatecall callback |\n"
            "| Vault | Vault.sol:800 | ruled-out | onlyOwner guards an unrelated setter |\n"
            "| Vault | Vault.sol:1100 | ruled-out | emit EmergencyPause is observability only |\n"
            "| Vault | Vault.sol:1400 | ruled-out | require(msg.sender) zero-check trivially passed |\n"
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={"contracts/Vault.sol": MOCK_EVM_VAULT_SOL},
            register_modules=["contracts"],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-all-defense-paths-enumerated")

    def test_evm_fail_missing_reentrancy_guard(self) -> None:
        """FAIL: table cites modifier + onlyOwner + emit + require but omits nonReentrant."""
        body = (
            "Severity: HIGH\nthe modifier does not block this reentrant withdraw path.\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| Vault | Vault.sol:200 | ruled-out | whenNotPaused not applied |\n"
            "| Vault | Vault.sol:800 | ruled-out | onlyOwner guards setter |\n"
            "| Vault | Vault.sol:1100 | ruled-out | emit is observability only |\n"
            "| Vault | Vault.sol:1400 | ruled-out | require zero-check passed |\n"
            # MISSING: nonReentrant at line 500
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={"contracts/Vault.sol": MOCK_EVM_VAULT_SOL},
            register_modules=["contracts"],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-defense-paths-missing-from-enumeration")
        # The unaccounted call site should include the nonReentrant token at line 500
        unaccounted = payload["evidence"]["unaccounted_call_sites"]
        self.assertTrue(
            any(h["line"] == 500 and "nonReentrant" in h["token"] for h in unaccounted),
            f"expected nonReentrant @ line 500 to be unaccounted, got: {unaccounted}",
        )


# ---- 3. Substrate / Polkadot ----------------------------------------------

def _make_mock_substrate_pallet_rs() -> str:
    """Substrate pallet with SignedExtension + on_initialize + ensure_signed + weight gate.

    Defense call sites spaced >120 lines apart so omitted rows produce
    grep hits outside `_hit_accounted_for`'s line_tolerance (+/-60).

    Line layout:
      line 200:  SignedExtension
      line 500:  ensure_signed(origin)
      line 800:  ensure_root(origin)
      line 1100: fn on_initialize(n: BlockNumber) -> Weight  (matches `on_initialize`)
      line 1400: #[pallet::weight(T::WeightInfo::do_something())]  (matches `pallet::weight`)
    """
    lines: list[str] = ["// substrate pallet stub", ""]
    _pad_to(lines, 200)
    lines.append("impl SignedExtension for CheckNonce { type Call = (); }  // line 200")
    _pad_to(lines, 500)
    lines.append("    let who = ensure_signed(origin)?;  // line 500")
    _pad_to(lines, 800)
    lines.append("    ensure_root(origin)?;  // line 800")
    _pad_to(lines, 1100)
    lines.append("    fn on_initialize(n: T::BlockNumber) -> Weight { Weight::zero() }  // line 1100")
    _pad_to(lines, 1400)
    lines.append("    #[pallet::weight(T::WeightInfo::do_something())]  // line 1400")
    _pad_to(lines, 1500)
    return "\n".join(lines) + "\n"


MOCK_SUBSTRATE_PALLET_RS = _make_mock_substrate_pallet_rs()


class SubstrateFixtureTests(unittest.TestCase):
    """R57 fixtures for the substrate target family."""

    SECTION_HEADER = "## Exhaustive Defense Chain Enumeration\n"

    def test_substrate_pass_all_defenses_enumerated(self) -> None:
        """PASS: table cites SignedExtension + ensure_signed + ensure_root + on_initialize + weight gate."""
        body = (
            "Severity: HIGH\nthe validator cannot reject this extrinsic via the pallet weight gate.\n"
            f"{self.SECTION_HEADER}\n"
            "Protection modules considered:\n"
            "- pallets/foo: SignedExtension chain + origin checks + on_initialize hook + weight gate\n\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| pallet-foo | pallet.rs:200 | ruled-out | SignedExtension only checks nonce |\n"
            "| pallet-foo | pallet.rs:500 | ruled-out | ensure_signed accepts the attacker origin |\n"
            "| pallet-foo | pallet.rs:800 | ruled-out | ensure_root guards a sibling extrinsic |\n"
            "| pallet-foo | pallet.rs:1100 | ruled-out | on_initialize hook is empty |\n"
            "| pallet-foo | pallet.rs:1400 | ruled-out | pallet::weight is under-charged for the attack path |\n"
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={"pallets/foo/src/pallet.rs": MOCK_SUBSTRATE_PALLET_RS},
            register_modules=["pallets/foo"],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-all-defense-paths-enumerated")

    def test_substrate_fail_missing_weight_gate(self) -> None:
        """FAIL: table cites SignedExtension + ensure_signed + ensure_root + on_initialize, omits weight gate."""
        body = (
            "Severity: HIGH\nthe validator cannot reject this extrinsic via the pallet weight gate.\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| pallet-foo | pallet.rs:200 | ruled-out | SignedExtension only checks nonce |\n"
            "| pallet-foo | pallet.rs:500 | ruled-out | ensure_signed accepts |\n"
            "| pallet-foo | pallet.rs:800 | ruled-out | ensure_root sibling |\n"
            "| pallet-foo | pallet.rs:1100 | ruled-out | on_initialize empty |\n"
            # MISSING: pallet::weight at line 1400
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={"pallets/foo/src/pallet.rs": MOCK_SUBSTRATE_PALLET_RS},
            register_modules=["pallets/foo"],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-defense-paths-missing-from-enumeration")
        unaccounted_lines = {h["line"] for h in payload["evidence"]["unaccounted_call_sites"]}
        self.assertIn(1400, unaccounted_lines)


# ---- 4. L2 rollup ----------------------------------------------------------

def _make_mock_l2_oracle_sol() -> str:
    """L2 output oracle with sequencer-propose + dispute game + force-withdraw + L1 challenger.

    Defense call sites spaced >120 lines apart so omitted rows produce
    grep hits outside `_hit_accounted_for`'s line_tolerance (+/-60).

    Line layout:
      line 200:  L2OutputOracle.propose (matches `L2OutputOracle\\..*propose`)
      line 500:  function challengeBlock(uint256 idx) external  (matches `challengeBlock`)
      line 800:  FaultDisputeGame.attack(...)                   (matches `FaultDisputeGame`)
      line 1100: function forceWithdraw(address user) external  (matches `forceWithdraw`)
      line 1400: disputeOutput(bytes32 root)                    (matches `disputeOutput`)
    """
    lines: list[str] = ["// L2 output oracle stub", "pragma solidity ^0.8.0;", "", "contract L2Output {"]
    _pad_to(lines, 200)
    lines.append("    L2OutputOracle(oracle).proposeL2Output(root, l2BlockNumber);  // line 200")
    _pad_to(lines, 500)
    lines.append("    function challengeBlock(uint256 idx) external { /* ... */ }  // line 500")
    _pad_to(lines, 800)
    lines.append("    FaultDisputeGame(game).attack(claimIdx, claim);  // line 800")
    _pad_to(lines, 1100)
    lines.append("    function forceWithdraw(address user) external { /* escape hatch */ }  // line 1100")
    _pad_to(lines, 1400)
    lines.append("    function disputeOutput(bytes32 root) external { /* L1 challenger entry */ }  // line 1400")
    _pad_to(lines, 1500)
    lines.append("}")
    return "\n".join(lines) + "\n"


MOCK_L2_OUTPUT_SOL = _make_mock_l2_oracle_sol()


class L2RollupFixtureTests(unittest.TestCase):
    """R57 fixtures for the l2_rollup target family."""

    SECTION_HEADER = "## Exhaustive Defense Chain Enumeration\n"

    def test_l2_pass_all_defenses_enumerated(self) -> None:
        """PASS: table cites sequencer-propose + dispute game + force-withdraw + L1 challenger."""
        body = (
            "Severity: HIGH\nthe challenger cannot dispute this forged output root within the window.\n"
            f"{self.SECTION_HEADER}\n"
            "Protection modules considered:\n"
            "- contracts/L2Output.sol: sequencer + prover + dispute game + L1 challenger\n\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| L2Output | L2Output.sol:200 | ruled-out | sequencer proposeL2Output accepts forged root |\n"
            "| L2Output | L2Output.sol:500 | ruled-out | challengeBlock window expired |\n"
            "| L2Output | L2Output.sol:800 | ruled-out | FaultDisputeGame attack requires bond attacker controls |\n"
            "| L2Output | L2Output.sol:1100 | ruled-out | forceWithdraw escape hatch disabled at audit-pin |\n"
            "| L2Output | L2Output.sol:1400 | ruled-out | disputeOutput L1 challenger entry is permissioned |\n"
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={"contracts/L2Output.sol": MOCK_L2_OUTPUT_SOL},
            register_modules=["contracts"],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-all-defense-paths-enumerated")

    def test_l2_fail_missing_l1_challenger(self) -> None:
        """FAIL: table cites sequencer + challengeBlock + dispute game + forceWithdraw, omits L1 disputeOutput."""
        body = (
            "Severity: HIGH\nthe challenger cannot dispute this forged output root within the window.\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| L2Output | L2Output.sol:200 | ruled-out | sequencer propose accepts forged root |\n"
            "| L2Output | L2Output.sol:500 | ruled-out | challengeBlock window expired |\n"
            "| L2Output | L2Output.sol:800 | ruled-out | FaultDisputeGame attack requires bond |\n"
            "| L2Output | L2Output.sol:1100 | ruled-out | forceWithdraw disabled |\n"
            # MISSING: disputeOutput L1 challenger entry at line 1400
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={"contracts/L2Output.sol": MOCK_L2_OUTPUT_SOL},
            register_modules=["contracts"],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-defense-paths-missing-from-enumeration")
        unaccounted_lines = {h["line"] for h in payload["evidence"]["unaccounted_call_sites"]}
        self.assertIn(1400, unaccounted_lines)


# ---- 5. Solana / Anchor ---------------------------------------------------

def _make_mock_solana_program_rs() -> str:
    """Solana / Anchor program with PDA owner check + CPI invoke + require_keys_eq + error type.

    Defense call sites spaced >120 lines apart so omitted rows produce
    grep hits outside `_hit_accounted_for`'s line_tolerance (+/-60).

    Line layout:
      line 200:  require_keys_eq!(ctx.accounts.pda.owner, program::id())
      line 500:  invoke(&instruction, &accounts)?;
      line 800:  invoke_signed(&instruction, &accounts, signer_seeds)?;
      line 1100: return Err(ProgramError::InvalidAccountData);
      line 1400: use anchor_lang::error_code;  (matches `anchor_lang::error`)
    """
    lines: list[str] = ["// Solana / Anchor program stub", "use anchor_lang::prelude::*;", ""]
    _pad_to(lines, 200)
    lines.append("    require_keys_eq!(ctx.accounts.pda.owner, program::id());  // line 200")
    _pad_to(lines, 500)
    lines.append("    invoke(&instruction, &accounts)?;  // line 500")
    _pad_to(lines, 800)
    lines.append("    invoke_signed(&instruction, &accounts, signer_seeds)?;  // line 800")
    _pad_to(lines, 1100)
    lines.append("    return Err(ProgramError::InvalidAccountData.into());  // line 1100")
    _pad_to(lines, 1400)
    lines.append("    use anchor_lang::error_code as anchor_err;  // line 1400")
    _pad_to(lines, 1500)
    return "\n".join(lines) + "\n"


MOCK_SOLANA_PROGRAM_RS = _make_mock_solana_program_rs()


class SolanaFixtureTests(unittest.TestCase):
    """R57 fixtures for the solana target family."""

    SECTION_HEADER = "## Exhaustive Defense Chain Enumeration\n"

    def test_solana_pass_all_defenses_enumerated(self) -> None:
        """PASS: table cites PDA owner check + invoke + invoke_signed + ProgramError + anchor error type."""
        body = (
            "Severity: HIGH\nthe defender cannot stop this CPI because every defensive path is gated.\n"
            f"{self.SECTION_HEADER}\n"
            "Protection modules considered:\n"
            "- programs/foo: PDA owner check + CPI invocations + ProgramError + anchor error type\n\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| program | program.rs:200 | ruled-out | require_keys_eq compares wrong key |\n"
            "| program | program.rs:500 | ruled-out | invoke is the vulnerable CPI itself |\n"
            "| program | program.rs:800 | ruled-out | invoke_signed signs with attacker-controlled seeds |\n"
            "| program | program.rs:1100 | ruled-out | ProgramError::InvalidAccountData branch unreachable |\n"
            "| program | program.rs:1400 | ruled-out | anchor_lang::error_code import has no guard call |\n"
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={"programs/foo/src/program.rs": MOCK_SOLANA_PROGRAM_RS},
            register_modules=["programs/foo"],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-all-defense-paths-enumerated")

    def test_solana_fail_missing_cpi_permission(self) -> None:
        """FAIL: table cites PDA owner + invoke_signed + ProgramError + anchor error, omits invoke CPI permission check."""
        body = (
            "Severity: HIGH\nthe defender cannot stop this CPI because every defensive path is gated.\n"
            f"{self.SECTION_HEADER}\n"
            "| Module | Defense path | Ruling | Reason |\n"
            "|--------|--------------|--------|--------|\n"
            "| program | program.rs:200 | ruled-out | require_keys_eq compares wrong key |\n"
            "| program | program.rs:800 | ruled-out | invoke_signed signs with attacker seeds |\n"
            "| program | program.rs:1100 | ruled-out | ProgramError branch unreachable |\n"
            "| program | program.rs:1400 | ruled-out | anchor error import has no guard |\n"
            # MISSING: invoke at line 500
        )
        draft, root = _write_draft_with_modules(
            body,
            modules={"programs/foo/src/program.rs": MOCK_SOLANA_PROGRAM_RS},
            register_modules=["programs/foo"],
        )
        rc, payload = mod.run(draft, workspace=root)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-defense-paths-missing-from-enumeration")
        unaccounted_lines = {h["line"] for h in payload["evidence"]["unaccounted_call_sites"]}
        self.assertIn(500, unaccounted_lines)


if __name__ == "__main__":
    unittest.main()
