# r36-rebuttal: funnel-enforcement-gates-AB
"""Tests for tools/early-prior-audit-dedup-gate.py (Gate B).

Covers:
  1. BAD CASE: F04 (onBuy reentrant withdraw) matches blackthorn-34 + SCOPE.md
     acknowledged-by-design clause -> verdict KILLED (exit code 1)
  2. GOOD CASE: novel candidate (no keyword overlap with any prior audit) ->
     verdict pass (exit code 0)
  3. Missing prior_audits/ -> verdict warn, not error
  4. integration: candidate_judgment_blocker() returns blocker for F04-like row
  5. integration: candidate_judgment_blocker() returns None for novel row
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_GATE_PATH = ROOT / "tools" / "early-prior-audit-dedup-gate.py"

spec = importlib.util.spec_from_file_location("early_prior_audit_dedup_gate", _GATE_PATH)
gate_mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(gate_mod)  # type: ignore[union-attr]

run_gate = gate_mod.run_gate
candidate_judgment_blocker = gate_mod.candidate_judgment_blocker
GATE = gate_mod.GATE
SCHEMA = gate_mod.SCHEMA

# ---------------------------------------------------------------------------
# Fixtures: realistic prior-audit + SCOPE.md text
# ---------------------------------------------------------------------------

# Mirrors key content from blackthorn-34 + Spearbit 5.4.5 language.
# Load-bearing keywords: onbuy, withdraw, reentrancy, callback, acknowledged
_BLACKTHORN_EXCERPT = """\
Issue L-15: Incumbent lenders are involuntarily rolled from realized cash back
into fresh borrower risk

Source: https://github.com/sherlock-audit/2026-04-morpho-midnight/issues/34

Vulnerability Detail
In the midnight design credits are fungible. A buyer can use the onBuy hook
because 100 will be credited before the onBuy hook is triggered. In the onBuy
callback he can withdraw 100. When control passes back, midnight pulls 60 from
the callback, leaving 40 as a reentrancy-style value extraction.

Impact
Incumbent lenders withdrawable bucket is drained.

Discussion
MathisGD: fixed in https://github.com/morpho-org/midnight/pull/872
MathisGD: We acknowledged the finding.

5.4.5 Trust assumptions for buyerCallback

The Midnight only calls the buyerCallback and then uses the buyer callback as
the payer. The callback is responsible for verifying the buyer.

Morpho: We acknowledge this issue.
Spearbit: Acknowledged.
"""

# SCOPE.md with an explicit acknowledged-by-design clause listing race-to-withdraw
_SCOPE_EXCERPT = """\
## Out of scope

- Privileged roles acting within their documented powers.
- External dependencies: oracle implementations.

## Documented design tradeoffs and acknowledged-by-design behaviour

Documented design tradeoffs in Midnight.sol NatSpec (ROUNDINGS, LIVENESS,
fee-manipulation on cheap-gas chains, LLTV=1 special-case, post-fork
market-id clash, race-to-withdraw incentive). These are acknowledged-by-design.

Token safety assumptions: must not re-enter on transfer/transferFrom.
"""

# Completely unrelated prior-audit text - no onBuy/withdraw/reentrancy overlap
_UNRELATED_PRIOR_AUDIT = """\
Finding 1: Stale oracle price in liquidation path

The oracle price used for liquidation is stale by up to 3600 seconds.
An attacker can exploit the delay to front-run the oracle update and profit.

Recommendation: use a TWAP with a shorter window.

Status: Acknowledged - team plans a mitigation in Q3.
"""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_workspace(
    *,
    prior_audit_text=_BLACKTHORN_EXCERPT,
    scope_text=_SCOPE_EXCERPT,
):
    """Create a minimal workspace in a temp directory."""
    tmp = Path(tempfile.mkdtemp())
    if prior_audit_text is not None:
        pa_dir = tmp / "prior_audits"
        pa_dir.mkdir()
        (pa_dir / "2026-05-21-blackthorn-DRAFT.txt").write_text(
            prior_audit_text, encoding="utf-8"
        )
    if scope_text is not None:
        (tmp / "SCOPE.md").write_text(scope_text, encoding="utf-8")
    return tmp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEarlyPriorAuditDedupGate(unittest.TestCase):

    def test_f04_onbuy_reentrancy_is_killed(self):
        """BAD CASE: F04 keywords (onBuy + withdraw + reentrancy) must be KILLED.

        This is the exact morpho-midnight failure: the LLM hunt surfaced F04
        as applies_to_target=yes.  Its root cause (onBuy withdraw reentrancy)
        is explicitly acknowledged by Morpho + Spearbit and fixed in PR #872.
        Gate B must fire BEFORE draft/PoC starts.
        """
        ws = _make_workspace()
        result = run_gate(
            ws,
            ["onbuy", "withdraw", "reentrancy", "credited", "callback"],
            title="F04 reentrant withdraw via onBuy hook",
            attack_class="reentrancy",
        )
        self.assertEqual(
            result["verdict"],
            "KILLED",
            msg=(
                "Expected KILLED for F04 onBuy reentrancy but got "
                f"{result['verdict']!r}; reason={result.get('reason')!r}; "
                f"strong_evidence={result.get('strong_evidence')}"
            ),
        )
        self.assertTrue(
            result["strong_evidence"],
            "Expected non-empty strong_evidence list for KILLED verdict",
        )

    def test_scope_ack_by_design_fires_gate(self):
        """BAD CASE: race-to-withdraw in SCOPE.md acknowledged section fires gate."""
        ws = _make_workspace(prior_audit_text=None)
        result = run_gate(
            ws,
            ["race", "withdraw", "withdrawable"],
            title="race-to-withdraw lender frontrun",
        )
        self.assertIn(
            result["verdict"],
            ("KILLED", "NEEDS-EXTENSION-DISTINCT"),
            msg=(
                "Expected KILLED or NEEDS-EXTENSION-DISTINCT for scope-ack "
                f"candidate but got {result['verdict']!r}"
            ),
        )

    def test_novel_candidate_passes(self):
        """GOOD CASE: novel candidate with zero keyword overlap must pass."""
        ws = _make_workspace(
            prior_audit_text=_UNRELATED_PRIOR_AUDIT,
            scope_text="## Scope\n\nIn scope: all contracts under src/.\n",
        )
        result = run_gate(
            ws,
            # Completely different class - nothing like oracle/stale/TWAP
            ["feecalculation", "overflow", "truncation", "uint256", "mulDiv"],
            title="Fee calculation integer overflow truncates protocol fees",
            attack_class="integer_overflow",
        )
        self.assertEqual(
            result["verdict"],
            "pass",
            msg=(
                "Expected pass for novel candidate but got "
                f"{result['verdict']!r}; reason={result.get('reason')!r}; "
                f"strong_evidence={result.get('strong_evidence')}"
            ),
        )

    def test_missing_prior_audits_warns_not_errors(self):
        """No prior_audits/ and no SCOPE.md -> warn (fail-open), not error."""
        ws = _make_workspace(prior_audit_text=None, scope_text=None)
        result = run_gate(ws, ["onbuy", "withdraw"])
        self.assertEqual(
            result["verdict"],
            "warn",
            msg=(
                "Expected warn (fail-open) when no corpus exists, "
                f"got {result['verdict']!r}"
            ),
        )

    def test_blocker_returns_blocker_for_f04_row(self):
        """integration: candidate_judgment_blocker returns blocker for F04 row."""
        ws = _make_workspace()
        row = {
            "title": "F04 reentrant withdraw via onBuy hook",
            "attack_class": "reentrancy",
            "function": "onBuy",
            "root_cause_hypothesis": (
                "onBuy callback is called before funds are settled, allowing "
                "the callback to call withdraw() and drain the withdrawable bucket"
            ),
        }
        blocker = candidate_judgment_blocker(row, ws)
        self.assertIsNotNone(
            blocker,
            "Expected non-None blocker for F04 onBuy reentrancy row",
        )
        self.assertIn(
            "early_prior_audit_dedup",
            blocker["blocker_code"],
            f"blocker_code should contain early_prior_audit_dedup: {blocker}",
        )
        self.assertIn(
            blocker["gate_verdict"],
            ("KILLED", "NEEDS-EXTENSION-DISTINCT"),
        )

    def test_blocker_returns_none_for_novel_row(self):
        """integration: candidate_judgment_blocker returns None for novel row."""
        ws = _make_workspace(
            prior_audit_text=_UNRELATED_PRIOR_AUDIT,
            scope_text="## Scope\nIn scope: src/.\n",
        )
        row = {
            "title": "Novel: missing slippage check in fee swap path",
            "attack_class": "slippage_manipulation",
            "function": "swapFeeToken",
            "root_cause_hypothesis": (
                "swapFeeToken does not check minAmountOut, allowing MEV bots "
                "to sandwich the swap and extract protocol fees"
            ),
        }
        blocker = candidate_judgment_blocker(row, ws)
        self.assertIsNone(
            blocker,
            f"Expected None for novel row but got: {blocker}",
        )

    def test_schema_fields_present(self):
        """Gate output contains all required schema fields."""
        ws = _make_workspace()
        result = run_gate(ws, ["onbuy", "withdraw"])
        for field in (
            "schema", "gate", "verdict", "effective_keywords",
            "files_scanned_count", "strong_evidence",
        ):
            self.assertIn(field, result, f"Missing required field: {field}")
        self.assertEqual(result["schema"], SCHEMA)
        self.assertEqual(result["gate"], GATE)

    # ---- Regression: false-red fixes (nuva begin-blocker DoS, 2026-07-04) ----

    def test_html_minified_js_contaminated_prior_audit_is_skipped(self):
        """A scraped-webpage/minified-JS prior_audits/*.txt dump must NOT anchor
        a dupe: its JS boilerplate (`self`, `func`, `window`) is not audit text."""
        js_blob = (
            "!function(t){function e(){var e=this||self;e.globalThis=e}}(Object);\n"
            'window.addEventListener("error",function(e){self.__next=1});\n'
        )
        ws = _make_workspace(prior_audit_text=js_blob, scope_text=None)
        # Keywords that would substring-hit the JS blob if it were scanned.
        result = run_gate(ws, ["self", "func", "onbuy"])
        self.assertEqual(
            result["verdict"], "pass",
            msg=f"contaminated JS blob should not anchor a dupe; got {result['verdict']!r}",
        )

    def test_word_boundary_prevents_substring_noise_match(self):
        """"func" must not match inside "function"; "vault" must not match inside
        "vaults" - substring matching anchored spurious KILLs on unrelated text."""
        prior = (
            "Issue X-1: an unrelated redemption sweep bug [ACKNOWLEDGED].\n"
            "The function sweeps that amount across the outer vaults during unwinding.\n"
        )
        ws = _make_workspace(prior_audit_text=prior, scope_text=None)
        # "func" and "vault" as candidate keywords must NOT hit "function"/"vaults".
        result = run_gate(ws, ["func", "vault"])
        self.assertEqual(
            result["verdict"], "pass",
            msg=f"word-boundary matching should drop func<-function noise; got {result['verdict']!r}",
        )

    def test_ack_section_boundary_closes_on_next_header(self):
        """An 'out-of-scope' header must not leave the ack-section flag stuck ON
        for the rest of the file (the r"\\\\s" literal-backslash bug), so an
        in-scope asset-list line under a LATER header is not mis-tagged as
        acknowledged-by-design."""
        scope = (
            "# Scope\n\n"
            "## Out Of Scope\n\n"
            "- Some excluded thing.\n\n"
            "## Assets In Scope\n\n"
            "- Provenance nvYLDS Vault Address: pb15specialtokenxyz\n"
        )
        ws = _make_workspace(prior_audit_text=None, scope_text=scope)
        # "pb15specialtokenxyz" only appears under "Assets In Scope" (a header
        # AFTER the OOS header); it must not be treated as scope-acknowledged.
        result = run_gate(ws, ["pb15specialtokenxyz", "nvylds"])
        self.assertEqual(
            result["verdict"], "pass",
            msg=f"in-scope asset under a later header must not be scope-ack; got {result['verdict']!r}",
        )

    def test_only_modifier_is_not_a_scope_or_prior_anchor(self):
        """Solidity `onlyManager` must not become the generic token `only`."""
        ws = _make_workspace(
            prior_audit_text=_BLACKTHORN_EXCERPT,
            scope_text=(
                "## Scope\n"
                "All Smart Contract impacts are ONLY related to AA assets.\n"
                "The package targets only the evm tree.\n"
            ),
        )
        src = ws / "src" / "Assistant.sol"
        src.parent.mkdir(parents=True)
        src.write_text(
            "contract Assistant {\n"
            "  function getGrossBalance() onlyManager internal view returns (uint) {\n"
            "    return 0;\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        row = {
            "title": "Read-only view reentrancy in getGrossBalance",
            "attack_class": "reentrancy",
            "source_refs": ["src/Assistant.sol:2"],
        }
        self.assertIsNone(candidate_judgment_blocker(row, ws))

    def test_broad_prior_density_requires_exact_current_function_anchor(self):
        """A broad report mentioning the class is not a duplicate without the
        same current function anchor."""
        ws = _make_workspace(
            prior_audit_text=_BLACKTHORN_EXCERPT,
            scope_text="## Scope\nIn scope: src/.\n",
        )
        src = ws / "src" / "Assistant.sol"
        src.parent.mkdir(parents=True)
        src.write_text(
            "contract Assistant {\n"
            "  function getOraclePriceOfNative() internal view returns (uint) {\n"
            "    return 0;\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        row = {
            "title": "Read-only view reentrancy in getOraclePriceOfNative",
            "attack_class": "reentrancy",
            "source_refs": ["src/Assistant.sol:2"],
        }
        self.assertIsNone(candidate_judgment_blocker(row, ws))


if __name__ == "__main__":
    unittest.main()
