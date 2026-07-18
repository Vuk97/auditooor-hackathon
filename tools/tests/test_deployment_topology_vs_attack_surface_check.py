"""Unit tests for Rule 48 deployment-topology-vs-attack-surface preflight."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "deployment_topology_vs_attack_surface_check",
    ROOT / "tools" / "deployment-topology-vs-attack-surface-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _write_draft(body: str, filename: str = "draft-HIGH.md") -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="r48_"))
    draft = tmp / filename
    draft.write_text(body, encoding="utf-8")
    return draft


# ---------------------------------------------------------------------------
# Fixture bodies
# ---------------------------------------------------------------------------

# PASS: Medium draft - scope gate (R48 only fires HIGH+)
_MEDIUM_BODY = """# Missing check leads to fund loss
- Severity: Medium
Only applies for deposit wallet accounts.
"""

# PASS: no topology restriction language at all
_NO_RESTRICTION_BODY = """# Reentrancy in settle() leads to fund drain
- Severity: High
Any user can call settle(). The function does not guard against reentrancy.
Direct loss of funds is possible.
"""

# PASS: restriction detected, section present, all 4 fields, non-empty population
_RESTRICTED_NON_EMPTY_BODY = """# Signature replay in deposit wallet leads to fund drain
- Severity: High
This issue only applies to Deposit Wallet accounts (EIP-1271 signers).

## Deployment Topology Attack Surface
- Production topology citation: DepositWallet.sol constructor at line 42
  configures the wallet type; the factory registers the deployment.
- Attacker actor existence: Deposit Wallets are the default wallet type for
  all retail users on the platform; population is confirmed non-empty.
- OOS test/staging clause citation: SEVERITY.md line 18 states
  "test-only deployments are out of scope"; Deposit Wallets are production.
- Verdict: restricted-but-population-non-empty

## Impact
Direct loss of funds via signature replay.
"""

# FAIL: restriction detected, no section
_RESTRICTED_NO_SECTION_BODY = """# Signature replay in deposit wallet leads to fund drain
- Severity: High
This issue only applies for deposit wallet accounts.

## Impact
Direct loss of funds via signature replay.
"""

# FAIL: section present but missing all 4 fields
_SECTION_MISSING_FIELDS_BODY = """# Signature replay restricted to deposit wallets
- Severity: High
restricted to Deposit Wallet accounts.

## Deployment Topology Attack Surface
This is a problem because the wallet is restricted.
The issue exists in the production deployment.

## Impact
Direct loss of funds.
"""

# FAIL: test-only deployment verdict
_TEST_ONLY_BODY = """# Reentrancy in mock settle() leads to fund drain
- Severity: High
This path is only deployed in the testnet environment.

## Deployment Topology Attack Surface
- Production topology citation: MockSettle.sol deployed only in test scripts.
- Attacker actor existence: No real users in testnet; actor does not exist in production.
- OOS test/staging clause citation: SCOPE.md line 9 "testnet-only deployments are OOS".
- Verdict: test-only-deployment

## Impact
Attacker drains mock funds.
"""

# FAIL: empty population verdict
_EMPTY_POPULATION_BODY = """# Access bypass in admin-only deposit wallet
- Severity: High
Only applies for specific admin deposit wallet accounts.

## Deployment Topology Attack Surface
- Production topology citation: AdminWallet.sol deployed once via governance multisig.
- Attacker actor existence: Attacker actor does not exist in production; zero users hold
  AdminWallet instances - only the protocol deployer.
- OOS test/staging clause citation: SCOPE.md line 22 "admin-only paths OOS".
- Verdict: restricted-and-population-empty

## Impact
Theoretical drain if attacker holds an AdminWallet.
"""

# PASS: rebuttal present and valid
_REBUTTAL_BODY = """# Signature replay in deposit wallet
- Severity: High
restricted to Deposit Wallet accounts.

r48-rebuttal: Deposit Wallets represent 80% of production users per on-chain analytics; population confirmed non-empty.

## Impact
Direct loss of funds.
"""

# PASS: HTML comment rebuttal
_REBUTTAL_COMMENT_BODY = """# Replay attack on proxy wallet
- Severity: Critical
requires smart wallet (ERC-1271 account).

<!-- r48-rebuttal: All Polymarket markets use Proxy Wallet contracts by default; non-empty production population confirmed by factory registry at ProxyWalletFactory.sol:L34. -->

## Impact
Direct loss.
"""

# FAIL: rebuttal too long (>200 chars)
_REBUTTAL_TOO_LONG_BODY = """# Replay attack
- Severity: High
restricted to Deposit Wallet only.

r48-rebuttal: """ + "A" * 201 + """

## Impact
Loss.
"""

# PASS: strict mode with non-restricted body still passes if section present
_STRICT_WITH_SECTION_BODY = """# Reentrancy in settle()
- Severity: High
Any user can call this function.

## Deployment Topology Attack Surface
- Production topology citation: Settle.sol is deployed in all production environments.
- Attacker actor existence: Any EOA; population is non-empty.
- OOS test/staging clause citation: SCOPE.md line 5 "no testnet-only exclusion listed".
- Verdict: not-restricted-by-topology

## Impact
Direct loss of funds.
"""

# PASS: Critical severity - should fire
_CRITICAL_BODY = """# Signature replay in deposit wallet leads to critical loss
- Severity: Critical
restricted to Deposit Wallet accounts (ERC-1271).

## Deployment Topology Attack Surface
- Production topology citation: ProxyWalletFactory.sol:L34 creates all Deposit Wallets.
- Attacker actor existence: All retail users have Deposit Wallets; population non-empty.
- OOS test/staging clause citation: SEVERITY.md line 10 "test-only is OOS".
- Verdict: restricted-but-population-non-empty

## Impact
Critical direct loss via signature replay.
"""

# PASS: no restriction + section present + not-restricted verdict
_EXPLICIT_NOT_RESTRICTED_BODY = """# Reentrancy in settle() leads to fund drain
- Severity: High

## Deployment Topology Attack Surface
- Production topology citation: Settle.sol is deployed in all production instances.
- Attacker actor existence: Any EOA can call settle(); all users.
- OOS test/staging clause citation: SCOPE.md has no testnet-only exclusion.
- Verdict: not-restricted-by-topology

## Impact
Direct loss.
"""


class TestR48DeploymentTopology(unittest.TestCase):

    def _check(self, body: str, **kwargs) -> dict:
        draft = _write_draft(body)
        return mod.check(draft, **kwargs)

    # --- scope gate ---
    def test_medium_out_of_scope(self):
        r = self._check(_MEDIUM_BODY)
        self.assertEqual(r["verdict"], "pass-out-of-scope")

    # --- no restriction ---
    def test_no_restriction_passes(self):
        r = self._check(_NO_RESTRICTION_BODY)
        self.assertEqual(r["verdict"], "pass-no-topology-restriction")

    # --- restricted + non-empty population ---
    def test_restricted_non_empty_population_passes(self):
        r = self._check(_RESTRICTED_NON_EMPTY_BODY)
        self.assertEqual(r["verdict"], "pass-restricted-but-population-non-empty")

    # --- restricted, no section ---
    def test_restricted_no_section_fails(self):
        r = self._check(_RESTRICTED_NO_SECTION_BODY)
        self.assertEqual(r["verdict"], "fail-no-topology-tabulation")
        self.assertIn("hints", r)

    # --- section present but missing fields ---
    def test_section_missing_fields_fails(self):
        r = self._check(_SECTION_MISSING_FIELDS_BODY)
        self.assertEqual(r["verdict"], "fail-no-topology-tabulation")
        self.assertIn("missing_fields", r)
        self.assertGreater(len(r["missing_fields"]), 0)

    # --- test-only deployment ---
    def test_test_only_deployment_fails(self):
        r = self._check(_TEST_ONLY_BODY)
        self.assertEqual(r["verdict"], "fail-test-only-deployment")

    # --- empty population ---
    def test_empty_population_fails(self):
        r = self._check(_EMPTY_POPULATION_BODY)
        self.assertEqual(r["verdict"], "fail-restricted-and-empty-population")

    # --- rebuttal (visible line) ---
    def test_rebuttal_line_accepted(self):
        r = self._check(_REBUTTAL_BODY)
        self.assertEqual(r["verdict"], "ok-rebuttal")

    # --- rebuttal (HTML comment) ---
    def test_rebuttal_comment_accepted(self):
        r = self._check(_REBUTTAL_COMMENT_BODY)
        self.assertEqual(r["verdict"], "ok-rebuttal")

    # --- rebuttal too long is ignored ---
    def test_rebuttal_too_long_fails(self):
        r = self._check(_REBUTTAL_TOO_LONG_BODY)
        # rebuttal ignored => falls through to fail
        self.assertIn(r["verdict"], ("fail-no-topology-tabulation",))

    # --- strict mode: non-restricted body still passes when section present ---
    def test_strict_with_section_passes(self):
        r = self._check(_STRICT_WITH_SECTION_BODY, strict=True)
        self.assertIn(r["verdict"], ("pass-no-topology-restriction", "pass-restricted-but-population-non-empty"))

    # --- critical severity fires the gate ---
    def test_critical_severity_fires(self):
        r = self._check(_CRITICAL_BODY)
        self.assertEqual(r["verdict"], "pass-restricted-but-population-non-empty")

    # --- explicit not-restricted-by-topology verdict ---
    def test_explicit_not_restricted_verdict(self):
        r = self._check(_EXPLICIT_NOT_RESTRICTED_BODY)
        self.assertIn(r["verdict"], ("pass-no-topology-restriction",))

    # --- severity override via kwarg ---
    def test_low_severity_override_passes(self):
        r = self._check(_RESTRICTED_NO_SECTION_BODY, severity_arg="low")
        self.assertEqual(r["verdict"], "pass-out-of-scope")

    # --- schema field present ---
    def test_schema_field_present(self):
        r = self._check(_NO_RESTRICTION_BODY)
        self.assertEqual(r["schema"], mod.SCHEMA_VERSION)
        self.assertEqual(r["gate"], mod.GATE)


if __name__ == "__main__":
    unittest.main()
