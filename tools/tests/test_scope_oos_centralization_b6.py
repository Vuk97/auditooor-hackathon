#!/usr/bin/env python3
"""PR #121 B6 regression — scope_oos centralization+delegatecall coverage.

Codex's PR #121 plan, item B6 (`ProxyWalletFactory delegatecall + onlyOwner
mutator`):

> Verify scope reasoner only — Confirm `tools/scope_oos_patterns.json` has
> centralization/admin delegatecall coverage; patch only if missing. This
> is OOS classification, not detector mining.

Outcome: the prior `centralization_risk_admin` regex matched only the
rhetorical phrasings (`admin can rug`, `centralization risk`, ...). It
missed the actual technical idiom that the Polymarket workspace's
suppression rule documents — `delegatecall` whose target is gated by
`onlyOwner` / `setGSNModule onlyOwner`. A finder writing a precise draft
that just describes the code (no rhetorical framing) would slip the
gate. We widened the regex to also catch the `delegatecall + onlyOwner /
owner-set / admin-set / governance-set` shape and the explicit
ProxyWalletFactory + setGSNModule signal. Reference idiom:
`~/audits/polymarket/SUPPRESSED_PATTERNS.json#delegatecall_proxywalletfactory_only_owner`.

Tests:

1. `test_b6_proxywalletfactory_delegatecall_fires_centralization_pattern`
   The technical-idiom fixture (delegatecall + setGSNModule onlyOwner,
   no rhetorical 'centralization' framing) must fire
   `centralization_risk_admin`.

2. `test_b6_clean_plugin_delegatecall_does_not_fire`
   A counter-fixture (generic plugin delegatecall with no admin /
   onlyOwner / governance / owner setter anywhere) must NOT fire the
   pattern. Guards against over-broad regex.

3. `test_b6_likely_oos_when_scope_md_excludes_centralization`
   End-to-end through the reasoner: when SCOPE.md enumerates
   centralization as OOS, the B6 fixture rises to `risk_level=likely-OOS`
   (not just `advisory`). This is the classification path the engagement
   actually relies on.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REASONER = ROOT / "tools" / "scope-reasoner.py"
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "scope_reasoner"


def _run_reasoner(draft: Path, scope: Path | None = None) -> dict:
    cmd = [sys.executable, str(REASONER), "--draft", str(draft)]
    if scope is not None:
        cmd += ["--scope", str(scope)]
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(proc.stdout)


class B6CentralizationDelegatecallTests(unittest.TestCase):
    def test_b6_proxywalletfactory_delegatecall_fires_centralization_pattern(self) -> None:
        """Positive: the B6 idiom (delegatecall target gated by onlyOwner
        setter) must fire `centralization_risk_admin` even when the draft
        is written in pure technical language with no 'centralization'
        rhetoric."""
        fixture = FIXTURES / "b6_centralization_delegatecall_fixture.md"
        self.assertTrue(fixture.exists(), fixture)

        out = _run_reasoner(fixture)
        names = [f["pattern_name"] for f in out.get("flags", [])]
        self.assertIn(
            "centralization_risk_admin",
            names,
            f"B6 fixture: expected centralization_risk_admin in {names} (raw: {out})",
        )

    def test_b6_clean_plugin_delegatecall_does_not_fire(self) -> None:
        """Negative: a generic delegatecall report with no admin / owner
        / governance / privileged-setter language must NOT fire the
        pattern. Guards against the widened regex over-flagging."""
        counter = FIXTURES / "b6_centralization_delegatecall_counterfixture.md"
        self.assertTrue(counter.exists(), counter)

        out = _run_reasoner(counter)
        names = [f["pattern_name"] for f in out.get("flags", [])]
        self.assertNotIn(
            "centralization_risk_admin",
            names,
            f"B6 counter-fixture: pattern fired falsely in {names} (raw: {out})",
        )

    def test_b6_likely_oos_when_scope_md_excludes_centralization(self) -> None:
        """End-to-end: with a SCOPE.md that lists centralization /
        admin-key custody as OOS, the B6 fixture must rise to
        `risk_level=likely-OOS` (not `advisory`). This is the path the
        engagement uses to suppress repeat ProxyWalletFactory drafts."""
        fixture = FIXTURES / "b6_centralization_delegatecall_fixture.md"
        self.assertTrue(fixture.exists(), fixture)

        scope_text = textwrap.dedent(
            """
            # Workspace SCOPE

            ## In-scope
            - Single-chain L1 contract state.

            ## Out of scope
            - Centralization risks (admin key custody, owner-controlled
              delegatecall targets, privileged setters of implementation
              addresses, governance-set module pointers).
            """
        ).strip() + "\n"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scope = tmp_path / "SCOPE.md"
            scope.write_text(scope_text)

            out = _run_reasoner(fixture, scope=scope)

            # The scope_file pointer is honored.
            self.assertEqual(out.get("scope_file", ""), str(scope), out)

            # The B6 pattern fires...
            names = [f["pattern_name"] for f in out.get("flags", [])]
            self.assertIn("centralization_risk_admin", names, out)

            # ...with severity=likely-OOS (because SCOPE.md OOS clause
            # mentions centralization / admin / owner / delegatecall).
            sev = next(
                f["severity"]
                for f in out["flags"]
                if f["pattern_name"] == "centralization_risk_admin"
            )
            self.assertEqual(sev, "likely-OOS", out)
            self.assertEqual(out.get("risk_level"), "likely-OOS", out)


if __name__ == "__main__":
    unittest.main()
