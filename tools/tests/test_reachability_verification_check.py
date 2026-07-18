"""Tests for tools/reachability-verification-check.py

Coverage:
  1. Medium+ draft WITH a reachability trace + file:line -> pass-reachability-traced
  2. Medium+ draft WITHOUT any trace -> fail-no-reachability-trace (rc=1)
  3. Draft whose trace shows code overridden in production -> fail-unreachable (rc=1)
  4. Informational / Low draft -> pass-not-fileable-tier (no trace needed)
  5. Rebuttal marker (<=200 chars) -> ok-rebuttal (rc=0)
  6. Strict mode rc=1 on fail-no-reachability-trace
  7. JSON output schema fields present
  8. SSTORE fixture: Istanbul-only fn overridden by Berlin in Sei genesis -> fail-unreachable
  9. High draft with dispatch-site citation -> pass-reachability-traced
  10. Rebuttal marker >200 chars is ignored -> fail-no-reachability-trace
"""

import importlib.util
import json
import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "reachability_verification_check",
    ROOT / "tools" / "reachability-verification-check.py",
)
rvchk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rvchk)  # type: ignore[union-attr]


def _write(tmp: Path, name: str, content: str) -> Path:
    p = tmp / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


class TestReachabilityVerificationCheck(unittest.TestCase):

    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    # 1. Medium+ draft WITH reachability trace + file:line -> pass
    def test_medium_with_trace_passes(self):
        draft = _write(self.tmp, "finding-MEDIUM.md", """
            ## Finding
            **Severity**: Medium

            ## Reachability Trace
            The buggy `handleFoo` function is dispatched via the router in
            `app/router.go:142` under the default configuration. Berlin is not
            activated; Istanbul rules apply from genesis. The handler is registered
            at `app/app.go:87` and called on every block.
        """)
        rc, payload = rvchk.run(draft)
        self.assertEqual(payload["verdict"], "pass-reachability-traced", payload)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["schema_version"], "auditooor.reachability_verification_check.v1")

    # 2. Medium+ draft WITHOUT trace -> fail-no-reachability-trace
    def test_medium_without_trace_fails(self):
        draft = _write(self.tmp, "finding-HIGH.md", """
            ## Finding
            **Severity**: High

            ## Description
            There is an integer overflow in `transferFrom`. The function does not
            validate the amount before adding it to the balance.
        """)
        rc, payload = rvchk.run(draft)
        self.assertEqual(payload["verdict"], "fail-no-reachability-trace", payload)
        self.assertEqual(rc, 1)

    # 3. Draft whose trace shows code IS overridden -> fail-unreachable
    def test_trace_shows_unreachable_fails(self):
        draft = _write(self.tmp, "finding-HIGH-unreachable.md", """
            ## Finding
            **Severity**: High

            ## Reachability Trace
            The buggy function `gasSStoreEIP2200` is present in gas_table.go but
            it is only active under Istanbul. In this chain, Berlin is activated from
            genesis via enable2929, which overwrites the SSTORE dynamicGas handler
            with a patched version. The Istanbul-only `gasSStoreEIP2200` is never
            dispatched in production.
        """)
        rc, payload = rvchk.run(draft)
        self.assertEqual(payload["verdict"], "fail-unreachable", payload)
        self.assertEqual(rc, 1)

    # 4. Low/Informational draft -> pass-not-fileable-tier
    def test_low_draft_passes_without_trace(self):
        draft = _write(self.tmp, "finding-LOW.md", """
            ## Finding
            **Severity**: Low

            ## Description
            A minor gas inefficiency in the EVM precompile lookup. No security impact.
        """)
        rc, payload = rvchk.run(draft)
        self.assertEqual(payload["verdict"], "pass-not-fileable-tier", payload)
        self.assertEqual(rc, 0)

    # 5. Rebuttal marker (<=200 chars) -> ok-rebuttal
    def test_rebuttal_marker_passes(self):
        draft = _write(self.tmp, "finding-HIGH-rebuttal.md", """
            ## Finding
            **Severity**: High

            ## Description
            Off-by-one in nonce validation.

            <!-- reachability-rebuttal: library called by 40+ callers; dispatch site is the EVM
            execution loop at evm.go:Run() - no single line to cite -->
        """)
        rc, payload = rvchk.run(draft)
        self.assertEqual(payload["verdict"], "ok-rebuttal", payload)
        self.assertEqual(rc, 0)
        self.assertIn("rebuttal", payload)

    # 6. Strict mode exit code on fail-no-reachability-trace
    def test_strict_mode_exits_nonzero(self):
        draft = _write(self.tmp, "finding-CRITICAL.md", """
            ## Finding
            **Severity**: Critical

            ## Description
            Arbitrary code execution in the bridge contract.
        """)
        rc, payload = rvchk.run(draft, strict=True)
        self.assertEqual(payload["verdict"], "fail-no-reachability-trace", payload)
        self.assertEqual(rc, 1)

    # 7. JSON output schema fields
    def test_json_schema_fields(self):
        draft = _write(self.tmp, "finding-MEDIUM-schema.md", """
            **Severity**: Medium

            ## Reachability Trace
            The `processDeposit` handler is registered at `bridge/handler.go:204`
            and dispatched from the MsgServer on every `MsgDeposit` transaction.
            Reachable from production entrypoint `app/app.go:RegisterServices:118`.
        """)
        rc, payload = rvchk.run(draft)
        required_fields = {
            "schema_version", "gate", "file", "severity", "severity_source",
            "strict", "evidence", "remediation_options", "verdict",
        }
        self.assertTrue(required_fields.issubset(set(payload.keys())), payload.keys())
        self.assertEqual(payload["schema_version"], "auditooor.reachability_verification_check.v1")
        self.assertEqual(payload["gate"], "REACHABILITY-VERIFICATION")

    # 8. SSTORE fixture: Istanbul-only function overridden by Berlin in Sei genesis
    def test_sstore_istanbul_only_sei_berlin_genesis(self):
        """
        Anchor: Sei field run 2026-05-22.
        gasSStoreEIP2200 in go-ethereum/core/vm/gas_table.go is Istanbul-only.
        Sei activates Berlin from genesis; enable2929 overwrites the SSTORE
        dynamicGas handler with makeGasSStoreFunc. The code is present but
        unreachable. The gate must return fail-unreachable.

        The draft is named without a severity in the filename; severity is read
        from the body (Medium) so the fileable-tier gate fires, then the
        unreachable evidence causes fail-unreachable.
        """
        draft = _write(self.tmp, "sei-sstore-gas-double-add-candidate.md", """
            ## Sei SSTORE gas double-add (candidate, killed as unreachable)

            **Severity**: Medium

            ### Root cause

            `gasSStoreEIP2200` in `go-ethereum/core/vm/gas_table.go` has a
            double-add in case 2.2.2.1 that can award excess gas refunds.

            ### Reachability Trace

            The candidate function `gasSStoreEIP2200` is Istanbul-only.
            Sei activates Berlin from genesis. During chain initialization,
            `enable2929` at `go-ethereum/core/vm/eips.go:enable2929:87`
            overwrites the SSTORE dynamicGas handler with `makeGasSStoreFunc`,
            which is the patched Berlin version. The Istanbul-only
            `gasSStoreEIP2200` is never dispatched in Sei production.
            Code present but unreachable. This candidate is KILLED.
        """)
        rc, payload = rvchk.run(draft)
        self.assertEqual(payload["verdict"], "fail-unreachable", payload)
        self.assertEqual(rc, 1)
        self.assertGreater(len(payload["evidence"].get("unreachable_hits", [])), 0)

    # 9. High draft with dispatch-site citation -> pass
    def test_high_with_dispatch_site_passes(self):
        draft = _write(self.tmp, "high-finding-traced.md", """
            ## Finding: Incorrect fee calculation

            **Severity**: High

            ## Reachability Trace

            The buggy `calculateFee` function is called from the production
            entrypoint at `x/market/keeper/msg_server.go:PlaceOrder:312`.
            The handler is dispatched on every `MsgPlaceOrder` transaction;
            the function is reachable from `app/app.go:RegisterServices`.
            No fork flag gates this path; it is active from genesis under
            default config.
        """)
        rc, payload = rvchk.run(draft)
        self.assertEqual(payload["verdict"], "pass-reachability-traced", payload)
        self.assertEqual(rc, 0)

    # 10. Rebuttal marker >200 chars is ignored -> fall through to fail
    def test_long_rebuttal_ignored(self):
        long_reason = "x" * 201
        draft = _write(self.tmp, "finding-HIGH-long-rebuttal.md", f"""
            ## Finding
            **Severity**: High

            ## Description
            Unchecked external call can drain funds.

            <!-- reachability-rebuttal: {long_reason} -->
        """)
        rc, payload = rvchk.run(draft)
        # Long rebuttal is ignored; no trace -> fail
        self.assertEqual(payload["verdict"], "fail-no-reachability-trace", payload)
        self.assertEqual(rc, 1)

    # Bonus: missing file path
    def test_missing_draft_returns_error(self):
        draft = self.tmp / "nonexistent.md"
        rc, payload = rvchk.run(draft)
        self.assertEqual(payload["verdict"], "error")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
