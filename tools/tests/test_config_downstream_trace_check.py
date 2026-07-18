"""Tests for tools/config-downstream-trace-check.py."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "config_downstream_trace_check",
    ROOT / "tools" / "config-downstream-trace-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _write(tmp: Path, name: str, body: str) -> Path:
    path = tmp / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


class TestConfigDownstreamTraceCheck(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_medium_bridge_claim_missing_both_sections_fails(self) -> None:
        draft = _write(
            self.tmp,
            "bridge-medium.md",
            """
            # Bridge route accepts malformed messages

            **Severity**: Medium

            The bridge relayer can submit a malformed cross-chain message that
            causes downstream accounting state corruption.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-config-downstream-trace")
        self.assertIn("missing_config_deployment_preconditions", payload["blockers"])
        self.assertIn("missing_downstream_consumer_trace", payload["blockers"])

    def test_oracle_claim_with_proven_config_and_downstream_trace_passes(self) -> None:
        draft = _write(
            self.tmp,
            "oracle-high.md",
            """
            # Oracle feed stale round is accepted by lending market

            **Severity**: High

            ## Configuration/Deployment Preconditions

            - proven deployed address: `0x1111111111111111111111111111111111111111`
              is the feed address for the market.
            - default config registers the oracle adapter at
              `contracts/OracleRouter.sol:88`.
            - source-cited market route is active in production at
              `deploy/mainnet.json:41`.

            ## Downstream Consumer Trace

            Producer entrypoint `OracleRouter.sol:120` emits the stale price.
            The downstream consumer reads it at
            `contracts/LendingMarket.sol:233`; no downstream revalidation or
            fallback result prevents the borrow. Final asset impact is a bad
            debt increase in the lending market.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-config-downstream-traced")
        self.assertEqual(payload["blockers"], [])

    def test_feature_flag_off_fails_even_with_sections(self) -> None:
        draft = _write(
            self.tmp,
            "rollup-high.md",
            """
            # Rollup proof verifier accepts bad roots

            **Severity**: High

            ## Configuration/Deployment Preconditions

            The verifier route is source-cited at `rollup/Router.sol:44`, but
            the optimized verifier feature flag is off by default and not active
            in production.

            ## Downstream Consumer Trace

            Producer entrypoint `rollup/Inbox.sol:90` stores the root. The
            downstream consumer reads the message root at
            `rollup/Outbox.sol:177` with no downstream revalidation before
            final asset impact.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("off_default_or_devnet_only_precondition", payload["blockers"])

    def test_privileged_config_action_required_fails(self) -> None:
        draft = _write(
            self.tmp,
            "consensus-high.md",
            """
            # Consensus validator set rotation can halt finality

            Severity: High

            ## Configuration/Deployment Preconditions

            The validator-set registry is proven at `consensus/registry.go:55`,
            but governance must enable the experimental rotation route before
            the path is live.

            ## Downstream Consumer Trace

            Producer entrypoint `consensus/keeper.go:91` writes the next set.
            The downstream consumer reads the validator set at
            `consensus/finality.go:210`, and no downstream guard prevents the
            consensus halt.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("privileged_config_action_required", payload["blockers"])

    def test_high_reasoned_only_downstream_without_cap_fails(self) -> None:
        draft = _write(
            self.tmp,
            "bridge-reasoned-high.md",
            """
            # Bridge domain mapping can drain escrow

            **Severity**: High

            ## Configuration/Deployment Preconditions

            The domain mapping is proven from `deploy/bridge.json:12` and the
            verifier adapter is source-cited at `bridge/Verifier.sol:66`.

            ## Downstream Consumer Trace

            This is a source-cited reasoned-only downstream trace with no
            executed PoC. The downstream consumer reads the proof at
            `bridge/Escrow.sol:144`; no independent revalidation blocks the
            bridge drain.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertIn("reasoned_only_downstream_high_plus", payload["blockers"])

    def test_reasoned_only_with_medium_cap_passes(self) -> None:
        draft = _write(
            self.tmp,
            "bridge-reasoned-capped.md",
            """
            # Bridge domain mapping is inconsistent

            **Severity**: Medium
            severity_cap_if_reasoned: Medium

            ## Configuration/Deployment Preconditions

            The domain mapping is proven from `deploy/bridge.json:12` and the
            verifier adapter is source-cited at `bridge/Verifier.sol:66`.

            ## Downstream Consumer Trace

            Source-cited reasoned-only trace: downstream consumer reads the
            proof at `bridge/Escrow.sol:144`; no independent revalidation
            blocks the state corruption. Claim is capped to Medium.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-config-downstream-traced")

    def test_not_applicable_requires_source_backed_same_component_reason(self) -> None:
        draft = _write(
            self.tmp,
            "oracle-not-applicable.md",
            """
            # Oracle local accumulator overflows

            **Severity**: Medium
            config_downstream_trace: not_applicable

            The impact is realized in the same module at `oracle/accum.go:77`;
            there is no downstream consumer.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-not-applicable")

    def test_invalid_not_applicable_fails(self) -> None:
        draft = _write(
            self.tmp,
            "oracle-invalid-not-applicable.md",
            """
            # Oracle feed controls a lending market

            **Severity**: Medium
            config_downstream_trace: not_applicable

            Trust me, this does not need any trace.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["blockers"], ["invalid_not_applicable"])

    def test_bounded_rebuttal_passes(self) -> None:
        draft = _write(
            self.tmp,
            "bridge-rebuttal.md",
            """
            # Bridge proof path has equivalent deployment evidence

            **Severity**: High

            The bridge proof path affects downstream withdrawal.

            <!-- config-downstream-rebuttal: source-backed route proof is in deploy/routes.json:44; checker cannot parse artifact bundle -->
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn("rebuttal", payload)

    def test_rebuttal_without_source_backing_fails(self) -> None:
        draft = _write(
            self.tmp,
            "bridge-unsourced-rebuttal.md",
            """
            # Bridge proof path has equivalent deployment evidence

            **Severity**: High

            The bridge proof path affects downstream withdrawal.

            <!-- config-downstream-rebuttal: trust me this bundle has the route proof -->
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-config-downstream-trace")
        self.assertTrue(payload["rebuttal_invalid"])
        self.assertIn("source-backed", payload["rebuttal_invalid_reason"])

    def test_empty_or_long_rebuttal_is_ignored(self) -> None:
        long_reason = "x" * 201
        draft = _write(
            self.tmp,
            "bridge-long-rebuttal.md",
            f"""
            # Bridge proof path has missing trace

            **Severity**: High

            The bridge proof path affects downstream withdrawal.

            <!-- config-downstream-rebuttal: {long_reason} -->
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-config-downstream-trace")
        self.assertTrue(payload["rebuttal_invalid"])

    def test_low_surface_claim_is_out_of_scope(self) -> None:
        draft = _write(
            self.tmp,
            "oracle-low.md",
            """
            # Oracle comment typo

            **Severity**: Low

            The oracle docs mention an old feed address.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_non_surface_medium_claim_is_out_of_scope(self) -> None:
        draft = _write(
            self.tmp,
            "erc20-medium.md",
            """
            # ERC20 allowance emits the wrong event

            **Severity**: Medium

            The token emits an event with the stale allowance.
            """,
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_emits_json_payload(self) -> None:
        draft = _write(
            self.tmp,
            "bridge-cli.md",
            """
            # Bridge route accepts malformed messages

            **Severity**: Medium

            The bridge relayer can submit a malformed cross-chain message.
            """,
        )
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "config-downstream-trace-check.py"), str(draft), "--json"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema_version"], mod.SCHEMA_VERSION)
        self.assertEqual(payload["gate"], "CONFIG-DOWNSTREAM-TRACE")
        self.assertEqual(payload["verdict"], "fail-config-downstream-trace")


if __name__ == "__main__":
    unittest.main()
