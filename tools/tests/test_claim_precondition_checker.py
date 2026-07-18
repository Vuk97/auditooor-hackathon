#!/usr/bin/env python3
"""Wave 2 capability uplift (Issue #345 follow-up).

The original `tools/tests/test_claim_precondition_check.py` already locked
the rc=0/1/2 contract for the directive parser and the legacy ``==`` / ``!=``
operators. These tests cover the Wave 2 additions:

  * numeric operators (``<``, ``<=``, ``>``, ``>=``)
  * per-network RPC env vars (``AUDITOOOR_LIVE_RPC_<NETWORK>``)
  * mocked ``cast call`` subprocess (no real RPC traffic in CI)
  * workspace deployment-topology resolution for ``<ContractName>`` symbols
  * ``--skip-live-verify`` bypass when no observed value is available
  * JSON manifest output at ``<workspace>/.auditooor/claim_precondition_results.json``
  * multi-directive aggregation (one contradicts -> overall contradicts)
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "claim-precondition-check.py"


def load_tool():
    name = "_claim_precondition_checker_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class NumericOperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def test_less_than_or_equal_match(self) -> None:
        directives = self.tool.parse_directives(
            "<!-- claim-precondition: token.totalSupply() <= 1000000 -->"
        )
        rc, _, entries = self.tool.evaluate(
            directives,
            observed={"token.totalSupply()": "999000"},
            rpc_url=None,
            skip_live_verify=False,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(entries[0]["status"], "match")
        self.assertEqual(entries[0]["op"], "<=")

    def test_less_than_or_equal_contradicts(self) -> None:
        directives = self.tool.parse_directives(
            "<!-- claim-precondition: token.totalSupply() <= 1000000 -->"
        )
        rc, _, entries = self.tool.evaluate(
            directives,
            observed={"token.totalSupply()": "1500000"},
            rpc_url=None,
            skip_live_verify=False,
        )
        self.assertEqual(rc, 1)
        self.assertEqual(entries[0]["status"], "contradicts")

    def test_greater_than_match(self) -> None:
        directives = self.tool.parse_directives(
            "<!-- claim-precondition: vault.deposits() > 0 -->"
        )
        rc, _, entries = self.tool.evaluate(
            directives,
            observed={"vault.deposits()": "42"},
            rpc_url=None,
            skip_live_verify=False,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(entries[0]["status"], "match")

    def test_hex_observed_value_compared_numerically(self) -> None:
        directives = self.tool.parse_directives(
            "<!-- claim-precondition: oracle.price() >= 1000 -->"
        )
        rc, _, entries = self.tool.evaluate(
            directives,
            observed={"oracle.price()": "0x4d2"},  # 1234
            rpc_url=None,
            skip_live_verify=False,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(entries[0]["status"], "match")

    def test_non_numeric_with_numeric_op_warns(self) -> None:
        directives = self.tool.parse_directives(
            "<!-- claim-precondition: oracle.live() >= 1 -->"
        )
        rc, _, entries = self.tool.evaluate(
            directives,
            observed={"oracle.live()": "yes"},
            rpc_url=None,
            skip_live_verify=False,
        )
        self.assertEqual(rc, 2)
        self.assertEqual(entries[0]["status"], "cannot-run")


class CastCallSubprocessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def test_mocked_cast_call_match(self) -> None:
        text = (
            "<!-- claim-precondition: 0x" + "a" * 40 + " isAdmin(address)(bool) "
            "0x" + "b" * 40 + " == false -->"
        )
        directives = self.tool.parse_directives(text)

        def fake_runner(left: str, rpc_url: str):
            self.assertIn("isAdmin", left)
            self.assertEqual(rpc_url, "https://test.example/rpc")
            return True, "false"

        rc, _, entries = self.tool.evaluate(
            directives,
            observed={},
            rpc_url="https://test.example/rpc",
            skip_live_verify=False,
            cast_runner=fake_runner,
        )
        self.assertEqual(rc, 0, entries)
        self.assertEqual(entries[0]["status"], "match")
        self.assertEqual(entries[0]["observed"], "false")

    def test_mocked_cast_call_contradicts(self) -> None:
        # Mirrors the negriskfeemodule live miss: claim says false, chain says true.
        text = (
            "<!-- claim-precondition: 0x" + "a" * 40 + " isAdmin(address)(bool) "
            "0x" + "b" * 40 + " == false -->"
        )
        directives = self.tool.parse_directives(text)

        def fake_runner(_left: str, _rpc: str):
            return True, "true"

        rc, _, entries = self.tool.evaluate(
            directives,
            observed={},
            rpc_url="https://test.example/rpc",
            skip_live_verify=False,
            cast_runner=fake_runner,
        )
        self.assertEqual(rc, 1)
        self.assertEqual(entries[0]["status"], "contradicts")

    def test_cast_runner_failure_is_advisory(self) -> None:
        text = "<!-- claim-precondition: 0x" + "a" * 40 + " owner()(address) == 0x0 -->"
        directives = self.tool.parse_directives(text)

        def fake_runner(_left: str, _rpc: str):
            return False, "cast: connection refused"

        rc, _, entries = self.tool.evaluate(
            directives,
            observed={},
            rpc_url="https://test.example/rpc",
            skip_live_verify=False,
            cast_runner=fake_runner,
        )
        self.assertEqual(rc, 2)
        self.assertEqual(entries[0]["status"], "cannot-run")
        self.assertIn("connection refused", entries[0]["note"])


class NetworkRpcResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def test_auditooor_live_rpc_env_takes_priority(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "AUDITOOOR_LIVE_RPC_POLYGON": "https://aud.example/polygon",
                "POLYGON_RPC_URL": "https://other.example/polygon",
            },
            clear=False,
        ):
            self.assertEqual(
                self.tool._network_rpc_url("polygon"),
                "https://aud.example/polygon",
            )

    def test_network_rpc_url_fallback(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"POLYGON_RPC_URL": "https://fallback.example/polygon"},
            clear=False,
        ):
            os.environ.pop("AUDITOOOR_LIVE_RPC_POLYGON", None)
            self.assertEqual(
                self.tool._network_rpc_url("polygon"),
                "https://fallback.example/polygon",
            )

    def test_missing_env_returns_empty(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.tool._network_rpc_url("zksync"), "")

    def test_directive_network_routes_to_per_network_rpc(self) -> None:
        text = (
            "<!-- claim-precondition: network=polygon 0x" + "a" * 40 + " "
            "isAdmin(address)(bool) 0x" + "b" * 40 + " == false -->"
        )
        directives = self.tool.parse_directives(text)
        self.assertEqual(directives[0].network, "polygon")

        seen: dict = {}

        def fake_runner(left: str, rpc_url: str):
            seen["rpc"] = rpc_url
            return True, "false"

        with mock.patch.dict(
            os.environ,
            {"AUDITOOOR_LIVE_RPC_POLYGON": "https://polygon.example/rpc"},
            clear=False,
        ):
            rc, _, entries = self.tool.evaluate(
                directives,
                observed={},
                rpc_url=None,
                skip_live_verify=False,
                cast_runner=fake_runner,
            )
        self.assertEqual(rc, 0, entries)
        self.assertEqual(seen["rpc"], "https://polygon.example/rpc")
        self.assertEqual(entries[0]["network"], "polygon")
        self.assertEqual(entries[0]["rpc_used"], "https://polygon.example/rpc")


class WorkspaceTopologyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def test_address_symbol_resolved_from_deployment_topology(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "deployment_topology.json").write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "contract": "NegRiskAdapter",
                                "resolved_address": "0x" + "1" * 40,
                            },
                            {
                                "contract": "NegRiskFeeModule",
                                "resolved_address": "0x" + "2" * 40,
                            },
                        ]
                    }
                )
            )
            topology = self.tool._load_workspace_topology(ws)
            self.assertEqual(topology["NegRiskAdapter"], "0x" + "1" * 40)

            text = (
                "<!-- claim-precondition: ${NegRiskAdapter} isAdmin(address)(bool) "
                "${NegRiskFeeModule} == false -->"
            )
            directives = self.tool.parse_directives(text)

            def fake_runner(left: str, rpc_url: str):
                # Both symbols must have been substituted before cast call.
                self.assertIn("0x" + "1" * 40, left)
                self.assertIn("0x" + "2" * 40, left)
                return True, "true"  # contradicts the claim

            rc, _, entries = self.tool.evaluate(
                directives,
                observed={},
                rpc_url="https://test.example/rpc",
                skip_live_verify=False,
                topology=topology,
                cast_runner=fake_runner,
            )
            self.assertEqual(rc, 1)
            self.assertEqual(entries[0]["status"], "contradicts")
            self.assertIn("resolved_left", entries[0])

    def test_unknown_symbol_left_in_place(self) -> None:
        result = self.tool._resolve_address_symbols(
            "${Unknown} owner()(address)", {"Foo": "0xabc"}
        )
        self.assertIn("${Unknown}", result)


class SkipLiveVerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def test_skip_live_verify_bypasses_unresolved_directive(self) -> None:
        text = "<!-- claim-precondition: x.y() == 1 -->"
        directives = self.tool.parse_directives(text)
        rc, messages, entries = self.tool.evaluate(
            directives,
            observed={},
            rpc_url=None,
            skip_live_verify=True,
        )
        # Without an observed value the directive cannot be confirmed, but we
        # do NOT hard-fail when the operator deliberately opts out.
        self.assertEqual(rc, 2)
        self.assertEqual(entries[0]["status"], "cannot-run")
        self.assertIn("skip-live-verify", entries[0]["note"])
        self.assertIn("skipped", "\n".join(messages))

    def test_skip_live_verify_does_not_dial_rpc(self) -> None:
        text = "<!-- claim-precondition: x.y() == 1 -->"
        directives = self.tool.parse_directives(text)

        def fake_runner(_left: str, _rpc: str):  # pragma: no cover
            self.fail("cast_runner must not be called when --skip-live-verify is set")

        rc, _, _ = self.tool.evaluate(
            directives,
            observed={},
            rpc_url="https://test.example/rpc",
            skip_live_verify=True,
            cast_runner=fake_runner,
        )
        self.assertEqual(rc, 2)


class MultiDirectiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def test_one_contradiction_fails_overall(self) -> None:
        text = (
            "<!-- claim-precondition: a.x() == 1 -->\n"
            "<!-- claim-precondition: b.y() == 2 -->\n"
            "<!-- claim-precondition: c.z() == 3 -->"
        )
        directives = self.tool.parse_directives(text)
        rc, _, entries = self.tool.evaluate(
            directives,
            observed={
                "a.x()": "1",
                "b.y()": "999",  # contradicts
                "c.z()": "3",
            },
            rpc_url=None,
            skip_live_verify=False,
        )
        self.assertEqual(rc, 1)
        statuses = [e["status"] for e in entries]
        self.assertEqual(statuses, ["match", "contradicts", "match"])


class ManifestOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def test_workspace_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            draft = ws / "draft.md"
            observed = ws / "observed.json"
            draft.write_text(
                "<!-- claim-precondition: feeModule.paused() == false -->"
            )
            observed.write_text(json.dumps({"feeModule.paused()": "true"}))
            rc = self.tool.main(
                [
                    str(draft),
                    "--observed-json",
                    str(observed),
                    "--workspace",
                    str(ws),
                ]
            )
            self.assertEqual(rc, 1)
            manifest_path = ws / ".auditooor" / "claim_precondition_results.json"
            self.assertTrue(manifest_path.exists())
            payload = json.loads(manifest_path.read_text())
            self.assertEqual(payload["schema"], "auditooor.claim_precondition_results.v1")
            self.assertEqual(payload["overall_status"], "contradicts")
            self.assertEqual(payload["entries"][0]["status"], "contradicts")
            self.assertEqual(payload["entries"][0]["observed"], "true")

    def test_no_directives_writes_no_directives_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            draft = ws / "draft.md"
            draft.write_text("# Draft with no directives\n")
            rc = self.tool.main([str(draft), "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            manifest_path = ws / ".auditooor" / "claim_precondition_results.json"
            self.assertTrue(manifest_path.exists())
            payload = json.loads(manifest_path.read_text())
            self.assertEqual(payload["overall_status"], "no-directives")
            self.assertEqual(payload["entries"], [])

    def test_manifest_out_overrides_workspace_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            draft = Path(td) / "draft.md"
            observed = Path(td) / "observed.json"
            manifest = Path(td) / "custom.json"
            draft.write_text("<!-- claim-precondition: x.y() == 1 -->")
            observed.write_text(json.dumps({"x.y()": "1"}))
            rc = self.tool.main(
                [
                    str(draft),
                    "--observed-json",
                    str(observed),
                    "--manifest-out",
                    str(manifest),
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue(manifest.exists())
            payload = json.loads(manifest.read_text())
            self.assertEqual(payload["overall_status"], "match")


class ParseDirectiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def test_network_token_parsed(self) -> None:
        directives = self.tool.parse_directives(
            "<!-- claim-precondition: network=Mainnet x.y() == 1 -->"
        )
        self.assertEqual(directives[0].network, "mainnet")

    def test_no_network_token_yields_empty_network(self) -> None:
        directives = self.tool.parse_directives(
            "<!-- claim-precondition: x.y() == 1 -->"
        )
        self.assertEqual(directives[0].network, "")

    def test_all_operators_parsed(self) -> None:
        text = "\n".join(
            f"<!-- claim-precondition: x.y() {op} 1 -->"
            for op in ("==", "!=", "<", "<=", ">", ">=")
        )
        directives = self.tool.parse_directives(text)
        ops = [d.op for d in directives]
        self.assertEqual(ops, ["==", "!=", "<", "<=", ">", ">="])


if __name__ == "__main__":
    unittest.main()
