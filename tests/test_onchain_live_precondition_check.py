"""Focused test for onchain-live-precondition-check.py (2026-07-14).

The generic on-chain live-precondition capability closes "agents claim no-RPC +
findings not grounded on live state": a finding whose impact tier hinges on a
live precondition must carry a ``live-verified`` verdict, else it is downgraded
(``contradicted-by-chain``) or flagged (``unverifiable``).

This test exercises the tool against a MOCK endpoint (no real network) across
the three-case matrix the wiring depends on:

  * precondition-holds      => live-verified   (rc 0)
  * precondition-contradicted => contradicted-by-chain (rc 1, downgrade)
  * no-endpoint             => unverifiable    (rc 2)

Plus a golden keccak selector vector so the EVM ``sig`` path stays correct, and
a verdict-jsonl emission check so the pre-submit gate has an artifact to read.
"""
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


_ROOT = pathlib.Path(__file__).resolve().parent.parent
_TOOL = _ROOT / "tools" / "onchain-live-precondition-check.py"
_spec = importlib.util.spec_from_file_location("_olp_check", _TOOL)
_m = importlib.util.module_from_spec(_spec)
sys.modules["_olp_check"] = _m
sys.path.insert(0, str(_ROOT / "tools" / "lib"))
_spec.loader.exec_module(_m)


COSMOS_CFG = {
    "schema": "auditooor.onchain_access.v1",
    "chain": "neutron",
    "kind": "cosmos-lcd",
    "endpoint": "https://rest.cosmos.example",
    "key_addresses": {"vaultMarker": "neutron1vaultmarker00000000000000000000000000"},
    "denom_usd": {"uusdc": {"source": "peg", "price_or_url": "1.0"}},
}
_MARKER_URL = (
    "https://rest.cosmos.example/cosmos/bank/v1beta1/balances/"
    "neutron1vaultmarker00000000000000000000000000"
)
COSMOS_MOCK = {_MARKER_URL: {"balances": [{"denom": "uusdc", "amount": "12345"}]}}

SPEC_BALANCE = {
    "id": "LP-balance",
    "finding_id": "denom-desync",
    "description": "vault marker balance > 0 (funds present to steal)",
    "address_ref": "vaultMarker",
    "query": {
        "path": "/cosmos/bank/v1beta1/balances/{address}",
        "json_field": "balances.0.amount",
    },
    "severity_dependent": True,
}


class _WS:
    """Temp workspace with .auditooor/onchain_access.json + spec/mock files."""

    def __init__(self, cfg):
        self.dir = tempfile.mkdtemp()
        self.root = pathlib.Path(self.dir)
        (self.root / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.root / ".auditooor" / "onchain_access.json").write_text(
            json.dumps(cfg), encoding="utf-8"
        )

    def write(self, name, obj):
        p = self.root / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)

    def run(self, argv):
        return _m.main(["--workspace", str(self.root)] + argv)


class OnchainLivePreconditionTest(unittest.TestCase):
    # --- three-case matrix ------------------------------------------------- #
    def test_precondition_holds_is_live_verified(self):
        ws = _WS(COSMOS_CFG)
        spec = dict(SPEC_BALANCE, op=">", expected="0")
        specf = ws.write("specs.json", [spec])
        mockf = ws.write("mock.json", COSMOS_MOCK)
        rc = ws.run(["--spec-file", specf, "--mock-responses", mockf])
        self.assertEqual(rc, 0)
        # verdict jsonl emitted with a live-verified row
        rows = [
            json.loads(l)
            for l in (ws.root / ".auditooor" / "live_precondition_verdicts.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        self.assertEqual(rows[-1]["verdict"], "live-verified")
        self.assertTrue(rows[-1]["promotion_allowed"])
        self.assertEqual(rows[-1]["schema"], "auditooor.live_precondition_verdicts.v1")

    def test_precondition_contradicted_downgrades(self):
        ws = _WS(COSMOS_CFG)
        # chain says amount == 12345, but the finding claims it is 0
        spec = dict(SPEC_BALANCE, op="==", expected="0")
        specf = ws.write("specs.json", [spec])
        mockf = ws.write("mock.json", COSMOS_MOCK)
        rc = ws.run(["--spec-file", specf, "--mock-responses", mockf])
        self.assertEqual(rc, 1)
        rows = [
            json.loads(l)
            for l in (ws.root / ".auditooor" / "live_precondition_verdicts.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        self.assertEqual(rows[-1]["verdict"], "contradicted-by-chain")
        self.assertFalse(rows[-1]["promotion_allowed"])

    def test_no_endpoint_is_unverifiable(self):
        # workspace has NO onchain_access.json => no endpoint configured
        ws = pathlib.Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        specf = ws / "specs.json"
        specf.write_text(json.dumps([dict(SPEC_BALANCE, op=">", expected="0")]), encoding="utf-8")
        rc = _m.main(["--workspace", str(ws), "--spec-file", str(specf)])
        self.assertEqual(rc, 2)

    def test_configured_but_network_not_allowed_is_unverifiable(self):
        ws = _WS(COSMOS_CFG)
        specf = ws.write("specs.json", [dict(SPEC_BALANCE, op=">", expected="0")])
        # no --mock-responses and no --allow-network => cannot reach chain
        rc = ws.run(["--spec-file", specf])
        self.assertEqual(rc, 2)

    # --- no specs => nothing to ground, non-blocking ----------------------- #
    def test_no_specs_passes(self):
        ws = _WS(COSMOS_CFG)
        rc = ws.run([])
        self.assertEqual(rc, 0)

    # --- EVM path via draft directive + computed selector ------------------ #
    def test_evm_directive_paused_true_live_verified(self):
        cfg = {
            "schema": "auditooor.onchain_access.v1",
            "chain": "polygon",
            "kind": "evm-rpc",
            "endpoint": "https://polygon-rpc.example",
            "key_addresses": {"clob": "0x1234567890abcdef1234567890abcdef12345678"},
        }
        ws = _WS(cfg)
        draft = ws.root / "draft.md"
        draft.write_text(
            "# CLOB paused\n\n"
            '<!-- live-precondition: {"id":"LP-paused","finding_id":"clob-paused",'
            '"to_ref":"clob","query":{"sig":"paused()(bool)","abi_out":"bool"},'
            '"op":"==","expected":"true"} -->\n',
            encoding="utf-8",
        )
        # selector paused() == 0x5c975abb; mock returns bool true
        key = "0x1234567890abcdef1234567890abcdef12345678|0x5c975abb"
        mockf = ws.write(
            "mock.json",
            {key: {"jsonrpc": "2.0", "id": 1, "result": "0x" + "0" * 63 + "1"}},
        )
        rc = ws.run(["--submission", str(draft), "--mock-responses", mockf, "--no-emit"])
        self.assertEqual(rc, 0)

    # --- keccak selector golden vectors ------------------------------------ #
    def test_selector_golden_vectors(self):
        self.assertEqual(_m.selector_for("paused()(bool)"), "0x5c975abb")
        self.assertEqual(_m.selector_for("totalSupply()(uint256)"), "0x18160ddd")
        self.assertEqual(_m.selector_for("transfer(address,uint256)"), "0xa9059cbb")
        self.assertEqual(
            _m.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    # --- gate mode: adopt persisted live-verified without network ---------- #
    def test_gate_adopts_persisted_live_verified(self):
        ws = _WS(COSMOS_CFG)
        spec = dict(SPEC_BALANCE, op=">", expected="0")
        specf = ws.write("specs.json", [spec])
        mockf = ws.write("mock.json", COSMOS_MOCK)
        # authoring run (with mock == live query) persists a live-verified row
        self.assertEqual(ws.run(["--spec-file", specf, "--mock-responses", mockf]), 0)
        # gate run WITHOUT network/mock still passes by adopting the persisted row
        rc = ws.run(["--spec-file", specf, "--gate"])
        self.assertEqual(rc, 0)

    def test_gate_unverified_when_no_persisted(self):
        ws = _WS(COSMOS_CFG)
        specf = ws.write("specs.json", [dict(SPEC_BALANCE, op=">", expected="0")])
        # no persisted verdict, no network at gate time => unverifiable (rc 2)
        rc = ws.run(["--spec-file", specf, "--gate"])
        self.assertEqual(rc, 2)

    def test_gate_ignores_non_severity_dependent(self):
        ws = _WS(COSMOS_CFG)
        # latent precondition (not severity-dependent) must not block filing
        spec = dict(SPEC_BALANCE, op=">", expected="0", severity_dependent=False)
        specf = ws.write("specs.json", [spec])
        rc = ws.run(["--spec-file", specf, "--gate"])
        self.assertEqual(rc, 0)

    def test_gate_contradiction_still_fails(self):
        ws = _WS(COSMOS_CFG)
        spec = dict(SPEC_BALANCE, op="==", expected="0")
        specf = ws.write("specs.json", [spec])
        mockf = ws.write("mock.json", COSMOS_MOCK)
        # persist a contradiction
        self.assertEqual(ws.run(["--spec-file", specf, "--mock-responses", mockf]), 1)
        # gate adopts the persisted contradiction => hard fail (rc 1)
        self.assertEqual(ws.run(["--spec-file", specf, "--gate"]), 1)

    # --- config safety: secret-bearing endpoint rejected ------------------- #
    def test_secret_endpoint_config_is_unverifiable(self):
        cfg = dict(COSMOS_CFG, endpoint="https://rpc.example/v3/deadbeefdeadbeefdeadbeef")
        ws = _WS(cfg)
        specf = ws.write("specs.json", [dict(SPEC_BALANCE, op=">", expected="0")])
        mockf = ws.write("mock.json", COSMOS_MOCK)
        rc = ws.run(["--spec-file", specf, "--mock-responses", mockf])
        # invalid/unsafe config => unverifiable, never queried
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
