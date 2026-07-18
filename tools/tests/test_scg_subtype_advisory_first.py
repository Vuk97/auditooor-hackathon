import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path("/Users/wolf/auditooor-mcp/tools")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, TOOLS / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _seed_ws(tmp, edges):
    scs = _load("state_coupling_schema", "state_coupling_schema.py")
    scs.write_edges(Path(tmp), edges)
    return Path(tmp)


def _base_gating_edge(scs):
    # base same-contract conserved-with: promotable=True, NO subtype key (state-coupling-graph.py:1445-1448)
    return scs.new_edge(
        edge_id="base00000001", language="solidity", kind="conserved-with",
        cell_a="totalShares", cell_b="totalAssets",
        writers_a=["deposit"], writers_b=["deposit"], violators=[],
        confidence="semantic-ssa",
        evidence={"grounding": "vmf", "tier": "value-conservation", "promotable": True})


def _xcontract_edge(scs):
    # A13 xcontract arm: kind=conserved-with BUT subtype/tier=cross-contract-conservation,
    # promotable=True UNCONDITIONALLY by construction (state-coupling-graph.py:1144/1166),
    # advisory-first flags set (:1168-1170). This is the false-RED hazard.
    return scs.new_edge(
        edge_id="xc0000000001", language="solidity", kind="conserved-with",
        cell_a="trancheA", cell_b="trancheB",
        writers_a=["split"], writers_b=["split"], violators=[],
        confidence="semantic-ssa",
        evidence={"grounding": "source-external-total-split",
                  "tier": "cross-contract-conservation",
                  "subtype": "cross-contract-conservation",
                  "cross_contract": True, "promotable": True,
                  "verdict": "needs-fuzz", "advisory": True, "auto_credit": False})


def _run_check(ws, subtypes_strict):
    chk = _load("state_coupling_cc", "state-coupling-completeness-check.py")
    keys = ("AUDITOOOR_L37_STRICT", "AUDITOOOR_SCG_SUBTYPES_STRICT")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        os.environ["AUDITOOOR_L37_STRICT"] = "1"  # strict umbrella: open promotable -> hard fail
        if subtypes_strict:
            os.environ["AUDITOOOR_SCG_SUBTYPES_STRICT"] = "1"
        else:
            os.environ.pop("AUDITOOOR_SCG_SUBTYPES_STRICT", None)
        rc = chk.main(["--workspace", str(ws), "--no-emit"])  # read seeded edges, do not re-emit
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    res = json.loads((ws / ".auditooor" / "state_coupling_completeness.json").read_text())
    return rc, res


class ScgSubtypeAdvisoryFirstTest(unittest.TestCase):
    def test_green_ws_with_only_subtype_edges_stays_green_by_default(self):
        # A ws whose ONLY promotable edge is the xcontract subtype edge is GREEN by default
        # (open_edges excludes it) and only RED under the dedicated opt-in. Non-vacuity: the
        # xcontract edge carries promotable=True, so WITHOUT the demotion this ws would false-RED.
        scs = _load("state_coupling_schema", "state_coupling_schema.py")
        with tempfile.TemporaryDirectory() as tmp:
            ws = _seed_ws(tmp, [_xcontract_edge(scs)])

            rc_off, res_off = _run_check(ws, subtypes_strict=False)
            self.assertEqual(res_off["open_edges"], 0, "subtype edge must NOT gate by default")
            self.assertNotIn("xc0000000001", set(res_off["open_edge_ids"]))
            self.assertEqual(res_off["advisory_edges"], 1, "it is demoted to advisory, not dropped")
            self.assertEqual(res_off["verdict"], "pass-state-coupling-completeness")
            self.assertEqual(rc_off, 0)

            rc_on, res_on = _run_check(ws, subtypes_strict=True)
            self.assertEqual(res_on["open_edges"], 1, "opt-in must gate the subtype edge")
            self.assertIn("xc0000000001", set(res_on["open_edge_ids"]))
            self.assertEqual(res_on["verdict"], "fail-state-coupling-open")
            self.assertEqual(rc_on, 1)

    def test_base_gating_edge_is_never_demoted(self):
        # The demotion predicate MUST NOT match a base always-on gating edge: a promotable base
        # conserved-with edge (no subtype) gates in BOTH modes, unaffected by the subtype toggle.
        scs = _load("state_coupling_schema", "state_coupling_schema.py")
        with tempfile.TemporaryDirectory() as tmp:
            ws = _seed_ws(tmp, [_base_gating_edge(scs), _xcontract_edge(scs)])

            _, res_off = _run_check(ws, subtypes_strict=False)
            ids_off = set(res_off["open_edge_ids"])
            self.assertIn("base00000001", ids_off, "base edge must still gate by default")
            self.assertNotIn("xc0000000001", ids_off, "xcontract demoted by default")

            _, res_on = _run_check(ws, subtypes_strict=True)
            ids_on = set(res_on["open_edge_ids"])
            self.assertIn("base00000001", ids_on, "base edge gates under opt-in too (surgical)")
            self.assertIn("xc0000000001", ids_on, "xcontract joins the gate under opt-in")


if __name__ == "__main__":
    unittest.main()
