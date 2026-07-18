"""Non-vacuous regression test for the WSITB B1 enforcement-plane (increment-1,
CONSERVATION class).

NON-VACUITY contract: mutating the JOIN logic must break a test.
  - test_union_find_recomposes_coupled_set: two pairwise edges sharing a cell
    (A<->B, B<->C) MUST collapse into ONE conservation node whose coupled_set is
    {A,B,C}. If union-find is removed (each edge -> its own node), the "exactly 1
    node" + "coupled_set==3 members" assertions fail.
  - test_dirty_fixture_flags_q3_and_severity: a violator with mutates != omits MUST
    set q3_partial_flush AND (owner in value-movers) MUST make it severity-eligible
    and un-analyzed. Break q3 (drop the mutates!=omits test) or severity (ignore the
    value-mover set) and the count drops to 0.
  - test_clean_fixture_zero: no conserved-with edges -> 0 nodes, 0 severity-eligible.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_SCS = _load("t_scs", "state_coupling_schema.py")
_PLANE = _load("t_plane", "wsitb-enforcement-plane.py")
_SCHEMA = _load("t_wsitb_schema", "wsitb_schema.py")


def _edge(edge_id, a, b, violator_fn, mutates, omits):
    return _SCS.new_edge(
        edge_id=edge_id, language="sol", kind="conserved-with",
        cell_a=a, cell_b=b,
        writers_a=[violator_fn], writers_b=[violator_fn],
        violators=[{"fn": violator_fn,
                    "file": "src/Vault.sol", "line": 42,
                    "mutates": mutates, "omits": omits}],
        confidence="semantic-ssa",
    )


def _advisory_edge(edge_id, kind="freshness-coupled-to-external-clock"):
    return _SCS.new_edge(
        edge_id=edge_id, language="sol", kind=kind,
        cell_a="snapshot", cell_b="external-clock",
        writers_a=["readValue"], writers_b=[],
        violators=[{"fn": "readValue", "file": "src/Vault.sol", "line": 9,
                    "mutates": ["snapshot"], "omits": ["external-clock"]}],
        confidence="semantic-ssa",
        evidence={"promotable": False},
    )


def _write_value_movers(ws, fns):
    p = ws / ".auditooor" / "value_moving_functions.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(
        {"functions": [{"function": f, "file": "src/Vault.sol"} for f in fns]}))


class WsitbEnforcementPlaneTest(unittest.TestCase):
    def test_union_find_recomposes_coupled_set(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".auditooor").mkdir(parents=True)
            # A<->B and B<->C: must merge into ONE set {A,B,C}.
            _SCS.write_edges(ws, [
                _edge("e1", "cellA", "cellB", "moveValue", ["cellA"], ["cellB"]),
                _edge("e2", "cellB", "cellC", "moveValue", ["cellB"], ["cellC"]),
            ])
            _write_value_movers(ws, ["moveValue"])
            _PLANE.emit_plane(ws)
            nodes = _SCHEMA.read_plane(ws)
            self.assertEqual(len(nodes), 1,
                             "union-find must collapse the two edges into ONE node")
            self.assertEqual(set(nodes[0]["coupled_set"]),
                             {"cellA", "cellB", "cellC"},
                             "coupled_set must be the union-find component")

    def test_dirty_fixture_flags_q3_and_severity(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".auditooor").mkdir(parents=True)
            # violator mutates cellA but omits cellB -> partial flush (q3).
            _SCS.write_edges(ws, [
                _edge("e1", "cellA", "cellB", "moveValue", ["cellA"], ["cellB"]),
            ])
            _write_value_movers(ws, ["moveValue"])  # owner is a value-mover -> severity
            acct = _PLANE.emit_plane(ws)
            nodes = _SCHEMA.read_plane(ws)
            self.assertEqual(len(nodes), 1)
            n = nodes[0]
            self.assertTrue(n["q3_partial_flush"],
                            "mutates != omits must flag q3_partial_flush")
            self.assertEqual(n["owner"], "moveValue")
            self.assertTrue(n["severity_eligible"],
                            "value-mover owner must be severity-eligible")
            self.assertFalse(n["analyzed"])
            self.assertEqual(n["q8_verdict"], "unanalyzed")
            self.assertGreaterEqual(acct["severity_eligible_unanalyzed"], 1)
            # B1-inc2b: a q3 + severity-eligible node is a CONFIRMED partial-flush.
            self.assertEqual(acct["violated_points"], 1)
            # the points sidecar must carry exactly the un-analyzed severity-eligible node.
            pts = (ws / ".auditooor" / "wsitb_enforcement_points.jsonl").read_text().strip()
            self.assertEqual(len([l for l in pts.splitlines() if l.strip()]), 1)

    def test_severity_gated_by_value_mover_set(self):
        # owner NOT in the value-mover set -> node exists but is NOT severity-eligible,
        # so the un-analyzed COUNT drops to 0 (proves the severity join is real).
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".auditooor").mkdir(parents=True)
            _SCS.write_edges(ws, [
                _edge("e1", "cellA", "cellB", "internalOnly", ["cellA"], ["cellB"]),
            ])
            _write_value_movers(ws, ["someOtherFn"])  # violator NOT a value-mover
            acct = _PLANE.emit_plane(ws)
            nodes = _SCHEMA.read_plane(ws)
            self.assertEqual(len(nodes), 1)
            self.assertFalse(nodes[0]["severity_eligible"])
            self.assertEqual(acct["severity_eligible_unanalyzed"], 0)
            # B1-inc2b: q3 present but NOT severity-eligible -> not a counted violation.
            self.assertEqual(acct["violated_points"], 0)

    def test_clean_fixture_zero(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".auditooor").mkdir(parents=True)
            # No conserved-with edges at all.
            _SCS.write_edges(ws, [])
            acct = _PLANE.emit_plane(ws)
            nodes = _SCHEMA.read_plane(ws)
            self.assertEqual(len(nodes), 0)
            self.assertEqual(acct["severity_eligible_unanalyzed"], 0)
            self.assertEqual(acct["nodes_emitted"], 0)

    def test_b1_excludes_advisory_scg_arms(self):
        """B1 must consume only the conservation producer contract.

        Freshness and other advisory-first SCG arms remain hunt fuel and are
        covered by their own downstream lanes; they must not become B1 points.
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".auditooor").mkdir(parents=True)
            _SCS.write_edges(ws, [_advisory_edge("fresh-1")])
            acct = _PLANE.emit_plane(ws)
            nodes = _SCHEMA.read_plane(ws)
            self.assertEqual(nodes, [])
            self.assertEqual(acct["nodes_emitted"], 0)
            self.assertEqual(acct["severity_eligible_unanalyzed"], 0)


if __name__ == "__main__":
    unittest.main()
