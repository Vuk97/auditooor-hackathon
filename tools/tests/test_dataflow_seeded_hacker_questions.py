#!/usr/bin/env python3
# r36-rebuttal: lane df-hackerq-seed registered in .auditooor/agent_pathspec.json
"""test_dataflow_seeded_hacker_questions.py - Bidirectional wiring 49a.

The data-flow slice (tools/dataflow-slice.py) emits DefUsePath records to
<ws>/.auditooor/dataflow_paths.jsonl with `unguarded` ALREADY closure-corrected.
This wiring makes three consumers USE that slice:

  1. tools/per-function-hacker-questions.py: a flow-seeded question SOURCE - one
     targeted question anchored at the REAL sink file:line for every UNGUARDED
     value-mover DefUsePath; tagged flow_seeded + dataflow_path_id.
  2. tools/per-fn-question-ranker.py: a +4.0 boost for flow_seeded questions.
  3. vault_per_function_hunter_brief: a DATA-FLOW CONTEXT block when the queried
     fn is a path source/sink.

These tests assert PRESENT-vs-ABSENT slice behavior:
  - seeded questions appear AT the sink line + carry flow_seeded/dataflow_path_id;
  - guarded (unguarded=False) / degraded / heuristic / non-value-mover paths
    yield NO seeded question;
  - the ranker boosts flow_seeded above an identical non-seeded question;
  - the brief includes data_flow_context ONLY when a path matches;
  - byte-identical hacker-question output when the slice is ABSENT.

synthetic_fixture: true - DefUsePath records are minimal schema-valid records.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
PFHQ_TOOL = TOOLS / "per-function-hacker-questions.py"
RANKER_TOOL = TOOLS / "per-fn-question-ranker.py"
DF_SCHEMA = TOOLS / "dataflow_schema.py"
MCP_SERVER = TOOLS / "vault-mcp-server.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


PFHQ = _load("pfhq_under_test", PFHQ_TOOL)
RANKER = _load("ranker_under_test", RANKER_TOOL)
DFS = _load("dataflow_schema_ut", DF_SCHEMA)


def _path(path_id: str, *, src_fn: str, src_file: str, src_line: int,
          sink_kind: str, sink_callee: str, sink_fn: str, sink_file: str,
          sink_line: int, unguarded: bool, confidence: str = "semantic-ssa",
          degraded: bool = False, call_depth: int = 0) -> dict:
    """Build a schema-valid DefUsePath. `unguarded`/`call_depth` are set directly
    (bypassing new_path's derivation) so the test can pin the closure verdict."""
    return {
        "schema": DFS.SCHEMA_VERSION,
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither.test",
        "source": {"kind": "param-entrypoint", "fn": src_fn, "var": "amount",
                   "file": src_file, "line": src_line},
        "sink": {"kind": sink_kind, "callee": sink_callee, "arg_pos": 0,
                 "fn": sink_fn, "file": sink_file, "line": sink_line},
        "hops": [],
        "call_depth": call_depth,
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
    }


def _write_slice(ws: Path, paths: list[dict]) -> None:
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "dataflow_paths.jsonl").open("w") as fh:
        for p in paths:
            fh.write(json.dumps(p) + "\n")


INV_FIXTURE = [
    {"function": "deposit", "file": "src/Vault.sol", "language": "solidity",
     "invariant_candidates": ["access-control-missing-1", "reentrancy-1"]},
    {"function": "withdraw", "file": "src/Vault.sol", "language": "solidity",
     "invariant_candidates": ["sum-preserved-1"]},
]


def _write_inv(p: Path) -> None:
    with p.open("w") as fh:
        for r in INV_FIXTURE:
            fh.write(json.dumps(r) + "\n")


# ---------------------------------------------------------------------------
# 1. Flow-seeded question SOURCE (present-vs-absent slice)
# ---------------------------------------------------------------------------

class TestFlowSeededSource(unittest.TestCase):

    def test_unguarded_value_mover_is_seeded_at_sink_line(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [
                _path("dfp-A", src_fn="Vault.withdraw(uint256)",
                      src_file="src/Vault.sol", src_line=10,
                      sink_kind="transfer", sink_callee="transfer",
                      sink_fn="Vault.withdraw(uint256)",
                      sink_file="src/Vault.sol", sink_line=42,
                      unguarded=True, call_depth=1),
            ])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        finally:
            import shutil
            shutil.rmtree(ws)
        seeded = [r for r in rows if r.get("question_source") == "flow-seeded"]
        self.assertEqual(len(seeded), 1, "exactly one seeded question for one unguarded flow")
        s = seeded[0]
        self.assertTrue(s.get("flow_seeded"))
        self.assertEqual(s.get("dataflow_path_id"), "dfp-A")
        # Anchored AT the real sink file:line.
        self.assertEqual(s.get("file"), "src/Vault.sol:42")
        self.assertIn("src/Vault.sol:42", s.get("question", ""))
        self.assertIn("R76", s.get("question", ""))

    def test_guarded_path_yields_no_seeded_question(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [
                _path("dfp-G", src_fn="Vault.adminSweep(uint256)",
                      src_file="src/Vault.sol", src_line=10,
                      sink_kind="transfer", sink_callee="transfer",
                      sink_fn="Vault.adminSweep(uint256)",
                      sink_file="src/Vault.sol", sink_line=50,
                      unguarded=False),  # role-gated: guard dominates the slice
            ])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            PFHQ.main(["--invariants", str(inv), "--output", str(out),
                       "--workspace", str(ws)])
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        finally:
            import shutil
            shutil.rmtree(ws)
        self.assertEqual([r for r in rows if r.get("flow_seeded")], [],
                         "a closure-guarded (unguarded=False) flow must NOT seed")

    def test_degraded_and_heuristic_paths_excluded(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [
                _path("dfp-D", src_fn="f", src_file="src/A.sol", src_line=1,
                      sink_kind="transfer", sink_callee="transfer", sink_fn="f",
                      sink_file="src/A.sol", sink_line=2, unguarded=True,
                      degraded=True),
                _path("dfp-H", src_fn="g", src_file="src/A.sol", src_line=3,
                      sink_kind="transfer", sink_callee="transfer", sink_fn="g",
                      sink_file="src/A.sol", sink_line=4, unguarded=True,
                      confidence="heuristic"),
            ])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            PFHQ.main(["--invariants", str(inv), "--output", str(out),
                       "--workspace", str(ws)])
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        finally:
            import shutil
            shutil.rmtree(ws)
        # read_paths drops degraded; _flow_path_is_seedable drops heuristic.
        self.assertEqual([r for r in rows if r.get("flow_seeded")], [],
                         "degraded + heuristic paths must not seed (R80)")

    def test_non_value_mover_sink_kind_excluded(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [
                _path("dfp-R", src_fn="f", src_file="src/A.sol", src_line=1,
                      sink_kind="state_read", sink_callee="x", sink_fn="f",
                      sink_file="src/A.sol", sink_line=2, unguarded=True),
            ])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            PFHQ.main(["--invariants", str(inv), "--output", str(out),
                       "--workspace", str(ws)])
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        finally:
            import shutil
            shutil.rmtree(ws)
        self.assertEqual([r for r in rows if r.get("flow_seeded")], [],
                         "a non-value-mover sink kind must not seed")

    def test_storage_value_sink_is_seeded(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [
                _path("dfp-SV", src_fn="Ops.withdrawEarnings(uint64,uint256)",
                      src_file="src/Ops.sol", src_line=90,
                      sink_kind="storage-value", sink_callee="operatorEthVUnits",
                      sink_fn="Ops.withdrawEarnings(uint64,uint256)",
                      sink_file="src/Ops.sol", sink_line=93, unguarded=True),
            ])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            PFHQ.main(["--invariants", str(inv), "--output", str(out),
                       "--workspace", str(ws)])
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        finally:
            import shutil
            shutil.rmtree(ws)
        seeded = [r for r in rows if r.get("flow_seeded")]
        self.assertEqual(len(seeded), 1)
        self.assertEqual(seeded[0]["flow_sink_kind"], "storage-value")
        self.assertEqual(seeded[0]["file"], "src/Ops.sol:93")

    def test_byte_identical_when_slice_absent(self):
        """No slice -> output byte-identical to a no-workspace run (default-off)."""
        td = Path(tempfile.mkdtemp())
        try:
            inv = td / "inv.jsonl"
            _write_inv(inv)
            out_ws = td / "q_ws.jsonl"      # workspace given but NO slice on disk
            out_none = td / "q_none.jsonl"  # no workspace at all
            PFHQ.main(["--invariants", str(inv), "--output", str(out_ws),
                       "--workspace", str(td)])
            PFHQ.main(["--invariants", str(inv), "--output", str(out_none)])
            self.assertEqual(out_ws.read_bytes(), out_none.read_bytes(),
                             "no-slice workspace run must be byte-identical to no-ws run")
            # And neither contains a flow-seeded row.
            rows = [json.loads(l) for l in out_ws.read_text().splitlines() if l.strip()]
            self.assertEqual([r for r in rows if r.get("flow_seeded")], [])
        finally:
            import shutil
            shutil.rmtree(td)

    def test_explicit_dataflow_paths_override(self):
        td = Path(tempfile.mkdtemp())
        try:
            df = td / "explicit.jsonl"
            with df.open("w") as fh:
                fh.write(json.dumps(_path(
                    "dfp-X", src_fn="f", src_file="src/A.sol", src_line=1,
                    sink_kind="mint", sink_callee="mint", sink_fn="f",
                    sink_file="src/A.sol", sink_line=9, unguarded=True)) + "\n")
            inv = td / "inv.jsonl"
            _write_inv(inv)
            out = td / "q.jsonl"
            PFHQ.main(["--invariants", str(inv), "--output", str(out),
                       "--dataflow-paths", str(df)])
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        finally:
            import shutil
            shutil.rmtree(td)
        seeded = [r for r in rows if r.get("flow_seeded")]
        self.assertEqual(len(seeded), 1)
        self.assertEqual(seeded[0]["dataflow_path_id"], "dfp-X")


# ---------------------------------------------------------------------------
# 2. Ranker flow-seeded boost
# ---------------------------------------------------------------------------

class TestRankerFlowBoost(unittest.TestCase):

    def _q(self, flow_seeded: bool) -> dict:
        q = {
            "file": "src/Vault.sol:42",
            "function": "withdraw",
            "callable_surface": "external",
            "function_visibility": "external",
            "question": "Can withdraw move value via an unguarded flow?",
            "question_class": "unguarded-transfer",
            "anchor_invariant": "",
        }
        if flow_seeded:
            q["flow_seeded"] = True
            q["question_source"] = "flow-seeded"
            q["dataflow_path_id"] = "dfp-A"
        return q

    def _score(self, q):
        return RANKER.score_question(q, [], [], {}, {}, {})

    def test_flow_seeded_gets_boost(self):
        r = self._score(self._q(True))
        self.assertEqual(r["score_breakdown"]["flow_boost"], 4.0)

    def test_non_flow_seeded_no_boost(self):
        r = self._score(self._q(False))
        self.assertEqual(r["score_breakdown"]["flow_boost"], 0.0)

    def test_flow_seeded_outranks_identical_non_seeded(self):
        r_seed = self._score(self._q(True))
        r_plain = self._score(self._q(False))
        self.assertGreater(r_seed["score"], r_plain["score"])
        self.assertAlmostEqual(r_seed["score"] - r_plain["score"], 4.0, places=3)

    def test_no_regression_when_no_flow_field(self):
        """A question with no flow_seeded field scores exactly as before."""
        q = {
            "file": "src/Vault.sol",
            "function": "withdraw",
            "callable_surface": "external",
            "function_visibility": "external",
            "question": "Can withdraw be reentered?",
            "question_class": "reentrancy",
            "anchor_invariant": "",
        }
        r = self._score(q)
        self.assertEqual(r["score_breakdown"]["flow_boost"], 0.0)
        self.assertEqual(r["verdict"], "rank-eligible")


# ---------------------------------------------------------------------------
# 3. Hunter brief DATA-FLOW CONTEXT block (present-vs-absent)
# ---------------------------------------------------------------------------

class TestHunterBriefDataFlowBlock(unittest.TestCase):

    def setUp(self):
        self.vmcp = _load("vmcp_brief_ut", MCP_SERVER)
        self._vault = Path(tempfile.mkdtemp())
        (self._vault / "INDEX.md").write_text("# INDEX\n", encoding="utf-8")
        self.query = self.vmcp.VaultQuery(self._vault, TOOLS.parent)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._vault, ignore_errors=True)

    def test_block_present_when_path_matches(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [
                _path("dfp-A", src_fn="Vault.withdraw(uint256)",
                      src_file="src/Vault.sol", src_line=10,
                      sink_kind="transfer", sink_callee="transfer",
                      sink_fn="Vault.withdraw(uint256)",
                      sink_file="src/Vault.sol", sink_line=42, unguarded=True),
            ])
            resp = self.query.vault_per_function_hunter_brief(
                workspace_path=str(ws),
                contract_path="src/Vault.sol",
                function_name="withdraw",
            )
        finally:
            import shutil
            shutil.rmtree(ws)
        dfc = resp.get("data_flow_context")
        self.assertIsInstance(dfc, list)
        self.assertEqual(len(dfc), 1)
        self.assertEqual(dfc[0]["dataflow_path_id"], "dfp-A")
        self.assertTrue(dfc[0]["unguarded"])
        self.assertIn("UNGUARDED", dfc[0]["closure_verdict"])
        self.assertIn("R76", dfc[0]["hunter_note"])
        self.assertEqual(resp["summary"]["data_flow_paths_matched"], 1)

    def test_block_absent_when_no_slice(self):
        ws = Path(tempfile.mkdtemp())
        try:
            (ws / ".auditooor").mkdir(parents=True)  # no slice file
            resp = self.query.vault_per_function_hunter_brief(
                workspace_path=str(ws),
                contract_path="src/Vault.sol",
                function_name="withdraw",
            )
        finally:
            import shutil
            shutil.rmtree(ws)
        self.assertEqual(resp.get("data_flow_context"), [])
        self.assertEqual(resp["summary"]["data_flow_paths_matched"], 0)

    def test_block_absent_when_function_not_on_any_path(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [
                _path("dfp-A", src_fn="Vault.withdraw(uint256)",
                      src_file="src/Vault.sol", src_line=10,
                      sink_kind="transfer", sink_callee="transfer",
                      sink_fn="Vault.withdraw(uint256)",
                      sink_file="src/Vault.sol", sink_line=42, unguarded=True),
            ])
            resp = self.query.vault_per_function_hunter_brief(
                workspace_path=str(ws),
                contract_path="src/Vault.sol",
                function_name="totallyUnrelatedFn",
            )
        finally:
            import shutil
            shutil.rmtree(ws)
        self.assertEqual(resp.get("data_flow_context"), [])

    def test_unguarded_sorted_first(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [
                _path("dfp-G", src_fn="Vault.withdraw(uint256)",
                      src_file="src/Vault.sol", src_line=10,
                      sink_kind="burn", sink_callee="burn",
                      sink_fn="Vault.withdraw(uint256)",
                      sink_file="src/Vault.sol", sink_line=88, unguarded=False),
                _path("dfp-U", src_fn="Vault.withdraw(uint256)",
                      src_file="src/Vault.sol", src_line=10,
                      sink_kind="transfer", sink_callee="transfer",
                      sink_fn="Vault.withdraw(uint256)",
                      sink_file="src/Vault.sol", sink_line=42, unguarded=True),
            ])
            resp = self.query.vault_per_function_hunter_brief(
                workspace_path=str(ws),
                contract_path="src/Vault.sol",
                function_name="withdraw",
            )
        finally:
            import shutil
            shutil.rmtree(ws)
        dfc = resp["data_flow_context"]
        self.assertEqual(len(dfc), 2)
        self.assertTrue(dfc[0]["unguarded"], "unguarded path must sort first")
        self.assertFalse(dfc[1]["unguarded"])


# ---------------------------------------------------------------------------
# 4. Guard-correctness BOUNDARY-SUSPECT consumer (Glider comparator semantics)
# ---------------------------------------------------------------------------

def _boundary_path(path_id: str, *, op: str = "<=", suggested: str = "<",
                   at_fn: str = "_route", guard_line: int = 30,
                   unguarded: bool = False, degraded: bool = False,
                   confidence: str = "semantic-ssa") -> dict:
    """A schema-valid DefUsePath carrying the additive boundary_suspect annotation
    the closure pass (apply_closure_unguarded) stamps. The path is GUARDED
    (unguarded=False) but may still be off-by-one exploitable."""
    return {
        "schema": DFS.SCHEMA_VERSION,
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither.test",
        "source": {"kind": "param-entrypoint", "fn": "Clean.withdraw(uint256)",
                   "var": "amount", "file": "src/Clean.sol", "line": 23},
        "sink": {"kind": "transferFrom", "callee": "transferFrom", "arg_pos": 2,
                 "fn": "Clean._pay(uint256)", "file": "src/Clean.sol", "line": 35},
        "hops": [],
        "call_depth": 2,
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
        # additive boundary annotation
        "boundary_suspect": True,
        "guard_comparator": {"op": op, "suggested_op": suggested, "at_fn": at_fn,
                             "at_end": "source", "line": guard_line,
                             "reason": "non-strict bound LEAD"},
    }


class TestBoundarySuspectConsumer(unittest.TestCase):

    def test_boundary_suspect_path_is_seedable(self):
        self.assertTrue(PFHQ._flow_path_is_boundary_suspect(_boundary_path("dfp-B")))

    def test_non_boundary_path_not_seedable(self):
        p = _boundary_path("dfp-B")
        del p["boundary_suspect"]
        self.assertFalse(PFHQ._flow_path_is_boundary_suspect(p))

    def test_degraded_and_heuristic_boundary_paths_excluded(self):
        self.assertFalse(PFHQ._flow_path_is_boundary_suspect(
            _boundary_path("dfp-B", degraded=True)))
        self.assertFalse(PFHQ._flow_path_is_boundary_suspect(
            _boundary_path("dfp-B", confidence="heuristic")))

    def test_boundary_question_anchored_at_guard_line(self):
        qs = PFHQ.gen_boundary_suspect_questions([_boundary_path("dfp-B")])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_class"], "boundary-off-by-one")
        self.assertEqual(q["question_source"], "flow-seeded-boundary")
        self.assertTrue(q["boundary_suspect"])
        self.assertEqual(q["dataflow_path_id"], "dfp-B")
        self.assertEqual(q["guard_comparator_op"], "<=")
        self.assertEqual(q["guard_comparator_suggested_op"], "<")
        # anchor at the GUARD's file:line, not the sink line.
        self.assertEqual(q["file"], "src/Clean.sol:30")
        self.assertIn("off-by-one", q["question"].lower())

    def test_boundary_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [_boundary_path("dfp-B")])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            bq = [r for r in rows if r.get("question_class") == "boundary-off-by-one"]
            self.assertEqual(len(bq), 1, "exactly one boundary question expected")
            self.assertEqual(bq[0]["dataflow_path_id"], "dfp-B")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_boundary_question_when_slice_absent(self):
        # Default-off: no slice -> no boundary question (byte-identical baseline).
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_class") == "boundary-off-by-one" for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)


# ---------------------------------------------------------------------------
# 5. Type-convertibility UNSAFE-DOWNCAST consumer (Glider can_convert semantics)
# ---------------------------------------------------------------------------

def _downcast_path(path_id: str, *, var: str = "amount", from_t: str = "uint256",
                   to_t: str = "uint64", kind: str = "narrowing",
                   at_end: str = "source", cast_line: int = 31,
                   unguarded: bool = False, degraded: bool = False,
                   confidence: str = "semantic-ssa") -> dict:
    """A schema-valid DefUsePath carrying the additive downcast_suspect annotation
    the closure pass (apply_closure_unguarded) stamps. Guard-independent: the lead
    holds whether or not the path is access-guarded."""
    return {
        "schema": DFS.SCHEMA_VERSION,
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither.test",
        "source": {"kind": "param-entrypoint", "fn": "Clean.pay(uint256)",
                   "var": var, "file": "src/Clean.sol", "line": 23},
        "sink": {"kind": "transfer", "callee": "transfer", "arg_pos": 1,
                 "fn": "Clean.pay(uint256)", "file": "src/Clean.sol", "line": 35},
        "hops": [],
        "call_depth": 0,
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
        # additive downcast annotation
        "downcast_suspect": True,
        "downcast": {"var": var, "from": from_t, "to": to_t, "kind": kind,
                     "at_fn": "pay", "at_end": at_end, "line": cast_line},
    }


class TestDowncastSuspectConsumer(unittest.TestCase):

    def test_downcast_suspect_path_is_seedable(self):
        self.assertTrue(PFHQ._flow_path_is_downcast_suspect(_downcast_path("dfp-D")))

    def test_non_downcast_path_not_seedable(self):
        p = _downcast_path("dfp-D")
        del p["downcast_suspect"]
        self.assertFalse(PFHQ._flow_path_is_downcast_suspect(p))

    def test_degraded_and_heuristic_downcast_paths_excluded(self):
        self.assertFalse(PFHQ._flow_path_is_downcast_suspect(
            _downcast_path("dfp-D", degraded=True)))
        self.assertFalse(PFHQ._flow_path_is_downcast_suspect(
            _downcast_path("dfp-D", confidence="heuristic")))

    def test_downcast_question_anchored_at_cast_line(self):
        qs = PFHQ.gen_downcast_suspect_questions([_downcast_path("dfp-D")])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_class"], "unsafe-downcast-truncation")
        self.assertEqual(q["question_source"], "flow-seeded-downcast")
        self.assertTrue(q["downcast_suspect"])
        self.assertEqual(q["dataflow_path_id"], "dfp-D")
        self.assertEqual(q["downcast_from"], "uint256")
        self.assertEqual(q["downcast_to"], "uint64")
        self.assertEqual(q["downcast_kind"], "narrowing")
        # anchor at the CAST file:line.
        self.assertEqual(q["file"], "src/Clean.sol:31")
        self.assertIn("truncat", q["question"].lower())

    def test_signflip_question_wording(self):
        qs = PFHQ.gen_downcast_suspect_questions(
            [_downcast_path("dfp-D", from_t="int256", to_t="uint256", kind="sign-flip")])
        self.assertEqual(qs[0]["downcast_kind"], "sign-flip")
        self.assertIn("sign-flip", qs[0]["question"].lower())

    def test_downcast_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [_downcast_path("dfp-D")])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            dq = [r for r in rows
                  if r.get("question_class") == "unsafe-downcast-truncation"]
            self.assertEqual(len(dq), 1, "exactly one downcast question expected")
            self.assertEqual(dq[0]["dataflow_path_id"], "dfp-D")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_downcast_question_when_slice_absent(self):
        # Default-off: no slice -> no downcast question (byte-identical baseline).
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_class") == "unsafe-downcast-truncation"
                    for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)


# ---------------------------------------------------------------------------
# 5b. Divide-before-multiply precision consumer (Glider gap W3)
# ---------------------------------------------------------------------------

def _div_before_mul_path(path_id: str, *, div_line: int = 30, mul_line: int = 30,
                         value_moving=True, at_end: str = "source",
                         unguarded: bool = False, degraded: bool = False,
                         confidence: str = "semantic-ssa") -> dict:
    """A schema-valid DefUsePath carrying the additive div_before_mul_suspect
    annotation the closure pass (apply_closure_unguarded) stamps. Guard-independent:
    the precision lead holds whether or not the path is access-guarded."""
    return {
        "schema": DFS.SCHEMA_VERSION,
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither.test",
        "source": {"kind": "param-entrypoint", "fn": "Clean.payout(uint256)",
                   "var": "amount", "file": "src/Clean.sol", "line": 23},
        "sink": {"kind": "transfer", "callee": "transfer", "arg_pos": 1,
                 "fn": "Clean.payout(uint256)", "file": "src/Clean.sol", "line": 35},
        "hops": [],
        "call_depth": 0,
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
        # additive divide-before-multiply annotation
        "div_before_mul_suspect": True,
        "div_before_mul": {"div_line": div_line, "mul_line": mul_line,
                           "at_fn": "payout", "at_end": at_end,
                           "value_moving": value_moving,
                           "severity_hint": "precision-loss"},
    }


class TestDivBeforeMulConsumer(unittest.TestCase):

    def test_div_before_mul_path_is_seedable(self):
        self.assertTrue(
            PFHQ._flow_path_is_div_before_mul_suspect(_div_before_mul_path("dfp-P")))

    def test_non_div_before_mul_path_not_seedable(self):
        p = _div_before_mul_path("dfp-P")
        del p["div_before_mul_suspect"]
        self.assertFalse(PFHQ._flow_path_is_div_before_mul_suspect(p))

    def test_degraded_and_heuristic_div_before_mul_paths_excluded(self):
        self.assertFalse(PFHQ._flow_path_is_div_before_mul_suspect(
            _div_before_mul_path("dfp-P", degraded=True)))
        self.assertFalse(PFHQ._flow_path_is_div_before_mul_suspect(
            _div_before_mul_path("dfp-P", confidence="heuristic")))

    def test_div_before_mul_question_anchored_at_div_line(self):
        qs = PFHQ.gen_div_before_mul_questions([_div_before_mul_path("dfp-P")])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_class"], "precision-divide-before-multiply")
        self.assertEqual(q["question_source"], "flow-seeded-div-before-mul")
        self.assertTrue(q["div_before_mul_suspect"])
        self.assertEqual(q["dataflow_path_id"], "dfp-P")
        self.assertEqual(q["div_before_mul_div_line"], 30)
        self.assertEqual(q["div_before_mul_value_moving"], True)
        # anchor at the DIVISION file:line.
        self.assertEqual(q["file"], "src/Clean.sol:30")
        self.assertIn("divide-before-multiply", q["question"].lower())

    def test_div_before_mul_attack_class_is_canonical(self):
        # R38: the suggested class must verbatim-match the taxonomy. `rounding` is the
        # live corpus fallback; whatever resolves must be a real taxonomy class (never
        # invented). When the taxonomy is unavailable in-tree, no class is attached.
        qs = PFHQ.gen_div_before_mul_questions([_div_before_mul_path("dfp-P")])
        ac = qs[0].get("attack_class")
        if ac is not None:
            self.assertEqual(qs[0]["attack_class_provenance"],
                             "dataflow_div_before_mul_suspect")

    def test_div_before_mul_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [_div_before_mul_path("dfp-P")])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            pq = [r for r in rows
                  if r.get("question_class") == "precision-divide-before-multiply"]
            self.assertEqual(len(pq), 1, "exactly one precision question expected")
            self.assertEqual(pq[0]["dataflow_path_id"], "dfp-P")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_div_before_mul_question_when_slice_absent(self):
        # Default-off: no slice -> no precision question (byte-identical baseline).
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_class") == "precision-divide-before-multiply"
                    for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)


# ---------------------------------------------------------------------------
# 6. Inline-assembly / Yul consumer (Glider is_assembly semantics)
# ---------------------------------------------------------------------------

def _asm_path(path_id: str, *, kind: str = "delegatecall", slot=None,
              at_end: str = "source", asm_line: int = 15,
              unguarded: bool = False, degraded: bool = False,
              confidence: str = "semantic-ssa") -> dict:
    """A schema-valid DefUsePath carrying the additive asm_suspect annotation the
    closure pass (apply_closure_unguarded) stamps. Guard-independent: a Yul
    delegatecall / storage-collision lead holds whether or not the path is
    access-guarded."""
    return {
        "schema": DFS.SCHEMA_VERSION,
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither.test",
        "source": {"kind": "param-entrypoint", "fn": "Proxy.forward(bytes)",
                   "var": "data", "file": "src/Proxy.sol", "line": 12},
        "sink": {"kind": "call", "callee": "delegatecall", "arg_pos": 1,
                 "fn": "Proxy.forward(bytes)", "file": "src/Proxy.sol", "line": 15},
        "hops": [],
        "call_depth": 0,
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
        # additive asm annotation
        "asm_suspect": True,
        "asm": {"kind": kind, "slot": slot, "at_fn": "forward", "at_end": at_end,
                "line": asm_line, "snippet": "delegatecall(gas(), impl, 0, ...)"},
    }


class TestAsmSuspectConsumer(unittest.TestCase):

    def test_asm_suspect_path_is_seedable(self):
        self.assertTrue(PFHQ._flow_path_is_asm_suspect(_asm_path("dfp-Z")))

    def test_non_asm_path_not_seedable(self):
        p = _asm_path("dfp-Z")
        del p["asm_suspect"]
        self.assertFalse(PFHQ._flow_path_is_asm_suspect(p))

    def test_degraded_and_heuristic_asm_paths_excluded(self):
        self.assertFalse(PFHQ._flow_path_is_asm_suspect(
            _asm_path("dfp-Z", degraded=True)))
        self.assertFalse(PFHQ._flow_path_is_asm_suspect(
            _asm_path("dfp-Z", confidence="heuristic")))

    def test_asm_delegatecall_question_anchored_at_asm_line(self):
        qs = PFHQ.gen_asm_suspect_questions([_asm_path("dfp-Z", kind="delegatecall")])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_class"], "asm-delegatecall-backdoor")
        self.assertEqual(q["question_source"], "flow-seeded-asm")
        self.assertTrue(q["asm_suspect"])
        self.assertEqual(q["dataflow_path_id"], "dfp-Z")
        self.assertEqual(q["asm_kind"], "delegatecall")
        # anchor at the ASM block file:line (source end).
        self.assertEqual(q["file"], "src/Proxy.sol:15")
        self.assertIn("delegatecall", q["question"].lower())
        # R38 attack-class: delegatecall-to-untrusted-target IS in the corpus.
        self.assertEqual(q.get("attack_class"), "delegatecall-to-untrusted-target")
        self.assertEqual(q.get("attack_class_provenance"), "dataflow_asm_suspect")

    def test_asm_sstore_literal_question_wording(self):
        qs = PFHQ.gen_asm_suspect_questions(
            [_asm_path("dfp-Z", kind="sstore-literal", slot="0x0")])
        q = qs[0]
        self.assertEqual(q["question_class"], "asm-storage-collision")
        self.assertEqual(q["asm_kind"], "sstore-literal")
        self.assertEqual(q["asm_slot"], "0x0")
        self.assertIn("collision", q["question"].lower())
        # R38: no GENERAL storage-collision class in the corpus today -> omitted
        # (omit-not-invent), never a fabricated over-narrow class.
        self.assertIsNone(q.get("attack_class"))

    def test_asm_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [_asm_path("dfp-Z")])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            aq = [r for r in rows
                  if r.get("question_class") == "asm-delegatecall-backdoor"]
            self.assertEqual(len(aq), 1, "exactly one asm question expected")
            self.assertEqual(aq[0]["dataflow_path_id"], "dfp-Z")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_asm_question_when_slice_absent(self):
        # Default-off: no slice -> no asm question (byte-identical baseline).
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_class", "").startswith("asm-") for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)


# ---------------------------------------------------------------------------
# 7. Same-fn CEI / intra-proc reentrancy consumer (Glider gap #5 intra-CFG)
# ---------------------------------------------------------------------------

def _intra_cei_path(path_id: str, *, var: str = "balances",
                    ext_line: int = 14, write_line: int = 16,
                    at_fn: str = "withdraw", at_end: str = "source",
                    unguarded: bool = True, degraded: bool = False,
                    confidence: str = "semantic-ssa") -> dict:
    """A schema-valid DefUsePath carrying the additive intra_cei_suspect annotation
    the closure pass (apply_closure_unguarded) stamps. Guard-independent: a same-fn
    reentrancy lead holds whether or not the path is access-guarded."""
    return {
        "schema": DFS.SCHEMA_VERSION,
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither.test",
        "source": {"kind": "param-entrypoint", "fn": "Vault.withdraw()",
                   "var": "amount", "file": "src/Vault.sol", "line": 12},
        "sink": {"kind": "call", "callee": "call", "arg_pos": 0,
                 "fn": "Vault.withdraw()", "file": "src/Vault.sol", "line": 14},
        "hops": [],
        "call_depth": 0,
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
        # additive same-fn CEI annotation
        "intra_cei_suspect": True,
        "intra_cei": {"ext_call_line": ext_line, "state_write_line": write_line,
                      "var": var, "at_fn": at_fn, "at_end": at_end},
    }


class TestIntraCeiSuspectConsumer(unittest.TestCase):

    def test_intra_cei_path_is_seedable(self):
        self.assertTrue(PFHQ._flow_path_is_intra_cei_suspect(_intra_cei_path("dfp-C")))

    def test_non_intra_cei_path_not_seedable(self):
        p = _intra_cei_path("dfp-C")
        del p["intra_cei_suspect"]
        self.assertFalse(PFHQ._flow_path_is_intra_cei_suspect(p))

    def test_degraded_and_heuristic_intra_cei_paths_excluded(self):
        self.assertFalse(PFHQ._flow_path_is_intra_cei_suspect(
            _intra_cei_path("dfp-C", degraded=True)))
        self.assertFalse(PFHQ._flow_path_is_intra_cei_suspect(
            _intra_cei_path("dfp-C", confidence="heuristic")))

    def test_intra_cei_question_anchored_at_write_line(self):
        qs = PFHQ.gen_intra_cei_questions([_intra_cei_path("dfp-C")])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_class"], "same-fn-reentrancy")
        self.assertEqual(q["question_source"], "flow-seeded-intra-cei")
        self.assertTrue(q["intra_cei_suspect"])
        self.assertEqual(q["dataflow_path_id"], "dfp-C")
        self.assertEqual(q["intra_cei_var"], "balances")
        # anchor at the post-call state-write file:line.
        self.assertEqual(q["file"], "src/Vault.sol:16")
        self.assertIn("reentr", q["question"].lower())
        # R38: `external-call-reentrancy` is in the corpus today.
        self.assertEqual(q.get("attack_class"), "external-call-reentrancy")
        self.assertEqual(q.get("attack_class_provenance"),
                         "dataflow_intra_cei_suspect")

    def test_intra_cei_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [_intra_cei_path("dfp-C")])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            cq = [r for r in rows if r.get("question_class") == "same-fn-reentrancy"]
            self.assertEqual(len(cq), 1, "exactly one same-fn-reentrancy question expected")
            self.assertEqual(cq[0]["dataflow_path_id"], "dfp-C")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_intra_cei_question_when_slice_absent(self):
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_class") == "same-fn-reentrancy" for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)


# ---------------------------------------------------------------------------
# 8. Unbounded-loop gas-griefing consumer (Glider gap #5 intra-CFG)
# ---------------------------------------------------------------------------

def _unbounded_loop_path(path_id: str, *, bound_var: str = "users",
                         loop_line: int = 17, at_fn: str = "distribute",
                         at_end: str = "source", unguarded: bool = True,
                         degraded: bool = False,
                         confidence: str = "semantic-ssa") -> dict:
    """A schema-valid DefUsePath carrying the additive unbounded_loop_suspect
    annotation the closure pass (apply_closure_unguarded) stamps."""
    return {
        "schema": DFS.SCHEMA_VERSION,
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither.test",
        "source": {"kind": "param-entrypoint", "fn": "Vault.distribute()",
                   "var": "x", "file": "src/Vault.sol", "line": 15},
        "sink": {"kind": "storage-value", "callee": "reward", "arg_pos": 0,
                 "fn": "Vault.distribute()", "file": "src/Vault.sol", "line": 18},
        "hops": [],
        "call_depth": 0,
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
        # additive unbounded-loop annotation
        "unbounded_loop_suspect": True,
        "unbounded_loop": {"loop_line": loop_line, "bound_var": bound_var,
                           "at_fn": at_fn, "at_end": at_end},
    }


class TestUnboundedLoopSuspectConsumer(unittest.TestCase):

    def test_unbounded_loop_path_is_seedable(self):
        self.assertTrue(
            PFHQ._flow_path_is_unbounded_loop_suspect(_unbounded_loop_path("dfp-L")))

    def test_non_unbounded_loop_path_not_seedable(self):
        p = _unbounded_loop_path("dfp-L")
        del p["unbounded_loop_suspect"]
        self.assertFalse(PFHQ._flow_path_is_unbounded_loop_suspect(p))

    def test_degraded_and_heuristic_unbounded_loop_paths_excluded(self):
        self.assertFalse(PFHQ._flow_path_is_unbounded_loop_suspect(
            _unbounded_loop_path("dfp-L", degraded=True)))
        self.assertFalse(PFHQ._flow_path_is_unbounded_loop_suspect(
            _unbounded_loop_path("dfp-L", confidence="heuristic")))

    def test_unbounded_loop_question_anchored_at_loop_line(self):
        qs = PFHQ.gen_unbounded_loop_questions([_unbounded_loop_path("dfp-L")])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_class"], "unbounded-loop-gas")
        self.assertEqual(q["question_source"], "flow-seeded-unbounded-loop")
        self.assertTrue(q["unbounded_loop_suspect"])
        self.assertEqual(q["dataflow_path_id"], "dfp-L")
        self.assertEqual(q["unbounded_loop_bound_var"], "users")
        # anchor at the loop file:line.
        self.assertEqual(q["file"], "src/Vault.sol:17")
        self.assertIn("gas", q["question"].lower())
        # R38: `dos` is in the corpus today.
        self.assertEqual(q.get("attack_class"), "dos")
        self.assertEqual(q.get("attack_class_provenance"),
                         "dataflow_unbounded_loop_suspect")

    def test_unbounded_loop_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [_unbounded_loop_path("dfp-L")])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            lq = [r for r in rows if r.get("question_class") == "unbounded-loop-gas"]
            self.assertEqual(len(lq), 1, "exactly one unbounded-loop question expected")
            self.assertEqual(lq[0]["dataflow_path_id"], "dfp-L")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_unbounded_loop_question_when_slice_absent(self):
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_class") == "unbounded-loop-gas" for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)


def _enumset_remove_in_loop_path(path_id: str, *, collection: str = "members",
                                 loop_line: int = 52, at_line: int = 53,
                                 remove_line: int = 54, at_fn: str = "purgeAll",
                                 at_end: str = "sink", unguarded: bool = True,
                                 degraded: bool = False,
                                 confidence: str = "semantic-ssa") -> dict:
    """A schema-valid DefUsePath carrying the additive
    enumset_remove_in_loop_suspect annotation the closure pass
    (apply_closure_unguarded) stamps (Glider gap W5)."""
    return {
        "schema": DFS.SCHEMA_VERSION,
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither.test",
        "source": {"kind": "collection-mutator", "fn": "Registry.purgeAll()",
                   "var": "members", "file": "src/Registry.sol", "line": 52},
        "sink": {"kind": "collection-mutator", "callee": "remove", "arg_pos": 0,
                 "fn": "Registry.purgeAll()", "file": "src/Registry.sol",
                 "line": 54},
        "hops": [],
        "call_depth": 0,
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
        # additive enumset-remove-in-loop annotation
        "enumset_remove_in_loop_suspect": True,
        "enumset_remove_in_loop": {
            "loop_line": loop_line, "at_line": at_line, "remove_line": remove_line,
            "collection": collection, "at_fn": at_fn, "at_end": at_end,
            "severity_hint": "iteration-skip"},
    }


class TestEnumsetRemoveInLoopConsumer(unittest.TestCase):

    def test_enumset_remove_in_loop_path_is_seedable(self):
        self.assertTrue(
            PFHQ._flow_path_is_enumset_remove_in_loop_suspect(
                _enumset_remove_in_loop_path("dfp-E")))

    def test_non_enumset_remove_in_loop_path_not_seedable(self):
        p = _enumset_remove_in_loop_path("dfp-E")
        del p["enumset_remove_in_loop_suspect"]
        self.assertFalse(PFHQ._flow_path_is_enumset_remove_in_loop_suspect(p))

    def test_degraded_and_heuristic_enumset_paths_excluded(self):
        self.assertFalse(PFHQ._flow_path_is_enumset_remove_in_loop_suspect(
            _enumset_remove_in_loop_path("dfp-E", degraded=True)))
        self.assertFalse(PFHQ._flow_path_is_enumset_remove_in_loop_suspect(
            _enumset_remove_in_loop_path("dfp-E", confidence="heuristic")))

    def test_enumset_question_anchored_at_remove_line(self):
        qs = PFHQ.gen_enumset_remove_in_loop_questions(
            [_enumset_remove_in_loop_path("dfp-E")])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_class"], "enumerable-set-remove-in-loop")
        self.assertEqual(q["question_source"], "flow-seeded-enumset-remove-in-loop")
        self.assertTrue(q["enumset_remove_in_loop_suspect"])
        self.assertEqual(q["dataflow_path_id"], "dfp-E")
        self.assertEqual(q["enumset_collection"], "members")
        # anchor at the REMOVE file:line (the load-bearing mutation site).
        self.assertEqual(q["file"], "src/Registry.sol:54")
        self.assertIn("iteration-skip", q["question"].lower())
        self.assertIn("backward", q["question"].lower())
        # R38: `protocol-invariant-bypass` is in the corpus today; no `dos` mis-class.
        self.assertEqual(q.get("attack_class"), "protocol-invariant-bypass")
        self.assertEqual(q.get("attack_class_provenance"),
                         "dataflow_enumset_remove_in_loop_suspect")

    def test_enumset_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [_enumset_remove_in_loop_path("dfp-E")])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            eq = [r for r in rows
                  if r.get("question_class") == "enumerable-set-remove-in-loop"]
            self.assertEqual(len(eq), 1,
                             "exactly one enumset-remove-in-loop question expected")
            self.assertEqual(eq[0]["dataflow_path_id"], "dfp-E")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_enumset_question_when_slice_absent(self):
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_class") == "enumerable-set-remove-in-loop"
                    for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)


def _unchecked_return_path(path_id: str, *, callee: str = "transfer",
                           kind: str = "transfer", call_line: int = 15,
                           at_fn: str = "pay", at_end: str = "source",
                           unguarded: bool = True, degraded: bool = False,
                           confidence: str = "semantic-ssa") -> dict:
    """A schema-valid DefUsePath carrying the additive
    unchecked_return_value_suspect annotation the closure pass
    (apply_closure_unguarded) stamps (Glider gap W6 P1)."""
    return {
        "schema": DFS.SCHEMA_VERSION,
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither.test",
        "source": {"kind": "external-call", "fn": "Vault.pay(address,uint256)",
                   "var": "token", "file": "src/Vault.sol", "line": 15},
        "sink": {"kind": "external-call", "callee": "transfer", "arg_pos": 0,
                 "fn": "Vault.pay(address,uint256)", "file": "src/Vault.sol",
                 "line": 15},
        "hops": [],
        "call_depth": 0,
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
        # additive unchecked-return-value annotation
        "unchecked_return_value_suspect": True,
        "unchecked_return_value": {
            "call_line": call_line, "callee": callee, "kind": kind,
            "at_fn": at_fn, "at_end": at_end, "at_file": "src/Vault.sol",
            "severity_hint": "unchecked-return"},
    }


class TestUncheckedReturnConsumer(unittest.TestCase):

    def test_unchecked_return_path_is_seedable(self):
        self.assertTrue(
            PFHQ._flow_path_is_unchecked_return_value_suspect(
                _unchecked_return_path("dfp-U")))

    def test_non_unchecked_return_path_not_seedable(self):
        p = _unchecked_return_path("dfp-U")
        del p["unchecked_return_value_suspect"]
        self.assertFalse(PFHQ._flow_path_is_unchecked_return_value_suspect(p))

    def test_degraded_and_heuristic_unchecked_return_paths_excluded(self):
        self.assertFalse(PFHQ._flow_path_is_unchecked_return_value_suspect(
            _unchecked_return_path("dfp-U", degraded=True)))
        self.assertFalse(PFHQ._flow_path_is_unchecked_return_value_suspect(
            _unchecked_return_path("dfp-U", confidence="heuristic")))

    def test_unchecked_return_question_anchored_at_call_line(self):
        qs = PFHQ.gen_unchecked_return_questions(
            [_unchecked_return_path("dfp-U")])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_class"], "unchecked-return-value")
        self.assertEqual(q["question_source"], "flow-seeded-unchecked-return-value")
        self.assertTrue(q["unchecked_return_value_suspect"])
        self.assertEqual(q["dataflow_path_id"], "dfp-U")
        self.assertEqual(q["unchecked_return_callee"], "transfer")
        self.assertEqual(q["unchecked_return_kind"], "transfer")
        # anchor at the CALL file:line (the load-bearing unconsumed-return site).
        self.assertEqual(q["file"], "src/Vault.sol:15")
        self.assertIn("return", q["question"].lower())
        # R38: none of the four candidate classes exists in the corpus today, so
        # the I2 mapper returns None and NO attack_class is attached (honest).
        self.assertNotIn("attack_class", q)
        self.assertNotIn("attack_class_provenance", q)

    def test_unchecked_return_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [_unchecked_return_path("dfp-U")])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            uq = [r for r in rows
                  if r.get("question_class") == "unchecked-return-value"]
            self.assertEqual(len(uq), 1,
                             "exactly one unchecked-return-value question expected")
            self.assertEqual(uq[0]["dataflow_path_id"], "dfp-U")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_unchecked_return_question_when_slice_absent(self):
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_class") == "unchecked-return-value"
                    for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_i2_attack_class_mapper_returns_none_today(self):
        # R38 honesty: the candidate priority list is
        # [unchecked-low-level-return, unchecked-return-value,
        #  unchecked-call-return, silent-transfer-failure]; none is in the
        # corpus today, so the mapper returns None (no fabrication).
        self.assertIsNone(
            PFHQ._suggest_unchecked_return_attack_class("external-call",
                                                        "transfer"))


def _override_dropped_guard_path(path_id: str, *, contract: str = "Derived",
                                 function: str = "setConfig",
                                 base_contract: str = "Base",
                                 base_fn: str = "setConfig",
                                 dropped: str = "onlyOwner",
                                 at_file: str = "src/Derived.sol",
                                 at_line: int = 30,
                                 unguarded: bool = True,
                                 degraded: bool = False,
                                 confidence: str = "semantic-ssa") -> dict:
    """A schema-valid DefUsePath carrying the additive
    override_dropped_guard_suspect annotation the closure pass
    (apply_closure_unguarded) stamps (Glider gap W1)."""
    return {
        "schema": DFS.SCHEMA_VERSION,
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither.test",
        "source": {"kind": "param-entrypoint", "fn": "Derived.setConfig(uint256)",
                   "var": "v", "file": "src/Derived.sol", "line": 30},
        "sink": {"kind": "storage-value", "callee": "config", "arg_pos": 0,
                 "fn": "Derived.setConfig(uint256)", "file": "src/Derived.sol",
                 "line": 31},
        "hops": [],
        "call_depth": 0,
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
        # additive override-dropped-guard annotation
        "override_dropped_guard_suspect": True,
        "override_dropped_guard": {
            "contract": contract, "function": function,
            "selector": function + "(uint256)", "base_contract": base_contract,
            "base_fn": base_fn, "dropped_guard": dropped,
            "at_file": at_file, "at_line": at_line,
            "severity_hint": "access-control"},
    }


class TestOverrideDroppedGuardConsumer(unittest.TestCase):

    def test_override_dropped_guard_path_is_seedable(self):
        self.assertTrue(
            PFHQ._flow_path_is_override_dropped_guard_suspect(
                _override_dropped_guard_path("dfp-O")))

    def test_non_override_dropped_guard_path_not_seedable(self):
        p = _override_dropped_guard_path("dfp-O")
        del p["override_dropped_guard_suspect"]
        self.assertFalse(PFHQ._flow_path_is_override_dropped_guard_suspect(p))

    def test_degraded_and_heuristic_override_paths_excluded(self):
        self.assertFalse(PFHQ._flow_path_is_override_dropped_guard_suspect(
            _override_dropped_guard_path("dfp-O", degraded=True)))
        self.assertFalse(PFHQ._flow_path_is_override_dropped_guard_suspect(
            _override_dropped_guard_path("dfp-O", confidence="heuristic")))

    def test_override_dropped_guard_question_anchored_at_drop_line(self):
        qs = PFHQ.gen_override_dropped_guard_questions(
            [_override_dropped_guard_path("dfp-O")])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_class"], "override-dropped-guard")
        self.assertEqual(q["question_source"], "flow-seeded-override-dropped-guard")
        self.assertTrue(q["override_dropped_guard_suspect"])
        self.assertEqual(q["dataflow_path_id"], "dfp-O")
        self.assertEqual(q["override_dropped_guard_base_contract"], "Base")
        self.assertEqual(q["override_dropped_guard_dropped"], "onlyOwner")
        # anchor at the override declaration file:line.
        self.assertEqual(q["file"], "src/Derived.sol:30")
        self.assertIn("override", q["question"].lower())
        # R38: `access-control` is in the corpus today.
        self.assertEqual(q.get("attack_class"), "access-control")
        self.assertEqual(q.get("attack_class_provenance"),
                         "dataflow_override_dropped_guard_suspect")

    def test_override_dropped_guard_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [_override_dropped_guard_path("dfp-O")])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            oq = [r for r in rows
                  if r.get("question_class") == "override-dropped-guard"]
            self.assertEqual(len(oq), 1,
                             "exactly one override-dropped-guard question expected")
            self.assertEqual(oq[0]["dataflow_path_id"], "dfp-O")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_override_dropped_guard_question_when_slice_absent(self):
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_class") == "override-dropped-guard"
                    for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)


def _oracle_swallow_path(path_id: str, *, contract: str = "OracleSwallow",
                         function: str = "refresh",
                         oracle_callee: str = "latestrounddata",
                         at_file: str = "src/OracleSwallow.sol",
                         try_line: int = 21, catch_line: int = 29,
                         unguarded: bool = True,
                         degraded: bool = False,
                         confidence: str = "semantic-ssa") -> dict:
    """A schema-valid DefUsePath carrying the additive oracle_swallow_suspect
    annotation the closure pass (apply_closure_unguarded) stamps (Glider gap W2)."""
    return {
        "schema": DFS.SCHEMA_VERSION,
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither.test",
        "source": {"kind": "param-entrypoint",
                   "fn": "OracleSwallow.refresh(uint256)",
                   "var": "collateralValue", "file": at_file, "line": 20},
        "sink": {"kind": "storage-value", "callee": "collateralValue",
                 "arg_pos": 0, "fn": "OracleSwallow.refresh(uint256)",
                 "file": at_file, "line": 34},
        "hops": [],
        "call_depth": 0,
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
        # additive oracle try/catch-swallow annotation
        "oracle_swallow_suspect": True,
        "oracle_swallow": {
            "contract": contract, "function": function,
            "selector": function + "(uint256)", "oracle_callee": oracle_callee,
            "try_line": try_line, "catch_line": catch_line,
            "at_file": at_file, "at_line": catch_line,
            "severity_hint": "oracle"},
    }


class TestOracleSwallowConsumer(unittest.TestCase):

    def test_oracle_swallow_path_is_seedable(self):
        self.assertTrue(
            PFHQ._flow_path_is_oracle_swallow_suspect(
                _oracle_swallow_path("dfp-OS")))

    def test_non_oracle_swallow_path_not_seedable(self):
        p = _oracle_swallow_path("dfp-OS")
        del p["oracle_swallow_suspect"]
        self.assertFalse(PFHQ._flow_path_is_oracle_swallow_suspect(p))

    def test_degraded_and_heuristic_oracle_paths_excluded(self):
        self.assertFalse(PFHQ._flow_path_is_oracle_swallow_suspect(
            _oracle_swallow_path("dfp-OS", degraded=True)))
        self.assertFalse(PFHQ._flow_path_is_oracle_swallow_suspect(
            _oracle_swallow_path("dfp-OS", confidence="heuristic")))

    def test_oracle_swallow_question_anchored_at_catch_line(self):
        qs = PFHQ.gen_oracle_swallow_questions(
            [_oracle_swallow_path("dfp-OS")])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_class"], "oracle-trycatch-swallow")
        self.assertEqual(q["question_source"], "flow-seeded-oracle-swallow")
        self.assertTrue(q["oracle_swallow_suspect"])
        self.assertEqual(q["dataflow_path_id"], "dfp-OS")
        self.assertEqual(q["oracle_swallow_callee"], "latestrounddata")
        # anchor at the catch clause file:line.
        self.assertEqual(q["file"], "src/OracleSwallow.sol:29")
        self.assertIn("swallow", q["question"].lower())
        # R38: `stale-or-manipulated-oracle` is in the corpus today.
        self.assertEqual(q.get("attack_class"), "stale-or-manipulated-oracle")
        self.assertEqual(q.get("attack_class_provenance"),
                         "dataflow_oracle_swallow_suspect")

    def test_oracle_swallow_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_slice(ws, [_oracle_swallow_path("dfp-OS")])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            oq = [r for r in rows
                  if r.get("question_class") == "oracle-trycatch-swallow"]
            self.assertEqual(len(oq), 1,
                             "exactly one oracle-trycatch-swallow question expected")
            self.assertEqual(oq[0]["dataflow_path_id"], "dfp-OS")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_oracle_swallow_question_when_slice_absent(self):
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_class") == "oracle-trycatch-swallow"
                    for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)


# ---------------------------------------------------------------------------
# P3. Coupled-state co-write seed source (state_coupling_edges.jsonl)
# ---------------------------------------------------------------------------

SCS = _load("state_coupling_schema_ut", TOOLS / "state_coupling_schema.py")


def _coupling_edge(edge_id: str, *, kind: str = "conserved-with",
                   cell_a: str = "totalShares", cell_b: str = "totalAssets",
                   vfn: str = "Vault.mintShares(uint256)",
                   vfile: str = "src/Vault.sol", vline: int = 88,
                   mutates=None, omits=None,
                   confidence: str = "semantic-ssa") -> dict:
    """A schema-valid StateCouplingEdge whose single violator MUTATES cell_a but
    OMITS the coupled sibling cell_b (a partial-update desync)."""
    violator = {"fn": vfn, "file": vfile, "line": vline,
                "mutates": mutates if mutates is not None else [cell_a],
                "omits": omits if omits is not None else [cell_b]}
    return SCS.new_edge(
        edge_id=edge_id, language="solidity", kind=kind,
        cell_a=cell_a, cell_b=cell_b, writers_a=[vfn], writers_b=["Vault.deposit()"],
        violators=[violator], confidence=confidence,
    )


def _write_coupling_edges(ws: Path, edges: list[dict]) -> None:
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "state_coupling_edges.jsonl").open("w") as fh:
        for e in edges:
            fh.write(json.dumps(e) + "\n")


class TestCoupledStateSeedSource(unittest.TestCase):

    def test_violator_omitting_sibling_is_seedable(self):
        edge = _coupling_edge("sce-1")
        self.assertEqual(len(PFHQ._coupling_violators_omitting_sibling(edge)), 1)

    def test_heuristic_edge_not_seedable(self):
        edge = _coupling_edge("sce-1", confidence="heuristic")
        self.assertEqual(PFHQ._coupling_violators_omitting_sibling(edge), [])

    def test_violator_with_empty_omits_not_seedable(self):
        edge = _coupling_edge("sce-1", omits=[])
        self.assertEqual(PFHQ._coupling_violators_omitting_sibling(edge), [])

    def test_coupled_question_anchored_at_violator_line(self):
        qs = PFHQ.gen_coupled_seeded_questions([_coupling_edge("sce-1")])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_source"], "coupled-seeded")
        self.assertTrue(q["flow_seeded"])
        self.assertTrue(q["coupled_seeded"])
        self.assertEqual(q["state_coupling_edge_id"], "sce-1")
        self.assertEqual(q["coupling_cell_a"], "totalShares")
        self.assertEqual(q["coupling_cell_b"], "totalAssets")
        self.assertEqual(q["coupling_omits"], "totalAssets")
        self.assertEqual(q["function"], "Vault.mintShares(uint256)")
        # anchored at the violator's real file:line.
        self.assertEqual(q["file"], "src/Vault.sol:88")
        self.assertIn("totalAssets", q["question"])
        self.assertIn("R76", q["question"])

    def test_coupled_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_coupling_edges(ws, [_coupling_edge("sce-1")])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            cs = [r for r in rows if r.get("question_source") == "coupled-seeded"]
            self.assertEqual(len(cs), 1, "exactly one coupled-seeded question expected")
            self.assertEqual(cs[0]["state_coupling_edge_id"], "sce-1")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_coupled_question_when_sidecar_absent(self):
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_source") == "coupled-seeded" for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)


# ---------------------------------------------------------------------------
# P3. Oracle-reachability seed source (oracle_reachability_hypotheses.jsonl)
# ---------------------------------------------------------------------------

def _oracle_hyp(*, fn: str = "Pool.swap(uint256)", file_: str = "src/Pool.sol",
                read_line: int = 120, sub_class: str = "movable-spot",
                read_kind: str = "getReserves() spot price") -> dict:
    """An ORL oracle-reachability hypothesis (flat dict, verdict=needs-fuzz)."""
    return {
        "workspace": "/abs/ws",
        "file": file_,
        "function": fn,
        "language": "sol",
        "read_site": f"{file_}:{read_line}",
        "read_snippet": "(uint112 r0, uint112 r1,) = pair.getReserves();",
        "read_kind": read_kind,
        "movability_reason": "spot reserves manipulable via a flash-loan swap",
        "value_loss_path": "price drives the mint/redeem amount",
        "attack_class": "oracle-price-manipulation",
        "sub_class": sub_class,
        "source": "ORL",
        "verdict": "needs-fuzz",
    }


def _write_oracle_hyps(ws: Path, hyps: list[dict]) -> None:
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "oracle_reachability_hypotheses.jsonl").open("w") as fh:
        for h in hyps:
            fh.write(json.dumps(h) + "\n")


class TestOracleReachabilitySeedSource(unittest.TestCase):

    def test_hypothesis_with_readsite_is_seedable(self):
        self.assertTrue(PFHQ._oracle_hyp_is_seedable(_oracle_hyp()))

    def test_hypothesis_missing_readsite_not_seedable(self):
        h = _oracle_hyp()
        del h["read_site"]
        self.assertFalse(PFHQ._oracle_hyp_is_seedable(h))

    def test_oracle_question_anchored_at_read_site(self):
        qs = PFHQ.gen_oracle_seeded_questions([_oracle_hyp()])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_source"], "oracle-seeded")
        self.assertTrue(q["flow_seeded"])
        self.assertTrue(q["oracle_seeded"])
        self.assertEqual(q["question_class"], "oracle-movable-spot")
        self.assertEqual(q["function"], "Pool.swap(uint256)")
        # anchored at the real read_site file:line.
        self.assertEqual(q["file"], "src/Pool.sol:120")
        self.assertEqual(q["oracle_verdict"], "needs-fuzz")
        self.assertIn("R76", q["question"])

    def test_oracle_question_emitted_through_main(self):
        ws = Path(tempfile.mkdtemp())
        try:
            _write_oracle_hyps(ws, [_oracle_hyp()])
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            os_ = [r for r in rows if r.get("question_source") == "oracle-seeded"]
            self.assertEqual(len(os_), 1, "exactly one oracle-seeded question expected")
            self.assertEqual(os_[0]["oracle_sub_class"], "movable-spot")
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_oracle_question_when_sidecar_absent(self):
        ws = Path(tempfile.mkdtemp())
        try:
            inv = ws / "inv.jsonl"
            _write_inv(inv)
            out = ws / "q.jsonl"
            rc = PFHQ.main(["--invariants", str(inv), "--output", str(out),
                            "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertFalse(
                any(r.get("question_source") == "oracle-seeded" for r in rows))
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
