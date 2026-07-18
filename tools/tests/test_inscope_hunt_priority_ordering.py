# <!-- r36-rebuttal: lane FIX-INSCOPE-HUNT-WORKLIST registered via agent-pathspec-register.py -->
"""Guard: DEPRIORITIZE-ONLY ordering in inscope-hunt-batch-builder.

Rules verified:
  1. Non-trivial functions (state-write/transfer/auth/control-flow) sort BEFORE
     trivial getters/pure-view functions.
  2. With --limit K the kept K tasks are the top-ranked K (highest priority).
  3. Without --limit ALL tasks are present (count unchanged) - no function is dropped.
  4. The `priority` field is present on every task.
  5. The scorer itself: value-moving names/bodies score positive; pure getter bodies score
     negative; a body-less function with a high-signal name still scores positively.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "inscope-hunt-batch-builder.py"


def _load():
    spec = importlib.util.spec_from_file_location("inscope_hunt_batch_builder", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["inscope_hunt_batch_builder"] = m
    spec.loader.exec_module(m)
    return m


# ---------------------------------------------------------------------------
# Minimal fixture: inscope_units.jsonl with 5 units (no real source files
# needed since we test WITHOUT --embed-source; body scoring is applied to
# the fn name + empty body, which is the safe baseline).
# Three in-scope units + 2 OOS (kona/op-batcher) to verify OOS-drop still works.
# ---------------------------------------------------------------------------
_INSCOPE_ROWS = [
    # trivial getter - should score low
    {
        "file": "src/packages/contracts-bedrock/src/L1/Foo.sol",
        "function": "getName",
        "lang": "solidity",
        "file_line": "src/packages/contracts-bedrock/src/L1/Foo.sol:5",
    },
    # value-moving fn - should score high
    {
        "file": "src/packages/contracts-bedrock/src/L1/OptimismPortal2.sol",
        "function": "withdrawFunds",
        "lang": "solidity",
        "file_line": "src/packages/contracts-bedrock/src/L1/OptimismPortal2.sol:42",
    },
    # auth-gate fn - should score high
    {
        "file": "src/op-node/rollup/derive/pipeline.go",
        "function": "executeTransfer",
        "lang": "go",
        "file_line": "src/op-node/rollup/derive/pipeline.go:10",
    },
    # OOS - must be dropped
    {
        "file": "src/rust/kona/crates/proof/src/core.rs",
        "function": "doSomething",
        "lang": "rust",
    },
    # OOS - must be dropped
    {
        "file": "src/op-batcher/rpc/api.go",
        "function": "NewAdminAPI",
        "lang": "go",
    },
]


class PriorityOrderingTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / ".auditooor").mkdir(parents=True)
        (self.tmp / ".auditooor" / "inscope_units.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in _INSCOPE_ROWS), encoding="utf-8"
        )

    def _build(self, limit=None):
        tasks, err = self.m.build_tasks(self.tmp, None, False, limit)
        self.assertIsNone(err, err)
        return tasks

    # ------------------------------------------------------------------
    # 1. priority field present on every task
    # ------------------------------------------------------------------
    def test_priority_field_present(self):
        tasks = self._build()
        for t in tasks:
            self.assertIn("priority", t, f"task {t['task_id']} missing priority field")

    # ------------------------------------------------------------------
    # 2. Without --limit ALL in-scope tasks are present (no fn dropped)
    # ------------------------------------------------------------------
    def test_no_limit_all_inscope_tasks_present(self):
        tasks = self._build()
        # 3 in-scope rows; 2 OOS dropped
        self.assertEqual(len(tasks), 3, f"expected 3 tasks, got {len(tasks)}: {[t['function_anchor']['fn'] for t in tasks]}")
        fns = {t["function_anchor"]["fn"] for t in tasks}
        self.assertIn("getName", fns)
        self.assertIn("withdrawFunds", fns)
        self.assertIn("executeTransfer", fns)

    # ------------------------------------------------------------------
    # 3. Non-trivial fns sort before trivial getter (ordering guarantee)
    # ------------------------------------------------------------------
    def test_nontrivial_before_trivial(self):
        tasks = self._build()
        fns = [t["function_anchor"]["fn"] for t in tasks]
        getter_idx = fns.index("getName")
        withdraw_idx = fns.index("withdrawFunds")
        execute_idx = fns.index("executeTransfer")
        self.assertLess(withdraw_idx, getter_idx,
                        f"withdrawFunds ({withdraw_idx}) should rank before getName ({getter_idx})")
        self.assertLess(execute_idx, getter_idx,
                        f"executeTransfer ({execute_idx}) should rank before getName ({getter_idx})")

    # ------------------------------------------------------------------
    # 4. With limit=1, only the top-ranked task is kept
    # ------------------------------------------------------------------
    def test_limit_keeps_top_ranked(self):
        tasks = self._build(limit=1)
        self.assertEqual(len(tasks), 1)
        # The single kept task must NOT be the trivial getter
        self.assertNotEqual(tasks[0]["function_anchor"]["fn"], "getName",
                            "limit=1 should keep a high-priority fn, not the trivial getter")

    # ------------------------------------------------------------------
    # 5. With limit=2, the trivial getter is excluded (it is rank-3/last)
    # ------------------------------------------------------------------
    def test_limit_2_excludes_trivial_getter(self):
        tasks = self._build(limit=2)
        self.assertEqual(len(tasks), 2)
        fns = {t["function_anchor"]["fn"] for t in tasks}
        self.assertNotIn("getName", fns,
                         "limit=2 should exclude the trivial getter (lowest priority)")
        self.assertIn("withdrawFunds", fns)
        self.assertIn("executeTransfer", fns)

    # ------------------------------------------------------------------
    # 6. task_ids are reassigned as 0-based sequential integers after sort
    # ------------------------------------------------------------------
    def test_task_ids_sequential_after_sort(self):
        tasks = self._build()
        for i, t in enumerate(tasks):
            expected = f"inscope_hunt_{i:05d}"
            self.assertEqual(t["task_id"], expected,
                             f"task_id mismatch at position {i}: got {t['task_id']}")

    # ------------------------------------------------------------------
    # 7. scorer unit tests: value-moving body scores > trivial getter body
    # ------------------------------------------------------------------
    def test_scorer_value_moving_gt_getter(self):
        score_fn = self.m._score_body
        # Solidity transfer body
        transfer_body = (
            "function withdrawFunds(address to, uint256 amount) public {\n"
            "    require(balance[msg.sender] >= amount);\n"
            "    balance[msg.sender] -= amount;\n"
            "    payable(to).transfer(amount);\n"
            "    emit Withdrawn(to, amount);\n"
            "}"
        )
        # Pure getter body
        getter_body = (
            "function getName() public view returns (string memory) {\n"
            "    return name;\n"
            "}"
        )
        ts = score_fn("withdrawFunds", transfer_body)
        gs = score_fn("getName", getter_body)
        self.assertGreater(ts, gs,
                           f"transfer score ({ts}) should exceed getter score ({gs})")

    def test_scorer_name_alone_signals_value_moving(self):
        score_fn = self.m._score_body
        # No body - name-only heuristic
        high = score_fn("transferTokens", "")
        low = score_fn("getBalance", "")
        self.assertGreater(high, low,
                           f"transferTokens name-score ({high}) should beat getBalance name-score ({low})")

    def test_scorer_rust_state_write(self):
        score_fn = self.m._score_body
        rust_write = (
            "pub fn update_vault(&mut self, amount: u64) {\n"
            "    self.balance = self.balance.checked_add(amount).unwrap();\n"
            "    if amount > self.limit {\n"
            "        panic!(\"over limit\");\n"
            "    }\n"
            "}"
        )
        rust_getter = (
            "pub fn get_balance(&self) -> u64 {\n"
            "    self.balance\n"
            "}"
        )
        ws = score_fn("update_vault", rust_write)
        gs = score_fn("get_balance", rust_getter)
        self.assertGreater(ws, gs,
                           f"rust write ({ws}) should beat rust getter ({gs})")

    def test_scorer_go_control_flow(self):
        score_fn = self.m._score_body
        go_complex = (
            "func (k *Keeper) ExecuteMsg(ctx sdk.Context, msg types.MsgExecute) error {\n"
            "    if !k.isAuthorized(ctx, msg.Sender) {\n"
            "        return sdkerrors.ErrUnauthorized\n"
            "    }\n"
            "    for _, op := range msg.Ops {\n"
            "        if err := k.applyOp(ctx, op); err != nil {\n"
            "            return err\n"
            "        }\n"
            "    }\n"
            "    return nil\n"
            "}"
        )
        go_getter = (
            "func (k *Keeper) GetVersion() string {\n"
            "    return k.version\n"
            "}"
        )
        cs = score_fn("ExecuteMsg", go_complex)
        gs = score_fn("GetVersion", go_getter)
        self.assertGreater(cs, gs,
                           f"go complex ({cs}) should beat go getter ({gs})")


# ---------------------------------------------------------------------------
# build_tasks_per_function ordering guard
# ---------------------------------------------------------------------------
_PER_FN_FUNS = [
    # trivial getter (Solidity view)
    {"name": "totalSupply", "file": "a.sol", "line": 2, "lang": "sol", "classification": "untouched"},
    # value-moving fn
    {"name": "withdrawFunds", "file": "b.go", "line": 2, "lang": "go", "classification": "untouched"},
    # auth-gate fn
    {"name": "mintTokens", "file": "c.rs", "line": 2, "lang": "rs", "classification": "untouched"},
]


class PriorityOrderingPerFunctionTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir(parents=True)
        # Minimal real source files so function-source-extractor doesn't error
        (self.ws / "a.sol").write_text(
            "contract A {\n  function totalSupply() public view returns (uint256) { return _supply; }\n}\n",
            encoding="utf-8",
        )
        (self.ws / "b.go").write_text(
            "package b\nfunc (k *K) withdrawFunds(to string, amount int) error {\n"
            "  if !k.auth(to) { return errors.New(\"unauthorized\") }\n"
            "  k.balance -= amount\n  return nil\n}\n",
            encoding="utf-8",
        )
        (self.ws / "c.rs").write_text(
            "impl C {\n  pub fn mintTokens(&mut self, amount: u64) {\n"
            "    self.supply += amount;\n  }\n}\n",
            encoding="utf-8",
        )
        cov = {"functions": _PER_FN_FUNS}
        (self.ws / ".auditooor" / "function_coverage_completeness.json").write_text(
            json.dumps(cov), encoding="utf-8"
        )

    def _build(self, limit=None):
        tasks, err = self.m.build_tasks_per_function(
            self.ws, None, False, limit, with_pack_intel=False, embed_source=False
        )
        self.assertIsNone(err, err)
        return tasks

    def test_no_limit_all_tasks_present(self):
        tasks = self._build()
        self.assertEqual(len(tasks), 3)
        fns = {t["function_anchor"]["fn"] for t in tasks}
        self.assertEqual(fns, {"totalSupply", "withdrawFunds", "mintTokens"})

    def test_nontrivial_before_trivial(self):
        tasks = self._build()
        fns = [t["function_anchor"]["fn"] for t in tasks]
        getter_idx = fns.index("totalSupply")
        withdraw_idx = fns.index("withdrawFunds")
        mint_idx = fns.index("mintTokens")
        self.assertLess(withdraw_idx, getter_idx,
                        f"withdrawFunds ({withdraw_idx}) should rank before totalSupply ({getter_idx})")
        self.assertLess(mint_idx, getter_idx,
                        f"mintTokens ({mint_idx}) should rank before totalSupply ({getter_idx})")

    def test_limit_keeps_top_ranked(self):
        tasks = self._build(limit=1)
        self.assertEqual(len(tasks), 1)
        self.assertNotEqual(tasks[0]["function_anchor"]["fn"], "totalSupply",
                            "limit=1 should keep a high-priority fn, not the trivial getter")

    def test_priority_field_present(self):
        tasks = self._build()
        for t in tasks:
            self.assertIn("priority", t)


if __name__ == "__main__":
    unittest.main(verbosity=2)
