#!/usr/bin/env python3
"""permanent-freeze-dos reasoner - regression + non-vacuity tests.

Pins tools/permanent-freeze-dos.py: the dominance + no-sibling-bypass closure
query over fund-EXIT functions.
  SURVIVORS = { exit fn F : exists R in revert/loop nodes of closure(F) with
                  attacker_influenced(R) AND dominates_release(R,F)
                  AND NOT has_sibling_recovery(F) }

Matrix (self-contained Solidity/Go string fixtures, no external toolchain):
  - growable-loop withdraw (Sol)    -> 1 survivor (attacker .push grows the array
                                        iterated in the exit loop; dominates the
                                        transfer; no admin bypass).
  - bounded-constant loop            -> 0 survivors (bound not attacker-growable).
  - revert-before-no-release          -> influence proven but release happens BEFORE
                                        R -> dropped by the dominance filter.
  - Go queue append DoS               -> 1 survivor (append-growable range loop before
                                        SendCoins release).

Non-vacuity mutation pair (the REQUIRED test):
  (1) add an admin force-exit SIBLING that releases without R -> the survivor
      DISAPPEARS (has_sibling_recovery filter).
  (2) make the revert/loop node UNREACHABLE (drop the internal call edge) -> the
      survivor DISAPPEARS (forward-closure reachability filter).
"""
from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "permanent_freeze_dos", TOOLS / "permanent-freeze-dos.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PFD = _load_tool()


def _run_on(files: dict):
    """Write the given {relpath: content} into a temp workspace/src and run the
    reasoner, returning the summary dict."""
    with tempfile.TemporaryDirectory() as td:
        ws = pathlib.Path(td)
        src = ws / "src"
        src.mkdir(parents=True)
        for rel, content in files.items():
            p = src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return PFD.run(["--workspace", str(ws), "--json"])


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
GROWABLE_LOOP_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address[] public queue;
    mapping(address => uint256) public bal;

    function enqueue(address u) external {
        queue.push(u);            // attacker-reachable grow site
    }

    function withdraw() external {
        for (uint256 i = 0; i < queue.length; i++) {
            address u = queue[i];
            payable(u).transfer(bal[u]);   // release dominated by the unbounded loop
        }
    }
}
"""

BOUNDED_CONST_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Fixed {
    mapping(address => uint256) public bal;
    function withdraw() external {
        for (uint256 i = 0; i < 8; i++) {
            payable(msg.sender).transfer(bal[msg.sender] / 8);
        }
    }
}
"""

RELEASE_BEFORE_REVERT_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Early {
    address[] public list;
    mapping(address => uint256) public bal;
    function push(address u) external { list.push(u); }
    function withdraw() external {
        payable(msg.sender).transfer(bal[msg.sender]);   // release FIRST
        for (uint256 i = 0; i < list.length; i++) {      // loop AFTER release
            bal[list[i]] = 0;
        }
    }
}
"""

GO_QUEUE_SOL_UNUSED = None

GO_QUEUE = """package keeper

type Keeper struct{}

func (k Keeper) Enqueue(u string) {
    k.pending = append(k.pending, u)   // attacker-reachable grow site
}

func (k Keeper) Withdraw(ctx Context) error {
    for _, u := range k.pending {      // unbounded range before the release
        if err := k.bankSendCoins(ctx, u); err != nil {
            return err
        }
    }
    return nil
}

func (k Keeper) bankSendCoins(ctx Context, u string) error {
    return k.bank.SendCoins(ctx, u)    // value release
}
"""


class TestPermanentFreezeDos(unittest.TestCase):

    def test_growable_loop_survivor(self):
        s = _run_on({"Vault.sol": GROWABLE_LOOP_SOL})
        self.assertGreaterEqual(s["n_exit_fns"], 1)
        self.assertEqual(s["n_survivors"], 1, s["survivors"])
        surv = s["survivors"][0]
        self.assertEqual(surv["dos_kind"], "loop")
        self.assertIn(surv["influence"],
                      ("growable-collection", "revert-on-receive-in-loop"))
        self.assertTrue(surv["exit_fn"].endswith(".withdraw"))
        self.assertFalse(s["substrate_vacuous"])

    def test_bounded_constant_no_survivor(self):
        s = _run_on({"Fixed.sol": BOUNDED_CONST_SOL})
        self.assertGreaterEqual(s["n_exit_fns"], 1)
        self.assertEqual(s["n_survivors"], 0)
        # cited-empty with an influence-unproven witness (the constant-bound loop).
        self.assertTrue(s["cited_empty"])
        self.assertGreaterEqual(s["n_kept_influence_unproven"], 1)

    def test_release_before_node_dropped_by_dominance(self):
        s = _run_on({"Early.sol": RELEASE_BEFORE_REVERT_SOL})
        self.assertEqual(s["n_survivors"], 0, s["survivors"])
        self.assertGreaterEqual(s["n_kept_not_dominating"], 1)
        reasons = {r["kept_reason"] for r in s["kept_not_dominating_sample"]}
        self.assertIn("release-before-node", reasons)

    def test_go_queue_append_survivor(self):
        s = _run_on({"keeper.go": GO_QUEUE})
        self.assertGreaterEqual(s["n_exit_fns"], 1)
        self.assertEqual(s["n_survivors"], 1, s["survivors"])
        self.assertEqual(s["survivors"][0]["dos_kind"], "loop")
        self.assertEqual(s["survivors"][0]["lang"], "go")

    def test_substrate_vacuous_when_no_exit_fn(self):
        no_exit = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract C { function ping() external returns (uint256) { return 1; } }
"""
        s = _run_on({"C.sol": no_exit})
        self.assertEqual(s["n_exit_fns"], 0)
        self.assertTrue(s["substrate_vacuous"])
        self.assertFalse(s["cited_empty"])

    # -------- non-vacuity mutation pair (REQUIRED) --------
    def test_mutate_add_admin_sibling_kills_survivor(self):
        """Add an admin force-exit sibling that releases WITHOUT the loop -> the
        survivor must disappear (has_sibling_recovery filter is load-bearing)."""
        base = _run_on({"Vault.sol": GROWABLE_LOOP_SOL})
        self.assertEqual(base["n_survivors"], 1)

        mutated = GROWABLE_LOOP_SOL.replace(
            "    function withdraw() external {",
            "    function emergencyWithdraw(address u) external onlyOwner {\n"
            "        payable(u).transfer(bal[u]);   // alternate exit, no loop\n"
            "    }\n\n"
            "    function withdraw() external {")
        mut = _run_on({"Vault.sol": mutated})
        self.assertEqual(mut["n_survivors"], 0,
                         "admin sibling should make the freeze recoverable")
        self.assertGreaterEqual(mut["n_kept_sibling_recovery"], 1)

    def test_mutate_unreachable_node_kills_survivor(self):
        """Move the unbounded loop into a helper and DROP the call edge from the exit
        fn -> the node is no longer in the forward closure -> survivor disappears
        (reachability filter is load-bearing). Control: WITH the call edge it is a
        survivor again."""
        # helper holds the loop; exit fn does NOT call it -> unreachable node.
        unreached = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract V {
    address[] public queue;
    mapping(address => uint256) public bal;
    function enqueue(address u) external { queue.push(u); }
    function _drain() internal {
        for (uint256 i = 0; i < queue.length; i++) {
            payable(queue[i]).transfer(bal[queue[i]]);
        }
    }
    function withdraw() external {
        payable(msg.sender).transfer(bal[msg.sender]);   // no call to _drain
    }
}
"""
        s0 = _run_on({"V.sol": unreached})
        self.assertEqual(s0["n_survivors"], 0,
                         "unreachable loop node must not be a survivor")

        # control: same code but the exit fn DOES call the helper -> reachable again.
        reached = unreached.replace(
            "        payable(msg.sender).transfer(bal[msg.sender]);   // no call to _drain",
            "        _drain();")
        s1 = _run_on({"V.sol": reached})
        self.assertEqual(s1["n_survivors"], 1,
                         "with the call edge the loop node is reachable -> survivor")


if __name__ == "__main__":
    unittest.main(verbosity=2)
