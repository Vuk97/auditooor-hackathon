#!/usr/bin/env python3
"""Regression tests for sol_ast_unbounded_attacker_growable_iteration - the EVM
permanent-freeze / loop-DoS detector (SSV operator/validator/cluster registration
class). Positive: an unbounded loop over an attacker-pushable array on the withdraw
path. Negatives: a capped loop, and an owner-only grow path (both must stay clean)."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "detectors" / \
    "sol_ast_unbounded_attacker_growable_iteration.py"
_spec = importlib.util.spec_from_file_location("sougi", _TOOL)
sougi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sougi)


def _tree(files: dict[str, str]) -> str:
    d = Path(tempfile.mkdtemp(prefix="sougi_"))
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return str(d)


# ---------------------------------------------------------------------------
# POSITIVE: SSV-style. Anyone can registerOperator() -> operators.push(...); the
# withdrawAll() exit path loops over operators.length with NO cap -> an attacker
# inflates `operators` and the withdraw reverts out-of-gas = PERMANENT FREEZE.
POS_ARRAY = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Registry {
    address[] public operators;
    mapping(address => uint256) public balance;

    // unprivileged grow: anyone can register (no onlyOwner / msg.sender check)
    function registerOperator(address op) external {
        operators.push(op);
    }

    // unbounded read on the EXIT path -> permanent freeze
    function withdrawAll() external {
        uint256 total = 0;
        for (uint256 i = 0; i < operators.length; i++) {
            total += balance[operators[i]];
        }
        payable(msg.sender).transfer(total);
    }
}
"""

# POSITIVE variant: OpenZeppelin EnumerableSet grown by an unprivileged fn and
# walked via .length()/.at(i) on a claim path.
POS_SET = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
contract Validators {
    using EnumerableSet for EnumerableSet.AddressSet;
    EnumerableSet.AddressSet private validators;

    function joinValidator() external {
        validators.add(msg.sender);
    }

    function claimRewards() external {
        for (uint256 i = 0; i < validators.length(); i++) {
            address v = validators.at(i);
            _payout(v);
        }
    }
    function _payout(address v) internal {}
}
"""


# ---------------------------------------------------------------------------
# NEGATIVE 1: CAPPED loop. Same attacker-growable array, but the withdraw loop is
# bounded by a MAX_BATCH cap -> NOT a freeze vector.
NEG_CAPPED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract RegistryCapped {
    address[] public cappedOps;
    uint256 constant MAX_BATCH = 100;

    function registerOperator(address op) external {
        cappedOps.push(op);
    }

    function withdrawBatch() external {
        uint256 len = cappedOps.length;
        uint256 bound = len < MAX_BATCH ? len : MAX_BATCH;
        for (uint256 i = 0; i < bound; i++) {
            // bounded iteration, cannot be griefed
        }
    }
}
"""

# NEGATIVE 2: OWNER-ONLY grow. The loop is unbounded, but only the owner can grow
# `operators`, so an unprivileged attacker cannot inflate it -> not attacker-growable.
NEG_OWNER_GROW = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract RegistryOwner {
    address[] public ownerOps;
    address owner;
    modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

    function registerOperator(address op) external onlyOwner {
        ownerOps.push(op);
    }

    function withdrawAll() external {
        uint256 total = 0;
        for (uint256 i = 0; i < ownerOps.length; i++) {
            total += i;
        }
    }
}
"""

# NEGATIVE 3: grow gated by an in-body require(msg.sender == owner) (no modifier).
NEG_REQUIRE_GROW = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract RegistryRequire {
    address[] public reqOps;
    address admin;

    function registerOperator(address op) external {
        require(msg.sender == admin, "not admin");
        reqOps.push(op);
    }

    function sweep() external {
        for (uint256 i = 0; i < reqOps.length; i++) {
            reqOps[i];
        }
    }
}
"""

# NEGATIVE 4: unbounded loop but the collection is NEVER grown by any fn (e.g.
# fixed-size or set once in constructor) -> no attacker-growable join.
NEG_NO_GROW = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract RegistryStatic {
    address[] public staticOps;

    function process() external {
        for (uint256 i = 0; i < staticOps.length; i++) {
            staticOps[i];
        }
    }
}
"""


class SolUnboundedAttackerGrowableTest(unittest.TestCase):
    def test_fires_on_array_push_withdraw_freeze(self):
        root = _tree({"src/Registry.sol": POS_ARRAY})
        rep = sougi.scan_root(root)
        fns = {f["function"] for f in rep["findings"]}
        self.assertIn("withdrawAll", fns, "must flag the uncapped withdraw loop")
        f = next(x for x in rep["findings"] if x["function"] == "withdrawAll")
        self.assertEqual(f["collection"], "operators")
        self.assertIn("registerOperator", f["grown_by"])
        self.assertTrue(f["on_exit_path"], "withdraw path -> permanent freeze")
        self.assertEqual(f["severity_hint"], "high")
        self.assertEqual(f["schema"], sougi.SCHEMA)

    def test_fires_on_enumerable_set_claim(self):
        root = _tree({"src/Validators.sol": POS_SET})
        rep = sougi.scan_root(root)
        fns = {f["function"] for f in rep["findings"]}
        self.assertIn("claimRewards", fns,
                      "must flag the EnumerableSet .length()/.at loop grown by joinValidator")
        f = next(x for x in rep["findings"] if x["function"] == "claimRewards")
        self.assertEqual(f["collection"], "validators")
        self.assertIn("joinValidator", f["grown_by"])

    def test_capped_loop_clean(self):
        root = _tree({"src/RegistryCapped.sol": NEG_CAPPED})
        rep = sougi.scan_root(root)
        self.assertEqual(rep["finding_count"], 0,
                         "MAX_BATCH-bounded loop must not be flagged")

    def test_owner_only_grow_clean(self):
        root = _tree({"src/RegistryOwner.sol": NEG_OWNER_GROW})
        rep = sougi.scan_root(root)
        self.assertEqual(rep["finding_count"], 0,
                         "owner-only grow is not attacker-growable")

    def test_require_sender_grow_clean(self):
        root = _tree({"src/RegistryRequire.sol": NEG_REQUIRE_GROW})
        rep = sougi.scan_root(root)
        self.assertEqual(rep["finding_count"], 0,
                         "require(msg.sender==admin) grow is not attacker-growable")

    def test_never_grown_collection_clean(self):
        root = _tree({"src/RegistryStatic.sol": NEG_NO_GROW})
        rep = sougi.scan_root(root)
        self.assertEqual(rep["finding_count"], 0,
                         "a collection never grown by any fn has no attacker-growable join")

    def test_all_negatives_together_clean(self):
        # cross-file: the grow and the loop can live in different files; ensure
        # the negatives stay clean even when scanned as one tree.
        root = _tree({
            "src/A.sol": NEG_CAPPED,
            "src/B.sol": NEG_OWNER_GROW,
            "src/C.sol": NEG_REQUIRE_GROW,
            "src/D.sol": NEG_NO_GROW,
        })
        rep = sougi.scan_root(root)
        self.assertEqual(rep["finding_count"], 0)

    def test_schema_shape_complete(self):
        root = _tree({"src/Registry.sol": POS_ARRAY})
        rep = sougi.scan_root(root)
        self.assertGreaterEqual(rep["finding_count"], 1)
        for f in rep["findings"]:
            for key in ("schema", "mechanism", "impact", "severity_hint", "file",
                        "line", "function", "reason", "source_record_id"):
                self.assertIn(key, f, f"finding missing required key {key}")
            self.assertIn(f["severity_hint"], ("critical", "high", "medium"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
