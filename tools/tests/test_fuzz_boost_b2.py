# <!-- r36-rebuttal: lane RW-RWBUILD-B2 registered via agent-pathspec-register.py -->
"""B2 fuzz-target priority boost regression: inscope-hunt-batch-builder.py reads
.auditooor/fuzz_targets.jsonl as an ADVISORY value-moving priority boost when
AUDITOOOR_FUZZ_BOOST=1 - value-moving fns sort earlier and carry fuzz_boosted -
and is BYTE-IDENTICAL (same ordering, no fuzz_boosted flag) when the env is unset."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "inscope-hunt-batch-builder.py"


def _load():
    spec = importlib.util.spec_from_file_location("inscope_hunt_batch_builder_b2", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["inscope_hunt_batch_builder_b2"] = m
    spec.loader.exec_module(m)
    return m


class FuzzBoostB2Test(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / ".auditooor").mkdir(parents=True)
        (self.tmp / "src").mkdir(parents=True)
        (self.tmp / "src" / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Vault {\n"
            "  function getBalance() external view returns (uint256) { return 1; }\n"
            "  function withdraw(uint256 amt) external { payable(msg.sender).transfer(amt); }\n"
            "}\n", encoding="utf-8")
        # manifest with a trivial getter (low priority) + a value-mover (withdraw).
        manifest = [
            {"file": "src/Vault.sol", "function": "getBalance", "lang": "solidity",
             "file_line": "src/Vault.sol:3", "prior_covered": False},
            {"file": "src/Vault.sol", "function": "withdraw", "lang": "solidity",
             "file_line": "src/Vault.sol:4", "prior_covered": False},
        ]
        (self.tmp / ".auditooor" / "inscope_units.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in manifest), encoding="utf-8")
        # fuzz_targets flags getBalance as a campaign-pending value-mover so the
        # boost measurably re-prioritizes a fn that scores LOW on the body heuristic.
        fuzz = [
            {"asset_basename": "Vault.sol", "asset_path": "src/Vault.sol",
             "fn_cluster": "getbalance", "functions": ["getBalance"],
             "needs_campaign": True, "verdict": "campaign-pending",
             "schema_version": "auditooor.fuzz_target_worklist.v1", "workspace": self.tmp.name},
        ]
        (self.tmp / ".auditooor" / "fuzz_targets.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in fuzz), encoding="utf-8")
        os.environ.pop("AUDITOOOR_FUZZ_BOOST", None)
        # Isolate B2 from the (default-ON) per-impact-frame expansion so the boost
        # is asserted at unit granularity (one task per fn, not one per fn x frame).
        self._prev_pif = os.environ.get("PER_IMPACT_FRAMES")
        os.environ["PER_IMPACT_FRAMES"] = "0"

    def tearDown(self):
        os.environ.pop("AUDITOOOR_FUZZ_BOOST", None)
        if self._prev_pif is None:
            os.environ.pop("PER_IMPACT_FRAMES", None)
        else:
            os.environ["PER_IMPACT_FRAMES"] = self._prev_pif

    def _run(self, out: Path):
        rc = self.m.main(["--workspace", str(self.tmp), "--out", str(out)])
        self.assertEqual(rc, 0)
        return out.read_bytes(), [json.loads(l) for l in out.read_text().splitlines() if l.strip()]

    def test_env_on_boosts_fuzz_target_fn(self):
        os.environ["AUDITOOOR_FUZZ_BOOST"] = "1"
        _, rows = self._run(self.tmp / "on.jsonl")
        boosted = [r for r in rows if r.get("fuzz_boosted")]
        self.assertEqual(len(boosted), 1)
        self.assertEqual(boosted[0]["function_anchor"]["fn"], "getBalance")

    def test_env_off_byte_identical(self):
        b1, rows = self._run(self.tmp / "off.jsonl")
        self.assertTrue(all(not r.get("fuzz_boosted") for r in rows))
        # env-off determinism / byte-stability
        b2, _ = self._run(self.tmp / "off2.jsonl")
        self.assertEqual(b1, b2)

    def test_boost_changes_ordering(self):
        # Two trivial getters (equal-low base priority); fuzz boosts ONLY getBalance,
        # so the deterministic tie-break flips and getBalance leads its sibling getter.
        (self.tmp / "src" / "Two.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Two {\n"
            "  function getBalance() external view returns (uint256) { return 1; }\n"
            "  function getName() external view returns (uint256) { return 2; }\n"
            "}\n", encoding="utf-8")
        (self.tmp / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/Two.sol", "function": "getName", "lang": "solidity",
                        "file_line": "src/Two.sol:4", "prior_covered": False}) + "\n"
            + json.dumps({"file": "src/Two.sol", "function": "getBalance", "lang": "solidity",
                          "file_line": "src/Two.sol:3", "prior_covered": False}) + "\n",
            encoding="utf-8")
        (self.tmp / ".auditooor" / "fuzz_targets.jsonl").write_text(
            json.dumps({"asset_basename": "Two.sol", "asset_path": "src/Two.sol",
                        "fn_cluster": "getbalance", "functions": ["getBalance"],
                        "needs_campaign": True, "verdict": "campaign-pending",
                        "schema_version": "auditooor.fuzz_target_worklist.v1",
                        "workspace": self.tmp.name}) + "\n", encoding="utf-8")
        _, off = self._run(self.tmp / "off.jsonl")
        off_prio = {r["function_anchor"]["fn"]: r["priority"] for r in off}
        # base priorities are equal-low for both getters
        self.assertEqual(off_prio["getBalance"], off_prio["getName"])
        os.environ["AUDITOOOR_FUZZ_BOOST"] = "1"
        _, on = self._run(self.tmp / "on.jsonl")
        on_prio = {r["function_anchor"]["fn"]: r["priority"] for r in on}
        # boosted getter now outranks its equal-base sibling and leads the sort.
        self.assertGreater(on_prio["getBalance"], on_prio["getName"])
        self.assertEqual([r["function_anchor"]["fn"] for r in on][0], "getBalance")


if __name__ == "__main__":
    unittest.main()
