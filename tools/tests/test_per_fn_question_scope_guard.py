"""Tests for the FINAL emit-time scope guard in
tools/per-function-hacker-questions.py (_scope_exclusion_skip + its fold into
main()'s invariant emit loop).

WHY: the per-fn question producer emits one record set per ``--invariants`` row.
If the upstream invariant generator absorbed the audit's OWN ``*Mutant*.sol``
mutation artifacts (they live in-tree under contracts/modules/), those leaked
into the scoped hunt plan and the orchestrator spent real Agent budget hunting
an intentionally-unsafe contract (observed on SSV: 4 SSVClustersMutantA rows
reached the n40 plan; one batch hunted the deliberate unchecked-underflow
``withdraw``). This guard reuses the canonical tools/lib/scope_exclusion predicate
as a last chokepoint so the leak is closed regardless of the upstream enumerator.

These prove (mechanically, additively):
  1. _scope_exclusion_skip True for a ``*Mutant*.sol`` basename + a test file.
  2. _scope_exclusion_skip False for real in-scope source and for empty/"?".
  3. main() drops a mutant invariant row but keeps the real one.
  4. AUDITOOOR_PERFN_Q_NO_SCOPE_FILTER=1 restores byte-identical legacy output
     (both rows emit questions).
  5. Fail-open: a pathological path never raises.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "per-function-hacker-questions.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("per_fn_hacker_q", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


class TestPerFnQuestionScopeGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()
        # Ensure the env override is clear for the default-on tests.
        os.environ.pop("AUDITOOOR_PERFN_Q_NO_SCOPE_FILTER", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_PERFN_Q_NO_SCOPE_FILTER", None)

    def test_predicate_skips_nonprod(self):
        skip = self.mod._scope_exclusion_skip
        self.assertTrue(skip("src/ssv-network/contracts/modules/SSVClustersMutantA.sol"))
        self.assertTrue(skip("contracts/test/MockToken.sol"))
        self.assertTrue(skip("test/Foo.t.sol"))

    def test_predicate_keeps_real_and_empty(self):
        skip = self.mod._scope_exclusion_skip
        self.assertFalse(skip("src/ssv-network/contracts/modules/SSVClusters.sol"))
        self.assertFalse(skip("src/Vault.sol"))
        self.assertFalse(skip("?"))
        self.assertFalse(skip(""))

    def test_predicate_fail_open_on_pathological(self):
        # Must never raise, regardless of input.
        for bad in (None, 123, "\x00", "a" * 5000):
            try:
                self.mod._scope_exclusion_skip(bad)  # type: ignore
            except Exception as exc:  # pragma: no cover
                self.fail(f"_scope_exclusion_skip raised on {bad!r}: {exc}")

    def _run_main(self, env_off: bool):
        with tempfile.TemporaryDirectory() as td:
            inv = Path(td) / "inv.jsonl"
            out = Path(td) / "q.jsonl"
            inv.write_text(
                json.dumps({
                    "function": "withdraw",
                    "file": "src/ssv-network/contracts/modules/SSVClustersMutantA.sol",
                    "language": "solidity",
                    "invariant_candidates": ["balance-conservation"],
                }) + "\n" +
                json.dumps({
                    "function": "withdraw",
                    "file": "src/ssv-network/contracts/modules/SSVClusters.sol",
                    "language": "solidity",
                    "invariant_candidates": ["balance-conservation"],
                }) + "\n",
                encoding="utf-8",
            )
            if env_off:
                os.environ["AUDITOOOR_PERFN_Q_NO_SCOPE_FILTER"] = "1"
            else:
                os.environ.pop("AUDITOOOR_PERFN_Q_NO_SCOPE_FILTER", None)
            rc = self.mod.main(["--invariants", str(inv), "--output", str(out)])
            self.assertEqual(rc, 0)
            files = {json.loads(l)["file"] for l in out.read_text().splitlines() if l.strip()}
            return files

    def test_main_drops_mutant_by_default(self):
        files = self._run_main(env_off=False)
        self.assertIn("src/ssv-network/contracts/modules/SSVClusters.sol", files)
        self.assertNotIn(
            "src/ssv-network/contracts/modules/SSVClustersMutantA.sol", files,
            "mutation artifact leaked into per-fn questions despite scope guard",
        )

    def test_main_env_off_is_legacy(self):
        files = self._run_main(env_off=True)
        self.assertIn("src/ssv-network/contracts/modules/SSVClusters.sol", files)
        self.assertIn(
            "src/ssv-network/contracts/modules/SSVClustersMutantA.sol", files,
            "AUDITOOOR_PERFN_Q_NO_SCOPE_FILTER=1 must restore legacy (no filter)",
        )


if __name__ == "__main__":
    unittest.main()
