#!/usr/bin/env python3
"""A6 cache/source WRITER-SET coherence regression.

The private invariant: for a DERIVED-CACHE pair (source S, cache C), the set of
functions that write S must be a SUBSET of the set that writes C. If a function
mutates S without refreshing C (M != K by membership), a later read of C is STALE
- the general shape subsuming partial-flush + VM-loader / stored-copy desync.

Covers:
  1. PLANTED POSITIVE (aggregate-cache): a mint that bumps `shares` but forgets
     `totalShares` -> desync fires; and (affix-cache): a setter that writes `price`
     but not `cachedPrice`.
  2. GUARDED NEGATIVE: the coherent variant (every source-writer refreshes the
     cache) stays SILENT.
  3. FP-GUARD net-neutral: an ERC20-style transfer that moves value between keys of
     the source mapping does NOT change the aggregate and must NOT force a total
     write -> SILENT.
  4. FP-GUARD accumulator bucket: two co-equal accumulators cross-referenced once
     (LiquidityPool totalValueInLp/totalValueOutOfLp class) are NOT a cache pair ->
     SILENT.
  5. NON-VACUITY: neutralizing the CORE predicate `writer_set_desync` (always {})
     makes the planted positive STOP firing -> proves the test is load-bearing.
  6. NATURAL real fleet (read-only): etherfi EETH.sol is guarded -> SILENT.
  7. MUTATION-VERIFY on a mkdtemp COPY of real EETH.sol (shared WS never mutated):
     the CLEAN copy is SILENT; the MUTANT copy (drops the `totalShares += _share`
     refresh in mintShares) FIRES with desync_writers == ['mintShares'].
  8. ADVISORY-FIRST: every emitted row carries verdict == 'needs-fuzz'.
"""
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    sys.modules[name] = m
    s.loader.exec_module(m)
    return m


A6 = _load("cache_source_writer_set_coherence",
           "cache-source-writer-set-coherence.py")

_EETH = Path("/Users/wolf/audits/etherfi/src/smart-contracts/src/EETH.sol")


# ---- synthetic fixtures --------------------------------------------------
AGG_VULN = """
contract T {
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    function mintShares(address u, uint256 a) external {
        shares[u] += a;                 // writes source, NOT the total -> desync
    }
    function burnShares(address u, uint256 a) external {
        shares[u] -= a;
        totalShares -= a;
    }
}
"""

AGG_CLEAN = """
contract T {
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    function mintShares(address u, uint256 a) external {
        shares[u] += a;
        totalShares += a;
    }
    function burnShares(address u, uint256 a) external {
        shares[u] -= a;
        totalShares -= a;
    }
    function transfer(address f, address t, uint256 a) external {
        shares[f] -= a;                 // net-neutral: moves between keys
        shares[t] += a;                 // must NOT force a totalShares write
    }
}
"""

AFFIX_VULN = """
contract P {
    uint256 public price;
    uint256 public cachedPrice;
    function poke(uint256 p) external {
        price = p;
        cachedPrice = p;
    }
    function sneak(uint256 p) external {
        price = p;                      // writes source, forgets cachedPrice
    }
}
"""

# two co-equal accumulators cross-referenced once (LiquidityPool FP class)
BUCKET_CLEAN = """
contract L {
    uint128 public totalValueInLp;
    uint128 public totalValueOutOfLp;
    function rebase(uint128 tvl) external {
        totalValueInLp = tvl;
        totalValueOutOfLp = tvl - totalValueInLp;   // derived-assign lookalike
    }
    function deployOut(uint128 a) external {
        totalValueInLp -= a;            // both accumulate independently ->
        totalValueOutOfLp += a;         // NOT a cache pair
    }
    function bringIn(uint128 a) external {
        totalValueInLp += a;
        totalValueOutOfLp -= a;
    }
}
"""


def _fire(src):
    return A6.analyze_source(src, "<t>")[0]


class TestA6(unittest.TestCase):
    def test_1_aggregate_positive_fires(self):
        h = _fire(AGG_VULN)
        self.assertEqual(len(h), 1, h)
        self.assertEqual(h[0]["source"], "shares")
        self.assertEqual(h[0]["cache"], "totalShares")
        self.assertEqual(h[0]["desync_writers"], ["mintShares"])
        self.assertEqual(h[0]["pairing_mode"], "aggregate-cache")

    def test_2_affix_positive_fires(self):
        h = _fire(AFFIX_VULN)
        self.assertEqual(len(h), 1, h)
        self.assertEqual(h[0]["source"], "price")
        self.assertEqual(h[0]["cache"], "cachedPrice")
        self.assertEqual(h[0]["desync_writers"], ["sneak"])
        self.assertEqual(h[0]["pairing_mode"], "affix-cache")

    def test_3_guarded_negative_silent(self):
        # coherent aggregate + a net-neutral transfer -> no rows
        self.assertEqual(_fire(AGG_CLEAN), [])

    def test_4_accumulator_bucket_not_paired(self):
        # two co-equal accumulators must NOT be treated as a cache pair
        self.assertEqual(_fire(BUCKET_CLEAN), [])

    def test_5_advisory_first(self):
        for h in _fire(AGG_VULN) + _fire(AFFIX_VULN):
            self.assertEqual(h["verdict"], "needs-fuzz")

    def test_6_non_vacuity_core_predicate(self):
        # neutralize the CORE predicate: with no set-difference, the planted
        # positive must STOP firing (proves the assertion is load-bearing).
        orig = A6.writer_set_desync
        try:
            A6.writer_set_desync = lambda s, c: set()
            self.assertEqual(_fire(AGG_VULN), [],
                             "neutralized predicate should silence the positive")
        finally:
            A6.writer_set_desync = orig
        # restored -> fires again
        self.assertEqual(len(_fire(AGG_VULN)), 1)

    @unittest.skipUnless(_EETH.is_file(), "real etherfi fleet source absent")
    def test_7_natural_real_eeth_silent(self):
        h, _ = A6.analyze_source(_EETH.read_text(errors="ignore"), str(_EETH))
        self.assertEqual(h, [], "guarded real EETH must be silent")

    @unittest.skipUnless(_EETH.is_file(), "real etherfi fleet source absent")
    def test_8_mutation_verify_temp_copy(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            dst = tmp / "EETH.sol"
            shutil.copy(_EETH, dst)             # never mutate the shared WS file
            clean = dst.read_text()
            # CLEAN copy: silent
            self.assertEqual(A6.analyze_source(clean, str(dst))[0], [])
            # MUTANT: drop the totalShares refresh in mintShares (weaken guard)
            mut = clean.replace(
                "        shares[_user] += _share;\n        totalShares += _share;",
                "        shares[_user] += _share;",
            )
            self.assertNotEqual(mut, clean, "mutation must apply")
            dst.write_text(mut)
            h, _ = A6.analyze_source(dst.read_text(), str(dst))
            self.assertEqual(len(h), 1, h)
            self.assertEqual(h[0]["source"], "shares")
            self.assertEqual(h[0]["cache"], "totalShares")
            self.assertEqual(h[0]["desync_writers"], ["mintShares"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        # the real WS file is untouched
        self.assertEqual(
            A6.analyze_source(_EETH.read_text(errors="ignore"), str(_EETH))[0],
            [],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
