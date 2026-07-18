"""Tests for the mutation-testing-artifact predicate in
tools/lib/scope_exclusion.py (is_mutation_artifact + its fold into is_oos /
is_oos_dir).

A seeded differential mutant (e.g. ``SSVClustersMutantA.sol`` with a header
``// MUTANT-A: Drop balance-sufficiency guard``) is a deliberately-BROKEN copy
used only for fuzz-harness non-vacuity verification - never an in-scope
production surface. Before this predicate existed in the SHARED module, only
workspace-coverage-heatmap.py excluded it; the ~25 other consumers of is_oos
(incl. FCC) counted the mutant's functions as in-scope, inflating denominators
with permanently-hollow rows (the SSV 7-hollow false-red).

These prove (mechanically, additively):
  1. is_mutation_artifact True for a ``*Mutant*.sol`` basename.
  2. is_mutation_artifact True for a MUTANT-header file (filename-clean).
  3. is_mutation_artifact False for real in-scope source (SSVClusters.sol /
     OperatorLib.sol).
  4. is_oos / is_oos_dir now return True for a mutant artifact (the fold).
  5. Fail-open: a pathological input never raises.
"""
from __future__ import annotations

import unittest

from tools.lib import scope_exclusion as se


_MUTANT_HEADER = "// MUTANT-A: Drop balance-sufficiency guard\npragma solidity ^0.8.0;\n"


class MutationArtifactPredicate(unittest.TestCase):
    def test_filename_mutant_is_artifact(self):
        # Real fixture shape from the SSV non-vacuity campaign.
        self.assertTrue(se.is_mutation_artifact("contracts/modules/SSVClustersMutantA.sol"))
        self.assertTrue(se.is_mutation_artifact("SSVEBAccountingMutantB.sol"))
        self.assertTrue(se.is_mutation_artifact("src/Mutant.sol"))
        # Lower-case variant.
        self.assertTrue(se.is_mutation_artifact("src/clustersMutant3.sol"))

    def test_header_mutant_is_artifact(self):
        # Un-conventionally named mutant - basename is clean, header is not.
        self.assertTrue(
            se.is_mutation_artifact("contracts/SSVClusters_seeded.sol", head=_MUTANT_HEADER))
        self.assertTrue(
            se.is_mutation_artifact(
                "src/Foo.sol", head="// this is a mutation-testing artifact, do not deploy"))

    def test_real_source_is_not_artifact(self):
        self.assertFalse(se.is_mutation_artifact("contracts/modules/SSVClusters.sol"))
        self.assertFalse(se.is_mutation_artifact("contracts/libraries/OperatorLib.sol"))
        # Clean source + clean head must not fire.
        self.assertFalse(
            se.is_mutation_artifact(
                "contracts/modules/SSVClusters.sol",
                head="// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n"))

    def test_is_oos_folds_mutation_artifact(self):
        # The whole point: shared is_oos now drops a seeded mutant so FCC and the
        # other ~25 consumers inherit the exclusion.
        self.assertTrue(se.is_oos("contracts/modules/SSVClustersMutantA.sol"))
        self.assertTrue(
            se.is_oos("contracts/SSVClusters_seeded.sol", head=_MUTANT_HEADER))
        # Negative control: real source stays in scope.
        self.assertFalse(se.is_oos("contracts/modules/SSVClusters.sol"))

    def test_is_oos_dir_folds_mutation_artifact(self):
        self.assertTrue(se.is_oos_dir("contracts/modules/SSVClustersMutantA.sol"))
        self.assertTrue(
            se.is_oos_dir("contracts/SSVClusters_seeded.sol", head=_MUTANT_HEADER))
        self.assertFalse(se.is_oos_dir("contracts/modules/SSVClusters.sol"))

    def test_fail_open_on_bad_input(self):
        # Must never raise; a non-mutant / pathological value returns False.
        self.assertFalse(se.is_mutation_artifact(None))  # type: ignore[arg-type]
        self.assertFalse(se.is_mutation_artifact(""))


if __name__ == "__main__":
    unittest.main()
