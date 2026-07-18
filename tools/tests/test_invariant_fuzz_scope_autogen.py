#!/usr/bin/env python3
"""G11 regression: invariant-fuzz-completeness (the ECONOMIC-invariant / step-2c
gate) must SCOPE OUT auto-generated per-function engine-harness scaffolds under
poc-tests/<Name>-engine-harness/, while KEEPING hand-authored chimera/Recon
economic harnesses.

The auto-gen scaffolds carry templated/tautological invariants (a>=b||b>=a control
+ harness-internal totalIn/totalOut accounting); their per-fn coverage is the step-3
hunt's job + non-vacuity is verified by engine-harness-proof-check. Counting them in
the economic-invariant denominator is over-counting and would demand a full rewrite
of each scaffold. NOT a fail-open: they remain covered by step-3 + engine-harness-proof.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "invariant-fuzz-completeness.py"
_s = importlib.util.spec_from_file_location("invariant_fuzz_completeness", _T)
ifc = importlib.util.module_from_spec(_s)
sys.modules["invariant_fuzz_completeness"] = ifc
_s.loader.exec_module(ifc)

_PROP = "contract H { function invariant_x() public { assert(true); } }"


class ScopeAutogenTest(unittest.TestCase):
    def test_autogen_engine_harness_excluded(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            ah = ws / "poc-tests" / "AaveV2MigrationAdapter-engine-harness" / "test"
            ah.mkdir(parents=True)
            (ah / "X_Invariant.t.sol").write_text(_PROP, encoding="utf-8")
            ch = ws / "chimera_harnesses" / "VaultV2"
            ch.mkdir(parents=True)
            (ch / "VaultV2EconomicInvariant.t.sol").write_text(_PROP, encoding="utf-8")
            dirs = [str(d) for d in ifc._find_harness_dirs(ws)]
            self.assertTrue(any("chimera_harnesses/VaultV2" in d for d in dirs),
                            "hand-authored chimera harness must be kept")
            self.assertFalse(any("engine-harness" in d for d in dirs),
                             "auto-gen poc-tests engine-harness must be scoped out")

    def test_predicate_matches_only_autogen(self):
        self.assertTrue(ifc._is_autogen_engine_harness(
            Path("/ws/poc-tests/Foo-engine-harness/test")))
        self.assertFalse(ifc._is_autogen_engine_harness(
            Path("/ws/chimera_harnesses/VaultV2")))
        self.assertFalse(ifc._is_autogen_engine_harness(
            Path("/ws/src/vault-v2/test")))
        # a hand-authored harness that merely lives under test/ is NOT excluded
        self.assertFalse(ifc._is_autogen_engine_harness(Path("/ws/test")))


if __name__ == "__main__":
    unittest.main()


class AuditedProjectTestScopeTest(unittest.TestCase):
    """NUVA 2026-06-30: the audited project's OWN test suite (a test/ dir nested
    under an in-scope src repo, e.g. src/nuva-evm-contracts/test) is OOS test infra,
    NOT one of OUR mutation-verified audit harnesses. It must be scoped out of the
    harness-obligation set; OUR chimera harness (outside src/) must still be kept."""

    def test_audited_project_test_dir_excluded_chimera_kept(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            proj = ws / "src" / "nuva-evm-contracts" / "test"
            proj.mkdir(parents=True)
            (proj / "CrossChainManagerProps.sol").write_text(_PROP, encoding="utf-8")
            ch = ws / "chimera_harnesses" / "NuvaVault" / "test"
            ch.mkdir(parents=True)
            (ch / "NuvaVault_Invariant.t.sol").write_text(_PROP, encoding="utf-8")
            dirs = [str(d) for d in ifc._find_harness_dirs(ws)]
            self.assertFalse(any("src/nuva-evm-contracts/test" in d for d in dirs),
                             "audited project's own test/ must be scoped out")
            self.assertTrue(any("chimera_harnesses/NuvaVault" in d for d in dirs),
                            "our chimera harness must be kept")

    def test_predicate_distinguishes_project_test_from_chimera(self):
        self.assertTrue(ifc._is_audited_project_test_dir(Path("src/nuva-evm-contracts/test")))
        self.assertTrue(ifc._is_audited_project_test_dir(Path("src/vault/keeper/tests")))
        self.assertFalse(ifc._is_audited_project_test_dir(Path("chimera_harnesses/NuvaVault/test")))
        self.assertFalse(ifc._is_audited_project_test_dir(Path("test")))
