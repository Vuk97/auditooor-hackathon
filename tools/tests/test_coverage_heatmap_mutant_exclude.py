#!/usr/bin/env python3
"""Guard: the coverage in-scope enumeration excludes mutation-test artifact
contracts (*Mutant*.sol + // MUTANT header) so a seeded-mutant left in
contracts/ does not inflate the denominator with permanently-hollow rows
(the SSV 7-hollow false-red on function-coverage / hollow gates)."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "workspace_coverage_heatmap", str(_TOOLS / "workspace-coverage-heatmap.py"))
wch = importlib.util.module_from_spec(_spec)
sys.modules["workspace_coverage_heatmap"] = wch
_spec.loader.exec_module(wch)


class TestMutantExclude(unittest.TestCase):
    def test_filename_pattern_matches_mutant(self):
        rx = wch._COVERAGE_FILE_EXCLUDE_BY_EXT[".sol"]
        self.assertTrue(rx.search("SSVClustersMutantA.sol"))
        self.assertTrue(rx.search("SSVEBAccountingMutantB.sol"))
        self.assertTrue(rx.search("Foo.t.sol"))
        # a real production contract must NOT match
        self.assertFalse(rx.search("SSVClusters.sol"))
        self.assertFalse(rx.search("OperatorLib.sol"))

    def test_mutation_header_marker(self):
        self.assertTrue(wch._MUTATION_ARTIFACT_HEADER_RE.search(
            "// MUTANT-A: Drop balance-sufficiency guard in withdraw"))
        self.assertFalse(wch._MUTATION_ARTIFACT_HEADER_RE.search(
            "// SPDX-License-Identifier: MIT"))

    def test_inscope_walk_drops_mutant_contract(self):
        ws = Path(tempfile.mkdtemp())
        mods = ws / "src" / "contracts" / "modules"
        mods.mkdir(parents=True)
        (ws / "src" / "foundry.toml").write_text("[profile.default]\n")
        (mods / "SSVClusters.sol").write_text(
            "// SPDX\ncontract SSVClusters { function deposit() public {} }\n")
        (mods / "SSVClustersMutantA.sol").write_text(
            "// MUTANT-A: Drop guard\ncontract SSVClustersMutantA { function withdraw() public {} }\n")
        rows = wch.build_inscope_manifest_rows(ws)
        files = {r.get("file", "") for r in rows}
        self.assertTrue(any("SSVClusters.sol" in f and "Mutant" not in f for f in files),
                        f"production contract should be in-scope: {files}")
        self.assertFalse(any("MutantA" in f for f in files),
                         f"mutant artifact must be excluded: {files}")


if __name__ == "__main__":
    unittest.main()
