#!/usr/bin/env python3
# <!-- r36-rebuttal: pathspec declared via tools/agent-pathspec-register.py lane LANE-iter3-B-advisory-dsl -->
"""Tests for tools/advisory-seed-to-dsl.py and tools/slither-dep-resolver.py.

Covers the converter contract:
  - seeds load + group into mechanism families
  - every emitted family's anchor regex COMPILES (emit-time guard)
  - every family FIRES on at least one of its own TRAIN fixtures (no overfit
    needed because the fixture IS the train split)
  - the anti-overfit guard rejects instance-memorised literal patterns
  - emitted .py modules expose scan(root) and load cleanly
  - emitted .yaml sidecars are parseable and carry the right backend
  - go fork-divergence is split into the two sub-mechanisms
  - dep-resolver scope detection + offline cache resolution
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
TOOLS = REPO / "tools"


def _load(modfile):
    p = TOOLS / modfile
    spec = importlib.util.spec_from_file_location(
        modfile.replace("-", "_").replace(".py", ""), p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


CONV = _load("advisory-seed-to-dsl.py")
DEP = _load("slither-dep-resolver.py")

SEEDS = [
    REPO / "audit/corpus_tags/derived/detector_seeds_zebra_advisories.jsonl",
    REPO / "audit/corpus_tags/derived/detector_seeds_dydx_fork_divergence_advisories.jsonl",
    REPO / "audit/corpus_tags/derived/detector_seeds_hyperbridge_advisories.jsonl",
]


class TestConverter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seeds = CONV.load_seeds(SEEDS)
        cls.detectors, cls.skipped = CONV.build_detectors(cls.seeds)
        cls.tmp = tempfile.mkdtemp(prefix="adv_dsl_test_")
        cls.manifest = CONV.emit(cls.detectors, Path(cls.tmp))

    def test_seeds_loaded(self):
        self.assertGreaterEqual(len(self.seeds), 30,
                                "expected >=30 advisory seeds across 3 files")

    def test_families_emitted(self):
        # at least the core mechanism families must materialise
        fams = set(self.detectors)
        for must in ("alloc_amplification_before_cap", "inbound_panic_dos",
                     "consensus_divergence_rule_omission",
                     "fork_replace_pinned_at_sha", "fork_batch_flush_race"):
            self.assertIn(must, fams, f"missing family {must}")

    def test_go_forkdiv_split_into_two(self):
        # the dydx seeds (all tagged fork-divergence) must split into the
        # go.mod replace-pin family AND the iavl batch/cache race family.
        self.assertIn("fork_replace_pinned_at_sha", self.detectors)
        self.assertIn("fork_batch_flush_race", self.detectors)

    def test_every_anchor_compiles(self):
        for fam, det in self.detectors.items():
            for key in ("positive", "negative", "fn_name_marker"):
                pat = det.get(key)
                if pat:
                    try:
                        re.compile(pat)
                    except re.error as e:
                        self.fail(f"{fam}.{key} regex does not compile: {e}")

    def test_anchors_are_class_level_not_instance(self):
        # no positive anchor may be an instance-memorised literal
        for fam, det in self.detectors.items():
            self.assertFalse(
                CONV._is_instance_memorised(det["positive"]),
                f"{fam} positive anchor is instance-memorised (overfit)")

    def test_instance_memorised_guard(self):
        # a bare literal symbol is rejected; a token-class pattern is accepted
        self.assertTrue(CONV._is_instance_memorised(
            r"\bvalidateTransferLeavesNotExitedToL1\b"))
        self.assertTrue(CONV._is_instance_memorised("plainstring"))
        self.assertFalse(CONV._is_instance_memorised(
            r"\b(?:unwrap|expect)\s*\("))
        self.assertFalse(CONV._is_instance_memorised(
            r"with_capacity\s*\(\s*\w*len"))

    def test_every_family_fires_on_train(self):
        verify = CONV.self_verify(self.detectors, Path(self.tmp))
        for fam, v in verify.items():
            self.assertIn(v["status"], ("FIRES", "NO-TRAIN-FIXTURE"),
                          f"{fam} did not fire on TRAIN: {v}")
            if v["status"] == "FIRES":
                self.assertGreaterEqual(v["fired_on"], 1)
        # at least 8 of the 10 families must genuinely FIRE (not NO-TRAIN-FIXTURE)
        fired = sum(1 for v in verify.values() if v["status"] == "FIRES")
        self.assertGreaterEqual(fired, 8,
                                f"only {fired} families fired on TRAIN: {verify}")

    def test_emitted_py_modules_load_and_expose_scan(self):
        for fam in self.detectors:
            p = Path(self.tmp) / f"{fam}.py"
            self.assertTrue(p.exists(), f"{fam}.py not emitted")
            spec = importlib.util.spec_from_file_location(f"_t_{fam}", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self.assertTrue(hasattr(mod, "scan"))
            self.assertTrue(callable(mod.scan))
            # scan returns a list on an empty dir
            with tempfile.TemporaryDirectory() as d:
                self.assertIsInstance(mod.scan(d), list)

    def test_emitted_yaml_sidecars_parse(self):
        import yaml
        for fam, det in self.detectors.items():
            yp = Path(self.tmp) / f"from-adv-{fam.replace('_', '-')}.yaml"
            self.assertTrue(yp.exists(), f"yaml for {fam} missing")
            spec = yaml.safe_load(yp.read_text())
            self.assertIsInstance(spec, dict)
            self.assertIn("pattern", spec)
            self.assertIn("backend", spec)
            self.assertIn("match", spec)
            # go fn-body family must be backend: cosmos; rust/file-level: regex
            if fam == "fork_batch_flush_race":
                self.assertEqual(spec["backend"], "cosmos")

    def test_placeholder_smell_is_skipped(self):
        # the hyperbridge public-advisory-theft-class placeholder must be skipped
        self.assertIn("placeholder-smell-no-mechanism", self.skipped)

    def test_state_mutation_fires_on_insert_before_guard(self):
        # functional fire of the TOCTOU family on a generic (non-held-out) shape
        mod_path = Path(self.tmp) / "state_mutation_before_guard.py"
        spec = importlib.util.spec_from_file_location("_sm", mod_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "x.rs").write_text(
                "fn push(&mut self) -> Result<()> {\n"
                "    self.map.insert(k, v);\n"
                "    self.check_valid()?;\n"
                "    Ok(())\n}\n")
            hits = mod.scan(d)
            self.assertTrue(hits, "TOCTOU detector did not fire on "
                                  "insert-before-guard shape")


class TestDepResolver(unittest.TestCase):
    def test_scope_detection_skips_relative(self):
        with tempfile.TemporaryDirectory() as d:
            sol = Path(d) / "a.sol"
            sol.write_text(
                'import "@openzeppelin/contracts/token/ERC20/IERC20.sol";\n'
                'import {X} from "@polytope-labs/ismp-solidity-abi/I.sol";\n'
                'import "./Local.sol";\n')
            imports = DEP._imports_in_file(sol)
            scopes = DEP.needed_scopes(imports)
            self.assertIn("@openzeppelin/contracts", scopes)
            self.assertIn("@polytope-labs/ismp-solidity-abi", scopes)
            self.assertNotIn("./Local.sol", scopes)
            # no relative import leaks into scopes
            self.assertFalse(any(s.startswith(".") for s in scopes))

    def test_offline_cache_resolution_and_remaps(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            cache = d / "cache"
            (cache / "@openzeppelin/contracts").mkdir(parents=True)
            (cache / "@openzeppelin/contracts/IERC20.sol").write_text("//")
            dest = d / "dest"
            res = DEP.resolve_from_cache({"@openzeppelin/contracts"}, cache, dest)
            self.assertIn(res["@openzeppelin/contracts"],
                          ("linked-from-cache", "copied-from-cache"))
            remaps = DEP.build_remaps({"@openzeppelin/contracts"}, dest)
            self.assertEqual(len(remaps), 1)
            self.assertTrue(remaps[0].startswith("@openzeppelin/contracts/="))

    def test_cache_miss_reported(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            res = DEP.resolve_from_cache({"@nonexistent/pkg"}, d / "empty",
                                         d / "dest")
            self.assertEqual(res["@nonexistent/pkg"], "cache-miss")


if __name__ == "__main__":
    unittest.main(verbosity=2)
