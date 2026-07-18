#!/usr/bin/env python3
"""Tests for discover-engine-harness-roots: recognizes poc-tests/*-engine-harness
AND the canonical echidna/medusa suite layout (the SSV blind spot)."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "discover_engine_harness_roots",
    Path(__file__).resolve().parent.parent / "discover-engine-harness-roots.py",
)
mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mod)


class TestDiscover(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())

    def test_poc_tests_engine_harness(self):
        d = self.ws / "poc-tests" / "x-engine-harness"
        d.mkdir(parents=True)
        (d / "foundry.toml").write_text("[profile.default]\n")
        roots = mod.discover(self.ws)
        self.assertIn(str(d.resolve()), roots)

    def test_echidna_suite_root_discovered(self):
        # the SSV layout: a foundry root with test/echidna/*Echidna.sol + yaml
        root = self.ws / "src" / "proj"
        ech = root / "test" / "echidna"
        ech.mkdir(parents=True)
        (root / "foundry.toml").write_text("[profile.default]\n")
        (ech / "FooEchidna.sol").write_text("contract FooEchidna {}\n")
        (ech / "echidna.foo.yaml").write_text("testMode: property\n")
        roots = mod.discover(self.ws)
        self.assertIn(str(root.resolve()), roots)

    def test_medusa_root_discovered(self):
        root = self.ws / "src" / "m"
        root.mkdir(parents=True)
        (root / "foundry.toml").write_text("[profile.default]\n")
        (root / "medusa.json").write_text("{}\n")
        roots = mod.discover(self.ws)
        self.assertIn(str(root.resolve()), roots)

    def test_node_modules_pruned(self):
        # an echidna dir inside node_modules must NOT make a root
        root = self.ws / "node_modules" / "dep"
        ech = root / "test" / "echidna"
        ech.mkdir(parents=True)
        (root / "foundry.toml").write_text("[profile.default]\n")
        (ech / "XEchidna.sol").write_text("contract XEchidna {}\n")
        roots = mod.discover(self.ws)
        self.assertEqual(roots, [])

    def test_plain_foundry_root_without_engine_harness_not_discovered(self):
        root = self.ws / "src" / "plain"
        (root / "test").mkdir(parents=True)
        (root / "foundry.toml").write_text("[profile.default]\n")
        (root / "test" / "Plain.t.sol").write_text("contract P {}\n")  # not an engine harness
        roots = mod.discover(self.ws)
        self.assertEqual(roots, [])


if __name__ == "__main__":
    unittest.main()
