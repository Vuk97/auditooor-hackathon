#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FOUNDRY-DEP-RESOLVE-NPM-SCOPE registered in commit message -->
"""Strata 2026-06-30: the '@openzeppelin/' DEP_REGISTRY entry blanket-mapped
'@openzeppelin/=lib/openzeppelin-contracts/'. That repo ships only the `contracts`
package; `contracts-upgradeable` is a SEPARATE npm package, so
'@openzeppelin/contracts-upgradeable/...' resolved to a non-existent
lib/openzeppelin-contracts/contracts-upgradeable/ dir and the authored-harness
test tree failed to compile -> deep engines reported build-broken / 0 genuine.

Fix: when node_modules/<scope> provides the packages (npm/hardhat projects),
emit per-package node_modules remaps. Pins: per-package remaps for BOTH contracts
and contracts-upgradeable; no node_modules scope -> falls back to lib (unchanged).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "foundry-harness-dep-resolve.py"


def _load():
    spec = importlib.util.spec_from_file_location("fhdr", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["fhdr"] = m
    spec.loader.exec_module(m)
    return m


fhdr = _load()


def _mk_root(*, with_node_modules: bool):
    root = Path(tempfile.mkdtemp(prefix="fhdr_"))
    (root / "foundry.toml").write_text(
        "[profile.default]\nsrc='contracts'\nlibs=['node_modules','lib']\ntest='test'\n",
        encoding="utf-8")
    test = root / "test"
    test.mkdir()
    # a harness that imports BOTH @openzeppelin packages (the failing shape)
    (test / "Harness.t.sol").write_text(
        'pragma solidity ^0.8.20;\n'
        'import "@openzeppelin/contracts/token/ERC20/ERC20.sol";\n'
        'import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";\n'
        'contract H {}\n', encoding="utf-8")
    if with_node_modules:
        for pkg in ("contracts", "contracts-upgradeable"):
            d = root / "node_modules" / "@openzeppelin" / pkg
            d.mkdir(parents=True)
            (d / "package.json").write_text("{}", encoding="utf-8")
    return root


class NpmScopeRemapTest(unittest.TestCase):
    def test_helper_emits_per_package_remaps(self):
        root = _mk_root(with_node_modules=True)
        remaps = fhdr._npm_scope_remaps(root, "@openzeppelin/")
        self.assertIn(
            "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/", remaps)
        self.assertIn(
            "@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/",
            remaps)

    def test_resolve_writes_node_modules_remaps(self):
        root = _mk_root(with_node_modules=True)
        out = fhdr.resolve(root, check_only=False)
        rm = (root / "remappings.txt").read_text(encoding="utf-8")
        # the load-bearing line: contracts-upgradeable -> node_modules (NOT lib)
        self.assertIn(
            "@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/",
            rm)
        # must NOT have relied on the broken blanket lib map as the only @oz remap
        self.assertIn("node_modules/@openzeppelin/contracts/", rm)
        # the broken bare-scope blanket must be DROPPED (forge can shadow the
        # per-package remap with it) - not merely out-prefixed.
        self.assertNotIn("@openzeppelin/=lib/openzeppelin-contracts/", rm)
        for ln in rm.splitlines():
            self.assertNotEqual(ln.split("=", 1)[0].strip(), "@openzeppelin/")
        self.assertEqual(out["verdict"], "pass-all-deps-resolved")

    def test_drops_preexisting_blanket(self):
        root = _mk_root(with_node_modules=True)
        (root / "remappings.txt").write_text(
            "@openzeppelin/=lib/openzeppelin-contracts/\n", encoding="utf-8")
        fhdr.resolve(root, check_only=False)
        rm = (root / "remappings.txt").read_text(encoding="utf-8")
        self.assertNotIn("@openzeppelin/=lib/openzeppelin-contracts/", rm)
        self.assertIn(
            "@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/",
            rm)

    def test_no_node_modules_falls_back_to_lib(self):
        # No node_modules scope -> the helper returns nothing; lib path unchanged.
        root = _mk_root(with_node_modules=False)
        self.assertEqual(fhdr._npm_scope_remaps(root, "@openzeppelin/"), [])

    def test_package_level_prefix_not_treated_as_scope(self):
        root = _mk_root(with_node_modules=True)
        # a package-level prefix (has a slash inside) must NOT be scope-expanded
        self.assertEqual(
            fhdr._npm_scope_remaps(root, "@openzeppelin/contracts/"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
