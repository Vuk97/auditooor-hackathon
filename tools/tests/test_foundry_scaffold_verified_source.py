#!/usr/bin/env python3
"""Regression tests for foundry-scaffold-verified-source.py.

Covers:
  - detection of a fetched verified-source dir (SOURCE_META marker)
  - foundry.toml + remappings.txt generation with correct solc + remaps
  - the self-referential @alias/src/=src/ remapping (avoids double-compile)
  - the @dep/=lib/dep/ remapping for a present lib dependency
  - NO-OP when foundry.toml already exists
  - NO-OP for a non-EVM dir (no src/*.sol)
  - NO-OP for an in-repo test fixture (src/*.sol but no verified-source marker)
  - idempotency on re-run
  - (optional) a real forge build of the generated project when forge is present
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "tools"
SCAFFOLD_PATH = TOOLS_DIR / "foundry-scaffold-verified-source.py"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


SCAF = _load_module("foundry_scaffold_verified_source", SCAFFOLD_PATH)


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _make_verified_source_dir(root: Path, *, with_marker: bool = True,
                              compiler: str = "v0.8.34+commit.80d5c536") -> Path:
    """Build a minimal fetched-verified-source contract dir.

    Layout:
      <root>/src/Entry.sol          imports @dep/src/Lib.sol (self-ref alias)
                                    and @solady/src/utils/X.sol (lib dep)
      <root>/src/Lib.sol            the self-referential target
      <root>/lib/solady/src/utils/X.sol   the lib dependency
      <root>/SOURCE_META.json       verified-source marker (compiler)
    """
    entry = root / "src" / "Entry.sol"
    _write(entry,
           "// SPDX-License-Identifier: MIT\n"
           "pragma solidity ^0.8.0;\n"
           'import {Lib} from "@dep/src/Lib.sol";\n'
           'import {X} from "@solady/src/utils/X.sol";\n'
           "contract Entry { function f() external pure returns (uint) { return Lib.v() + X.v(); } }\n")
    _write(root / "src" / "Lib.sol",
           "// SPDX-License-Identifier: MIT\n"
           "pragma solidity ^0.8.0;\n"
           "library Lib { function v() internal pure returns (uint) { return 1; } }\n")
    _write(root / "lib" / "solady" / "src" / "utils" / "X.sol",
           "// SPDX-License-Identifier: MIT\n"
           "pragma solidity ^0.8.0;\n"
           "library X { function v() internal pure returns (uint) { return 2; } }\n")
    if with_marker:
        _write(root / "SOURCE_META.json",
               json.dumps({"name": "Entry", "compiler": compiler}))
    return root


class TestDetection(unittest.TestCase):
    def test_detect_verified_source_dir(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make_verified_source_dir(ws / "contracts" / "Entry")
            dirs = SCAF.find_verified_source_dirs(ws)
            self.assertEqual([str(d) for d in dirs],
                             [str((ws / "contracts" / "Entry").resolve())])

    def test_noop_when_no_marker_fixture(self):
        # src/*.sol but NO SOURCE_META / ABI marker -> must NOT be detected
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make_verified_source_dir(ws / "fixtures" / "Kit", with_marker=False)
            dirs = SCAF.find_verified_source_dirs(ws)
            self.assertEqual(dirs, [])

    def test_noop_when_foundry_present(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            cdir = _make_verified_source_dir(ws / "c" / "Entry")
            _write(cdir / "foundry.toml", "[profile.default]\nsrc=\"src\"\n")
            dirs = SCAF.find_verified_source_dirs(ws)
            self.assertEqual(dirs, [])

    def test_noop_non_evm(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "src" / "main.rs", "fn main() {}\n")
            _write(ws / "Cargo.toml", "[package]\nname=\"x\"\n")
            dirs = SCAF.find_verified_source_dirs(ws)
            self.assertEqual(dirs, [])


class TestGeneration(unittest.TestCase):
    def test_remaps_and_solc(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            cdir = _make_verified_source_dir(ws / "Entry")
            imports = SCAF.collect_import_prefixes(cdir)
            remaps = SCAF.derive_remappings(cdir, imports)
            # self-referential alias -> @dep/src/=src/
            self.assertEqual(remaps.get("@dep/src/"), "src/")
            # lib dependency -> @solady/=lib/solady/
            self.assertEqual(remaps.get("@solady/"), "lib/solady/")
            self.assertEqual(SCAF.detect_solc_version(cdir), "0.8.34")

    def test_no_bare_alias_double_compile_remap(self):
        # The self-ref remap MUST be @dep/src/=src/, never @dep/=./ which
        # double-compiles. Assert we never emit a `=./` or `=.` target.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            cdir = _make_verified_source_dir(ws / "Entry")
            remaps = SCAF.derive_remappings(cdir, SCAF.collect_import_prefixes(cdir))
            for k, v in remaps.items():
                self.assertNotIn(v, ("./", "."),
                                 f"remap {k}={v} would double-compile src/")

    def test_fix_writes_and_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            cdir = _make_verified_source_dir(ws / "Entry")
            r1 = SCAF.run(ws, write=True, do_solc_install=False)
            self.assertEqual(r1["detected_count"], 1)
            self.assertTrue(r1["scaffolded"][0]["wrote"])
            self.assertTrue((cdir / "foundry.toml").is_file())
            self.assertTrue((cdir / "remappings.txt").is_file())
            self.assertTrue((cdir / ".auditooor" / "foundry_scaffold.json").is_file())
            # idempotent re-run: the dir now has a foundry.toml, so detection
            # skips it -> workspace-level no-op (0 detected, 0 writes).
            toml_before = (cdir / "foundry.toml").read_text()
            r2 = SCAF.run(ws, write=True, do_solc_install=False)
            self.assertEqual(r2["detected_count"], 0)
            self.assertEqual(r2["scaffolded"], [])
            # content unchanged
            self.assertEqual((cdir / "foundry.toml").read_text(), toml_before)

    def test_solc_falls_back_to_auto_detect(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # no SOURCE_META and a pragma we still parse -> version from pragma
            cdir = _make_verified_source_dir(ws / "Entry", with_marker=False)
            # add a marker so it's still detected, but with a non-version compiler
            _write(cdir / "ABI.json", "[]")
            v = SCAF.detect_solc_version(cdir)
            # pragma is ^0.8.0 -> parsed lower bound 0.8.0
            self.assertEqual(v, "0.8.0")
            toml = SCAF.build_foundry_toml(None, {})
            self.assertIn("auto_detect_solc = true", toml)


class TestCLI(unittest.TestCase):
    def test_check_mode_writes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            cdir = _make_verified_source_dir(ws / "Entry")
            r = subprocess.run(
                [sys.executable, str(SCAFFOLD_PATH), str(ws), "--check", "--json"],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0)
            payload = json.loads(r.stdout)
            self.assertEqual(payload["detected_count"], 1)
            self.assertFalse((cdir / "foundry.toml").is_file())


@unittest.skipUnless(shutil.which("forge"), "forge not installed")
class TestForgeBuild(unittest.TestCase):
    def test_generated_project_builds(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            cdir = _make_verified_source_dir(ws / "Entry")
            SCAF.run(ws, write=True, do_solc_install=False)
            # Build with auto_detect_solc so we don't depend on a pinned solc
            # being installed in CI; rewrite the pinned version to auto-detect.
            toml = (cdir / "foundry.toml").read_text()
            toml = toml.replace('solc_version = "0.8.34"', "auto_detect_solc = true")
            (cdir / "foundry.toml").write_text(toml)
            r = subprocess.run(["forge", "build", "--skip", "test", "--no-cache"],
                               cwd=cdir, capture_output=True, text=True, timeout=300)
            self.assertIn("Compiler run successful", r.stdout + r.stderr,
                          msg=f"stdout={r.stdout}\nstderr={r.stderr}")


if __name__ == "__main__":
    unittest.main()
