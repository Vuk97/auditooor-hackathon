"""Loop-fix 2026-07-12: mutation-verify-coverage._default_runner defaulted the
Solidity engine to ``halmos --root <workspace>`` over the WHOLE audit tree. On a
mixed-compiler / Hardhat monorepo (axelar-sc: 3 Hardhat repos, different solc
versions, NO root foundry.toml) that hands the entire monorepo to crytic-compile,
which cannot pick a single compiler and build-fails -> two SC coverage lanes fell
back to --register-manual-mvc on 2026-07-12.

Fix: when the harness has no enclosing foundry project (root fell back to ws) AND
the workspace is a Hardhat / mixed-solc monorepo, scope the build+run to the
harness's own directory instead of --root <ws>. A normal single-foundry-project
workspace (or a harness inside a nested foundry project) is untouched - the
invocation stays byte-identical.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("mvc_mc", str(_TOOLS / "mutation-verify-coverage.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mvc_mc"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestMixedCompilerScopedRoot(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_hardhat_monorepo_scopes_to_harness_dir_not_ws(self):
        """No root foundry.toml + a hardhat.config.* in a subrepo => the halmos
        --root must be the harness's own dir, NOT the monorepo root."""
        ws = Path(tempfile.mkdtemp()).resolve()
        # axelar-sc shape: a Hardhat subrepo, no root foundry.toml anywhere.
        (ws / "axelar-cgp-solidity").mkdir(parents=True)
        (ws / "axelar-cgp-solidity" / "hardhat.config.js").write_text("module.exports = {}\n")
        hdir = ws / "poc-tests" / "cluster-A"
        hdir.mkdir(parents=True)
        harness = hdir / "Repro.t.sol"
        harness.write_text("contract Repro_Cluster_A {}\n")

        self.assertTrue(self.m._is_mixed_compiler_ws(ws))
        cmd, cwd = self.m._default_runner("solidity", ws, harness)
        root_arg = cmd[cmd.index("--root") + 1]
        self.assertEqual(root_arg, str(hdir),
                         "mixed-compiler ws must scope --root to the harness dir, not ws")
        self.assertNotEqual(root_arg, str(ws),
                            "must NOT run halmos over the monorepo root")
        self.assertEqual(cwd, hdir)

    def test_nested_foundry_project_still_used_when_present(self):
        """Even in a mixed-compiler ws, a harness INSIDE its own foundry project
        resolves to that project (unchanged) - not the bare harness dir."""
        ws = Path(tempfile.mkdtemp()).resolve()
        (ws / "hardhat.config.ts").write_text("export default {}\n")  # mixed ws
        proj = ws / "poc-tests" / "cluster-B"
        (proj / "test").mkdir(parents=True)
        (proj / "foundry.toml").write_text("[profile.default]\n")
        harness = proj / "test" / "Repro.t.sol"
        harness.write_text("contract Repro_Cluster_B {}\n")

        cmd, cwd = self.m._default_runner("solidity", ws, harness)
        self.assertEqual(cwd, proj)
        self.assertIn(f"--root {proj}", " ".join(cmd))

    def test_normal_single_foundry_ws_is_byte_identical(self):
        """Root foundry.toml => not mixed; invocation unchanged (root == ws)."""
        ws = Path(tempfile.mkdtemp()).resolve()
        (ws / "foundry.toml").write_text("[profile.default]\n")
        (ws / "test").mkdir()
        harness = ws / "test" / "Inv.t.sol"
        harness.write_text("contract Inv_Harness {}\n")

        self.assertFalse(self.m._is_mixed_compiler_ws(ws))
        cmd, cwd = self.m._default_runner("solidity", ws, harness)
        self.assertEqual(cwd, ws)
        self.assertIn(f"--root {ws}", " ".join(cmd))
        # Contract match preserved exactly as before.
        self.assertIn("--contract", cmd)

    def test_plain_ws_without_hardhat_is_not_mixed(self):
        """No foundry.toml AND no hardhat config => not classified mixed (keeps the
        legacy ws-root fallback rather than mis-scoping an unknown layout)."""
        ws = Path(tempfile.mkdtemp()).resolve()
        (ws / "src").mkdir()
        (ws / "src" / "Foo.sol").write_text("contract Foo {}\n")
        self.assertFalse(self.m._is_mixed_compiler_ws(ws))


if __name__ == "__main__":
    unittest.main(verbosity=2)
