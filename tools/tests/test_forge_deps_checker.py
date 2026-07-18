#!/usr/bin/env python3
"""Regression tests for Foundry project discovery in env/dependency checks."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "tools"
FORGE_DEPS_PATH = REPO_ROOT / "tools" / "forge-deps-checker.py"
ENGAGE_PATH = REPO_ROOT / "tools" / "engage.py"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


FORGE_DEPS = _load_module("forge_deps_checker", FORGE_DEPS_PATH)
ENGAGE = _load_module("engage_for_foundry_discovery_test", ENGAGE_PATH)


class FoundryDiscoveryTests(unittest.TestCase):
    def test_forge_deps_finds_external_nested_foundry_project(self) -> None:
        with tempfile.TemporaryDirectory(prefix="forge-deps-") as tmp:
            ws = Path(tmp)
            project = ws / "external" / "reserve-governor"
            project.mkdir(parents=True)
            (project / "foundry.toml").write_text("[profile.default]\nsrc = 'contracts'\n")

            self.assertEqual(FORGE_DEPS.find_forge_project(ws), project.resolve())

    def test_forge_deps_ignores_dependency_foundry_projects(self) -> None:
        with tempfile.TemporaryDirectory(prefix="forge-deps-") as tmp:
            ws = Path(tmp)
            dep = ws / "external" / "reserve-governor" / "lib" / "dependency"
            dep.mkdir(parents=True)
            (dep / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n")

            self.assertIsNone(FORGE_DEPS.find_forge_project(ws))

    def test_engage_env_check_detects_external_nested_foundry_project(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engage-env-") as tmp:
            ws = Path(tmp)
            project = ws / "external" / "reserve-governor"
            project.mkdir(parents=True)
            (project / "foundry.toml").write_text("[profile.default]\nsrc = 'contracts'\n")

            self.assertTrue(ENGAGE._has_foundry_project(ws))

    def test_remappings_resolve_node_modules_and_contract_aliases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="forge-deps-remap-") as tmp:
            project = Path(tmp)
            (project / "foundry.toml").write_text("[profile.default]\nsrc = 'contracts'\n")
            (project / "remappings.txt").write_text(
                "\n".join(
                    [
                        "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/",
                        "@governance/=contracts/governance/",
                        "@interfaces/=contracts/interfaces/",
                    ]
                )
                + "\n"
            )
            (project / "contracts").mkdir()
            (project / "contracts" / "StakingVault.sol").write_text(
                "\n".join(
                    [
                        "pragma solidity ^0.8.28;",
                        'import "@openzeppelin/contracts/token/ERC20/IERC20.sol";',
                        'import "@governance/ReserveOptimisticGovernor.sol";',
                        'import "@interfaces/IDeployer.sol";',
                        "contract StakingVault {}",
                    ]
                )
                + "\n"
            )
            for rel in [
                "node_modules/@openzeppelin/contracts/token/ERC20/IERC20.sol",
                "contracts/governance/ReserveOptimisticGovernor.sol",
                "contracts/interfaces/IDeployer.sol",
            ]:
                path = project / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("pragma solidity ^0.8.28;\n")

            self.assertEqual(FORGE_DEPS.check_lib_imports(project), [])

    def test_unresolved_remapped_import_is_reported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="forge-deps-unresolved-") as tmp:
            project = Path(tmp)
            (project / "foundry.toml").write_text("[profile.default]\nsrc = 'contracts'\n")
            (project / "remappings.txt").write_text("@missing/=node_modules/@missing/\n")
            (project / "contracts").mkdir()
            (project / "contracts" / "Example.sol").write_text(
                'pragma solidity ^0.8.28;\nimport "@missing/Package.sol";\ncontract Example {}\n'
            )

            self.assertEqual(
                FORGE_DEPS.check_lib_imports(project),
                ["Unresolved import: @missing/Package.sol"],
            )

    def test_check_remappings_skips_foundry_artifact_dirs_named_sol(self) -> None:
        with tempfile.TemporaryDirectory(prefix="forge-deps-remap-dir-") as tmp:
            project = Path(tmp)
            (project / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n")
            artifact_dir = project / "src" / "out" / "HashLib.sol"
            artifact_dir.mkdir(parents=True)
            (artifact_dir / "HashLib.json").write_text("{}\n")
            (project / "src" / "UsesAlias.sol").write_text(
                'pragma solidity ^0.8.28;\nimport "@openzeppelin/contracts/token/ERC20/IERC20.sol";\n'
            )

            self.assertEqual(
                FORGE_DEPS.check_remappings(project),
                ["Imports use remapped paths (@...) but no remappings configured"],
            )

    def test_solidity_caret_pragmas_match_later_patch_versions(self) -> None:
        self.assertTrue(FORGE_DEPS._satisfies_pragma((0, 8, 33), "^0.8.28"))
        self.assertTrue(FORGE_DEPS._satisfies_pragma((0, 8, 33), "^0.8.10"))
        self.assertFalse(FORGE_DEPS._satisfies_pragma((0, 9, 0), "^0.8.28"))


class _FakeProc:
    def __init__(self, returncode: int, stderr: str = ""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = ""


class FixGitSubmodulesShallowFallbackTests(unittest.TestCase):
    """A shallow superproject clone fails `--init --recursive` on nested pinned
    submodules; fix_git_submodules must fall back to a non-recursive --depth 1
    top-level init (the ethereum-optimism/optimism case)."""

    def _patch(self, calls, outcomes):
        import subprocess as _sp
        orig = _sp.run

        def fake_run(args, **kwargs):
            calls.append(list(args))
            return outcomes.pop(0)

        _sp.run = fake_run
        self.addCleanup(lambda: setattr(_sp, "run", orig))

    def test_recursive_fail_then_shallow_fallback_succeeds(self):
        calls = []
        self._patch(calls, [
            _FakeProc(1, "fatal: Unable to find current revision in submodule path '.../ds-test'"),
            _FakeProc(0),
        ])
        ok = FORGE_DEPS.fix_git_submodules(Path("/tmp/whatever"))
        self.assertTrue(ok, "shallow fallback should succeed when recursive fails")
        self.assertEqual(len(calls), 2, "must attempt recursive then fallback")
        self.assertIn("--recursive", calls[0])
        self.assertNotIn("--recursive", calls[1])
        self.assertIn("--depth", calls[1])
        self.assertIn("1", calls[1])

    def test_recursive_success_no_fallback(self):
        calls = []
        self._patch(calls, [_FakeProc(0)])
        ok = FORGE_DEPS.fix_git_submodules(Path("/tmp/whatever"))
        self.assertTrue(ok)
        self.assertEqual(len(calls), 1, "no fallback when recursive succeeds")

    def test_both_fail_returns_false(self):
        calls = []
        self._patch(calls, [_FakeProc(1, "err1"), _FakeProc(1, "err2")])
        ok = FORGE_DEPS.fix_git_submodules(Path("/tmp/whatever"))
        self.assertFalse(ok)
        self.assertEqual(len(calls), 2)


class HardhatFoundryShimTest(unittest.TestCase):
    def _make_hardhat_repo(self, root: Path) -> Path:
        repo = root / "src" / "evm-contracts"
        (repo / "contracts" / "prime").mkdir(parents=True)
        (repo / "package.json").write_text('{"name":"x","devDependencies":{}}')
        (repo / "hardhat.config.js").write_text("module.exports={solidity:{version:'0.8.28'}};")
        (repo / "contracts" / "prime" / "Vault.sol").write_text(
            'import "@openzeppelin/contracts/token/ERC20/ERC20.sol";\ncontract V {}\n')
        oz = repo / "node_modules" / "@openzeppelin" / "contracts" / "token" / "ERC20"
        oz.mkdir(parents=True)
        (oz / "ERC20.sol").write_text("contract ERC20 {}")
        (repo / "node_modules" / "hardhat").mkdir(parents=True)
        return repo

    def test_detects_hardhat_repo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self._make_hardhat_repo(Path(td))
            dirs = [d.resolve() for d in FORGE_DEPS._hardhat_npm_solidity_dirs(Path(td))]
            self.assertIn(repo.resolve(), dirs)

    def test_scaffolds_shim_with_via_ir_and_remappings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self._make_hardhat_repo(Path(td))
            self.assertTrue(FORGE_DEPS._scaffold_hardhat_foundry_shim(Path(td), do_fix=True))
            ft = (repo / "foundry.toml").read_text()
            self.assertIn('src = "contracts"', ft)
            self.assertIn("via_ir = true", ft)
            self.assertIn('solc = "0.8.28"', ft)
            rm = (repo / "remappings.txt").read_text()
            self.assertIn("@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/", rm)

    def test_check_mode_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self._make_hardhat_repo(Path(td))
            FORGE_DEPS._scaffold_hardhat_foundry_shim(Path(td), do_fix=False)
            self.assertFalse((repo / "foundry.toml").exists())

    def test_skips_repo_with_existing_foundry_toml(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self._make_hardhat_repo(Path(td))
            (repo / "foundry.toml").write_text("[profile.default]\n")
            self.assertEqual(FORGE_DEPS._hardhat_npm_solidity_dirs(Path(td)), [])


if __name__ == "__main__":
    unittest.main()
