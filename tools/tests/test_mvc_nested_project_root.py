"""Loop-fix 2026-06-22 (KEYSTONE coverage fix): mutation-verify-coverage._default_runner
hardcoded the audit-tree ROOT as the engine cwd + halmos --root. Multi-project workspaces
nest the real build project in a SUBDIR (src/pol-token/foundry.toml, src/bor/go.mod) with its
OWN remappings/deps, so running from the root made every import unresolvable
("forge-std/Test.sol not found") -> the auto-harness 'no-execution'/engine-error that blocked
function/core/engine coverage on polygon. Now the runner resolves the nearest enclosing project
dir. Proven: a hand-authored PolygonMigration invariant harness built + mutation-verified once
the cwd/root was the nested src/pol-token project.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("mvc_nr", str(_TOOLS / "mutation-verify-coverage.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mvc_nr"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestNestedProjectRoot(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp()).resolve()
        proj = self.ws / "src" / "pol-token"
        (proj / "test").mkdir(parents=True)
        (proj / "foundry.toml").write_text("[profile.default]\n")
        self.harness = proj / "test" / "Inv.t.sol"
        self.harness.write_text("// harness")
        self.proj = proj

    def test_resolves_nested_foundry_project(self):
        root = self.m._project_root(self.harness, self.ws, "foundry.toml")
        self.assertEqual(root, self.proj, "must resolve the nested src/pol-token, not ws")

    def test_runner_cwd_and_root_are_nested_project(self):
        cmd, cwd = self.m._default_runner("solidity", self.ws, self.harness)
        self.assertEqual(cwd, self.proj)
        self.assertIn(str(self.proj), " ".join(cmd))  # halmos --root <project>

    def test_fallback_to_ws_when_no_marker(self):
        bare = Path(tempfile.mkdtemp()).resolve()
        (bare / "x.sol").write_text("//")
        self.assertEqual(self.m._project_root(bare / "x.sol", bare, "foundry.toml"), bare)

    def test_go_nested_gomod(self):
        proj = self.ws / "src" / "bor"
        (proj / "consensus").mkdir(parents=True)
        (proj / "go.mod").write_text("module bor\n")
        h = proj / "consensus" / "bor.go"
        h.write_text("package consensus")
        self.assertEqual(self.m._project_root(h, self.ws, "go.mod"), proj)

    def test_premade_mutant_runs_from_nested_project(self):
        """The premade-mutant/explicit-command branch (verify_premade_mutant) must
        ALSO derive the engine cwd from harness_path's nested project - not default
        to the audit-tree root - else baseline errors to 'no-baseline'. We run a cheap
        `pwd` command as both baseline and mutant and assert the cwd was the nested
        src/pol-token project (recorded in runner_cwd / observable in the pwd tail)."""
        res = self.m.verify_premade_mutant(
            workspace=self.ws,
            source_file=self.proj / "src" / "Foo.sol",
            function="foo()",
            baseline_harness="pwd",
            mutant_harness="pwd",
            timeout=30,
            harness_path=str(self.harness),
        )
        self.assertEqual(res["runner_cwd"], str(self.proj),
                         "premade-mutant cwd must be the nested project, not ws")
        # pwd's own stdout must echo the nested project dir, proving _run used it.
        self.assertIn(str(self.proj), res["baseline"]["tail"])

    def test_premade_mutant_falls_back_to_ws_without_harness(self):
        res = self.m.verify_premade_mutant(
            workspace=self.ws,
            source_file=self.ws / "Foo.sol",
            function="foo()",
            baseline_harness="pwd",
            mutant_harness="pwd",
            timeout=30,
            harness_path=None,
        )
        self.assertEqual(res["runner_cwd"], str(self.ws))


if __name__ == "__main__":
    unittest.main(verbosity=2)
