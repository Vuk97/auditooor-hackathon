"""Regression: go-dataflow._run_binary must STRIP -mod from GOFLAGS when a go.work
governs the module cwd. go.work (workspace mode) is incompatible with -mod, so
go/packages.Load fails and the Go dataflow arm degrades to a 725-byte degrade
record instead of loading the module (verified NUVA 2026-07-06: the audit-deep
launch env carries GOFLAGS=-mod=mod; with it the arm produced a degrade, without
it 15MB of real in-scope Go vault dataflow). This guards the sanitizer + go.work
detection stay wired."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "gdf_wsflags", os.path.join(_HERE, "..", "go-dataflow.py"))
_gdf = importlib.util.module_from_spec(_spec)
import sys
sys.path.insert(0, os.path.join(_HERE, ".."))
_spec.loader.exec_module(_gdf)


class TestGoflagsWorkspaceSanitize(unittest.TestCase):
    def setUp(self):
        os.environ.pop("GOWORK", None)

    def test_strips_mod_under_go_work(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.work").write_text("go 1.25\n")
            out = _gdf._sanitize_goflags_for_workspace("-mod=mod -count=1", Path(d))
            self.assertNotIn("-mod", out)
            self.assertIn("-count=1", out, "non -mod flags must be preserved")

    def test_leaves_flags_when_no_go_work(self):
        with tempfile.TemporaryDirectory() as d:
            out = _gdf._sanitize_goflags_for_workspace("-mod=mod", Path(d))
            self.assertEqual(out, "-mod=mod", "single-module tree keeps -mod=mod")

    def test_gowork_off_disables_workspace_mode(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.work").write_text("go 1.25\n")
            os.environ["GOWORK"] = "off"
            try:
                out = _gdf._sanitize_goflags_for_workspace("-mod=mod", Path(d))
                self.assertEqual(out, "-mod=mod", "GOWORK=off => not workspace mode")
            finally:
                os.environ.pop("GOWORK", None)

    def test_has_go_work_walks_up(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.work").write_text("go 1.25\n")
            nested = Path(d) / "a" / "b"
            nested.mkdir(parents=True)
            self.assertTrue(_gdf._has_go_work(nested))


class TestWorkspaceToolchainPin(unittest.TestCase):
    """Regression (root-caused NUVA 2026-07-08): the Go arm must PIN the ws-required
    toolchain. NUVA's go.work pins `toolchain go1.25.8`; without pinning, the arm inherited
    the ambient go1.26.2 which fails to compile a dep (bytedance/sonic) -> packages.Load
    silently degraded to 35 state-write sinks vs 686 under the pin (~20x coupled-state
    under-count). _workspace_toolchain extracts the pin; _run_binary must put it in the env."""

    def test_extracts_toolchain_directive_from_go_work(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.work").write_text("go 1.25.8\n\ntoolchain go1.25.8\n\nuse (\n\t.\n)\n")
            self.assertEqual(_gdf._workspace_toolchain(Path(d)), "go1.25.8")

    def test_falls_back_to_go_mod_go_directive(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.mod").write_text("module x\n\ngo 1.24.3\n")
            self.assertEqual(_gdf._workspace_toolchain(Path(d)), "go1.24.3")

    def test_no_pin_when_absent(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(_gdf._workspace_toolchain(Path(d)), "")

    def test_run_binary_timeout_is_env_configurable(self):
        # The hardcoded 900s SILENTLY truncated large cosmos-sdk modules once the toolchain
        # fix let them load FULLY (NUVA vault ~19min -> 900s degraded to ~1 record). The
        # per-module timeout must be env-configurable so heavy Go ws are not silently cut.
        captured = {}

        def _fake_run(cmd, cwd=None, env=None, timeout=None, **kw):
            captured["timeout"] = timeout

            class _P:
                stdout = "[]"
                stderr = ""
                returncode = 0
            return _P()

        with tempfile.TemporaryDirectory() as d:
            orig = _gdf.subprocess.run
            os.environ["AUDITOOOR_GO_DATAFLOW_RUN_TIMEOUT"] = "2400"
            _gdf.subprocess.run = _fake_run
            try:
                _gdf._run_binary("/nonexistent/binary", Path(d), ["./..."], 8, False)
            finally:
                _gdf.subprocess.run = orig
                os.environ.pop("AUDITOOOR_GO_DATAFLOW_RUN_TIMEOUT", None)
            self.assertEqual(captured["timeout"], 2400,
                             "AUDITOOOR_GO_DATAFLOW_RUN_TIMEOUT must set the subprocess timeout")

    def test_run_binary_default_timeout_lifted_above_900(self):
        # default must be high enough for a real large-module slice (>900s).
        captured = {}

        def _fake_run(cmd, cwd=None, env=None, timeout=None, **kw):
            captured["timeout"] = timeout

            class _P:
                stdout = "[]"
                stderr = ""
                returncode = 0
            return _P()

        with tempfile.TemporaryDirectory() as d:
            orig = _gdf.subprocess.run
            os.environ.pop("AUDITOOOR_GO_DATAFLOW_RUN_TIMEOUT", None)
            _gdf.subprocess.run = _fake_run
            try:
                _gdf._run_binary("/nonexistent/binary", Path(d), ["./..."], 8, False)
            finally:
                _gdf.subprocess.run = orig
            self.assertGreater(captured["timeout"], 900,
                               "default per-module timeout must exceed the old 900s that truncated NUVA")

    def test_run_binary_sets_GOTOOLCHAIN_from_workspace_pin(self):
        # THE behavior that prevents the silent degrade: _run_binary's subprocess env must
        # carry GOTOOLCHAIN=<ws pin>. Monkeypatch subprocess.run to capture the env without
        # a ~19min real slice.
        captured = {}

        def _fake_run(cmd, cwd=None, env=None, **kw):
            captured["env"] = env

            class _P:
                stdout = "[]"
                stderr = ""
                returncode = 0
            return _P()

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.work").write_text("go 1.25.8\ntoolchain go1.25.8\nuse (\n\t.\n)\n")
            orig = _gdf.subprocess.run
            _gdf.subprocess.run = _fake_run
            try:
                _gdf._run_binary("/nonexistent/binary", Path(d), ["./..."], 8, False)
            finally:
                _gdf.subprocess.run = orig
            self.assertEqual(captured["env"].get("GOTOOLCHAIN"), "go1.25.8",
                             "the ws-pinned toolchain must be threaded into the subprocess env")


if __name__ == "__main__":
    unittest.main()
