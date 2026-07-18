"""Regression test for the `detectors/run_custom.py` loader's @dataclass safety.

Issue: prior to the Wave-2 PR-B detector-loader-fix commit, the loader did:

    spec = importlib.util.spec_from_file_location(stem, py_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

Without registering `module` in `sys.modules[stem]` BEFORE `exec_module()`,
Python 3.13+ `dataclasses.@dataclass` decorator fails at class-definition time
when it introspects `sys.modules.get(cls.__module__).__dict__` for KW_ONLY
sentinels - the entry is None, raising
`AttributeError: 'NoneType' object has no attribute '__dict__'`.

Six wave17 detectors (and any future @dataclass-using detector) silently
disappeared from the active set under that loader shape. See
docs/SLITHER_IR_BROKEN_DETECTORS_2026-05-16.md for the full diagnostic.

This test:
1. Synthesises a minimal @dataclass-using module on disk (synthetic_fixture: true).
2. Loads it via the SAME `importlib.util.spec_from_file_location` +
   `module_from_spec` + `exec_module` pattern the production loader uses,
   pre-registering in sys.modules before exec.
3. Asserts the load succeeds.
4. Pins the production loader source: asserts the `sys.modules[py_file.stem]
   = module` registration line and the symmetric `sys.modules.pop(...)`
   cleanup-on-failure are present in `detectors/run_custom.py`.
"""

# synthetic_fixture: true
import importlib.util
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


_DATACLASS_DETECTOR_SOURCE = textwrap.dedent(
    """
    # synthetic_fixture: true
    from dataclasses import dataclass


    @dataclass
    class Finding:
        file_path: str
        line: int
        severity: str = "info"


    def scan(source: str, file_path: str):
        # Minimal regex-style detector contract used by stdlib-only detectors.
        if "DANGER" in source:
            return [Finding(file_path=file_path, line=1, severity="high")]
        return []
    """
).strip() + "\n"


class TestRunCustomLoaderDataclassSafety(unittest.TestCase):
    """Pin down the sys.modules pre-registration fix in detectors/run_custom.py."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.det_path = self.tmp / "dataclass_detector_synthetic.py"
        self.det_path.write_text(_DATACLASS_DETECTOR_SOURCE)
        # Cleanup any module name leakage from prior tests
        sys.modules.pop("dataclass_detector_synthetic", None)

    def tearDown(self):
        sys.modules.pop("dataclass_detector_synthetic", None)
        self._tmpdir.cleanup()

    def _load_with_preregistration(self):
        """Mirror the FIXED loader shape: register in sys.modules before exec."""
        stem = self.det_path.stem
        spec = importlib.util.spec_from_file_location(stem, self.det_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[stem] = module  # pre-registration is the fix
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(stem, None)
            raise
        return module

    def test_fixed_loader_loads_dataclass_detector_cleanly(self):
        """Positive: pre-registered loader loads a @dataclass-using detector."""
        module = self._load_with_preregistration()
        self.assertTrue(hasattr(module, "Finding"))
        self.assertTrue(hasattr(module, "scan"))
        # Smoke-fire the detector contract
        results = module.scan("contract X { DANGER }", "X.sol")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "high")

    def test_production_run_custom_loader_uses_preregistration(self):
        """Read run_custom.py and assert the sys.modules registration line is present.

        Structural pin: if a future refactor accidentally drops the
        pre-registration, this test fails fast without having to actually
        load all 9 previously-broken detectors to notice.
        """
        repo_root = Path(__file__).resolve().parents[2]
        run_custom = repo_root / "detectors" / "run_custom.py"
        self.assertTrue(run_custom.is_file(), f"missing {run_custom}")
        src = run_custom.read_text()
        self.assertIn(
            "sys.modules[py_file.stem] = module",
            src,
            "loader regression: sys.modules pre-registration is missing; "
            "@dataclass detectors will silently fail to load. "
            "See docs/SLITHER_IR_BROKEN_DETECTORS_2026-05-16.md",
        )
        # Also assert the symmetric cleanup-on-failure pop is present.
        self.assertIn(
            "sys.modules.pop(py_file.stem, None)",
            src,
            "loader regression: missing sys.modules cleanup on exec_module failure",
        )


if __name__ == "__main__":
    unittest.main()
