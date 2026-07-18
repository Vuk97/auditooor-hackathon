"""Tests for tools/wave2-mcp-callable-inventory-healthcheck.py.

Synthetic fixtures are marked with `synthetic_fixture: true` in tempdirs.
Live coverage of the production server is asserted in
``test_live_server_parity_no_issues`` as a non-strict floor check.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "wave2-mcp-callable-inventory-healthcheck.py"


def _load_module():
    name = "wave2_mcp_callable_inventory_healthcheck"
    spec = importlib.util.spec_from_file_location(name, TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass can resolve cls.__module__.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


HEALTHCHECK = _load_module()


def _write_synthetic_server(
    path: Path,
    schemas: list[str],
    methods: list[str],
    dispatch: list[str],
) -> None:
    """Write a synthetic vault-mcp-server.py stub that the healthcheck can parse.

    The healthcheck looks at three regexes anchored to the documented
    structure of vault-mcp-server.py:
      - Schema name:   ``^\\s*"name": "vault_..."``
      - Method def:    ``^    def vault_...(`` (class-body indent = 4 spaces)
      - Dispatch:      ``^\\s+if name == "vault_...":``
    We emit explicit indentation so the file mirrors that shape. This file
    is marked as a synthetic fixture for traceability.
    """
    lines: list[str] = []
    lines.append("# synthetic_fixture: true")
    lines.append("TOOL_SCHEMAS = [")
    for n in schemas:
        # Mirror production layout: one key per line, name on its own.
        lines.append("    {")
        lines.append(f'        "name": "{n}",')
        lines.append('        "description": "synthetic fixture",')
        lines.append("    },")
    lines.append("]")
    lines.append("")
    lines.append("")
    lines.append("class FakeServer:")
    if methods:
        for n in methods:
            lines.append(f"    def {n}(self, **kw):")
            lines.append("        return None")
    else:
        lines.append("    pass")
    lines.append("")
    lines.append("    def call_tool(self, name):")
    if dispatch:
        for n in dispatch:
            lines.append(f'        if name == "{n}":')
            lines.append("            return None")
    else:
        lines.append("        pass")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_synthetic_tests(
    tests_dir: Path,
    callable_names: list[str],
) -> None:
    tests_dir.mkdir(parents=True, exist_ok=True)
    for name in callable_names:
        f = tests_dir / f"test_{name}.py"
        f.write_text(
            "# synthetic_fixture: true\n"
            "import unittest\n"
            f"class T_{name}(unittest.TestCase):\n"
            "    def test_smoke(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )


class SyntheticFixtureBase(unittest.TestCase):
    def setUp(self) -> None:  # noqa: D401
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.server_path = self.root / "vault-mcp-server.py"
        self.tests_dir = self.root / "tests"


class TestPassFullParity(SyntheticFixtureBase):
    def test_pass_3_callables_full_parity_and_tests(self) -> None:
        names = ["vault_alpha", "vault_beta", "vault_gamma"]
        _write_synthetic_server(self.server_path, names, names, names)
        _write_synthetic_tests(self.tests_dir, names)

        report = HEALTHCHECK.build_inventory_report(self.server_path, self.tests_dir)

        self.assertEqual(report.total_callables, 3)
        self.assertEqual(report.total_schemas, 3)
        self.assertEqual(report.total_methods, 3)
        self.assertEqual(report.total_dispatch, 3)
        self.assertEqual(report.total_tests, 3)
        self.assertEqual(report.parity_issues, [])
        self.assertEqual(report.schema_version_mismatches, [])
        self.assertAlmostEqual(report.test_coverage_pct, 1.0)
        self.assertEqual(report.overall_status, "PASS")


class TestFailOrphanSchema(SyntheticFixtureBase):
    def test_fail_orphan_schema_no_method(self) -> None:
        schemas = ["vault_alpha", "vault_orphan_schema"]
        methods = ["vault_alpha"]
        dispatch = ["vault_alpha"]
        _write_synthetic_server(self.server_path, schemas, methods, dispatch)
        _write_synthetic_tests(self.tests_dir, schemas)

        report = HEALTHCHECK.build_inventory_report(self.server_path, self.tests_dir)

        self.assertEqual(report.overall_status, "FAIL")
        types = {i.issue_type for i in report.parity_issues}
        self.assertIn("orphan_schema_no_method", types)
        self.assertIn("missing_dispatch", types)
        names = {i.callable_name for i in report.parity_issues}
        self.assertIn("vault_orphan_schema", names)


class TestFailOrphanMethod(SyntheticFixtureBase):
    def test_fail_orphan_method_no_schema(self) -> None:
        schemas = ["vault_alpha"]
        methods = ["vault_alpha", "vault_orphan_method"]
        dispatch = ["vault_alpha"]
        _write_synthetic_server(self.server_path, schemas, methods, dispatch)
        _write_synthetic_tests(self.tests_dir, methods)

        report = HEALTHCHECK.build_inventory_report(self.server_path, self.tests_dir)

        self.assertEqual(report.overall_status, "FAIL")
        types = {i.issue_type for i in report.parity_issues}
        self.assertIn("orphan_method_no_schema", types)
        names = {i.callable_name for i in report.parity_issues}
        self.assertIn("vault_orphan_method", names)


class TestWarningUntested(SyntheticFixtureBase):
    def test_warning_low_test_coverage_no_parity_violations(self) -> None:
        # 10 callables, only 2 with tests -> 20% coverage. Below the 80%
        # threshold -> WARNING (no parity issues).
        names = [f"vault_x{i}" for i in range(10)]
        _write_synthetic_server(self.server_path, names, names, names)
        _write_synthetic_tests(self.tests_dir, names[:2])

        report = HEALTHCHECK.build_inventory_report(self.server_path, self.tests_dir)

        self.assertEqual(report.parity_issues, [])
        self.assertEqual(report.schema_version_mismatches, [])
        self.assertLess(report.test_coverage_pct, HEALTHCHECK.COVERAGE_PASS_THRESHOLD)
        self.assertEqual(report.overall_status, "WARNING")
        self.assertEqual(len(report.untested_callables), 8)


class TestFailSchemaVersionMismatch(SyntheticFixtureBase):
    def test_fail_versioned_callable_without_predecessor(self) -> None:
        # vault_foo_v3 with no vault_foo and no vault_foo_v2 -> mismatch.
        names = ["vault_alpha", "vault_foo_v3"]
        _write_synthetic_server(self.server_path, names, names, names)
        _write_synthetic_tests(self.tests_dir, names)

        report = HEALTHCHECK.build_inventory_report(self.server_path, self.tests_dir)

        self.assertEqual(report.overall_status, "FAIL")
        self.assertEqual(len(report.schema_version_mismatches), 1)
        mismatch = report.schema_version_mismatches[0]
        self.assertEqual(mismatch["callable_name"], "vault_foo_v3")

    def test_pass_versioned_callable_with_unversioned_base(self) -> None:
        # vault_foo + vault_foo_v2 -> consistent.
        names = ["vault_foo", "vault_foo_v2", "vault_foo_v3"]
        _write_synthetic_server(self.server_path, names, names, names)
        _write_synthetic_tests(self.tests_dir, names)

        report = HEALTHCHECK.build_inventory_report(self.server_path, self.tests_dir)

        self.assertEqual(report.parity_issues, [])
        self.assertEqual(report.schema_version_mismatches, [])
        self.assertEqual(report.overall_status, "PASS")


class TestCliStrictExitCode(SyntheticFixtureBase):
    def test_strict_exits_1_on_fail(self) -> None:
        # Orphan schema -> FAIL.
        schemas = ["vault_alpha", "vault_orphan"]
        methods = ["vault_alpha"]
        dispatch = ["vault_alpha"]
        _write_synthetic_server(self.server_path, schemas, methods, dispatch)
        _write_synthetic_tests(self.tests_dir, schemas)

        argv = [
            "--server-path",
            str(self.server_path),
            "--tests-dir",
            str(self.tests_dir),
            "--json",
            "--strict",
        ]
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = HEALTHCHECK.main(argv)
        self.assertEqual(rc, 1)
        # Validate JSON shape.
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["schema_id"], HEALTHCHECK.SCHEMA_ID)
        self.assertEqual(parsed["overall_status"], "FAIL")
        self.assertGreater(parsed["parity_issues_count"], 0)

    def test_strict_exits_0_on_pass(self) -> None:
        names = ["vault_alpha", "vault_beta"]
        _write_synthetic_server(self.server_path, names, names, names)
        _write_synthetic_tests(self.tests_dir, names)

        argv = [
            "--server-path",
            str(self.server_path),
            "--tests-dir",
            str(self.tests_dir),
            "--json",
            "--strict",
        ]
        out = io.StringIO()
        with redirect_stdout(out):
            rc = HEALTHCHECK.main(argv)
        self.assertEqual(rc, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["overall_status"], "PASS")


class TestLongestPrefixMatch(SyntheticFixtureBase):
    def test_v3_test_assigned_to_v3_callable_not_base(self) -> None:
        # Both callables exist; test files for both should resolve correctly.
        names = ["vault_corpus_search", "vault_corpus_search_v3"]
        _write_synthetic_server(self.server_path, names, names, names)
        self.tests_dir.mkdir(parents=True, exist_ok=True)
        # test_vault_corpus_search_v3_callable.py must bind to v3.
        (self.tests_dir / "test_vault_corpus_search_v3_callable.py").write_text(
            "# synthetic_fixture: true\n", encoding="utf-8"
        )
        # test_vault_corpus_search_callable.py binds to base.
        (self.tests_dir / "test_vault_corpus_search_callable.py").write_text(
            "# synthetic_fixture: true\n", encoding="utf-8"
        )

        test_files = HEALTHCHECK._scan_test_files(self.tests_dir)
        coverage = HEALTHCHECK._assign_tests_to_callables(names, test_files)

        self.assertIn("test_vault_corpus_search_v3_callable.py", coverage["vault_corpus_search_v3"])
        self.assertIn("test_vault_corpus_search_callable.py", coverage["vault_corpus_search"])
        # Cross-contamination check: v3 test must NOT also land on base.
        self.assertNotIn(
            "test_vault_corpus_search_v3_callable.py",
            coverage["vault_corpus_search"],
        )


class TestLiveServerParityNoIssues(unittest.TestCase):
    """Non-strict floor: the live vault-mcp-server.py must have zero parity issues.

    This guards against regressions where someone adds a schema entry without
    a corresponding method / dispatch (or vice versa).
    """

    def test_live_server_zero_parity_issues(self) -> None:
        live_server = REPO_ROOT / "tools" / "vault-mcp-server.py"
        live_tests = REPO_ROOT / "tools" / "tests"
        if not live_server.is_file():  # pragma: no cover - defensive
            self.skipTest(f"Live server not found at {live_server}")
        report = HEALTHCHECK.build_inventory_report(live_server, live_tests)
        self.assertEqual(
            report.parity_issues,
            [],
            msg=(
                "Live vault-mcp-server.py has parity violations: "
                + json.dumps([i.to_dict() for i in report.parity_issues], indent=2)
            ),
        )
        self.assertEqual(
            report.schema_version_mismatches,
            [],
            msg=f"Live server has schema-version mismatches: {report.schema_version_mismatches}",
        )
        # W2.8 note: 66 callables. Floor check: at least 60 to absorb pre-W2.8 history.
        self.assertGreaterEqual(report.total_callables, 60)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
