"""Tests for ``tools/wave2-firm-parser-coverage-matrix.py``.

The tests build a tiny synthetic workspace tree with two stub firm
parsers + fixture builders, run the matrix tool against it, and check
the schema invariants. We also re-import the tool to exercise a couple
of pure helpers directly (no PDF generation needed for those).

All synthetic fixture YAML bodies carry ``synthetic_fixture: true`` per
operator discipline.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "wave2-firm-parser-coverage-matrix.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("w2_coverage_matrix", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["w2_coverage_matrix"] = mod
    spec.loader.exec_module(mod)
    return mod


_TOOL = _load_tool()


# ---------------------------------------------------------------------------
# Synthetic-workspace builders.
# ---------------------------------------------------------------------------


_STUB_PARSER_TEMPLATE = '''#!/usr/bin/env python3
"""Synthetic firm parser stub for coverage-matrix tests.

# synthetic_fixture: true
"""
FIRM_PREFIX = "{firm_prefix}"
PARSER_FIRM_VARIANT = "{variant}"


def _attack_class_from_title(title: str) -> str:
    """Stub heuristic; we never call this directly from the matrix tool."""
    return "audit-firm-finding-other"


# Reference call so the regex sees pdf_finding_extractor.extract_<variant>_findings.
def _ref():
    import pdf_finding_extractor  # type: ignore
    return pdf_finding_extractor.extract_{variant}_findings
'''


_STUB_FIXTURE_BUILDER_TEMPLATE = '''"""Synthetic fixture builder for {variant}.

# synthetic_fixture: true
"""
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent / "{variant}"


def _sample_one() -> list:
    return ["dummy"]


def _sample_two() -> list:
    return ["dummy"]


_FIXTURES = {{
    "{variant}_a.pdf": _sample_one,
    "{variant}_b.pdf": _sample_two,
}}


def ensure_fixtures() -> dict:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    out = {{}}
    for name in _FIXTURES:
        p = FIXTURE_DIR / name
        # Tests inject fake "extraction results" via a monkeypatched
        # extractor; the PDF body content itself is irrelevant.
        if not p.is_file():
            p.write_bytes(b"%PDF-1.4 synthetic\\n%%EOF\\n")
        out[name] = p
    return out
'''


_STUB_TEST_TEMPLATE = '''"""Synthetic test file for {variant} (placeholder).

# synthetic_fixture: true
"""

def test_one():
    assert True


def test_two():
    assert True


def test_three():
    assert True
'''


def _write_stub_workspace(root: Path, firms: list) -> Path:
    """Create a tools/ tree + tests/ tree with stub parsers for `firms`."""
    tools = root / "tools"
    tests = tools / "tests"
    fixtures = tests / "fixtures" / "audit_firm_pdf_samples"
    lib = tools / "lib"
    for d in (tools, tests, fixtures, lib):
        d.mkdir(parents=True, exist_ok=True)

    # Copy the real pdf_finding_extractor so the tool can import it (the
    # tool calls extract_structured_pages on whatever PDF body we wrote).
    real_lib = REPO_ROOT / "tools" / "lib" / "pdf_finding_extractor.py"
    shutil.copy(real_lib, lib / "pdf_finding_extractor.py")

    for variant, firm_prefix in firms:
        # Parser stub.
        (tools / f"hackerman-etl-from-audit-firm-pdf-{variant}.py").write_text(
            _STUB_PARSER_TEMPLATE.format(firm_prefix=firm_prefix, variant=variant),
            encoding="utf-8",
        )
        # Fixture builder.
        (fixtures / f"_{variant}_fixture_builder.py").write_text(
            _STUB_FIXTURE_BUILDER_TEMPLATE.format(variant=variant),
            encoding="utf-8",
        )
        # Test file.
        (tests / f"test_hackerman_etl_from_audit_firm_pdf_{variant}.py").write_text(
            _STUB_TEST_TEMPLATE.format(variant=variant),
            encoding="utf-8",
        )
    return root


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------


class CoverageMatrixSyntheticTest(unittest.TestCase):
    """Run the tool against a 2-firm synthetic workspace with deterministic counts."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="w2cm_test_")
        cls.root = Path(cls._tmp)
        _write_stub_workspace(cls.root, [
            ("alphafirm", "alphafirm-audits"),
            ("betafirm", "betafirm-audits"),
        ])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def test_two_firm_synthetic_workspace_pass(self):
        # Stub parsers ship without their own ``extract_<variant>_findings``
        # in pdf_finding_extractor.py, so the matrix tool will warn and the
        # emitted-record count will be 0. That is fine: we are checking the
        # firms_discovered list and schema, not the record yield.
        summary = _TOOL.build_coverage_matrix(self.root)
        self.assertEqual(summary["schema_version"], _TOOL.SCHEMA_VERSION)
        self.assertEqual(summary["overall_status"], "INFO")
        self.assertEqual(sorted(summary["firms_discovered"]), ["alphafirm", "betafirm"])
        # Each firm has 2 fixtures.
        self.assertEqual(summary["total_fixtures"], 4)
        # Every firm should have an all-zero row in both matrices.
        for firm in ("alphafirm", "betafirm"):
            self.assertIn(firm, summary["bug_class_matrix"])
            self.assertIn(firm, summary["severity_matrix"])
            for c in _TOOL.BUG_CLASS_COLUMNS:
                self.assertEqual(summary["bug_class_matrix"][firm][c], 0)


class CoverageMatrixDiscoveryTest(unittest.TestCase):
    """The tool must auto-discover parsers via glob; not a hard-coded list."""

    def test_auto_discovers_live_corpus_parsers(self):
        summary = _TOOL.build_coverage_matrix(REPO_ROOT)
        firms = summary["firms_discovered"]
        # The live corpus should ship at least the original 7 firm parsers.
        self.assertGreaterEqual(len(firms), 7)
        # Sanity: known firms appear in the discovered list (variants).
        known = {"trailofbits", "sherlock", "pashov", "zellic", "cyfrin", "spearbit", "chainsecurity"}
        self.assertTrue(known.issubset(set(firms)),
                        f"missing known firms: {known - set(firms)}")


class CoverageMatrixGapDetectionTest(unittest.TestCase):
    """A synthetic firm with zero re-entrancy fixtures appears in coverage_gaps."""

    def test_coverage_gap_detected_for_synthetic_firm(self):
        with tempfile.TemporaryDirectory(prefix="w2cm_gap_") as tmp:
            root = Path(tmp)
            _write_stub_workspace(root, [("gammafirm", "gammafirm-audits")])
            summary = _TOOL.build_coverage_matrix(root)
            # All gammafirm columns should be in coverage_gaps because the
            # extractor has no extract_gammafirm_findings function.
            gap_pairs = {tuple(p) for p in summary["coverage_gaps"]}
            self.assertIn(("gammafirm", "reentrancy"), gap_pairs)
            self.assertIn(("gammafirm", "access-control"), gap_pairs)
            self.assertIn(("gammafirm", "oracle-manip"), gap_pairs)


class CoverageMatrixMarkdownRenderTest(unittest.TestCase):
    """``--markdown`` emits a valid Github-flavored markdown table."""

    def test_render_markdown_contains_required_sections(self):
        summary = _TOOL.build_coverage_matrix(REPO_ROOT)
        md = _TOOL.render_markdown(summary)
        self.assertIn("# Wave-2 firm-parser coverage matrix", md)
        self.assertIn("## Bug-class matrix", md)
        self.assertIn("## Severity matrix", md)
        # GFM table header line.
        self.assertIn("| firm |", md)
        # Each firm appears in the rendered output.
        for firm in summary["firms_discovered"]:
            self.assertIn(f"| {firm} |", md)


class CoverageMatrixConsistencyTest(unittest.TestCase):
    """Severity matrix row sums == bug-class matrix row sums for every firm."""

    def test_severity_and_bug_class_totals_consistent(self):
        summary = _TOOL.build_coverage_matrix(REPO_ROOT)
        for firm in summary["firms_discovered"]:
            bug_total = sum(summary["bug_class_matrix"][firm].values())
            sev_total = sum(summary["severity_matrix"][firm].values())
            self.assertEqual(
                bug_total,
                sev_total,
                f"firm {firm}: bug-class total {bug_total} != severity total {sev_total}",
            )


class CoverageMatrixCLITest(unittest.TestCase):
    """Spawn the CLI in a subprocess and validate JSON output."""

    def test_json_output_parses(self):
        result = subprocess.run(
            [sys.executable, str(TOOL_PATH), "--workspace", str(REPO_ROOT), "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema_version"], _TOOL.SCHEMA_VERSION)
        self.assertIn("firms_discovered", payload)
        self.assertIn("bug_class_matrix", payload)
        self.assertIn("severity_matrix", payload)


class CoverageMatrixNormaliseHelpersTest(unittest.TestCase):
    """Direct unit tests on the small pure helpers."""

    def test_normalise_severity(self):
        self.assertEqual(_TOOL.normalise_severity("Critical"), "critical")
        self.assertEqual(_TOOL.normalise_severity("info"), "informational")
        self.assertEqual(_TOOL.normalise_severity(""), "undetermined")
        self.assertEqual(_TOOL.normalise_severity("Gas"), "gas")

    def test_normalise_bug_class_from_parser_attack_class(self):
        self.assertEqual(
            _TOOL.normalise_bug_class("integer-overflow", "Integer overflow on fee"),
            "arithmetic",
        )
        self.assertEqual(
            _TOOL.normalise_bug_class("oracle-manipulation", "Oracle price manipulation"),
            "oracle-manip",
        )
        self.assertEqual(
            _TOOL.normalise_bug_class("audit-firm-finding-other", "Governance proposal bypass"),
            "governance",
        )
        # Fully unknown title + parser verdict falls back to other.
        self.assertEqual(
            _TOOL.normalise_bug_class("audit-firm-finding-other", "Misc code-quality nit"),
            "other",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
