"""Regression test for Worker-U Loop 5 path A: extend the
``check_yaml_wave17_consistency`` doc-only-status filter set.

Worker-R Loop 4 confirmed (see ``docs/next-loop/yaml_wave17_wiring_2026-05-06.md``)
that the missing-py bucket of 15 was dominated by 12 YAMLs whose top-level
``status:`` field was set to one of:

    * ``not-submit-ready``
    * ``handwritten-detector``
    * ``blocked_semantic_detector``

Worker-U extended the ``documentation-only`` filter in
``tools/audit-closeout-check.py`` to also exclude these three tokens, dropping
the bucket from 15 to ~3.

This test locks the contract for the new filter set:

* a synthetic YAML with ``status: not-submit-ready`` MUST be excluded from the
  ``missing_py`` bucket (i.e., not counted as a wiring gap),
* a synthetic YAML with ``status: implemented_v0`` MUST still be counted (the
  filter is exact-match on the four allow-listed tokens, never a wildcard).

The filter must remain exact-match on the top-level ``status:`` scalar; never
a substring match against random fields. See the inline docstring on
``check_yaml_wave17_consistency`` and ``_yaml_pattern_records`` for the
contract this test guards.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


def _load_closeout_module():
    """Import tools/audit-closeout-check.py despite the dashed filename."""
    spec = importlib.util.spec_from_file_location(
        "audit_closeout_check_under_test_path_a",
        REPO / "tools" / "audit-closeout-check.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_pattern(root: Path, kebab: str, status: str | None) -> None:
    body = f"pattern: {kebab}\n"
    if status is not None:
        body += f"status: {status}\n"
    body += textwrap.dedent(
        """\
        match:
          - kind: function
            preconditions: []
        """
    )
    (root / f"{kebab}.yaml").write_text(body, encoding="utf-8")


class DocOnlyStatusFilterContractTest(unittest.TestCase):
    """Lock the four-token doc-only-status filter set."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_root = Path(self._tmp.name)
        (self.repo_root / "reference" / "patterns.dsl").mkdir(parents=True)
        (self.repo_root / "detectors" / "wave17").mkdir(parents=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ------------------------------------------------------------------ excluded
    def test_not_submit_ready_status_is_filtered_out(self) -> None:
        m = _load_closeout_module()
        _write_pattern(
            self.repo_root / "reference" / "patterns.dsl",
            "synthetic-not-submit-ready",
            "not-submit-ready",
        )
        result = m.check_yaml_wave17_consistency(
            self.repo_root, require_strict_wiring=False,
        )
        self.assertNotIn(
            "synthetic_not_submit_ready",
            result.detail.get("missing_py", []),
            "not-submit-ready YAML must be excluded from missing_py bucket",
        )
        self.assertEqual(result.detail.get("missing_py_total", 0), 0)
        # Documentation-only counter MUST include this row (path A reuses
        # the same bucket as ``documentation-only``).
        self.assertEqual(
            result.detail.get("documentation_only_yaml_count", 0), 1,
        )

    def test_handwritten_detector_status_is_filtered_out(self) -> None:
        m = _load_closeout_module()
        _write_pattern(
            self.repo_root / "reference" / "patterns.dsl",
            "synthetic-handwritten",
            "handwritten-detector",
        )
        result = m.check_yaml_wave17_consistency(
            self.repo_root, require_strict_wiring=False,
        )
        self.assertEqual(result.detail.get("missing_py_total", 0), 0)

    def test_blocked_semantic_detector_status_is_filtered_out(self) -> None:
        m = _load_closeout_module()
        _write_pattern(
            self.repo_root / "reference" / "patterns.dsl",
            "synthetic-blocked-semantic",
            "blocked_semantic_detector",
        )
        result = m.check_yaml_wave17_consistency(
            self.repo_root, require_strict_wiring=False,
        )
        self.assertEqual(result.detail.get("missing_py_total", 0), 0)

    def test_documentation_only_status_remains_filtered_out(self) -> None:
        """Backwards-compatibility: original ``documentation-only`` token
        must keep working."""
        m = _load_closeout_module()
        _write_pattern(
            self.repo_root / "reference" / "patterns.dsl",
            "synthetic-doc-only",
            "documentation-only",
        )
        result = m.check_yaml_wave17_consistency(
            self.repo_root, require_strict_wiring=False,
        )
        self.assertEqual(result.detail.get("missing_py_total", 0), 0)

    # ------------------------------------------------------------------ counted
    def test_implemented_v0_status_is_counted(self) -> None:
        """Filter is exact-match on the four allow-listed tokens; any other
        status (including the canonical ``implemented_v0``) MUST flag the
        wiring gap."""
        m = _load_closeout_module()
        _write_pattern(
            self.repo_root / "reference" / "patterns.dsl",
            "synthetic-implemented-v0",
            "implemented_v0",
        )
        result = m.check_yaml_wave17_consistency(
            self.repo_root, require_strict_wiring=False,
        )
        self.assertIn(
            "synthetic_implemented_v0",
            result.detail.get("missing_py", []),
            (
                "implemented_v0 YAML with no wave17 .py mate MUST be "
                "counted as a missing-py wiring gap; path A must NOT "
                "expand the filter to non-allow-listed tokens"
            ),
        )
        self.assertGreaterEqual(result.detail.get("missing_py_total", 0), 1)

    def test_no_status_field_is_counted(self) -> None:
        """A YAML missing a ``status:`` field entirely MUST count as a gap
        (Worker-R found 3 such EIP-712 YAMLs in the bucket)."""
        m = _load_closeout_module()
        _write_pattern(
            self.repo_root / "reference" / "patterns.dsl",
            "synthetic-no-status",
            None,
        )
        result = m.check_yaml_wave17_consistency(
            self.repo_root, require_strict_wiring=False,
        )
        self.assertIn(
            "synthetic_no_status",
            result.detail.get("missing_py", []),
        )

    def test_filter_is_top_level_scalar_not_substring(self) -> None:
        """Substring 'not-submit-ready' appearing inside a non-status field
        (e.g., a comment or description) must NOT exclude the YAML."""
        m = _load_closeout_module()
        kebab = "synthetic-substring-trap"
        body = textwrap.dedent(
            f"""\
            pattern: {kebab}
            status: implemented_v0
            description: |
              This pattern is not-submit-ready in some downstream branches
              but the top-level status above is the source of truth.
            match:
              - kind: function
                preconditions: []
            """
        )
        (self.repo_root / "reference" / "patterns.dsl"
         / f"{kebab}.yaml").write_text(body, encoding="utf-8")
        result = m.check_yaml_wave17_consistency(
            self.repo_root, require_strict_wiring=False,
        )
        self.assertIn(
            "synthetic_substring_trap",
            result.detail.get("missing_py", []),
            (
                "Substring match would incorrectly exclude this YAML; "
                "filter must read the top-level status: scalar only."
            ),
        )


if __name__ == "__main__":
    unittest.main()
