"""Regression test for I-22 (PR #158 follow-up).

`detectors/run_custom.py` must honor `status: documentation-only` YAMLs so that
running `python3 detectors/run_custom.py <target> <argument>` against a
companion descriptor (e.g. wave18 hand-written canonical detector) skips
cleanly with a clear message pointing at the canonical wave18 .py — instead of
silently no-op-ing or erroring with a misleading "no detectors found".

Mirrors PR #133's case-insensitive `.strip().lower() == "documentation-only"`
guard added to `tools/pattern-compile.py`.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("run_custom", RUN_CUSTOM)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class RunCustomDocOnlyHelperTest(unittest.TestCase):
    """Unit-level tests for the _check_documentation_only_yaml helper."""

    def _make_repo(self, tmp: Path, yaml_body: str | None, wave18_py: bool):
        (tmp / "reference" / "patterns.dsl").mkdir(parents=True)
        (tmp / "detectors" / "wave18").mkdir(parents=True)
        if yaml_body is not None:
            (tmp / "reference" / "patterns.dsl" / "fake-doc-only.yaml").write_text(yaml_body)
        if wave18_py:
            (tmp / "detectors" / "wave18" / "fake_doc_only.py").write_text("# canonical\n")
        return tmp

    def test_documentation_only_yaml_returns_true_with_canonical(self):
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(
                Path(tmp),
                yaml_body=textwrap.dedent(
                    """\
                    pattern: fake-doc-only
                    status: documentation-only
                    """
                ),
                wave18_py=True,
            )
            is_doc, path = mod._check_documentation_only_yaml("fake-doc-only", root)
            self.assertTrue(is_doc, "documentation-only YAML must report True")
            self.assertIsNotNone(path)
            self.assertEqual(path.name, "fake_doc_only.py")

    def test_documentation_only_yaml_no_canonical(self):
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(
                Path(tmp),
                yaml_body=textwrap.dedent(
                    """\
                    pattern: fake-doc-only
                    status: documentation-only
                    """
                ),
                wave18_py=False,
            )
            is_doc, path = mod._check_documentation_only_yaml("fake-doc-only", root)
            self.assertTrue(is_doc)
            self.assertIsNone(path, "no wave18/<arg>.py → canonical path None")

    def test_uppercase_documentation_only_matches(self):
        """Mirror PR #133: case-insensitive match after .strip().lower()."""
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(
                Path(tmp),
                yaml_body=textwrap.dedent(
                    """\
                    pattern: fake-doc-only
                    status: Documentation-Only
                    """
                ),
                wave18_py=False,
            )
            is_doc, _ = mod._check_documentation_only_yaml("fake-doc-only", root)
            self.assertTrue(is_doc, "case-insensitive skip required")

    def test_normal_yaml_returns_false(self):
        """Non-documentation-only YAML → fall through to load_detectors."""
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(
                Path(tmp),
                yaml_body=textwrap.dedent(
                    """\
                    pattern: fake-doc-only
                    status: ready
                    """
                ),
                wave18_py=False,
            )
            is_doc, _ = mod._check_documentation_only_yaml("fake-doc-only", root)
            self.assertFalse(is_doc, "status:ready must NOT trigger skip")

    def test_non_slither_backend_yaml_is_detected(self):
        """Rust/CosmWasm corpus rows must not be loaded as Slither detectors."""
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(
                Path(tmp),
                yaml_body=textwrap.dedent(
                    """\
                    pattern: fake-doc-only
                    backend: rust
                    status: ready
                    """
                ),
                wave18_py=False,
            )
            skip, backend = mod._check_non_slither_backend_yaml("fake-doc-only", root)
            self.assertTrue(skip)
            self.assertEqual(backend, "rust")

    def test_slither_backend_yaml_is_not_skipped_by_backend_guard(self):
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(
                Path(tmp),
                yaml_body=textwrap.dedent(
                    """\
                    pattern: fake-doc-only
                    backend: solidity
                    status: ready
                    """
                ),
                wave18_py=False,
            )
            skip, backend = mod._check_non_slither_backend_yaml("fake-doc-only", root)
            self.assertFalse(skip)
            self.assertEqual(backend, "solidity")

    def test_missing_yaml_returns_false(self):
        """No YAML at all → fall through (preserve existing error path)."""
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(Path(tmp), yaml_body=None, wave18_py=False)
            is_doc, path = mod._check_documentation_only_yaml("nonexistent-arg", root)
            self.assertFalse(is_doc, "missing YAML must fall through, not skip")
            self.assertIsNone(path)

    def test_yaml_without_status_returns_false(self):
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(
                Path(tmp),
                yaml_body="pattern: fake-doc-only\n",
                wave18_py=False,
            )
            is_doc, _ = mod._check_documentation_only_yaml("fake-doc-only", root)
            self.assertFalse(is_doc, "missing status field → no skip")

    def test_empty_argument_returns_false(self):
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(Path(tmp), yaml_body=None, wave18_py=False)
            is_doc, _ = mod._check_documentation_only_yaml("", root)
            self.assertFalse(is_doc)

    def test_whitespace_padded_status_matches(self):
        mod = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._make_repo(
                Path(tmp),
                yaml_body=textwrap.dedent(
                    """\
                    pattern: fake-doc-only
                    status: "  documentation-only  "
                    """
                ),
                wave18_py=False,
            )
            is_doc, _ = mod._check_documentation_only_yaml("fake-doc-only", root)
            self.assertTrue(is_doc, "whitespace-padded status must still match")


class RunCustomDocOnlyRealCorpusTest(unittest.TestCase):
    """Integration check against a real documentation-only YAML in the repo."""

    def test_real_doc_only_yaml_in_corpus_is_detected(self):
        """`reference/patterns.dsl/forwarder-nonce-on-revert.yaml` is a known
        documentation-only descriptor whose canonical implementation lives at
        `detectors/wave18/forwarder_nonce_on_revert.py`. The helper must
        identify it as doc-only and find the canonical path."""
        mod = _load_module()
        yaml_path = REPO / "reference" / "patterns.dsl" / "forwarder-nonce-on-revert.yaml"
        wave18_path = REPO / "detectors" / "wave18" / "forwarder_nonce_on_revert.py"
        if not yaml_path.is_file() or not wave18_path.is_file():
            self.skipTest("real corpus assets missing — skip integration check")
        is_doc, path = mod._check_documentation_only_yaml(
            "forwarder-nonce-on-revert", REPO
        )
        self.assertTrue(is_doc, "real doc-only YAML must be detected as such")
        self.assertIsNotNone(path)
        self.assertEqual(path, wave18_path)


class RunCustomCliHygieneTest(unittest.TestCase):
    def test_help_does_not_require_slither(self):
        proc = subprocess.run(
            [sys.executable, str(RUN_CUSTOM), "--help"],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Usage:", proc.stdout)
        self.assertNotIn("slither-analyzer not installed", proc.stderr)


if __name__ == "__main__":
    unittest.main()
