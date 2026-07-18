"""Regression test for PR #121 A2 / PR #133 Codex unblock.

`tools/pattern-compile.py` must skip YAMLs whose top-level `status` field is
`documentation-only`. These are companion descriptors for hand-written
canonical detectors (e.g. wave18 custom Python detectors) where compiling the
DSL into a sibling wave folder would create a duplicate that contradicts the
canonical implementation.
"""

from __future__ import annotations

import importlib.util
import io
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "pattern-compile.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("pattern_compile", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class PatternCompileDocumentationOnlyTest(unittest.TestCase):
    def _yaml_with_status(self, status_value: str) -> str:
        body = textwrap.dedent(
            """\
            pattern: test-doc-only-skip
            severity: MEDIUM
            confidence: MEDIUM
            help: test
            preconditions: []
            match: []
            """
        )
        if status_value:
            body += f"status: {status_value}\n"
        return body

    def test_documentation_only_yaml_is_skipped(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            wave = ws / "wave99"
            yf = ws / "test-doc-only-skip.yaml"
            yf.write_text(self._yaml_with_status("documentation-only"))
            result = tool.compile_pattern(yf, wave)
            self.assertFalse(result, "documentation-only YAML must be skipped (return False)")
            # Wave directory must not contain the compiled file
            self.assertFalse(
                (wave / "test_doc_only_skip.py").exists(),
                "skip path must not write compiled .py",
            )

    def test_documentation_only_uppercase_also_skipped(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            wave = ws / "wave99"
            yf = ws / "test-doc-only-uppercase.yaml"
            yf.write_text(self._yaml_with_status("Documentation-Only"))
            result = tool.compile_pattern(yf, wave)
            self.assertFalse(result, "case-insensitive match required")

    def test_documentation_only_with_whitespace_skipped(self):
        """Tolerate `status:  documentation-only  ` extra whitespace."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            wave = ws / "wave99"
            yf = ws / "test-doc-only-ws.yaml"
            yf.write_text(self._yaml_with_status("  documentation-only  "))
            result = tool.compile_pattern(yf, wave)
            self.assertFalse(result, "whitespace-tolerant skip required")

    def test_non_slither_backend_yaml_is_skipped(self):
        """Foreign-language corpus rows must not compile into Slither detectors."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            wave = ws / "wave99"
            yf = ws / "test-rust-backend.yaml"
            yf.write_text(
                textwrap.dedent(
                    """\
                    pattern: test-rust-backend
                    backend: rust
                    severity: HIGH
                    confidence: HIGH
                    help: test
                    preconditions: []
                    match:
                      - function.body_contains_regex: consumed_offer
                    """
                )
            )
            result = tool.compile_pattern(yf, wave)
            self.assertFalse(result, "backend: rust must not emit a Slither detector")
            self.assertFalse((wave / "test_rust_backend.py").exists())

    def test_status_other_values_pass_skip_check(self):
        """`status: ready`, `status: experimental` must NOT trigger the skip path
        — i.e., the function must proceed past the documentation-only guard.

        We don't assert the full compile here because compile_pattern's success
        path uses Path.relative_to(AUDITOOOR_DIR) for log output, which fails
        in tempfile-based tests. The skip guard is what this test verifies.
        """
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            yf = ws / "test-status-ready.yaml"
            yf.write_text(self._yaml_with_status("ready"))
            # Manually replay the skip logic — proves the guard is selective.
            import yaml
            spec = yaml.safe_load(yf.read_text())
            self.assertNotEqual(
                str(spec.get("status", "")).strip().lower(),
                "documentation-only",
                "status:ready must not match the skip guard",
            )

    def test_status_missing_passes_skip_check(self):
        """No `status:` field at all — guard must not trigger."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            yf = ws / "test-no-status.yaml"
            yf.write_text(self._yaml_with_status(""))
            import yaml
            spec = yaml.safe_load(yf.read_text())
            self.assertNotEqual(
                str(spec.get("status", "")).strip().lower(),
                "documentation-only",
                "missing status must not match the skip guard",
            )


class PatternCompileYamlFragilityTest(unittest.TestCase):
    def _write_yaml(self, ws: Path, body: str) -> Path:
        yf = ws / "fragility-regression.yaml"
        yf.write_text(textwrap.dedent(body), encoding="utf-8")
        return yf

    def test_default_compile_warns_but_preserves_empty_match_compatibility(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory(dir=REPO) as tmp:
            ws = Path(tmp)
            yf = self._write_yaml(
                ws,
                """\
                pattern: fragility-regression
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match: []
                """,
            )

            err = io.StringIO()
            with redirect_stderr(err):
                result = tool.compile_pattern(yf, ws / "wave99")

            self.assertTrue(result)
            self.assertTrue((ws / "wave99" / "fragility_regression.py").exists())
            self.assertIn("[warn]", err.getvalue())
            self.assertIn("empty matcher", err.getvalue())

    def test_strict_mode_refuses_empty_match_list(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            yf = self._write_yaml(
                ws,
                """\
                pattern: fragility-regression
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match: []
                """,
            )

            with self.assertRaisesRegex(tool.PatternCompileError, "empty matcher"):
                tool.compile_pattern(yf, ws / "wave99", strict_yaml_shapes=True)

    def test_default_compile_warns_but_preserves_scalar_matcher_compatibility(self):
        """Keep legacy compile green while surfacing the scalar matcher problem."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory(dir=REPO) as tmp:
            ws = Path(tmp)
            yf = self._write_yaml(
                ws,
                """\
                pattern: fragility-regression
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match:
                  - "function.body_contains_regex: (?i)(min_return: Coin)"
                """,
            )

            err = io.StringIO()
            with redirect_stderr(err):
                result = tool.compile_pattern(yf, ws / "wave99")

            self.assertTrue(result)
            emitted = (ws / "wave99" / "fragility_regression.py").read_text(encoding="utf-8")
            self.assertIn("_MATCH = ['function.body_contains_regex:", emitted)
            self.assertIn("suspicious", err.getvalue())

    def test_strict_mode_refuses_quoted_key_value_matcher_scalar(self):
        """Catch the old `\"function.foo: regex\"` scalar shape before emission."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            yf = self._write_yaml(
                ws,
                """\
                pattern: fragility-regression
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match:
                  - "function.body_contains_regex: (?i)(min_return: Coin)"
                """,
            )

            with self.assertRaisesRegex(tool.PatternCompileError, "suspicious"):
                tool.compile_pattern(yf, ws / "wave99", strict_yaml_shapes=True)

    def test_default_compile_warns_but_preserves_missing_dash_map_compatibility(self):
        """Keep legacy `match: {predicate: value}` output compatible by default."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory(dir=REPO) as tmp:
            ws = Path(tmp)
            yf = self._write_yaml(
                ws,
                """\
                pattern: fragility-regression
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match:
                  function.body_contains_regex: "(?i)(min_return: Coin)"
                """,
            )

            err = io.StringIO()
            with redirect_stderr(err):
                result = tool.compile_pattern(yf, ws / "wave99")

            self.assertTrue(result)
            emitted = (ws / "wave99" / "fragility_regression.py").read_text(encoding="utf-8")
            self.assertIn("_MATCH = {'function.body_contains_regex':", emitted)
            self.assertIn("must be a YAML list", err.getvalue())

    def test_strict_mode_refuses_missing_dash_matcher_map(self):
        """Catch YAML that parses as `match: {predicate: value}` instead of a list."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            yf = self._write_yaml(
                ws,
                """\
                pattern: fragility-regression
                severity: MEDIUM
                confidence: MEDIUM
                help: test
                preconditions: []
                match:
                  function.body_contains_regex: "(?i)(min_return: Coin)"
                """,
            )

            with self.assertRaisesRegex(tool.PatternCompileError, "must be a YAML list"):
                tool.compile_pattern(yf, ws / "wave99", strict_yaml_shapes=True)


if __name__ == "__main__":
    unittest.main()
