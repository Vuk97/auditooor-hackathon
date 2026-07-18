#!/usr/bin/env python3
"""Tests for tools/detector-registry-completeness-check.py.

Coverage:
  1. Pattern documented AND wired  → check exits 0, row marked "wired".
  2. Pattern documented + NOT wired → check exits 1 under STRICT, "unwired".
  3. Pattern in allowlist           → check exits 0, row marked "allowlisted".
  4. New pattern fixture            → check exits 0 when wired (fresh pattern).
  5. Native Cosmos DSL row          → check exits 0 when base-scan wired.

All tests use a synthetic repo in a tempdir so the real worktree is untouched.
"""

from __future__ import annotations

import sys
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

# Import the module under test (not via subprocess so coverage works).
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "detector_registry_completeness_check",
    REPO / "tools" / "detector-registry-completeness-check.py",
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

run_check = _mod.run_check
_collect_documented_patterns = _mod._collect_documented_patterns
_collect_wired_detectors = _mod._collect_wired_detectors
_load_allowlist = _mod._load_allowlist


# ---------------------------------------------------------------------------
# Synthetic repo helpers
# ---------------------------------------------------------------------------

def _make_repo(tmp_path: Path) -> Path:
    """Create minimal fake repo skeleton in *tmp_path*."""
    (tmp_path / "Makefile").write_text("# fake makefile\n")
    (tmp_path / "detectors").mkdir()
    (tmp_path / "detectors" / "wave99").mkdir()
    (tmp_path / "reference").mkdir()
    (tmp_path / "reference" / "patterns.dsl").mkdir()
    (tmp_path / "patterns").mkdir()
    return tmp_path


def _add_yaml(repo: Path, pattern_id: str, dsl_dir: str = "patterns.dsl") -> Path:
    """Add a minimal pattern YAML to reference/<dsl_dir>/<pattern_id>.yaml."""
    dsl = repo / "reference" / dsl_dir
    dsl.mkdir(parents=True, exist_ok=True)
    yaml_path = dsl / f"{pattern_id}.yaml"
    yaml_path.write_text(textwrap.dedent(f"""\
        id: {pattern_id}
        status: active
        title: {pattern_id}
    """))
    return yaml_path


def _add_cosmos_yaml(
    repo: Path,
    pattern_id: str,
    *,
    declared_pattern: str | None = None,
    dsl_dir: str = "patterns.dsl",
) -> Path:
    """Add a minimal backend: cosmos DSL row."""
    dsl = repo / "reference" / dsl_dir
    dsl.mkdir(parents=True, exist_ok=True)
    yaml_path = dsl / f"{pattern_id}.yaml"
    yaml_path.write_text(textwrap.dedent(f"""\
        pattern: {declared_pattern or pattern_id}
        backend: cosmos
        status: active
        title: {pattern_id}
        preconditions:
          - chain.is_cosmos_sdk: true
        match:
          - function.kind: cosmos_msg_handler
    """))
    return yaml_path


def _add_detector(repo: Path, argument: str, wave: str = "wave99") -> Path:
    """Add a minimal detector .py with the given ARGUMENT to detectors/<wave>/."""
    wave_dir = repo / "detectors" / wave
    wave_dir.mkdir(parents=True, exist_ok=True)
    stem = argument.replace("-", "_")
    py_path = wave_dir / f"{stem}.py"
    py_path.write_text(textwrap.dedent(f"""\
        from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
        class FakeDetector(AbstractDetector):
            ARGUMENT = "{argument}"
            HELP = "fake"
            IMPACT = DetectorClassification.HIGH
            CONFIDENCE = DetectorClassification.MEDIUM
            WIKI = "https://example.com"
            WIKI_TITLE = "fake"
            WIKI_DESCRIPTION = "fake"
            WIKI_EXPLOIT_SCENARIO = "fake"
            WIKI_RECOMMENDATION = "fake"
            def _detect(self):
                return []
    """))
    return py_path


def _add_allowlist(repo: Path, pattern_ids: list[str]) -> Path:
    """Write patterns/.unwired_allowlist with the given IDs."""
    (repo / "patterns").mkdir(parents=True, exist_ok=True)
    path = repo / "patterns" / ".unwired_allowlist"
    path.write_text("\n".join(pattern_ids) + "\n")
    return path


def _add_native_cosmos_runner(repo: Path, *, base_scan_wired: bool = True) -> None:
    """Create the native Cosmos runner and optional base scan reference."""
    tools_dir = repo / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    (tools_dir / "cosmos-detector-runner.py").write_text("# native cosmos runner\n")
    base_scan_text = (
        'COSMOS_DETECT = "tools/cosmos-detector-runner.py"\n'
        if base_scan_wired
        else "# base scan exists but does not call the cosmos runner\n"
    )
    (tools_dir / "workspace-scan-orchestrator.py").write_text(base_scan_text)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestDetectorRegistryCompleteness(unittest.TestCase):

    # ------------------------------------------------------------------
    # Case 1: Pattern documented AND wired → exit 0, wired row
    # ------------------------------------------------------------------
    def test_documented_and_wired_passes(self):
        """A pattern with a matching detector is reported as wired; exit 0."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            _add_yaml(repo, "my-rounding-bug")
            _add_detector(repo, "my-rounding-bug")

            rc = run_check(repo=repo, strict=True, tsv=False)
            self.assertEqual(rc, 0, "Expected exit 0 when pattern is wired")

    # ------------------------------------------------------------------
    # Case 2: Pattern documented + NOT wired → exit 1 under STRICT
    # ------------------------------------------------------------------
    def test_documented_unwired_fails_strict(self):
        """An unwired documented pattern causes exit 1 when STRICT=True."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            _add_yaml(repo, "missing-detector-pattern")
            # Deliberately do NOT add a detector .py

            rc = run_check(repo=repo, strict=True, tsv=False)
            self.assertEqual(rc, 1, "Expected exit 1 for unwired pattern with STRICT")

    def test_documented_unwired_warns_without_strict(self):
        """An unwired documented pattern is a warning (not failure) without STRICT."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            _add_yaml(repo, "missing-detector-pattern-2")

            rc = run_check(repo=repo, strict=False, tsv=False)
            self.assertEqual(rc, 0, "Expected exit 0 (warn only) without STRICT")

    # ------------------------------------------------------------------
    # Case 3: Pattern in allowlist → exit 0, allowlisted row
    # ------------------------------------------------------------------
    def test_allowlisted_pattern_passes(self):
        """A pattern in .unwired_allowlist is accepted without a detector."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            _add_yaml(repo, "rust-only-pattern")
            _add_allowlist(repo, ["rust-only-pattern"])

            rc = run_check(repo=repo, strict=True, tsv=False)
            self.assertEqual(rc, 0, "Allowlisted pattern should not fail even with STRICT")

    def test_allowlist_does_not_exempt_other_patterns(self):
        """Allowlist only exempts the listed ID; other unwired patterns still fail."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            _add_yaml(repo, "rust-only-pattern")
            _add_yaml(repo, "another-unwired-pattern")
            _add_allowlist(repo, ["rust-only-pattern"])

            rc = run_check(repo=repo, strict=True, tsv=False)
            self.assertEqual(rc, 1, "Non-allowlisted unwired pattern should still fail")

    # ------------------------------------------------------------------
    # Case 4: New pattern fixture (wired fresh pattern) → exit 0
    # ------------------------------------------------------------------
    def test_new_pattern_fixture_wired(self):
        """A freshly-added documented pattern with a matching detector passes."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            _add_yaml(repo, "geometric-pool-ask-exact-amount-out-rounds-wrong-direction-allowing-theft",
                      dsl_dir="patterns.dsl.r94_solodit_rust")
            _add_detector(repo,
                          "geometric-pool-ask-exact-amount-out-rounds-wrong-direction-allowing-theft")

            rc = run_check(repo=repo, strict=True, tsv=False)
            self.assertEqual(rc, 0, "New pattern fixture with detector should pass")

    # ------------------------------------------------------------------
    # Case 5: Native Cosmos DSL row wired through base scan → exit 0
    # ------------------------------------------------------------------
    def test_cosmos_backend_pattern_wired_by_native_runner(self):
        """A backend: cosmos row is wired by the native Cosmos runner."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            _add_cosmos_yaml(repo, "w68-cosmos-native-pattern")
            _add_native_cosmos_runner(repo, base_scan_wired=True)

            wired = _collect_wired_detectors(repo)
            self.assertEqual(
                wired["w68-cosmos-native-pattern"],
                "tools/cosmos-detector-runner.py",
            )
            rc = run_check(repo=repo, strict=True, tsv=False)
            self.assertEqual(rc, 0, "Native Cosmos row should satisfy completeness")

    def test_cosmos_backend_requires_base_scan_wiring(self):
        """A Cosmos runner file alone is not enough; base scan must invoke it."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            _add_cosmos_yaml(repo, "w68-cosmos-runner-only-pattern")
            _add_native_cosmos_runner(repo, base_scan_wired=False)

            wired = _collect_wired_detectors(repo)
            self.assertNotIn("w68-cosmos-runner-only-pattern", wired)
            rc = run_check(repo=repo, strict=True, tsv=False)
            self.assertEqual(rc, 1, "Runner-only Cosmos row should remain unwired")

    def test_cosmos_backend_requires_pattern_field_to_match_filename(self):
        """Native runner rows must agree on filename stem and DSL pattern id."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            _add_cosmos_yaml(
                repo,
                "w68-cosmos-filename-pattern",
                declared_pattern="different-runtime-pattern",
            )
            _add_native_cosmos_runner(repo, base_scan_wired=True)

            wired = _collect_wired_detectors(repo)
            self.assertNotIn("w68-cosmos-filename-pattern", wired)
            rc = run_check(repo=repo, strict=True, tsv=False)
            self.assertEqual(rc, 1, "Mismatched native pattern id should remain unwired")

    # ------------------------------------------------------------------
    # TSV output sanity
    # ------------------------------------------------------------------
    def test_tsv_output_has_header_and_rows(self):
        """TSV mode emits a header line + one data row per documented pattern."""
        import io
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            _add_yaml(repo, "alpha-bug")
            _add_detector(repo, "alpha-bug")
            _add_yaml(repo, "beta-bug")  # unwired

            from unittest.mock import patch
            captured = io.StringIO()
            with patch("sys.stdout", captured):
                rc = run_check(repo=repo, strict=False, tsv=True)

            output = captured.getvalue()
            lines = [l for l in output.splitlines() if l.strip()]
            # Header + 2 data rows + 1 summary line
            self.assertGreaterEqual(len(lines), 3)
            self.assertIn("pattern_name", lines[0])
            self.assertIn("wired_status", lines[0])

    # ------------------------------------------------------------------
    # Helper unit tests
    # ------------------------------------------------------------------
    def test_load_allowlist_empty_when_missing(self):
        """_load_allowlist returns empty set when no allowlist file exists."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            result = _load_allowlist(repo)
            self.assertEqual(result, set())

    def test_load_allowlist_strips_comments(self):
        """_load_allowlist ignores comment lines and blank lines."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            _add_allowlist(repo, [
                "# this is a comment",
                "",
                "real-pattern-id",
                "# another comment",
                "second-pattern",
            ])
            result = _load_allowlist(repo)
            self.assertIn("real-pattern-id", result)
            self.assertIn("second-pattern", result)
            self.assertNotIn("# this is a comment", result)
            self.assertNotIn("", result)

    def test_collect_documented_patterns_empty_on_no_reference(self):
        """_collect_documented_patterns returns empty list when reference/ absent."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "Makefile").write_text("")
            (repo / "detectors").mkdir()
            result = _collect_documented_patterns(repo)
            self.assertEqual(result, [])

    def test_collect_wired_detectors_excludes_quarantine(self):
        """Detectors under _quarantine dirs are not counted as wired."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = _make_repo(Path(td))
            # Create a quarantine directory with a detector
            q_dir = repo / "detectors" / "wave99" / "_quarantine_test"
            q_dir.mkdir()
            py = q_dir / "quarantined_detector.py"
            py.write_text('ARGUMENT = "quarantined-pattern"\n')

            wired = _collect_wired_detectors(repo)
            self.assertNotIn("quarantined-pattern", wired)


if __name__ == "__main__":
    unittest.main()
