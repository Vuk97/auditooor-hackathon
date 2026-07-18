"""Tests for tools/l29_filing_check.py — L29-Filing pre-submit gates."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
import pathlib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "l29_filing_check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("l29_filing_check", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["l29_filing_check"] = module
    spec.loader.exec_module(module)
    return module


l29 = _load_module()


def _make_workspace(tmp: Path) -> tuple[Path, Path]:
    """Build a fake workspace ``<tmp>/ws`` with a paste-ready and a manifest stub.

    Returns ``(paste_path, manifest_path)``.
    """
    ws = tmp / "ws"
    (ws / "submissions" / "packaged" / "f1").mkdir(parents=True, exist_ok=True)
    paste = ws / "submissions" / "packaged" / "f1" / "finding.md"
    manifest = ws / "submissions" / "packaged" / "f1" / "manifest.json"
    return paste, manifest


# -------------------- Check A --------------------


class CheckATitleOverlap(unittest.TestCase):
    def test_pass_no_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste, manifest = _make_workspace(Path(td))
            paste.write_text(
                "# Front-running risk in mempool ordering causes MEV leakage\n\n"
                "Body.\n"
            )
            manifest.write_text(
                json.dumps({
                    "not_proven_impacts": [
                        "permanent freezing of funds — not demonstrated",
                        "chain split via L1 finalization — not demonstrated",
                    ],
                })
            )
            passed, msg = l29.check_a_title_overlap(paste)
            self.assertTrue(passed, msg)

    def test_fail_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste, manifest = _make_workspace(Path(td))
            paste.write_text(
                "# Validator bug leads to chain split between honest peers\n\n"
                "Body.\n"
            )
            manifest.write_text(
                json.dumps({
                    "gates": {
                        "rubric": {
                            "not_proven_impacts": [
                                "Unintended permanent chain split requiring hard fork",
                            ],
                        },
                    },
                })
            )
            passed, msg = l29.check_a_title_overlap(paste)
            self.assertFalse(passed, msg)
            self.assertIn("chain split", msg)


# -------------------- Check B --------------------


class CheckBProvenEvidence(unittest.TestCase):
    def test_pass_proven_with_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste, manifest = _make_workspace(Path(td))
            paste.write_text("# any title\n")
            poc = paste.parent / "test_x.t.sol"
            poc.write_text("function test_x() {}\n")
            manifest.write_text(
                json.dumps({
                    "proven_impacts": [
                        {
                            "impact": "loss-of-funds",
                            "poc_path": "submissions/packaged/f1/test_x.t.sol",
                            "pass_evidence_lines": [10, 11, 12],
                        }
                    ],
                })
            )
            passed, msg = l29.check_b_proven_evidence(paste)
            self.assertTrue(passed, msg)

    def test_fail_missing_pass_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste, manifest = _make_workspace(Path(td))
            paste.write_text("# any title\n")
            poc = paste.parent / "test_x.t.sol"
            poc.write_text("function test_x() {}\n")
            manifest.write_text(
                json.dumps({
                    "proven_impacts": [
                        {
                            "impact": "loss-of-funds",
                            "poc_path": "submissions/packaged/f1/test_x.t.sol",
                            # pass_evidence_lines missing
                        }
                    ],
                })
            )
            passed, msg = l29.check_b_proven_evidence(paste)
            self.assertFalse(passed, msg)
            self.assertIn("pass_evidence_lines", msg)


# -------------------- Check C --------------------


class CheckCContentHash(unittest.TestCase):
    def test_pass_record_then_verify(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste, _ = _make_workspace(Path(td))
            paste.write_text("# title\nbody\n")
            ok, _ = l29.check_c_record_hash(paste)
            self.assertTrue(ok)
            ok, msg = l29.check_c_verify_hash(paste)
            self.assertTrue(ok, msg)

    def test_fail_hash_mismatch_after_edit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste, _ = _make_workspace(Path(td))
            paste.write_text("# title\nbody\n")
            ok, _ = l29.check_c_record_hash(paste)
            self.assertTrue(ok)
            # tamper
            paste.write_text("# title\nedited body\n")
            ok, msg = l29.check_c_verify_hash(paste)
            self.assertFalse(ok, msg)
            self.assertIn("mismatch", msg)


# -------------------- Check D --------------------


class CheckDManifestAndTestNames(unittest.TestCase):
    def test_pass_no_cross_cite_no_test_names(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste, manifest = _make_workspace(Path(td))
            paste.write_text(
                "# title\n\n"
                "This finding has no cross citations and no test_ references.\n"
            )
            manifest.write_text(json.dumps({}))
            passed, msg = l29.check_d_manifest_and_testnames(paste)
            self.assertTrue(passed, msg)

    def test_pass_test_name_resolves_in_cited_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste, manifest = _make_workspace(Path(td))
            test_file = paste.parent / "MyPoC.t.sol"
            test_file.write_text(
                "contract X {\n  function test_first_path() public {}\n}\n"
            )
            paste.write_text(
                "# title\n\n"
                "See `submissions/packaged/f1/MyPoC.t.sol` and run `test_first_path`.\n"
            )
            manifest.write_text(json.dumps({}))
            passed, msg = l29.check_d_manifest_and_testnames(paste)
            self.assertTrue(passed, msg)

    def test_fail_cross_cite_without_manifest_field(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste, manifest = _make_workspace(Path(td))
            paste.write_text(
                "# title\n\n"
                "This finding cross-cites another lane's PoC.\n"
            )
            manifest.write_text(json.dumps({"some_other_field": []}))
            passed, msg = l29.check_d_manifest_and_testnames(paste)
            self.assertFalse(passed, msg)
            self.assertIn("cross_cited_proof_artifacts", msg)

    def test_fail_test_name_missing_in_cited_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            paste, manifest = _make_workspace(Path(td))
            test_file = paste.parent / "MyPoC.t.sol"
            test_file.write_text(
                "contract X {\n  function test_real_name() public {}\n}\n"
            )
            paste.write_text(
                "# title\n\n"
                "See `submissions/packaged/f1/MyPoC.t.sol` and run "
                "`test_imaginary_name`.\n"
            )
            manifest.write_text(json.dumps({}))
            passed, msg = l29.check_d_manifest_and_testnames(paste)
            self.assertFalse(passed, msg)
            self.assertIn("test-name", msg)




# -------------------- _rglob_sorted helper (bug: unsorted rglob[:N]) --------------------


class RglobSortedHelper(unittest.TestCase):
    """Unit tests for _rglob_sorted - the fix for unsorted rglob fallback.

    Before the fix: list(root.rglob(base))[:N] returned filesystem-order hits,
    which on many OSes is creation-order.  A mock file created first would
    shadow the real source file.

    After the fix: _rglob_sorted returns hits ordered by (depth, mock-flag, path)
    so the shallowest non-mock file is always first.
    """

    def test_shallower_path_preferred_over_deeper(self) -> None:
        """Shallower path (fewer separators) wins regardless of creation order."""
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            deep = root / "a" / "b" / "c" / "test_poc.py"
            shallow = root / "src" / "test_poc.py"
            deep.parent.mkdir(parents=True)
            shallow.parent.mkdir(parents=True)
            # Create deep first so naive filesystem iteration might return it first
            deep.write_text("deep")
            shallow.write_text("shallow")
            hits = l29._rglob_sorted(root, "test_poc.py", 5)
            self.assertGreater(len(hits), 1, "expected both hits")
            self.assertEqual(hits[0], shallow, f"Expected shallow first, got {hits[0]}")

    def test_mock_path_deprioritised(self) -> None:
        """Path with 'mock' in any component is deprioritised vs same-depth real path."""
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            mock_file = root / "mocks" / "test_poc.py"
            real_file = root / "src" / "test_poc.py"
            mock_file.parent.mkdir(parents=True)
            real_file.parent.mkdir(parents=True)
            # Create mock first - at same depth as real
            mock_file.write_text("def test_something(): pass  # stub")
            real_file.write_text("def test_something(): assert True")
            hits = l29._rglob_sorted(root, "test_poc.py", 5)
            self.assertEqual(len(hits), 2)
            self.assertEqual(hits[0], real_file, f"Expected real_file first, got {hits[0]}")
            self.assertEqual(hits[1], mock_file)

    def test_stub_and_fake_also_deprioritised(self) -> None:
        """'stub' and 'fake' in path component trigger the same deprioritisation."""
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            stub_file = root / "stubs" / "test_poc.py"
            fake_file = root / "fake" / "test_poc.py"
            real_file = root / "src" / "test_poc.py"
            for f in (stub_file, fake_file, real_file):
                f.parent.mkdir(parents=True)
                f.write_text("content")
            hits = l29._rglob_sorted(root, "test_poc.py", 5)
            self.assertEqual(hits[0], real_file, f"Expected real_file first, got {hits[0]}")

    def test_cap_respected(self) -> None:
        """cap parameter limits the returned list."""
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            for i in range(6):
                d = root / f"dir{i}"
                d.mkdir()
                (d / "test_poc.py").write_text(f"content {i}")
            hits = l29._rglob_sorted(root, "test_poc.py", 3)
            self.assertEqual(len(hits), 3)


class CheckBRglobFallbackPicksNonMock(unittest.TestCase):
    """End-to-end test: Check B rglob fallback must not pick a mock over real source.

    Scenario: poc_path in manifest is a bare basename (triggers rglob fallback).
    Two files exist: ws/mocks/test_poc.py (stub) and ws/src/test_poc.py (real).
    Mock created first so naive filesystem iteration returns it first.
    After fix: Check B resolves to the real (shallower / non-mock) file.
    Before fix: Check B resolves to the mock, which also has pass_evidence_lines
    in the manifest, so the check FALSELY passes despite the real file being missing
    from the resolved path.
    """

    def test_resolves_shallower_non_mock_over_mock(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            ws = root / "ws"
            (ws / "submissions").mkdir(parents=True)
            # Create mock FIRST so naive rglob would return it first
            mock_poc = ws / "mocks" / "test_poc.py"
            mock_poc.parent.mkdir(parents=True)
            mock_poc.write_text("def test_something(): pass\n")
            # Create real source at shallower depth
            real_poc = ws / "src" / "test_poc.py"
            real_poc.parent.mkdir(parents=True)
            real_poc.write_text("def test_something(): assert True\n")
            # Set up paste and manifest
            paste = ws / "submissions" / "finding.md"
            paste.write_text("# poc test\n")
            manifest = ws / "submissions" / "manifest.json"
            manifest.write_text(json.dumps({
                "proven_impacts": [{
                    "impact": "loss-of-funds",
                    # bare basename - triggers rglob fallback
                    "poc_path": "test_poc.py",
                    "pass_evidence_lines": ["PASS"],
                }]
            }))
            # After fix: resolves to the shallower real file, not the mock
            resolved = l29._resolve_poc_path("test_poc.py", ws, paste)
            self.assertIsNotNone(resolved, "expected a resolved path")
            resolved_str = str(resolved)
            self.assertNotIn("mock", resolved_str.lower(),
                f"rglob fallback returned a mock path: {resolved_str}")
            self.assertIn("src", resolved_str,
                f"Expected src/ path, got: {resolved_str}")


# r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
# NOTE: the "_rglob_sorted prefers real source over mock/deep duplicate" behavior is
# already guarded by the five ordering tests above (depth-ascending, mock-flag,
# lexicographic). A prior end-to-end test here placed the candidate .py files OUTSIDE
# check_d_manifest_and_testnames' actual search root, so it passed for the wrong reason
# (vacuous) rather than exercising the fix. It was removed instead of left as a
# misleading green guard.

if __name__ == "__main__":
    unittest.main()
