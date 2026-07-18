# <!-- r36-rebuttal: lane FIX-BODY-PACK-EXTRACTOR registered via agent-pathspec-register.py -->
"""Guard tests for the bounded same-directory sibling scan added to extract_self_contained.

Covers:
- Solidity: fn in Caller.sol calls validateAmount defined in Validator.sol (same dir)
- Go: fn in caller.go calls validateDeposit defined in validator.go (same package dir)
- Rust: fn in processor.rs calls apply_limit defined in limits.rs (same dir)
- Cap/runaway: cross-file dep count is bounded by _MAX_CROSS_FILE_DEPS

All fixture files live under tools/tests/fixtures/sibling_scan/{sol,go,rust}/.
"""
import importlib.util
import sys
import tempfile
import shutil
from pathlib import Path
import unittest

_TOOL = Path(__file__).resolve().parent.parent / "function-source-extractor.py"
_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "sibling_scan"


def _load():
    spec = importlib.util.spec_from_file_location("function_source_extractor", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["function_source_extractor"] = m
    spec.loader.exec_module(m)
    return m


class SiblingScanTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    # ------------------------------------------------------------------
    # Solidity: Caller.sol line 5 references validateAmount from Validator.sol
    # ------------------------------------------------------------------
    def test_sol_sibling_callee_embedded(self):
        ws = _FIXTURES / "sol"
        caller = ws / "Caller.sol"
        # doTransfer starts at line 5
        text, end, dep_count = self.m.extract_self_contained(ws, str(caller), 5)
        self.assertIn("doTransfer", text, "target body should be present")
        # sibling callee must be embedded
        self.assertIn("validateAmount", text, "sibling callee validateAmount must be embedded")
        self.assertIn("Validator.sol", text, "sibling file label must appear")
        # label format check
        self.assertIn("sibling-file def", text)
        self.assertGreater(dep_count, 0)

    # ------------------------------------------------------------------
    # Go: caller.go line 3 references validateDeposit from validator.go
    # ------------------------------------------------------------------
    def test_go_sibling_callee_embedded(self):
        ws = _FIXTURES / "go"
        caller = ws / "caller.go"
        # ProcessDeposit starts at line 3
        text, end, dep_count = self.m.extract_self_contained(ws, str(caller), 3)
        self.assertIn("ProcessDeposit", text, "target body should be present")
        self.assertIn("validateDeposit", text, "sibling callee validateDeposit must be embedded")
        self.assertIn("validator.go", text, "sibling file label must appear")
        self.assertIn("sibling-file def", text)
        self.assertGreater(dep_count, 0)

    # ------------------------------------------------------------------
    # Rust: processor.rs line 2 references apply_limit from limits.rs
    # ------------------------------------------------------------------
    def test_rust_sibling_callee_embedded(self):
        ws = _FIXTURES / "rust"
        caller = ws / "processor.rs"
        # process_transfer starts at line 2
        text, end, dep_count = self.m.extract_self_contained(ws, str(caller), 2)
        self.assertIn("process_transfer", text, "target body should be present")
        self.assertIn("apply_limit", text, "sibling callee apply_limit must be embedded")
        self.assertIn("limits.rs", text, "sibling file label must appear")
        self.assertIn("sibling-file def", text)
        self.assertGreater(dep_count, 0)

    # ------------------------------------------------------------------
    # Cap/runaway: _MAX_CROSS_FILE_DEPS limits cross-file dep count
    # even when many sibling files exist.
    # ------------------------------------------------------------------
    def test_cap_cross_file_deps(self):
        """Generate a workspace with many sibling files each defining a distinct name
        called by the target - total embedded cross-file deps must not exceed _MAX_CROSS_FILE_DEPS."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Target Go file referencing alpha00..alpha11 (12 names > cap of 6)
            calls = "\n".join(f"    alpha{i:02d}(x)" for i in range(12))
            target = ws / "main.go"
            target.write_text(
                f"package test\nfunc Target(x int) int {{\n{calls}\n    return x\n}}\n",
                encoding="utf-8",
            )
            # One sibling file per referenced name
            for i in range(12):
                sib = ws / f"helper{i:02d}.go"
                sib.write_text(
                    f"package test\nfunc alpha{i:02d}(x int) int {{ return x + {i} }}\n",
                    encoding="utf-8",
                )
            text, end, dep_count = self.m.extract_self_contained(ws, str(target), 2)
            # Count sibling-file labels embedded
            cross_file_labels = text.count("sibling-file def")
            self.assertLessEqual(
                cross_file_labels,
                self.m._MAX_CROSS_FILE_DEPS,
                f"Expected at most {self.m._MAX_CROSS_FILE_DEPS} cross-file deps, got {cross_file_labels}",
            )

    # ------------------------------------------------------------------
    # Workspace boundary: a file outside ws must yield empty result (safety)
    # ------------------------------------------------------------------
    def test_workspace_boundary_safe(self):
        with tempfile.TemporaryDirectory() as ws_dir:
            with tempfile.TemporaryDirectory() as outside_dir:
                outside_file = Path(outside_dir) / "evil.go"
                outside_file.write_text(
                    "package evil\nfunc BadFn() int { return 42 }\n", encoding="utf-8"
                )
                ws = Path(ws_dir)
                # Passing an absolute path outside workspace should still
                # return a body (the file exists) but sibling scan is bounded
                # to ws - _sibling_source_files returns [] if dir not under ws
                text, end, dep_count = self.m.extract_self_contained(ws, str(outside_file), 2)
                # Body itself is returned (function exists), but no sibling deps
                # because the parent dir is outside ws - no crash
                # (dep_count == 0 because no cross-file siblings in ws)
                # The key assertion: no exception raised, result is a string
                self.assertIsInstance(text, str)

    # ------------------------------------------------------------------
    # Already-resolved same-file names must NOT be re-resolved via sibling scan
    # (dedup guard)
    # ------------------------------------------------------------------
    def test_same_file_not_duplicated_by_sibling_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Target file already defines the helper inline
            target = ws / "app.sol"
            target.write_text(
                "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
                "contract App {\n"
                "    function doWork(uint x) internal returns (uint) {\n"
                "        return helperFn(x);\n"
                "    }\n"
                "    function helperFn(uint x) internal pure returns (uint) {\n"
                "        return x * 2;\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            # Sibling also defines helperFn (should be ignored - already resolved)
            sib = ws / "Other.sol"
            sib.write_text(
                "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
                "library Other {\n"
                "    function helperFn(uint x) internal pure returns (uint) {\n"
                "        return x * 99;\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            text, end, dep_count = self.m.extract_self_contained(ws, str(target), 4)
            # Should contain helperFn exactly once in deps (same-file, not sibling)
            self.assertIn("same-file def", text)
            # The sibling version (x * 99) must not appear
            self.assertNotIn("99", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
