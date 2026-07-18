#!/usr/bin/env python3
"""Tests for tools/zk-function-mindset.py.

Wave-5 Track K-zkBugs Step 8. Verifies the orchestrator runs
end-to-end against a Halo2 fixture and produces a Markdown brief with
the expected sections.
"""
from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "zk-function-mindset.py"
FIX_DIR = ROOT / "detectors" / "halo2_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("zfm_test_mod", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkFunctionMindsetTest(unittest.TestCase):
    def test_extract_template_body_finds_impl(self) -> None:
        mod = _load()
        src = (FIX_DIR / "halo2_chip_unconstrained_advice_positive_1.rs").read_text(encoding="utf-8")
        body, start, end = mod._extract_template_body(src, "BadChip", "halo2")
        self.assertGreater(end - start, 200)
        self.assertIn("impl BadChip", body)
        # Body should include the configure body, where assign_advice lives
        self.assertIn("assign_advice", body)

    def test_load_detectors_returns_six_halo2(self) -> None:
        mod = _load()
        dets = mod._load_detectors_for_framework("halo2")
        self.assertEqual(len(dets), 6)
        names = [n for n, _ in dets]
        self.assertIn("halo2_chip_unconstrained_advice", names)
        self.assertIn("halo2_selector_inactive_constraint_leak", names)

    def test_orchestrator_writes_brief_against_positive_fixture(self) -> None:
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            argv = [
                str(FIX_DIR / "halo2_chip_unconstrained_advice_positive_1.rs"),
                "--template", "BadChip",
                "--framework", "halo2",
                "--workspace", tmp,
                "--no-mcp",
                "--no-verifier",
            ]
            rc = mod.main(argv)
            self.assertEqual(rc, 0)
            auditooor_dir = Path(tmp) / ".auditooor"
            self.assertTrue(auditooor_dir.is_dir())
            briefs = list(auditooor_dir.glob("zk_function_mindset_halo2_BadChip_*.md"))
            self.assertEqual(len(briefs), 1)
            text = briefs[0].read_text(encoding="utf-8")
            self.assertIn("## (a) Detector hits", text)
            self.assertIn("## (b) Prior-finding collisions", text)
            self.assertIn("## (c) Novel hypotheses", text)
            self.assertIn("## (d) Recommended next steps", text)
            # Detector hit landed in the brief
            self.assertIn("halo2_chip_unconstrained_advice", text)

    # --- Solidity-Honk arm (zk-hunt Stage 3 .sol dispatch) ---

    _SOL_FIXTURE = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract HonkVerifier {\n"
        "    function verifyShplemini(bytes calldata proof)\n"
        "        public\n"
        "        view\n"
        "        returns (bool)\n"
        "    {\n"
        "        uint256 r = squeezeChallenge();\n"
        "        return checkOpening(proof, r);\n"
        "    }\n"
        "}\n"
    )

    def test_extract_template_body_finds_solidity_function(self) -> None:
        mod = _load()
        body, start, end = mod._extract_template_body(
            self._SOL_FIXTURE, "verifyShplemini", "solidity-honk"
        )
        # Body must be the function block, not the whole file.
        self.assertGreater(end - start, 50)
        self.assertLess(end - start, len(self._SOL_FIXTURE))
        self.assertIn("function verifyShplemini", body)
        self.assertIn("squeezeChallenge", body)
        # Multi-line signature with returns clause must be matched.
        self.assertTrue(body.rstrip().endswith("}"))

    def test_solidity_alias_normalizes_to_solidity_honk(self) -> None:
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "HonkVerifier.sol"
            sol.write_text(self._SOL_FIXTURE, encoding="utf-8")
            # zk-hunt Stage 3 passes "--framework solidity"; it must resolve
            # to the canonical "solidity-honk" tag (brief filename proves it).
            rc = mod.main([
                str(sol),
                "--template", "verifyShplemini",
                "--framework", "solidity",
                "--workspace", tmp,
                "--no-mcp",
                "--no-verifier",
            ])
            self.assertEqual(rc, 0)
            briefs = list(
                (Path(tmp) / ".auditooor").glob(
                    "zk_function_mindset_solidity-honk_verifyShplemini_*.md"
                )
            )
            self.assertEqual(len(briefs), 1)
            text = briefs[0].read_text(encoding="utf-8")
            self.assertIn("Framework: `solidity-honk`", text)

    def test_sol_extension_infers_solidity_honk(self) -> None:
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            sol = Path(tmp) / "HonkVerifier.sol"
            sol.write_text(self._SOL_FIXTURE, encoding="utf-8")
            # No --framework: .sol must infer solidity-honk (not halo2).
            rc = mod.main([
                str(sol),
                "--template", "verifyShplemini",
                "--workspace", tmp,
                "--no-mcp",
                "--no-verifier",
            ])
            self.assertEqual(rc, 0)
            briefs = list(
                (Path(tmp) / ".auditooor").glob(
                    "zk_function_mindset_solidity-honk_*.md"
                )
            )
            self.assertEqual(len(briefs), 1)
            # The .sol file must NOT have fallen through to halo2.
            halo2 = list(
                (Path(tmp) / ".auditooor").glob("zk_function_mindset_halo2_*.md")
            )
            self.assertEqual(len(halo2), 0)

    def test_orchestrator_handles_no_match_template(self) -> None:
        mod = _load()
        with tempfile.TemporaryDirectory() as tmp:
            argv = [
                str(FIX_DIR / "halo2_chip_unconstrained_advice_negative_1.rs"),
                "--template", "DefinitelyNotPresent",
                "--framework", "halo2",
                "--workspace", tmp,
                "--no-mcp",
                "--no-verifier",
            ]
            rc = mod.main(argv)
            self.assertEqual(rc, 0)
            briefs = list((Path(tmp) / ".auditooor").glob("zk_function_mindset_*.md"))
            self.assertEqual(len(briefs), 1)


if __name__ == "__main__":
    unittest.main()
