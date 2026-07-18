#!/usr/bin/env python3
"""The canonical source-extension registry - the SSOT that fixes the systemic
.sol/.go/.rs-hardcode language-blindness (Obyte Oscript 2026-07-09)."""
import importlib.util, sys, unittest
from pathlib import Path
_T = Path(__file__).resolve().parent.parent
s = importlib.util.spec_from_file_location("srcext", _T / "lib" / "source_extensions.py")
M = importlib.util.module_from_spec(s); sys.modules["srcext"] = M; s.loader.exec_module(M)


class TestSourceExtensions(unittest.TestCase):
    def test_oscript_and_aa_recognized(self):
        self.assertEqual(M.lang_of("src/prediction-markets-aa/agent.oscript"), "oscript")
        self.assertEqual(M.lang_of("src/obyte-cascading-donations/agent.aa"), "oscript")
        self.assertEqual(M.lang_of(".oscript"), "oscript")

    def test_mainstream_unchanged(self):
        self.assertEqual(M.lang_of("A.sol"), "solidity")
        self.assertEqual(M.lang_of("m.go"), "go")
        self.assertEqual(M.lang_of("l.rs"), "rust")
        self.assertEqual(M.lang_of("x.js"), "javascript")

    def test_unknown_is_none(self):
        self.assertIsNone(M.lang_of("README.md"))
        self.assertIsNone(M.lang_of("data.json"))
        self.assertFalse(M.is_source_file("x.txt"))

    def test_engine_vs_llm_only(self):
        # Solidity/Go have engines; Oscript/Cairo/Move are LLM-hunt-only
        self.assertFalse(M.is_llm_hunt_only("solidity"))
        self.assertFalse(M.is_llm_hunt_only("A.sol"))
        self.assertTrue(M.is_llm_hunt_only("oscript"))
        self.assertTrue(M.is_llm_hunt_only("agent.oscript"))
        self.assertTrue(M.is_llm_hunt_only("cairo"))

    def test_grep_include_globs(self):
        globs = M.grep_include_globs()
        self.assertIn("--include=*.sol", globs)
        self.assertIn("--include=*.oscript", globs)
        self.assertIn("--include=*.aa", globs)

    def test_all_exts_have_lang(self):
        for e in M.SOURCE_EXTS:
            self.assertIn(e, M.EXT_TO_LANG)


if __name__ == "__main__":
    unittest.main()
