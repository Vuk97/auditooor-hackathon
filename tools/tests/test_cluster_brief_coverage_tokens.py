#!/usr/bin/env python3
# r36: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json
"""test_cluster_brief_coverage_tokens.py - FIX 2 regression lock.

The per-class hunt writes one markdown brief per SCOPE impact class to
<ws>/.auditooor/hunt_cluster_briefs/<slug>.md. Before FIX 2 the coverage
tokenizers ignored these, so impact classes went DARK in the capability matrix
(fail-dark-families) and uncovered in the cluster-coverage check
(fail-missing-cluster-coverage). FIX 2 adds the brief stems as coverage tokens
in BOTH tools/capability-coverage-matrix-build.py and
tools/hunt-completeness-check.py, so the existing normalized-substring
coverage test matches the impact-class cluster names. Generic across languages.
"""
from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent


def _load(name: str, fname: str):
    # r36-rebuttal: lane L37-RUST-CREDIT registered in .auditooor/agent_pathspec.json
    # Register under a STABLE sys.modules name so dataclasses defined in the
    # module resolve their fields (py3.12+ GC-safety).
    import sys
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, TOOLS / fname)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class ClusterBriefCoverageTokensTest(unittest.TestCase):
    def setUp(self) -> None:
        self.matrix = _load("cmb_under_test",
                            "capability-coverage-matrix-build.py")
        self.hunt = _load("hcc_under_test", "hunt-completeness-check.py")
        self.tmp = Path(tempfile.mkdtemp())
        self.ws = self.tmp / "ws"
        self.bdir = self.ws / ".auditooor" / "hunt_cluster_briefs"
        self.bdir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _brief(self, stem: str) -> None:
        (self.bdir / f"{stem}.md").write_text(
            f"# {stem} hunt brief\n\nQuestions...\n", encoding="utf-8")

    def test_matrix_builder_picks_up_brief_stems(self) -> None:
        self._brief("stealing-or-loss-of-funds")
        self._brief("price-manipulation")
        toks = self.matrix._cluster_brief_tokens(self.ws)
        self.assertIn("stealing-or-loss-of-funds", toks)
        self.assertIn("price-manipulation", toks)

    def test_hunt_check_picks_up_brief_stems(self) -> None:
        self._brief("unauthorized-transaction")
        toks = self.hunt._cluster_brief_tokens(self.ws)
        self.assertIn("unauthorized-transaction", toks)

    def test_non_md_files_ignored(self) -> None:
        (self.bdir / "notes.txt").write_text("x", encoding="utf-8")
        (self.bdir / ".hidden.md").write_text("x", encoding="utf-8")
        toks = self.matrix._cluster_brief_tokens(self.ws)
        self.assertNotIn("notes", toks)
        self.assertNotIn(".hidden", toks)

    def test_brief_token_makes_cluster_covered_in_matrix(self) -> None:
        # the matrix builder's _is_covered uses normalized-substring; a brief
        # whose stem matches the SCOPE cluster name should flip DARK -> COVERED.
        self._brief("stealing-or-loss-of-funds")
        toks = self.matrix._coverage_tokens(self.ws)
        self.assertTrue(
            self.matrix._is_covered("Stealing or loss of funds", toks))

    def test_brief_token_covers_cluster_in_hunt_check(self) -> None:
        # the hunt-completeness cluster-coverage matcher is the same
        # normalized-substring test; confirm the brief token is in the set.
        self._brief("cryptographic-flaws")
        toks = self.hunt._coverage_tokens(self.ws)
        # normalized form must contain the cluster
        import re
        cl_norm = re.sub(r"[^a-z0-9]+", "", "Cryptographic flaws".lower())
        matched = any(
            cl_norm in re.sub(r"[^a-z0-9]+", "", t) or
            re.sub(r"[^a-z0-9]+", "", t) in cl_norm
            for t in toks
        )
        self.assertTrue(matched)

    def test_absent_dir_is_empty_set(self) -> None:
        shutil.rmtree(self.bdir)
        self.assertEqual(self.matrix._cluster_brief_tokens(self.ws), set())
        self.assertEqual(self.hunt._cluster_brief_tokens(self.ws), set())


if __name__ == "__main__":
    unittest.main()
