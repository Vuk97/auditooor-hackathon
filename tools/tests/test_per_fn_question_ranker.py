"""test_per_fn_question_ranker.py

Guards against two confirmed bugs in tools/per-fn-question-ranker.py:

Bug 1 (line ~260, over-aggressive-filter): KDE filter used bare strings with no
  file/function scope, so a dead-end for OldOracle.sol::getPrice would suppress
  unrelated questions in NewVault.sol::deposit that share 4 common DeFi words.

Bug 2 (line ~217, wrong-field-reference): surface_score block read the bare
  function *name* for "payable"/"external"/"public"/"pure"/"view" substrings
  instead of the dedicated callable_surface / function_visibility fields emitted
  by the miner.  Every real function fell to the else branch (1.0).

These tests call score_question() and load_kde() directly - no subprocess needed.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "per-fn-question-ranker.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("per_fn_question_ranker", TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["per_fn_question_ranker"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_kde_entry(file: str, function: str, kill_reason: str) -> dict:
    """Construct a KDE dict as returned by the fixed load_kde()."""
    return {"file": file, "function": function, "kill_reason": kill_reason.lower()}


def _score(q: dict, kde_phrases=None, oos_patterns=None):
    return MOD.score_question(
        q,
        oos_patterns or [],
        kde_phrases or [],
        {},   # chain_idx
        {},   # inv_idx
        {},   # observed_yield
    )


# ---------------------------------------------------------------------------
# Bug 1: KDE file+function scope guard
# ---------------------------------------------------------------------------

class TestKDEFileFunctionScope(unittest.TestCase):
    """KDE suppression must be scoped to the same (file, function) pair."""

    # A kill_reason whose >=5-char words overlap heavily with both test questions
    KILL_REASON = (
        "price oracle staleness check not needed in this context "
        "based on design review"
    )

    def _make_q(self, file: str, function: str) -> dict:
        return {
            "file": file,
            "function": function,
            "question": (
                "Could the price oracle staleness check be bypassed in "
                + function + "?"
            ),
            "question_class": "staleness",
            "anchor_invariant": "inv-staleness-1",
            "callable_surface": "external",
            "function_visibility": "external",
        }

    def test_same_file_function_is_suppressed(self):
        """Q targeting the exact file+fn from a KDE entry must be suppressed."""
        kde = [_make_kde_entry(
            "contracts/OldOracle.sol", "getPrice", self.KILL_REASON
        )]
        q = self._make_q("contracts/OldOracle.sol", "getPrice")
        result = _score(q, kde_phrases=kde)
        self.assertEqual(
            result["verdict"], "skip-kde-match",
            f"Expected skip-kde-match for same file+fn; got {result['verdict']}"
        )

    def test_different_file_function_is_NOT_suppressed(self):
        """Q targeting a different file+fn must NOT be suppressed (was the bug)."""
        kde = [_make_kde_entry(
            "contracts/OldOracle.sol", "getPrice", self.KILL_REASON
        )]
        q = self._make_q("contracts/NewVault.sol", "deposit")
        result = _score(q, kde_phrases=kde)
        self.assertEqual(
            result["verdict"], "rank-eligible",
            f"Expected rank-eligible for different file+fn; got {result['verdict']} "
            f"(KDE over-suppression bug still present)"
        )

    def test_different_function_same_file_is_NOT_suppressed(self):
        """Same file but different function - must not be suppressed."""
        kde = [_make_kde_entry(
            "contracts/OldOracle.sol", "getPrice", self.KILL_REASON
        )]
        q = self._make_q("contracts/OldOracle.sol", "setPrice")
        result = _score(q, kde_phrases=kde)
        self.assertEqual(
            result["verdict"], "rank-eligible",
            f"Expected rank-eligible for different function in same file; "
            f"got {result['verdict']}"
        )

    def test_unscoped_kde_entry_uses_higher_threshold(self):
        """An unscoped KDE entry (no file, no function) requires >=6 word overlap."""
        # This kill reason has exactly 4 overlapping >=5-char words with the question
        # ('price', 'oracle', 'staleness', 'check'); under the old code that was
        # enough to suppress; under the new code the threshold for unscoped records
        # is 6, so it must pass through.
        kde = [_make_kde_entry("", "", self.KILL_REASON)]
        q = self._make_q("contracts/NewVault.sol", "deposit")
        result = _score(q, kde_phrases=kde)
        self.assertEqual(
            result["verdict"], "rank-eligible",
            f"Unscoped KDE with only 4-word overlap must not suppress; "
            f"got {result['verdict']}"
        )

    def test_unscoped_kde_suppresses_at_6_word_overlap(self):
        """An unscoped KDE entry with 6+ overlapping words should suppress."""
        # Build a kill_reason that shares >=6 long words with the question text
        kill_reason = (
            "price oracle staleness check context needed design review "
            "bypass function bypassed"
        )
        kde = [_make_kde_entry("", "", kill_reason)]
        q = {
            "file": "contracts/Foo.sol",
            "function": "someFunc",
            "question": (
                "Could the price oracle staleness check context needed design "
                "review bypass function be bypassed?"
            ),
            "question_class": "staleness",
            "anchor_invariant": "",
            "callable_surface": "",
            "function_visibility": "",
        }
        result = _score(q, kde_phrases=kde)
        # Confirm 6+ overlap words (all >=5 chars)
        q_words = set(re.findall(r"\b[a-z]{5,}\b", q["question"].lower()))
        kr_words = set(re.findall(r"\b[a-z]{5,}\b", kill_reason.lower()))
        overlap_count = len(q_words & kr_words)
        self.assertGreaterEqual(overlap_count, 6,
                                f"Test setup: need >=6 overlapping words, got {overlap_count}")
        self.assertEqual(
            result["verdict"], "skip-kde-match",
            f"Unscoped KDE with {overlap_count} overlapping words should suppress; "
            f"got {result['verdict']}"
        )

    def test_load_kde_preserves_file_function(self):
        """load_kde must return dicts with file/function fields, not bare strings."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as tf:
            json.dump({
                "workspace": "ws_test",
                "file": "contracts/OldOracle.sol",
                "function": "getPrice",
                "kill_reason": "price oracle staleness not applicable here",
            }, tf)
            tf.write("\n")
            tf_path = tf.name

        # Temporarily patch AUDITOOOR_ROOT so load_kde finds our fixture
        tmp_root = Path(tempfile.mkdtemp())
        reports_dir = tmp_root / "reports"
        reports_dir.mkdir()
        shutil.copy(tf_path, reports_dir / "known_dead_ends.jsonl")

        original_root = MOD.AUDITOOOR_ROOT
        MOD.AUDITOOOR_ROOT = tmp_root
        try:
            entries = MOD.load_kde("ws_test")
        finally:
            MOD.AUDITOOOR_ROOT = original_root
            shutil.rmtree(tmp_root)
            os.unlink(tf_path)

        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertIsInstance(entry, dict,
                              "load_kde must return list[dict], not list[str]")
        self.assertIn("file", entry)
        self.assertIn("function", entry)
        self.assertIn("kill_reason", entry)
        self.assertEqual(entry["file"], "contracts/OldOracle.sol")
        self.assertEqual(entry["function"], "getPrice")


# ---------------------------------------------------------------------------
# Bug 2: surface_score reads callable_surface / function_visibility correctly
# ---------------------------------------------------------------------------

class TestSurfaceScoreFields(unittest.TestCase):
    """surface_score must use callable_surface and function_visibility, not
    substring-scan of the bare function name."""

    def _base_q(self, function: str, callable_surface: str,
                function_visibility: str) -> dict:
        return {
            "file": "contracts/Vault.sol",
            "function": function,
            "callable_surface": callable_surface,
            "function_visibility": function_visibility,
            "question": f"Can {function} be exploited?",
            "question_class": "reentrancy",
            "anchor_invariant": "",
        }

    def test_external_function_scores_2(self):
        """external callable_surface -> surface_score 2.0."""
        q = self._base_q("deposit", "external", "external")
        result = _score(q)
        self.assertEqual(result["verdict"], "rank-eligible")
        self.assertEqual(
            result["score_breakdown"]["surface"], 2.0,
            f"external function must score 2.0; got {result['score_breakdown']['surface']}"
        )

    def test_payable_visibility_scores_2(self):
        """payable in function_visibility -> surface_score 2.0."""
        q = self._base_q("deposit", "external", "external payable")
        result = _score(q)
        self.assertEqual(result["score_breakdown"]["surface"], 2.0)

    def test_public_function_scores_1_5(self):
        """public function_visibility (no callable_surface) -> surface_score 1.5."""
        q = self._base_q("transfer", "", "public")
        result = _score(q)
        self.assertEqual(result["score_breakdown"]["surface"], 1.5,
                         f"public visibility must score 1.5; "
                         f"got {result['score_breakdown']['surface']}")

    def test_view_function_scores_minus_half(self):
        """view function_visibility -> surface_score -0.5."""
        q = self._base_q("getBalance", "internal", "view")
        result = _score(q)
        self.assertEqual(
            result["score_breakdown"]["surface"], -0.5,
            f"view function must score -0.5; got {result['score_breakdown']['surface']}"
        )

    def test_pure_function_scores_minus_half(self):
        """pure function_visibility -> surface_score -0.5."""
        q = self._base_q("computeHash", "internal", "pure")
        result = _score(q)
        self.assertEqual(
            result["score_breakdown"]["surface"], -0.5,
            f"pure function must score -0.5; got {result['score_breakdown']['surface']}"
        )

    def test_internal_mutating_function_scores_1(self):
        """internal callable_surface with non-view/pure visibility -> 1.0."""
        q = self._base_q("transferFrom", "internal", "internal")
        result = _score(q)
        self.assertEqual(
            result["score_breakdown"]["surface"], 1.0,
            f"mutating internal must score 1.0; "
            f"got {result['score_breakdown']['surface']}"
        )

    def test_legacy_fallback_no_fields_external_name(self):
        """When both callable_surface and function_visibility are absent,
        fall back to bare name scan (legacy JSONL without new fields)."""
        q = {
            "file": "contracts/Old.sol",
            "function": "externalDeposit",
            "question": "Can externalDeposit be exploited?",
            "question_class": "reentrancy",
            "anchor_invariant": "",
        }
        result = _score(q)
        self.assertEqual(
            result["score_breakdown"]["surface"], 2.0,
            f"Legacy fallback: 'external' in function name -> 2.0; "
            f"got {result['score_breakdown']['surface']}"
        )

    def test_no_fields_plain_name_scores_1(self):
        """Without callable_surface/function_visibility AND no keywords in name,
        legacy fallback yields 1.0 (correct default for unknown visibility)."""
        q = {
            "file": "contracts/Old.sol",
            "function": "deposit",
            "question": "Can deposit be exploited?",
            "question_class": "reentrancy",
            "anchor_invariant": "",
        }
        result = _score(q)
        self.assertEqual(
            result["score_breakdown"]["surface"], 1.0,
            f"No visibility info -> 1.0; got {result['score_breakdown']['surface']}"
        )


# ---------------------------------------------------------------------------
# Wave-4: scanner-corroboration ranking boost
#
# Bug (scanner-corroboration-ranking-boost): static-analyzer hits (slither /
# aderyn / semgrep / regex / go / cosmos) were NEVER joined to the per-fn
# ranker, so a HIGH on a treasury/accounting fn was scored identically to an
# un-flagged fn and could be buried below the top-N dispatch cut. The fix joins
# the workspace scan artifacts to score_question via (file, function) and adds a
# +2.0 boost (+0.5 for MEDIUM) plus a scanner_corroborated flag that bypasses the
# top-N truncation.
# ---------------------------------------------------------------------------

def _score_with_scanner(q: dict, scanner_index: dict):
    return MOD.score_question(
        q,
        [],   # oos_patterns
        [],   # kde_phrases
        {},   # chain_idx
        {},   # inv_idx
        {},   # observed_yield
        scanner_index,
    )


class TestScannerCorroborationBoost(unittest.TestCase):
    """A HIGH/CRITICAL scanner hit on the SAME (file, fn) must boost the score
    and mark the row scanner_corroborated."""

    def _q(self, file: str, function: str) -> dict:
        return {
            "file": file,
            "function": function,
            "callable_surface": "external",
            "function_visibility": "external",
            "question": f"Can {function} drain the treasury?",
            "question_class": "reentrancy",
            "anchor_invariant": "",
        }

    def test_high_hit_on_same_file_fn_boosts_and_flags(self):
        ftail = MOD._norm_scan_file("src/treasury/Vault.sol")
        scanner_index = {"idx": {(ftail, "sweep"): "HIGH"}, "file_idx": {ftail: "HIGH"}}
        q = self._q("src/treasury/Vault.sol", "sweep")
        r = _score_with_scanner(q, scanner_index)
        self.assertTrue(r["scanner_corroborated"],
                        "HIGH scanner hit on same (file,fn) must set scanner_corroborated")
        self.assertEqual(r["score_breakdown"]["scanner_boost"], 2.0)
        self.assertEqual(r["score_breakdown"]["scanner_match"], "file+function")

    def test_corroborated_fn_ranks_above_identical_uncorroborated_fn(self):
        """Guard: a fn WITH a HIGH slither hit ranks above an identical fn WITHOUT
        one (the load-bearing exploit-finding benefit)."""
        ftail = MOD._norm_scan_file("src/treasury/Vault.sol")
        scanner_index = {"idx": {(ftail, "sweep"): "HIGH"}, "file_idx": {ftail: "HIGH"}}
        corroborated = self._q("src/treasury/Vault.sol", "sweep")
        # Identical surface/class but a different fn/file with no scanner hit.
        plain = self._q("src/util/Helper.sol", "sweep")
        r_corr = _score_with_scanner(corroborated, scanner_index)
        r_plain = _score_with_scanner(plain, scanner_index)
        self.assertGreater(
            r_corr["score"], r_plain["score"],
            "corroborated fn must out-rank an identical un-corroborated fn"
        )
        self.assertAlmostEqual(r_corr["score"] - r_plain["score"], 2.0, places=3)

    def test_medium_hit_smaller_boost_not_flagged(self):
        ftail = MOD._norm_scan_file("src/treasury/Vault.sol")
        scanner_index = {"idx": {(ftail, "sweep"): "MEDIUM"}, "file_idx": {ftail: "MEDIUM"}}
        r = _score_with_scanner(self._q("src/treasury/Vault.sol", "sweep"), scanner_index)
        self.assertFalse(r["scanner_corroborated"])
        self.assertEqual(r["score_breakdown"]["scanner_boost"], 0.5)

    def test_no_scanner_hit_no_boost(self):
        r = _score_with_scanner(self._q("src/treasury/Vault.sol", "sweep"),
                                {"idx": {}, "file_idx": {}})
        self.assertFalse(r["scanner_corroborated"])
        self.assertEqual(r["score_breakdown"]["scanner_boost"], 0.0)
        self.assertEqual(r["scanner_severity"], "")

    def test_file_only_fallback_when_fn_absent_in_scanner(self):
        """Slither/aderyn emit no function -> file-level corroboration still fires."""
        ftail = MOD._norm_scan_file("src/treasury/Vault.sol")
        scanner_index = {"idx": {}, "file_idx": {ftail: "HIGH"}}
        r = _score_with_scanner(self._q("src/treasury/Vault.sol", "sweep"), scanner_index)
        self.assertTrue(r["scanner_corroborated"])
        self.assertEqual(r["score_breakdown"]["scanner_match"], "file-only")

    def test_unrelated_file_does_not_corroborate(self):
        ftail = MOD._norm_scan_file("src/treasury/Vault.sol")
        scanner_index = {"idx": {(ftail, "sweep"): "HIGH"}, "file_idx": {ftail: "HIGH"}}
        # question is in a DIFFERENT file -> must not be corroborated
        r = _score_with_scanner(self._q("src/util/Other.sol", "sweep"), scanner_index)
        self.assertFalse(r["scanner_corroborated"])
        self.assertEqual(r["score_breakdown"]["scanner_boost"], 0.0)


class TestLoadScannerIndex(unittest.TestCase):
    """load_scanner_index must read the real on-disk scan artifacts and key by
    (file_tail, function) with the MAX severity."""

    def test_regex_manifest_and_engage_report_indexed(self):
        ws = Path(tempfile.mkdtemp())
        try:
            (ws / ".auditooor").mkdir()
            # regex manifest: carries file + function + severity
            (ws / "regex_detectors_manifest.json").write_text(json.dumps({
                "findings": [
                    {"file": "/abs/prefix/src/treasury/Vault.sol",
                     "function": "sweep", "severity": "HIGH",
                     "message": "missing access control on sweep"},
                    {"file": "src/util/Helper.sol", "function": "noop",
                     "severity": "LOW", "message": "style"},
                ]
            }))
            # engage_report: slither-style cluster hits (file:line, no function)
            (ws / "engage_report.json").write_text(json.dumps({
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {"detector_slug": "reentrancy", "hits": [
                        {"file_path": "contracts/Bank.sol:42", "severity": "CRITICAL",
                         "snippet": "reentrancy in withdraw"},
                    ]},
                ],
            }))
            idx = MOD.load_scanner_index(ws)
        finally:
            shutil.rmtree(ws)

        vtail = MOD._norm_scan_file("src/treasury/Vault.sol")
        self.assertEqual(idx["idx"].get((vtail, "sweep")), "HIGH",
                         "regex manifest HIGH on (file,fn) must be indexed")
        # LOW must still be present at file level but not lift to boost-tier
        htail = MOD._norm_scan_file("src/util/Helper.sol")
        self.assertEqual(idx["file_idx"].get(htail), "LOW")
        # engage_report cluster hit: file-level only (slither has no fn)
        btail = MOD._norm_scan_file("contracts/Bank.sol")
        self.assertEqual(idx["file_idx"].get(btail), "CRITICAL")

    def test_max_severity_kept_per_key(self):
        ws = Path(tempfile.mkdtemp())
        try:
            (ws / "regex_detectors_manifest.json").write_text(json.dumps({
                "findings": [
                    {"file": "src/A.sol", "function": "f", "severity": "MEDIUM",
                     "message": "m"},
                    {"file": "src/A.sol", "function": "f", "severity": "HIGH",
                     "message": "m"},
                ]
            }))
            idx = MOD.load_scanner_index(ws)
        finally:
            shutil.rmtree(ws)
        atail = MOD._norm_scan_file("src/A.sol")
        self.assertEqual(idx["idx"].get((atail, "f")), "HIGH",
                         "MAX severity (HIGH) must win over MEDIUM for same key")

    def test_missing_artifacts_return_empty_not_raise(self):
        ws = Path(tempfile.mkdtemp())
        try:
            idx = MOD.load_scanner_index(ws)
        finally:
            shutil.rmtree(ws)
        self.assertEqual(idx["idx"], {})
        self.assertEqual(idx["file_idx"], {})


class TestScannerCorroborationCapBypass(unittest.TestCase):
    """A scanner-corroborated row that falls below the top-N cut must survive
    the truncation via the bypass path in main()."""

    def test_corroborated_row_survives_top_n_cap(self):
        ws = Path(tempfile.mkdtemp())
        qdir = Path(tempfile.mkdtemp())
        try:
            # Scanner: a HIGH on a single (file, fn).
            (ws / "regex_detectors_manifest.json").write_text(json.dumps({
                "findings": [
                    {"file": "src/treasury/Vault.sol", "function": "sweep",
                     "severity": "HIGH", "message": "missing access control"},
                ]
            }))
            # Questions: many high-scoring decoys + one corroborated row that
            # (because we set top_n=2) would otherwise be truncated out.
            qpath = qdir / "questions.jsonl"
            with qpath.open("w") as fh:
                # 3 decoys with strong surface/class so they out-score by base.
                for i in range(3):
                    fh.write(json.dumps({
                        "file": f"src/decoy/D{i}.sol", "function": f"hot{i}",
                        "callable_surface": "external",
                        "function_visibility": "external payable",
                        "question": f"decoy {i}",
                        "question_class": "reentrancy",
                        "anchor_invariant": "",
                    }) + "\n")
                # The corroborated row: view fn (low base surface) so its base
                # score is low; only the +2.0 scanner boost saves it.
                fh.write(json.dumps({
                    "file": "src/treasury/Vault.sol", "function": "sweep",
                    "callable_surface": "internal",
                    "function_visibility": "view",
                    "question": "Can sweep drain the treasury?",
                    "question_class": "generic",
                    "anchor_invariant": "",
                }) + "\n")
            out_path = qdir / "ranked.jsonl"
            rc = MOD.main([
                "--questions", str(qpath),
                "--workspace", str(ws),
                "--output", str(out_path),
                "--top-n", "2",
            ])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out_path.read_text().splitlines() if l.strip()]
        finally:
            shutil.rmtree(ws)
            shutil.rmtree(qdir)

        # The corroborated sweep row must be present in the output EVEN THOUGH
        # top_n=2 and its base (view) score would not place it in the top 2.
        corroborated = [r for r in rows
                        if r.get("function") == "sweep" and r.get("scanner_corroborated")]
        self.assertEqual(len(corroborated), 1,
                         f"scanner-corroborated sweep row must survive top-2 cap; "
                         f"got rows={[(r.get('function'), r.get('score')) for r in rows]}")


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Lane ranker-kde-feedback: file_line cross-pin KDE skip + density demotion
#
# Bug (learning-loop feedback): load_kde filtered by workspace==name only
# (missing cross-pin rows where the label is "unknown" or a full audit path),
# keyed only on (file, function) prose overlap, and read only `kill_reason`
# (89% of the real store uses `reason`). The skip path could not fire on a
# file_line collision, and OOS boilerplate (bor cmd/) ranked #1-#20 while
# value-moving entrypoints (claimAsset/buySPOL) were dropped. The fix:
#  (1) skip/demote a question whose file_line matches a prior dead-end's
#      file_line (coalesce file/file_line/source_path); and
#  (2) DENSITY DEMOTION: a file with >=K (env AUDITOOOR_RANKER_KDE_DENSITY,
#      default 3) prior dead-ends gets a strong negative score so fresh
#      in-scope value-movers outrank ruled-out boilerplate.
# Back-compat: identical ranking when no KDE store exists.
# ---------------------------------------------------------------------------


def _kde_fl(file: str, file_line: str, function: str = "") -> dict:
    """Build a KDE dict carrying a file_line anchor (as fixed load_kde emits)."""
    # Reuse the tool's own normaliser so the test's file_line key matches.
    return {
        "file": file,
        "file_line": MOD._kde_file_line(file_line),
        "function": function,
        "kill_reason": "",
    }


class TestKDEFileLineCrossPinSkip(unittest.TestCase):
    """A question at a file_line matching a prior dead-end's file_line is skipped,
    regardless of workspace label or prose overlap."""

    def _q(self, file: str, function: str, file_line: str = "") -> dict:
        return {
            "file": file,
            "file_line": file_line,
            "function": function,
            "callable_surface": "external",
            "function_visibility": "external",
            "question": f"Can {function} drain funds in a fresh way?",
            "question_class": "reentrancy",
            "anchor_invariant": "",
        }

    def test_same_file_line_is_skipped(self):
        kde = [_kde_fl("src/cmd/bor.go", "src/cmd/bor.go:86")]
        q = self._q("src/cmd/bor.go", "run", file_line="src/cmd/bor.go:86")
        r = _score(q, kde_phrases=kde)
        self.assertEqual(r["verdict"], "skip-kde-match",
                         f"file_line collision must skip; got {r['verdict']}")
        self.assertIn("kde_file_line", r["score_breakdown"])

    def test_file_line_match_via_question_file_field(self):
        """The question may carry the file:line in its plain `file` field."""
        kde = [_kde_fl("src/cmd/bor.go", "src/cmd/bor.go:86")]
        q = self._q("src/cmd/bor.go:86", "run")
        r = _score(q, kde_phrases=kde)
        self.assertEqual(r["verdict"], "skip-kde-match")

    def test_fresh_in_scope_question_at_different_line_NOT_skipped(self):
        """A fresh in-scope question (different file_line) outranks/survives."""
        kde = [_kde_fl("src/cmd/bor.go", "src/cmd/bor.go:86")]
        q = self._q("contracts/SPOL.sol", "buySPOL", file_line="contracts/SPOL.sol:42")
        r = _score(q, kde_phrases=kde)
        self.assertEqual(r["verdict"], "rank-eligible",
                         f"fresh in-scope unit must survive; got {r['verdict']}")

    def test_fresh_question_outranks_demoted_boilerplate(self):
        """The load-bearing benefit: a value-moving entrypoint outranks a unit
        whose file_line is a prior dead-end."""
        kde = [_kde_fl("src/cmd/bor.go", "src/cmd/bor.go:86")]
        ruled_out = self._q("src/cmd/bor.go", "run", file_line="src/cmd/bor.go:86")
        fresh = self._q("contracts/SPOL.sol", "buySPOL",
                        file_line="contracts/SPOL.sol:42")
        r_ruled = _score(ruled_out, kde_phrases=kde)
        r_fresh = _score(fresh, kde_phrases=kde)
        # ruled-out is hard-skipped (score 0.0); fresh is rank-eligible (positive)
        self.assertEqual(r_ruled["score"], 0.0)
        self.assertGreater(r_fresh["score"], r_ruled["score"])


class TestKDEDensityDemotion(unittest.TestCase):
    """A file with >=K prior dead-ends gets a strong negative score so fresh
    value-movers outrank ruled-out boilerplate even when its file_line is novel."""

    def _q(self, file: str, function: str, file_line: str) -> dict:
        return {
            "file": file,
            "file_line": file_line,
            "function": function,
            "callable_surface": "external",
            "function_visibility": "external",
            "question": f"Can {function} be abused?",
            "question_class": "reentrancy",
            "anchor_invariant": "",
        }

    def test_high_density_file_is_demoted(self):
        # 3 dead-ends in bor.go at DIFFERENT lines -> density 3 (>= default K=3).
        kde = [
            _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:10"),
            _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:20"),
            _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:30"),
        ]
        # A NEW line in the same dense file (not a file_line collision).
        q = self._q("src/cmd/bor.go", "newCmd", file_line="src/cmd/bor.go:99")
        r = _score(q, kde_phrases=kde)
        self.assertEqual(r["verdict"], "rank-eligible",
                         "novel line in dense file is demoted, not hard-skipped")
        self.assertEqual(r["score_breakdown"]["kde_density_penalty"], -5.0)
        self.assertGreaterEqual(r["score_breakdown"]["kde_file_density"], 3)

    def test_value_mover_outranks_dense_boilerplate(self):
        kde = [
            _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:10"),
            _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:20"),
            _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:30"),
        ]
        boilerplate = self._q("src/cmd/bor.go", "newCmd",
                              file_line="src/cmd/bor.go:99")
        value_mover = self._q("contracts/SPOL.sol", "buySPOL",
                              file_line="contracts/SPOL.sol:42")
        r_boiler = _score(boilerplate, kde_phrases=kde)
        r_value = _score(value_mover, kde_phrases=kde)
        self.assertGreater(
            r_value["score"], r_boiler["score"],
            "fresh value-moving entrypoint must outrank dense ruled-out boilerplate")

    def test_below_threshold_no_demotion(self):
        # Only 2 dead-ends -> below K=3 -> no penalty.
        kde = [
            _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:10"),
            _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:20"),
        ]
        q = self._q("src/cmd/bor.go", "newCmd", file_line="src/cmd/bor.go:99")
        r = _score(q, kde_phrases=kde)
        self.assertEqual(r["score_breakdown"]["kde_density_penalty"], 0.0)

    def test_env_override_threshold(self):
        kde = [_kde_fl("src/cmd/bor.go", "src/cmd/bor.go:10"),
               _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:20")]
        q = self._q("src/cmd/bor.go", "newCmd", file_line="src/cmd/bor.go:99")
        prev = os.environ.get("AUDITOOOR_RANKER_KDE_DENSITY")
        os.environ["AUDITOOOR_RANKER_KDE_DENSITY"] = "2"
        try:
            r = _score(q, kde_phrases=kde)
        finally:
            if prev is None:
                os.environ.pop("AUDITOOOR_RANKER_KDE_DENSITY", None)
            else:
                os.environ["AUDITOOOR_RANKER_KDE_DENSITY"] = prev
        self.assertEqual(r["score_breakdown"]["kde_density_penalty"], -5.0,
                         "K=2 override must demote a file with 2 dead-ends")

    def test_scanner_corroborated_exempt_from_density(self):
        """A HIGH static-analyzer hit overrides prior-noise density."""
        kde = [
            _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:10"),
            _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:20"),
            _kde_fl("src/cmd/bor.go", "src/cmd/bor.go:30"),
        ]
        ftail = MOD._norm_scan_file("src/cmd/bor.go")
        scanner_index = {"idx": {(ftail, "newCmd"): "HIGH"},
                         "file_idx": {ftail: "HIGH"}}
        q = self._q("src/cmd/bor.go", "newCmd", file_line="src/cmd/bor.go:99")
        r = MOD.score_question(q, [], kde, {}, {}, {}, scanner_index)
        self.assertEqual(r["score_breakdown"]["kde_density_penalty"], 0.0,
                         "scanner-corroborated row must be exempt from density demotion")
        self.assertTrue(r["scanner_corroborated"])


class TestKDENoStoreBackCompat(unittest.TestCase):
    """No KDE store -> empty kde_phrases -> ranking is unchanged (no skip, no
    density penalty); identical to the pre-fix behaviour."""

    def _q(self, file: str, function: str, file_line: str) -> dict:
        return {
            "file": file,
            "file_line": file_line,
            "function": function,
            "callable_surface": "external",
            "function_visibility": "external",
            "question": f"Can {function} be abused?",
            "question_class": "reentrancy",
            "anchor_invariant": "",
        }

    def test_empty_kde_no_skip_no_penalty(self):
        q = self._q("src/cmd/bor.go", "run", file_line="src/cmd/bor.go:86")
        r = _score(q, kde_phrases=[])
        self.assertEqual(r["verdict"], "rank-eligible")
        self.assertEqual(r["score_breakdown"]["kde_density_penalty"], 0.0)
        self.assertEqual(r["score_breakdown"]["kde_file_density"], 0)

    def test_score_identical_with_and_without_empty_kde(self):
        """A question scored against an empty KDE list must equal the same
        question scored with no KDE arg at all (default [])."""
        q = self._q("contracts/SPOL.sol", "buySPOL", file_line="contracts/SPOL.sol:42")
        r_empty = _score(dict(q), kde_phrases=[])
        r_none = _score(dict(q), kde_phrases=None)
        self.assertEqual(r_empty["score"], r_none["score"])


class TestLoadKDECoalescesFields(unittest.TestCase):
    """load_kde must coalesce reason field names (reason/kill_reason), file_line
    field names (file/evidence_file_line/source_path), and relax workspace scope
    to catch cross-pin rows."""

    def _write_store(self, rows: list[dict]) -> Path:
        tmp_root = Path(tempfile.mkdtemp())
        reports = tmp_root / "reports"
        reports.mkdir()
        with (reports / "known_dead_ends.jsonl").open("w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        return tmp_root

    def test_reason_field_is_read_not_just_kill_reason(self):
        tmp_root = self._write_store([
            {"workspace": "polygon", "file": "src/cmd/bor.go:86",
             "reason": "bor command boilerplate ruled out by design review"},
        ])
        prev = MOD.AUDITOOOR_ROOT
        MOD.AUDITOOOR_ROOT = tmp_root
        try:
            entries = MOD.load_kde("polygon")
        finally:
            MOD.AUDITOOOR_ROOT = prev
            shutil.rmtree(tmp_root)
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["kill_reason"],
                        "`reason` field must populate kill_reason")
        self.assertTrue(entries[0]["file_line"],
                        "`file` with :line must populate file_line")

    def test_evidence_file_line_field_coalesced(self):
        tmp_root = self._write_store([
            {"workspace": "hyperbridge", "kill_verdict": "FP",
             "evidence_file_line": "src/Foo.sol:543,547"},
        ])
        prev = MOD.AUDITOOOR_ROOT
        MOD.AUDITOOOR_ROOT = tmp_root
        try:
            entries = MOD.load_kde("hyperbridge")
        finally:
            MOD.AUDITOOOR_ROOT = prev
            shutil.rmtree(tmp_root)
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["file_line"].endswith(":543,547"),
                        f"evidence_file_line must coalesce; got {entries[0]['file_line']}")

    def test_workspace_scope_relaxed_cross_pin(self):
        """A row labelled with a different pin (full audit path / 'unknown') for
        the same workspace must still be returned."""
        tmp_root = self._write_store([
            {"workspace": "/Users/wolf/audits/polygon", "reason": "x ruled out here",
             "file": "src/cmd/bor.go:10"},
            {"workspace": "unknown", "reason": "y ruled out here",
             "file": "src/cmd/bor.go:20"},
            {"workspace": "some-other-ws", "reason": "z ruled out elsewhere",
             "file": "src/cmd/other.go:30"},
        ])
        prev = MOD.AUDITOOOR_ROOT
        MOD.AUDITOOOR_ROOT = tmp_root
        try:
            entries = MOD.load_kde("polygon")
        finally:
            MOD.AUDITOOOR_ROOT = prev
            shutil.rmtree(tmp_root)
        files = {e["file"] for e in entries}
        # cross-pin (full path) + 'unknown' bucket are included
        self.assertIn("src/cmd/bor.go:10", files)
        self.assertIn("src/cmd/bor.go:20", files)
        # an unrelated workspace's row is excluded
        self.assertNotIn("src/cmd/other.go:30", files)

    def test_na_placeholder_file_line_dropped(self):
        """An N/A file_line must not form a join key (would skip everything)."""
        self.assertEqual(MOD._kde_file_line("N/A"), "")
        self.assertEqual(MOD._kde_file_line("N/A (Conceptual Claim)"), "")
        self.assertEqual(MOD._kde_file_line(""), "")


class TestProbeClassInference(unittest.TestCase):
    """probe_class is R80-safe question metadata (what the question ASKS), so the
    mimo yield matrix can key on it instead of collapsing claim-free coverage-fold
    questions into one 'generic' bucket."""

    def test_template_reverse_match(self):
        self.assertEqual(
            MOD.infer_probe_class("Can a non-owner address call foo directly and trigger a state change?"),
            "access-control-missing")
        self.assertEqual(
            MOD.infer_probe_class("Can foo be reentered before its state-write step completes?"),
            "reentrancy")

    def test_keyword_fallback(self):
        self.assertEqual(
            MOD.infer_probe_class("Does decode(encode(x)) hold for every input?"),
            "serialization-roundtrip")

    def test_unrelated_is_generic(self):
        self.assertEqual(MOD.infer_probe_class("completely unrelated freeform prose"), "generic")

    def test_claim_free_is_not_a_claim(self):
        # probe_class describes the QUESTION, never asserts the function HAS the bug.
        # An access-control PROBE on a function is not an access-control FINDING.
        self.assertEqual(MOD.infer_probe_class(""), "generic")


class TestLoadYieldPrefersBanked(unittest.TestCase):
    """load_attack_class_yield_observed prefers the banked mimo_observed_yield.json,
    summing raw yes/total counts across workspaces (volume-weighting), with a >=5
    noise floor, and gracefully falls back to the legacy glob when the bank is
    absent."""

    def test_load_yield_prefers_banked_json(self):
        # (a) Banked file: two workspaces each carry reentrancy counts. Aggregated
        # = (6+4) yes / (10+10) total = 10/20 = 0.5.
        tmp_root = Path(tempfile.mkdtemp())
        derived = tmp_root / "audit" / "corpus_tags" / "derived"
        derived.mkdir(parents=True)
        banked = {
            "by_workspace": {
                "wsA": {"reentrancy": {"yes": 6, "total": 10}},
                "wsB": {"reentrancy": {"yes": 4, "total": 10}},
                # total<5 class must be excluded after aggregation
                "wsC": {"oracle-staleness": {"yes": 1, "total": 3}},
            }
        }
        (derived / "mimo_observed_yield.json").write_text(
            json.dumps(banked), encoding="utf-8")

        original_root = MOD.AUDITOOOR_ROOT
        MOD.AUDITOOOR_ROOT = tmp_root
        try:
            result = MOD.load_attack_class_yield_observed()
        finally:
            MOD.AUDITOOOR_ROOT = original_root
            shutil.rmtree(tmp_root)

        # (a) cross-workspace count-summing: 10 yes / 20 total
        self.assertAlmostEqual(result["reentrancy"], 0.5, places=6)
        # (b) total<5 class is excluded by the noise floor
        self.assertNotIn("oracle-staleness", result)

    def test_count_summing_not_rate_averaging(self):
        # Volume-weighting proof: 9/10 (0.9) and 1/100 (0.01). Rate-averaging
        # would give ~0.455; count-summing gives 10/110 = ~0.0909.
        tmp_root = Path(tempfile.mkdtemp())
        derived = tmp_root / "audit" / "corpus_tags" / "derived"
        derived.mkdir(parents=True)
        banked = {
            "by_workspace": {
                "wsA": {"access-control": {"yes": 9, "total": 10}},
                "wsB": {"access-control": {"yes": 1, "total": 100}},
            }
        }
        (derived / "mimo_observed_yield.json").write_text(
            json.dumps(banked), encoding="utf-8")

        original_root = MOD.AUDITOOOR_ROOT
        MOD.AUDITOOOR_ROOT = tmp_root
        try:
            result = MOD.load_attack_class_yield_observed()
        finally:
            MOD.AUDITOOOR_ROOT = original_root
            shutil.rmtree(tmp_root)

        self.assertAlmostEqual(result["access-control"], 10 / 110, places=6)
        # A rate-average (~0.455) would be wildly different; assert we are nowhere
        # near it.
        self.assertLess(result["access-control"], 0.2)

    def test_fallback_to_legacy_glob_when_bank_missing(self):
        # No banked file, but a populated mimo_harness_* sidecar dir is present.
        # The loader must fall through to the legacy glob and return its dict.
        tmp_root = Path(tempfile.mkdtemp())
        derived = tmp_root / "audit" / "corpus_tags" / "derived"
        harness_dir = derived / "mimo_harness_wsLegacy"
        harness_dir.mkdir(parents=True)
        # 6 sidecars for the same class so the >=5 floor passes; 2 YES of 6.
        for i in range(6):
            applies = "yes" if i < 2 else "no"
            sidecar = {
                "status": "ok",
                "result": json.dumps(
                    {"attack_class": "reentrancy", "applies_to_target": applies}),
            }
            (harness_dir / f"q{i}.json").write_text(
                json.dumps(sidecar), encoding="utf-8")

        original_root = MOD.AUDITOOOR_ROOT
        MOD.AUDITOOOR_ROOT = tmp_root
        try:
            result = MOD.load_attack_class_yield_observed()
        finally:
            MOD.AUDITOOOR_ROOT = original_root
            shutil.rmtree(tmp_root)

        self.assertTrue(result, "legacy glob fallback must return a non-empty dict")
        self.assertAlmostEqual(result["reentrancy"], 2 / 6, places=6)


class TestEngageSchemaDedupNotCollapsed(unittest.TestCase):
    """Regression: engage.py per-fn rows use unit_id/source_path (NO file/function/
    question_class). The dedup keyed on (file,function,question_class) collapsed
    EVERY row to ("","","") -> the ranked set became 1 row and step-3's scoped hunt
    covered 1 unit. The dedup must fall back to unit_id/source_path so distinct
    functions keep distinct anchors."""

    def test_engage_schema_rows_are_not_collapsed_to_one(self):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / ".auditooor").mkdir(parents=True)
            qpath = ws / "q.jsonl"
            with qpath.open("w") as fh:
                for i in range(25):
                    fh.write(json.dumps({
                        "schema_version": "1", "workspace": str(ws), "run_id": "r1",
                        "unit_id": f"Contract{i}.sol::func{i}",
                        "source_path": f"src/Contract{i}.sol",
                        "question": f"can an unprivileged caller drain funds via func{i} reentrancy {i}",
                        "priority_score": 5.0,
                    }) + "\n")
            out = ws / "ranked.jsonl"
            r = subprocess.run(
                [sys.executable, str(TOOL), "--questions", str(qpath),
                 "--workspace", str(ws), "--output", str(out)],
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            n = sum(1 for ln in out.read_text().splitlines() if ln.strip())
            self.assertGreater(n, 1, f"engage-schema rows collapsed to {n} (dedup-key bug)")
            self.assertGreaterEqual(n, 20, f"expected ~25 distinct anchors, got {n}")


if __name__ == "__main__":
    unittest.main()
