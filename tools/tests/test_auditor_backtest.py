#!/usr/bin/env python3
# <!-- r36-rebuttal: pathspec declared via tools/agent-pathspec-register.py lane LANE-auditor-backtest; orchestrator commits; sibling files untouched -->
"""Tests for tools/auditor-backtest.py.

synthetic_fixture: true

Covers:
  1. parse_file_line / normalize_vuln_class / class_matches token logic.
  2. locate_source: local-checkout hit, basename fallback, miss, no-ref NA.
  3. backtest_case CAUGHT  - engine stub fires a relevant DSL detector at line.
  4. backtest_case MISSED  - relevant detectors exist but stay silent.
  5. backtest_case MISSED  - no relevant detector + corpus knows class
                             -> missing_capability=corpus-knows-class-... .
  6. backtest_case NA      - source unavailable (no checkout, no repo/ref).
  7. human_report renders CAUGHT / MISSED / NA without raising.
  8. CLI single-case dispatch exits 0 and emits valid JSON.

The engine is STUBBED so tests do not depend on solc compilation; the stub
exercises the same (fired, hit_lines, error) contract run_dsl_on_file returns.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "auditor-backtest.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("auditor_backtest", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


AB = _load_module()


class TestPureHelpers(unittest.TestCase):
    def test_parse_file_line(self):
        self.assertEqual(AB.parse_file_line("src/Vault.sol:142"), ("src/Vault.sol", 142))
        self.assertEqual(AB.parse_file_line("src/Vault.sol"), ("src/Vault.sol", None))
        self.assertEqual(AB.parse_file_line(""), (None, None))

    def test_normalize_vuln_class(self):
        self.assertEqual(AB.normalize_vuln_class("Access_Control"), "access-control")
        self.assertEqual(AB.normalize_vuln_class("  Re Entrancy "), "re-entrancy")

    def test_class_matches_token_overlap(self):
        self.assertTrue(AB.class_matches("access-control", {"access"}))
        self.assertTrue(AB.class_matches("access", {"access-control"}))
        self.assertTrue(AB.class_matches("reentrancy", {"reentrancy"}))
        self.assertFalse(AB.class_matches("reentrancy", {"oracle"}))
        self.assertFalse(AB.class_matches("", {"oracle"}))


class TestLocateSource(unittest.TestCase):
    def test_local_checkout_direct_hit(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / "src").mkdir()
            f = base / "src" / "Vault.sol"
            f.write_text("contract Vault {}")
            case = {"file_line": "src/Vault.sol:10"}
            path, codir, reason = AB.locate_source(case, str(base), d)
            self.assertEqual(path, f)
            self.assertEqual(codir, base)
            self.assertIn("located-in-local-checkout", reason)

    def test_local_checkout_basename_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / "deep" / "nested").mkdir(parents=True)
            f = base / "deep" / "nested" / "Vault.sol"
            f.write_text("contract Vault {}")
            case = {"file_line": "contracts/Vault.sol:1"}
            path, _, reason = AB.locate_source(case, str(base), d)
            self.assertEqual(path, f)
            self.assertIn("located-by-basename", reason)

    def test_local_checkout_miss(self):
        with tempfile.TemporaryDirectory() as d:
            case = {"file_line": "src/Nope.sol:1"}
            path, _, reason = AB.locate_source(case, d, d)
            self.assertIsNone(path)
            self.assertIn("file-not-found-in-local-checkout", reason)

    def test_no_checkout_no_ref_is_na(self):
        with tempfile.TemporaryDirectory() as d:
            case = {"file_line": "src/X.sol:1"}  # no repo / no prefix_ref
            path, _, reason = AB.locate_source(case, None, d)
            self.assertIsNone(path)
            self.assertIn("missing-repo-or-prefix-ref", reason)


def _fake_engine_factory(fire_at_line=None, error=None, silent=False):
    """Build (engine_tuple, run_dsl_override). We monkeypatch run_dsl_on_file."""
    def fake_run(spec, sol_path, engine, target_line=None):
        if error:
            return False, [], error
        if silent:
            return False, [], None
        return True, [fire_at_line if fire_at_line is not None else 100], None
    # engine tuple just needs to be non-None
    return ("e0", "e1", "e2", "e3"), fake_run


class TestBacktestCase(unittest.TestCase):
    def _local_case(self, d, vuln_class="reentrancy", line=140):
        base = Path(d)
        (base / "src").mkdir(exist_ok=True)
        (base / "src" / "Vault.sol").write_text("contract Vault {}")
        return {"id": "BUG-1", "repo": "o/r", "prefix_ref": "abc",
                "vuln_class": vuln_class, "file_line": f"src/Vault.sol:{line}"}

    def test_caught_engine_fires_at_line(self):
        with tempfile.TemporaryDirectory() as d:
            case = self._local_case(d, line=140)
            engine, fake_run = _fake_engine_factory(fire_at_line=145)  # within +/-25
            orig = AB.run_dsl_on_file
            # force at least one relevant detector regardless of taxonomy
            orig_load = AB.load_relevant_dsl
            AB.run_dsl_on_file = fake_run
            AB.load_relevant_dsl = lambda vc, pd, ch, **kw: [("reentrancy-cei", {})]
            try:
                rec = AB.backtest_case(case, d, AB.DEFAULT_PATTERNS_DIR, None, engine, d)
            finally:
                AB.run_dsl_on_file = orig
                AB.load_relevant_dsl = orig_load
            self.assertEqual(rec["outcome"], "CAUGHT")
            self.assertIn("dsl_detectors", rec["caught_by"])
            self.assertEqual(rec["fired_at_line"], 145)
            self.assertIsNone(rec["missing_capability"])

    def test_missed_detector_silent(self):
        with tempfile.TemporaryDirectory() as d:
            case = self._local_case(d)
            engine, fake_run = _fake_engine_factory(silent=True)
            orig, orig_load = AB.run_dsl_on_file, AB.load_relevant_dsl
            AB.run_dsl_on_file = fake_run
            AB.load_relevant_dsl = lambda vc, pd, ch, **kw: [("reentrancy-cei", {})]
            try:
                rec = AB.backtest_case(case, d, AB.DEFAULT_PATTERNS_DIR, None, engine, d)
            finally:
                AB.run_dsl_on_file, AB.load_relevant_dsl = orig, orig_load
            self.assertEqual(rec["outcome"], "MISSED")
            self.assertEqual(rec["caught_by"], [])
            self.assertIn("stayed-silent", rec["missing_capability"])

    def test_missed_no_detector_but_corpus_knows(self):
        with tempfile.TemporaryDirectory() as d:
            case = self._local_case(d, vuln_class="reentrancy")
            engine, _ = _fake_engine_factory()
            orig_load = AB.load_relevant_dsl
            orig_corpus = AB.corpus_knows_class
            AB.load_relevant_dsl = lambda vc, pd, ch, **kw: []  # zero relevant detectors
            AB.corpus_knows_class = lambda vc: (3, ["INV-ATM-EX-0001"])  # corpus knows
            try:
                rec = AB.backtest_case(case, d, AB.DEFAULT_PATTERNS_DIR, None, engine, d)
            finally:
                AB.load_relevant_dsl = orig_load
                AB.corpus_knows_class = orig_corpus
            self.assertEqual(rec["outcome"], "MISSED")
            self.assertEqual(rec["missing_capability"],
                             "corpus-knows-class-but-no-firing-detector")

    def test_na_source_unavailable(self):
        with tempfile.TemporaryDirectory() as d:
            # no local checkout, no repo/ref -> not fetchable -> NA (PR3a gate
            # fires before the clone attempt; both are honest NA, not MISSED).
            case = {"id": "BUG-NA", "vuln_class": "oracle", "file_line": "src/X.sol:1"}
            engine, _ = _fake_engine_factory()
            rec = AB.backtest_case(case, None, AB.DEFAULT_PATTERNS_DIR, None, engine, d)
            self.assertEqual(rec["outcome"], "NA")
            self.assertEqual(rec["missing_capability"], "non-fetchable")

    def test_na_source_unavailable_after_fetch_attempt(self):
        with tempfile.TemporaryDirectory() as d:
            # repo+ref present (fetchable coordinates) but the clone/locate fails
            # -> source-unavailable NA, exercised via a stubbed locate_source.
            case = {"id": "BUG-NA2", "repo": "o/r", "prefix_ref": "abc",
                    "vuln_class": "oracle", "file_line": "src/X.sol:1"}
            engine, _ = _fake_engine_factory()
            orig = AB.locate_source
            AB.locate_source = lambda c, lc, wr: (None, None, "fetch-failed: offline")
            try:
                rec = AB.backtest_case(case, None, AB.DEFAULT_PATTERNS_DIR, None,
                                       engine, d)
            finally:
                AB.locate_source = orig
            self.assertEqual(rec["outcome"], "NA")
            self.assertEqual(rec["missing_capability"], "source-unavailable")


class TestReportAndCLI(unittest.TestCase):
    def test_human_report_renders_all_outcomes(self):
        recs = [
            {"id": "A", "outcome": "CAUGHT", "vuln_class": "reentrancy",
             "file_line": "x:1", "caught_by": ["dsl_detectors"], "fired_at_line": 5,
             "layers": {"dsl_detectors": {"fired_slugs": ["s1"]}}},
            {"id": "B", "outcome": "MISSED", "vuln_class": "oracle", "file_line": "y:2",
             "missing_capability": "no-detector-for-class:oracle",
             "layers": {"dsl_detectors": {"selected": 0}, "corpus_invariants": {"matched": 0}}},
            {"id": "C", "outcome": "NA", "vuln_class": "dos", "file_line": "z:3",
             "reason": "fetch-failed", "layers": {}},
        ]
        out = AB.human_report(recs)
        self.assertIn("CAUGHT=1", out)
        self.assertIn("MISSED=1", out)
        self.assertIn("NA=1", out)
        self.assertIn("MISSING CAPABILITY", out)
        self.assertIn("1/2 = 50.0%", out)

    def test_cli_single_case_na_exits_zero_json(self):
        # No repo/ref/checkout -> NA, but must exit 0 with valid JSON envelope.
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH),
             "--id", "CLI-1", "--vuln-class", "reentrancy",
             "--file-line", "src/X.sol:1", "--json"],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.auditor_backtest.v1")
        self.assertEqual(len(payload["cases"]), 1)
        self.assertEqual(payload["cases"][0]["id"], "CLI-1")
        self.assertEqual(payload["cases"][0]["outcome"], "NA")


class TestPR3aFetchableAndSplit(unittest.TestCase):
    """PR3a: fetchable-only admission, prose/fabricated drop, non-fetchable->NA,
    split normalization/filter, and the --corpus-detector-dir flag."""

    # ---- split normalization ----
    def test_normalize_split_canonical_and_aliases(self):
        self.assertEqual(AB.normalize_split("train"), "TRAIN")
        self.assertEqual(AB.normalize_split("held-out"), "HELD_OUT")
        self.assertEqual(AB.normalize_split("heldout"), "HELD_OUT")
        self.assertEqual(AB.normalize_split("fresh"), "FRESH_TARGET")
        self.assertEqual(AB.normalize_split("fixed_ref"), "FIXED_REF")
        self.assertEqual(AB.normalize_split("test"), "HELD_OUT")
        self.assertEqual(AB.normalize_split("bogus"), "")
        self.assertEqual(AB.normalize_split(""), "")

    def test_case_split_reads_any_key(self):
        self.assertEqual(AB.case_split({"split": "HELD_OUT"}), "HELD_OUT")
        self.assertEqual(AB.case_split({"split_tag": "train"}), "TRAIN")
        self.assertEqual(AB.case_split({}), "")

    # ---- droppable (prose / fabricated / quarantine) ----
    def test_droppable_prose_fabricated_quarantine(self):
        self.assertTrue(AB.is_droppable_record({"trust_state": "prose_memory"})[0])
        self.assertTrue(AB.is_droppable_record({"trust_state": "quarantine"})[0])
        self.assertTrue(AB.is_droppable_record({"is_fabricated": True})[0])
        self.assertTrue(AB.is_droppable_record({"is_prose_only": True})[0])
        self.assertTrue(AB.is_droppable_record({"r76_verdict": "fail-conceptual-file-line"})[0])
        self.assertFalse(AB.is_droppable_record({"trust_state": "active"})[0])
        self.assertFalse(AB.is_droppable_record({})[0])

    # ---- fetchable detection ----
    def test_fetchable_by_status_and_coordinates(self):
        self.assertTrue(AB.is_fetchable({"fetch_status": "immutable_ready"}, None)[0])
        self.assertTrue(AB.is_fetchable({"repo": "o/r", "prefix_ref": "abc"}, None)[0])
        self.assertTrue(AB.is_fetchable({}, "/some/checkout")[0])
        # explicit non-fetchable always wins
        self.assertFalse(AB.is_fetchable({"fetch_status": "dead_source",
                                          "repo": "o/r", "prefix_ref": "x"}, None)[0])
        # nothing to go on
        self.assertFalse(AB.is_fetchable({"vuln_class": "oracle"}, None)[0])

    # ---- non-fetchable case -> NA (NOT MISSED) ----
    def test_non_fetchable_case_is_na_not_missed(self):
        with tempfile.TemporaryDirectory() as d:
            case = {"id": "NF-1", "vuln_class": "reentrancy",
                    "file_line": "src/X.sol:1", "fetch_status": "dead_source",
                    "repo": "o/r", "prefix_ref": "abc"}
            engine, _ = _fake_engine_factory()
            rec = AB.backtest_case(case, None, AB.DEFAULT_PATTERNS_DIR, None,
                                   engine, d)
            self.assertEqual(rec["outcome"], "NA")
            self.assertEqual(rec["missing_capability"], "non-fetchable")
            self.assertIn("non-fetchable", rec["reason"])

    def test_record_carries_split_tag(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / "src").mkdir()
            (base / "src" / "Vault.sol").write_text("contract Vault {}")
            case = {"id": "S-1", "repo": "o/r", "prefix_ref": "abc",
                    "vuln_class": "reentrancy", "file_line": "src/Vault.sol:10",
                    "split": "HELD_OUT"}
            engine, fake_run = _fake_engine_factory(silent=True)
            orig, orig_load = AB.run_dsl_on_file, AB.load_relevant_dsl
            AB.run_dsl_on_file = fake_run
            AB.load_relevant_dsl = lambda vc, pd, ch, **kw: [("reentrancy-cei", {})]
            try:
                rec = AB.backtest_case(case, d, AB.DEFAULT_PATTERNS_DIR, None, engine, d)
            finally:
                AB.run_dsl_on_file, AB.load_relevant_dsl = orig, orig_load
            self.assertEqual(rec["split"], "HELD_OUT")

    # ---- CLI: fetchable case (proceeds), prose drop, split filter ----
    def _write_cases(self, d, rows):
        p = Path(d) / "cases.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        return p

    def test_cli_drops_prose_and_filters_split(self):
        with tempfile.TemporaryDirectory() as d:
            rows = [
                # prose record -> dropped, never scored
                {"id": "PROSE", "vuln_class": "reentrancy",
                 "file_line": "src/A.sol:1", "repo": "o/r", "prefix_ref": "z",
                 "is_prose_only": True, "split": "HELD_OUT"},
                # non-fetchable HELD_OUT -> NA
                {"id": "DEAD", "vuln_class": "oracle", "file_line": "src/B.sol:1",
                 "fetch_status": "dead_source", "split": "HELD_OUT"},
                # off-split TRAIN -> skipped by --split HELD_OUT
                {"id": "TRAINONLY", "vuln_class": "dos", "file_line": "src/C.sol:1",
                 "repo": "o/r", "prefix_ref": "z", "split": "TRAIN"},
            ]
            cases = self._write_cases(d, rows)
            proc = subprocess.run(
                [sys.executable, str(MODULE_PATH), "--cases", str(cases),
                 "--split", "HELD_OUT", "--json"],
                capture_output=True, text=True, timeout=180,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            ids = [c["id"] for c in payload["cases"]]
            # PROSE dropped; TRAINONLY off-split skipped; only DEAD scored (as NA)
            self.assertNotIn("PROSE", ids)
            self.assertNotIn("TRAINONLY", ids)
            self.assertIn("DEAD", ids)
            adm = payload["admission"]
            self.assertEqual(adm["split_requested"], "HELD_OUT")
            self.assertEqual(adm["split_skipped"], 1)         # TRAINONLY
            self.assertEqual(adm["dropped_non_fetchable_records"], 1)  # PROSE
            dead = next(c for c in payload["cases"] if c["id"] == "DEAD")
            self.assertEqual(dead["outcome"], "NA")
            self.assertEqual(dead["missing_capability"], "non-fetchable")

    def test_cli_bad_split_value_errors(self):
        with tempfile.TemporaryDirectory() as d:
            cases = self._write_cases(d, [{"id": "X", "vuln_class": "dos",
                                           "file_line": "a:1", "repo": "o/r",
                                           "prefix_ref": "z"}])
            proc = subprocess.run(
                [sys.executable, str(MODULE_PATH), "--cases", str(cases),
                 "--split", "NONSENSE"],
                capture_output=True, text=True, timeout=120,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("is not one of", proc.stderr)

    def test_cli_corpus_detector_dir_flag_accepted_and_echoed(self):
        with tempfile.TemporaryDirectory() as d:
            extra = Path(d) / "class_detectors"
            extra.mkdir()
            cases = self._write_cases(d, [
                {"id": "DEAD2", "vuln_class": "oracle", "file_line": "src/B.sol:1",
                 "fetch_status": "dead_source"}])
            proc = subprocess.run(
                [sys.executable, str(MODULE_PATH), "--cases", str(cases),
                 "--corpus-detector-dir", str(extra),
                 "--corpus-detector-dir", str(extra),  # repeatable
                 "--json"],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["admission"]["corpus_detector_dirs"],
                             [str(extra), str(extra)])

    def test_human_report_renders_partial_and_admission(self):
        recs = [
            {"id": "P", "outcome": "PARTIAL", "vuln_class": "reentrancy",
             "file_line": "x:1", "caught_by": ["dsl_detectors"], "fired_at_line": 9,
             "missing_capability": "fired-in-file-but-not-at-cited-line",
             "layers": {"dsl_detectors": {}}},
            {"id": "C", "outcome": "CAUGHT", "vuln_class": "oracle",
             "file_line": "y:2", "caught_by": ["dsl_detectors"], "fired_at_line": 2,
             "layers": {"dsl_detectors": {"fired_slugs": ["s"]}}},
        ]
        adm = {"split_requested": "HELD_OUT", "split_skipped": 4,
               "dropped_non_fetchable_records": 2, "corpus_detector_dirs": ["/x"]}
        out = AB.human_report(recs, admission=adm)
        self.assertIn("PARTIAL=1", out)
        self.assertIn("strict line recall", out)
        self.assertIn("1/2 = 50.0%", out)          # CAUGHT/(CAUGHT+PARTIAL+MISSED)
        self.assertIn("split: HELD_OUT", out)
        self.assertIn("dropped (prose/fabricated/quarantined", out)


class TestPR4PerLanguage(unittest.TestCase):
    """PR4: the backtest applies the detector layer wired for the TARGET
    language (Rust/Go via pure-regex runners, Solidity via Slither, TS via
    semgrep) and an optional novel-vector engine arm. These tests use the REAL
    runners (pure-regex, no toolchain) so they verify the wiring end-to-end."""

    # ---- language detection ----
    def test_language_of(self):
        self.assertEqual(AB.language_of("src/Vault.sol:10"), "solidity")
        self.assertEqual(AB.language_of("src/lib.rs:4"), "rust")
        self.assertEqual(AB.language_of("watch.go:7"), "go")
        self.assertEqual(AB.language_of("a/b.ts:1"), "typescript")
        self.assertEqual(AB.language_of("a/b.js:1"), "javascript")
        self.assertEqual(AB.language_of("README.md:1"), "unknown")
        self.assertEqual(AB.language_of(""), "unknown")

    def _case(self, d, rel, body, vuln_class, line):
        base = Path(d)
        fp = base / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(body)
        return {"id": "PL", "repo": "o/r", "prefix_ref": "abc",
                "vuln_class": vuln_class, "file_line": f"{rel}:{line}"}

    # ---- Rust: real rust-detector-runner fires the FROST aggregate detector ----
    def test_rust_aggregate_under_threshold_caught(self):
        body = (
            "use std::collections::BTreeMap;\n"
            "pub fn aggregate(signature_shares: &BTreeMap<Identifier, Share>)"
            " -> Result<Sig, Error> {\n"
            "    let mut group = Sig::default();\n"
            "    for (_id, s) in signature_shares { group = group.add(s); }\n"
            "    Ok(group)\n}\n"
        )
        with tempfile.TemporaryDirectory() as d:
            case = self._case(d, "src/aggregate.rs", body, "signature", 2)
            engine = AB.import_engine()  # Slither path unused for .rs
            rec = AB.backtest_case(case, d, AB.DEFAULT_PATTERNS_DIR, None, engine, d)
            self.assertEqual(rec["language"], "rust")
            self.assertEqual(rec["outcome"], "CAUGHT")
            self.assertEqual(rec["layers"]["dsl_detectors"]["engine"],
                             "rust-detector-runner")
            self.assertIn("rust.frost.aggregate.under_threshold_signature_shares",
                          rec["layers"]["dsl_detectors"]["fired_slugs"])

    # ---- Go: real go-detector-runner fires the self-heal detector ----
    def test_go_self_heal_caught(self):
        body = (
            "package w\n"
            "func Process(node *Node) {\n"
            "    if node.Status != Expected {\n"
            '        Warnf("unexpected %v", node.Status)\n'
            "    }\n"
            "    node.Status = Available\n}\n"
        )
        with tempfile.TemporaryDirectory() as d:
            case = self._case(d, "heal.go", body, "logic", 4)
            engine = AB.import_engine()
            rec = AB.backtest_case(case, d, AB.DEFAULT_PATTERNS_DIR, None, engine, d)
            self.assertEqual(rec["language"], "go")
            self.assertEqual(rec["outcome"], "CAUGHT")
            self.assertEqual(rec["layers"]["dsl_detectors"]["engine"], "go+cosmos")

    # ---- cross-file no-leak: a hit in a SIBLING file is never credited ----
    def test_no_cross_file_credit(self):
        # The vulnerable file is benign; a sibling file in the same checkout
        # carries the firing shape. Only the target file is scanned, so MISSED.
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / "src").mkdir(parents=True)
            (base / "src" / "benign.rs").write_text(
                "pub fn noop(x: u64) -> u64 { x }\n")
            (base / "src" / "sibling.rs").write_text(
                "pub fn aggregate(signature_shares: &Vec<S>) -> R {"
                " do_agg(signature_shares) }\n")
            case = {"id": "NL", "repo": "o/r", "prefix_ref": "abc",
                    "vuln_class": "signature", "file_line": "src/benign.rs:1"}
            engine = AB.import_engine()
            rec = AB.backtest_case(case, d, AB.DEFAULT_PATTERNS_DIR, None, engine, d)
            self.assertEqual(rec["outcome"], "MISSED")
            self.assertEqual(rec["layers"]["dsl_detectors"]["fired_slugs"], [])

    # ---- engine arm credits PARTIAL (file-recall), never a line-level CAUGHT ----
    def test_engine_arm_partial_file_recall(self):
        body = (
            "pub fn deposit(amount: u64, total_supply: u64) -> u64 {"
            " amount * total_supply }\n"
        )
        with tempfile.TemporaryDirectory() as d:
            case = self._case(d, "src/pool.rs", body, "conservation", 1)
            engine = AB.import_engine()
            rec = AB.backtest_case(case, d, AB.DEFAULT_PATTERNS_DIR, None, engine, d,
                                   engine_arm_enabled=True)
            # no detector fires for 'conservation' on this .rs, but the novel-
            # vector miner derives a 'conservation' family invariant -> PARTIAL.
            self.assertEqual(rec["outcome"], "PARTIAL")
            self.assertEqual(rec["caught_by"], ["novel_vector_engine"])
            nv = rec["layers"]["novel_vector_engine"]
            self.assertTrue(nv["fired"])
            self.assertIn("conservation", nv["families"])
            # file-recall only: never a line-level catch
            self.assertIsNone(rec["fired_at_line"])

    def test_engine_arm_off_by_default(self):
        body = "pub fn deposit(a: u64, t: u64) -> u64 { a * t }\n"
        with tempfile.TemporaryDirectory() as d:
            case = self._case(d, "src/pool.rs", body, "conservation", 1)
            engine = AB.import_engine()
            rec = AB.backtest_case(case, d, AB.DEFAULT_PATTERNS_DIR, None, engine, d)
            # arm not enabled -> no novel_vector_engine layer, outcome MISSED.
            self.assertNotIn("novel_vector_engine", rec["layers"])
            self.assertEqual(rec["outcome"], "MISSED")

    # ---- unknown / unwired language -> MISSED with honest capability gap ----
    def test_unknown_language_missed(self):
        with tempfile.TemporaryDirectory() as d:
            case = self._case(d, "notes.md", "# nothing\n", "reentrancy", 1)
            engine = AB.import_engine()
            rec = AB.backtest_case(case, d, AB.DEFAULT_PATTERNS_DIR, None, engine, d)
            self.assertEqual(rec["language"], "unknown")
            self.assertEqual(rec["outcome"], "MISSED")
            self.assertEqual(rec["missing_capability"],
                             "no-detector-layer-for-unknown-language")

    # ---- pid -> class hint mapping ----
    def test_pid_extra_classes(self):
        self.assertIn("signature", AB._pid_extra_classes(
            "rust.frost.aggregate.under_threshold_signature_shares"))
        self.assertIn("access-control", AB._pid_extra_classes(
            "go.statemachine.guard_only_on_one_path"))
        self.assertEqual(AB._pid_extra_classes("totally.unrelated.pattern"), set())


class TestIter4CorpusDetectorDirUnion(unittest.TestCase):
    """iter4 regression: the Rust/Go arms must LOAD + RUN scan()-exposing
    detector modules found under --corpus-detector-dir, not only the wired
    runner registry. Before iter4 the rust arm called scan_workspace on the
    wired runner and silently ignored --corpus-detector-dir, so detectors under
    detectors/from_advisories/*.py never loaded -> a covered-class TRAIN case
    was reported MISSED with empty fired_slugs."""

    def _build_detector_dir(self, lang):
        """Drop a tiny self-contained scan()-exposing detector module into a
        temp dir so the test does not depend on detectors/from_advisories/
        contents. The module mirrors the advisory-seed emit shape exactly:
        module-level DETECTOR_ID / CLASS_TAG / LANGUAGE / _EXT + scan(root)."""
        d = Path(tempfile.mkdtemp(prefix="iter4_detdir_"))
        ext = ".rs" if lang == "rust" else ".go"
        (d / "alloc_amp_test.py").write_text(
            "from pathlib import Path\n"
            "DETECTOR_ID = 'alloc_amp_test'\n"
            "CLASS_TAG = 'allocation-amplification'\n"
            f"LANGUAGE = {lang!r}\n"
            f"_EXT = {ext!r}\n"
            "def scan(root):\n"
            "    hits = []\n"
            "    for f in Path(root).rglob('*' + _EXT):\n"
            "        src = f.read_text(errors='ignore')\n"
            "        for i, ln in enumerate(src.splitlines(), 1):\n"
            "            if 'with_capacity' in ln and 'CAP' not in src:\n"
            "                hits.append((str(f), i, DETECTOR_ID + ': ' + ln.strip()))\n"
            "    return hits\n"
        )
        return d

    def test_rust_arm_loads_corpus_detector_dir(self):
        det_dir = self._build_detector_dir("rust")
        with tempfile.TemporaryDirectory() as ws:
            wsp = Path(ws)
            (wsp / "parse.rs").write_text(
                "pub fn read(r: &mut R) -> Vec<u8> {\n"
                "    let len = r.read_u32() as usize;\n"
                "    let mut buf = Vec::with_capacity(len);\n"
                "    buf\n"
                "}\n"
            )
            case = {"id": "T", "vuln_class": "allocation-amplification",
                    "file_line": "parse.rs:3", "split": "TRAIN"}
            engine = None  # rust arm is pure-regex, no slither needed

            # WITHOUT corpus dir -> the wired registry does not cover this class.
            rec0 = AB.backtest_case(case, ws, AB.DEFAULT_PATTERNS_DIR, None,
                                    engine, ws, corpus_detector_dirs=[])
            self.assertEqual(rec0["outcome"], "MISSED")
            self.assertEqual(rec0["layers"]["dsl_detectors"]["fired_slugs"], [])

            # WITH corpus dir -> the from_advisories-shaped detector fires.
            rec1 = AB.backtest_case(case, ws, AB.DEFAULT_PATTERNS_DIR, None,
                                    engine, ws,
                                    corpus_detector_dirs=[str(det_dir)])
            self.assertEqual(rec1["outcome"], "CAUGHT")
            self.assertEqual(rec1["fired_at_line"], 3)
            self.assertIn("alloc_amp_test",
                          rec1["layers"]["dsl_detectors"]["fired_slugs"])

    def test_corpus_dir_negative_control_fixed_source(self):
        """Fixed source (CAP guard present) must NOT fire -> mechanism-matched,
        not always-on. Proves a truthful low number is achievable."""
        det_dir = self._build_detector_dir("rust")
        with tempfile.TemporaryDirectory() as ws:
            wsp = Path(ws)
            (wsp / "parse.rs").write_text(
                "pub fn read(r: &mut R) -> Vec<u8> {\n"
                "    let CAP: usize = 1024;\n"
                "    let mut buf = Vec::with_capacity(CAP);\n"
                "    buf\n"
                "}\n"
            )
            case = {"id": "T", "vuln_class": "allocation-amplification",
                    "file_line": "parse.rs:3", "split": "FIXED_REF"}
            rec = AB.backtest_case(case, ws, AB.DEFAULT_PATTERNS_DIR, None,
                                   None, ws,
                                   corpus_detector_dirs=[str(det_dir)])
            self.assertEqual(rec["outcome"], "MISSED")
            self.assertEqual(rec["layers"]["dsl_detectors"]["fired_slugs"], [])

    def test_corpus_dir_class_mismatch_not_credited(self):
        """A vulnerable file but a vuln_class the detector's CLASS_TAG does not
        match must NOT be credited -> the class gate works (not noise)."""
        det_dir = self._build_detector_dir("rust")
        with tempfile.TemporaryDirectory() as ws:
            wsp = Path(ws)
            (wsp / "parse.rs").write_text(
                "pub fn read(r: &mut R) -> Vec<u8> {\n"
                "    let len = r.read_u32() as usize;\n"
                "    let mut buf = Vec::with_capacity(len);\n"
                "    buf\n"
                "}\n"
            )
            case = {"id": "T", "vuln_class": "reentrancy",
                    "file_line": "parse.rs:3", "split": "TRAIN"}
            rec = AB.backtest_case(case, ws, AB.DEFAULT_PATTERNS_DIR, None,
                                   None, ws,
                                   corpus_detector_dirs=[str(det_dir)])
            self.assertEqual(rec["outcome"], "MISSED")
            self.assertEqual(rec["layers"]["dsl_detectors"]["fired_slugs"], [])

    def test_corpus_dir_language_filter_skips_mismatched_lang(self):
        """A .go-declared detector must not run against a .rs target (and vice
        versa) - the language filter keeps the arm honest."""
        det_dir = self._build_detector_dir("go")  # LANGUAGE='go', _EXT='.go'
        with tempfile.TemporaryDirectory() as ws:
            wsp = Path(ws)
            (wsp / "parse.rs").write_text(
                "pub fn read(r: &mut R) -> Vec<u8> {\n"
                "    let mut buf = Vec::with_capacity(len);\n"
                "    buf\n"
                "}\n"
            )
            case = {"id": "T", "vuln_class": "allocation-amplification",
                    "file_line": "parse.rs:2", "split": "TRAIN"}
            rec = AB.backtest_case(case, ws, AB.DEFAULT_PATTERNS_DIR, None,
                                   None, ws,
                                   corpus_detector_dirs=[str(det_dir)])
            # go detector skipped on rust target -> nothing fires.
            self.assertEqual(rec["layers"]["dsl_detectors"]["fired_slugs"], [])

    def test_real_from_advisories_dir_loads(self):
        """Smoke: the real detectors/from_advisories dir (8 rust + 2 go) loads
        through the rust arm and credits the alloc detector on a vulnerable
        rust file. Guards against a real-corpus regression."""
        adv = AB.REPO_ROOT / "detectors" / "from_advisories"
        if not adv.is_dir():
            self.skipTest("detectors/from_advisories absent")
        with tempfile.TemporaryDirectory() as ws:
            wsp = Path(ws)
            (wsp / "parse.rs").write_text(
                "pub fn read_message(r: &mut R) -> Vec<u8> {\n"
                "    let len = r.read_u32() as usize;\n"
                "    let mut buf = Vec::with_capacity(len);\n"
                "    buf.resize(len, 0u8);\n"
                "    buf\n"
                "}\n"
            )
            case = {"id": "T", "vuln_class": "allocation-amplification",
                    "file_line": "parse.rs:3", "split": "TRAIN"}
            rec = AB.backtest_case(case, ws, AB.DEFAULT_PATTERNS_DIR, None,
                                   None, ws, corpus_detector_dirs=[str(adv)])
            self.assertEqual(rec["outcome"], "CAUGHT")
            self.assertIn("alloc_amplification_before_cap",
                          rec["layers"]["dsl_detectors"]["fired_slugs"])


if __name__ == "__main__":
    unittest.main()
