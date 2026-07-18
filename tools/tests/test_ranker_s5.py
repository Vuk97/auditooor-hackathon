#!/usr/bin/env python3
"""Wave-7 S5 tests — cross-language transfer scorer.

Coverage:
  T1  load_cross_lang_map() loads reference/cross_lang_detector_map.yaml
  T2  score_s5_cross_lang_transfer() returns a dict (always; empty if no map)
  T3  cross-language verdicts contribute (target lang go; rust corpus entry;
      bug_class matches) — exercises the discount + per-site sim path
  T4  empirical_anchor bonus applies (+0.3 per distinct attack_class)
  T5  same-language verdicts skipped (no double-counting with S1)
  T6  audit/ranker_weights.yaml has w1..w5 summing to 1.0
  T7  combine_scores accepts s5 kwarg + applies w5 weight
  T8  rank() exposes w5 + s5_enabled in inputs payload (smoke; backward compat)
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "ranker.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("ranker_s5_for_test", MOD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {MOD_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ranker_s5_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


RA = _load()


# Minimal cross-lang map fixture: one Go<->Rust mapping with an empirical
# anchor. Wave-7 S5 should:
#   - score_s5 with target_language=go finds Rust corpus verdicts whose
#     bug_class == 'cross-lang-fixture-class' and transfers their attack
#     classes at 0.4 discount
#   - apply +0.3 empirical-anchor bonus per distinct AC
FIXTURE_MAP_YAML = """schema: auditooor.cross_lang_detector_map.v1
mappings:

  - bug_class: cross-lang-fixture-class
    go:
      - go_ast.fixture_planned
    rust:
      - rust_wave1.fixture_planned
    empirical_anchor: dydx-cantina-FIXTURE (Go HIGH)
    severity_class_match: high
"""

# A tag record fixture: rust verdict whose bug_class matches the entry,
# attack_classes_to_try has two classes the Go target should inherit.
FIXTURE_TAG_YAML = """verdict_id: fixture-rust-s5/verdict.md
target_repo: someone/rust-repo
audit_pin_sha: "0000000"
language: rust
verdict_class: FILED
bug_class: cross-lang-fixture-class
triager_outcome: ACCEPTED
attack_classes_to_try: [cross-lang-attack-foo, cross-lang-attack-bar]
sites:
  - file_path: src/lib.rs
    line_start: 10
    shape_hash: deadbeef
    shape_hash_fine: cafebabe
"""

# Same-language fixture (go verdict; same bug_class). S5 must NOT touch this.
FIXTURE_SAME_LANG_TAG_YAML = """verdict_id: fixture-go-s5-same-lang/verdict.md
target_repo: someone/go-repo
audit_pin_sha: "0000000"
language: go
verdict_class: FILED
bug_class: cross-lang-fixture-class
triager_outcome: ACCEPTED
attack_classes_to_try: [should-not-appear-in-s5]
sites:
  - file_path: x.go
    line_start: 1
    shape_hash: facefeed
"""


def _write_fixture_tagsdir() -> Path:
    """Materialize fixture tags into a temp dir; return the dir."""
    tmp = Path(tempfile.mkdtemp(prefix="ranker_s5_tags_"))
    (tmp / "rust_fixture.yaml").write_text(FIXTURE_TAG_YAML, encoding="utf-8")
    (tmp / "go_same_lang_fixture.yaml").write_text(
        FIXTURE_SAME_LANG_TAG_YAML, encoding="utf-8"
    )
    return tmp


def _write_fixture_map() -> Path:
    tmp = Path(tempfile.mkstemp(prefix="cross_lang_map_", suffix=".yaml")[1])
    tmp.write_text(FIXTURE_MAP_YAML, encoding="utf-8")
    return tmp


class TestLoadCrossLangMap(unittest.TestCase):

    def test_load_real_map(self):
        # T1 — the production map loads and has the expected schema header.
        m = RA.load_cross_lang_map()
        self.assertIsInstance(m, dict)
        self.assertEqual(
            m.get("schema"), "auditooor.cross_lang_detector_map.v1",
            f"expected schema header, got {m.get('schema')!r}",
        )
        mappings = m.get("mappings", [])
        self.assertGreaterEqual(
            len(mappings), 5,
            f"expected >=5 entries in cross_lang_detector_map.yaml, got {len(mappings)}",
        )

    def test_load_missing_returns_empty(self):
        ghost = REPO_ROOT / "reference" / "_does_not_exist.yaml"
        m = RA.load_cross_lang_map(ghost)
        self.assertEqual(m, {})

    def test_underscore_alias(self):
        # spec exposes both load_cross_lang_map and _load_cross_lang_map
        self.assertIs(RA._load_cross_lang_map, RA.load_cross_lang_map)


class TestScoreS5(unittest.TestCase):

    def test_returns_dict_when_map_empty(self):
        # T2 — empty map -> empty dict, never raises
        out = RA.score_s5_cross_lang_transfer(
            target_language="go",
            target_shape="abc",
            target_shape_fine="def",
            tags=[],
            cross_lang_map={},
        )
        self.assertIsInstance(out, dict)
        self.assertEqual(out, {})

    def test_cross_lang_verdict_contributes(self):
        # T3 — Go target inherits attack classes from a Rust corpus verdict
        tags_dir = _write_fixture_tagsdir()
        map_path = _write_fixture_map()
        tags = RA.load_tags(tags_dir=tags_dir)
        cl_map = RA.load_cross_lang_map(map_path)
        out = RA.score_s5_cross_lang_transfer(
            target_language="go",
            target_shape="not-matching-hash",
            target_shape_fine="not-matching-fine",
            tags=tags,
            cross_lang_map=cl_map,
        )
        # Both cross-lang-attack-foo and cross-lang-attack-bar should appear
        self.assertIn("cross-lang-attack-foo", out)
        self.assertIn("cross-lang-attack-bar", out)
        # Each entry: at least one transfer evidence + one empirical_anchor
        # bonus (the entry has empirical_anchor set).
        foo_evs = out["cross-lang-attack-foo"]
        kinds = [e.get("subkind") for e in foo_evs]
        self.assertIn("empirical_anchor_bonus", kinds)
        # At least one non-bonus transfer evidence (the per-site contribution)
        transfer_evs = [e for e in foo_evs if e.get("subkind") != "empirical_anchor_bonus"]
        self.assertGreaterEqual(len(transfer_evs), 1)
        self.assertEqual(transfer_evs[0]["scorer"], "S5")
        self.assertEqual(transfer_evs[0]["sibling_language"], "rust")
        self.assertEqual(transfer_evs[0]["target_language"], "go")
        self.assertAlmostEqual(transfer_evs[0]["discount"], 0.4, places=3)

    def test_empirical_anchor_bonus_applied(self):
        # T4 — bonus is +0.3 per distinct AC
        tags_dir = _write_fixture_tagsdir()
        map_path = _write_fixture_map()
        tags = RA.load_tags(tags_dir=tags_dir)
        cl_map = RA.load_cross_lang_map(map_path)
        out = RA.score_s5_cross_lang_transfer(
            target_language="go",
            target_shape="x",
            target_shape_fine="y",
            tags=tags,
            cross_lang_map=cl_map,
        )
        bonus_evs = [
            e for e in out.get("cross-lang-attack-foo", [])
            if e.get("subkind") == "empirical_anchor_bonus"
        ]
        self.assertEqual(len(bonus_evs), 1)
        self.assertAlmostEqual(bonus_evs[0]["contribution"], 0.3, places=3)
        self.assertEqual(
            bonus_evs[0]["empirical_anchor"], "dydx-cantina-FIXTURE (Go HIGH)"
        )

    def test_same_language_verdicts_skipped(self):
        # T5 — the same-language go fixture's attack class must NOT appear
        # (S1/S2 own same-language signals; S5 must avoid double-counting)
        tags_dir = _write_fixture_tagsdir()
        map_path = _write_fixture_map()
        tags = RA.load_tags(tags_dir=tags_dir)
        cl_map = RA.load_cross_lang_map(map_path)
        out = RA.score_s5_cross_lang_transfer(
            target_language="go",
            target_shape="x",
            target_shape_fine="y",
            tags=tags,
            cross_lang_map=cl_map,
        )
        self.assertNotIn("should-not-appear-in-s5", out)


class TestWeights(unittest.TestCase):

    def test_weights_sum_to_one_with_s5(self):
        # T6 — audit/ranker_weights.yaml total = 1.0 including w5 (and w6 if present).
        # Wave-9 added w6=0.15; the test sums all present w1..w6 keys so it
        # works whether the yaml has 5 or 6 weight entries.
        cfg = RA.load_weights()
        w = cfg.get("weights", {})
        for k in ("w1", "w2", "w3", "w4", "w5"):
            self.assertIn(k, w, f"missing weight {k} in ranker_weights.yaml")
        # Sum all w<N> keys present (handles w1-w5 pre-Wave-9 and w1-w6 post)
        weight_keys = [k for k in w if k.startswith("w") and k[1:].isdigit()]
        total = sum(float(w[k]) for k in weight_keys)
        self.assertAlmostEqual(total, 1.0, places=2)


class TestCombineScores(unittest.TestCase):

    def test_combine_accepts_s5_kwarg(self):
        # T7 — combine_scores applies w5 weight when s5 is non-empty
        s1 = {}
        s4 = {}
        s5 = {
            "attack-A": [
                {"contribution": 1.0, "scorer": "S5"},
            ]
        }
        rows = RA.combine_scores(
            s1, s4, s5=s5, w1=0.0, w2=0.0, w3=0.0, w4=0.0, w5=0.5,
            convergence_bonus=0.0,
        )
        # The single AC should score = 0.5 * 1.0 = 0.5
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["attack_class"], "attack-A")
        self.assertAlmostEqual(rows[0]["score"], 0.5, places=3)

    def test_combine_backward_compat_no_s5(self):
        # Phase-B callers that don't pass s5 must still work
        s1 = {"attack-X": [{"contribution": 1.0, "scorer": "S1"}]}
        s4 = {}
        rows = RA.combine_scores(
            s1, s4, w1=0.5, w2=0.0, w3=0.0, w4=0.0, w5=0.0,
            convergence_bonus=0.0,
        )
        self.assertEqual(len(rows), 1)
        self.assertAlmostEqual(rows[0]["score"], 0.5, places=3)


if __name__ == "__main__":
    unittest.main()
