#!/usr/bin/env python3
"""Wave-8 S5 synonym extension tests.

Coverage:
  T1  load_cross_lang_synonyms() loads reference/cross_lang_bug_class_synonyms.yaml
      and returns a non-empty inverted dict.
  T2  anchor-signer-check-missing resolves to missing-authority-check-on-msg-server
      (exact synonym entry).
  T3  signature-validation-gap resolves to missing-authority-check-on-msg-server
      (synonym entry added for FROST signer-check pattern).
  T4  S5 scorer reads synonyms automatically (no caller change required);
      a Rust tag with bug_class=signature-validation-gap contributes to Go
      target via the missing-authority-check-on-msg-server canonical entry.
  T5  A tag with cross_lang_canonical_bug_classes field is indexed and
      contributes to a Go target without needing a synonym entry.
  T6  S5 pure-pass with real corpus tags: at least one non-zero S5
      contribution exists for a Go target shape (cantina-192-shape proxy)
      when synonym map is active.
  T7  Synonym-matched contributions carry match_kind == "synonym" in the
      evidence dict.
  T8  cross_lang_canonical_bug_classes contributions carry
      match_kind == "canonical_field".

Run with:
    python3 -m unittest tools.tests.test_cross_lang_synonyms
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "ranker.py"
SYNONYMS_PATH = REPO_ROOT / "reference" / "cross_lang_bug_class_synonyms.yaml"
CROSS_LANG_MAP_PATH = REPO_ROOT / "reference" / "cross_lang_detector_map.yaml"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("ranker_synonyms_for_test", MOD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {MOD_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ranker_synonyms_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


RA = _load()


# ---------------------------------------------------------------------------
# Fixture: minimal cross-lang map with the missing-authority-check canonical
# ---------------------------------------------------------------------------

FIXTURE_MAP_YAML = """schema: auditooor.cross_lang_detector_map.v1
mappings:
  - bug_class: missing-authority-check-on-msg-server
    go:
      - go_ast.permissionless_admin_key_sentinel
    rust:
      - rust_wave1.anchor_owner_check_missing_on_authority
      - rust_wave1.anchor_signer_check_missing_on_authority
    empirical_anchor: dydx-cantina-192 (Go HIGH -- permissionless msgServer)
    severity_class_match: high

  - bug_class: fork-divergence-blocksync-gap
    go:
      - go_ast.fork_divergence_blocksync
    rust: []
    empirical_anchor: dydx-LEAD-CMTBFT-FORK-LAG (Go HIGH)
    severity_class_match: high
"""

# Synonym map fixture: maps signature-validation-gap to canonical
FIXTURE_SYNONYMS_YAML = """schema: auditooor.cross_lang_bug_class_synonyms.v1
canonical_synonyms:
  missing-authority-check-on-msg-server:
    - anchor-signer-check-missing
    - signature-validation-gap
  fork-divergence-blocksync-gap:
    - upstream-fix-not-backported
    - missing-verification-hardening-in-cometbft-fork
"""

# Rust tag with specific bug_class=signature-validation-gap (HUNT-L4 shape)
RUST_TAG_SYNONYM_YAML = """verdict_id: wave8-synonym-test/rust-signature-validation-gap.md
target_repo: lightsparkdev/frost
audit_pin_sha: "0000000"
language: rust
verdict_class: CANDIDATE
bug_class: signature-validation-gap
attack_classes_to_try:
  - signature-forgery
  - admin-bypass
sites:
  - file_path: src/signing.rs
    line_start: 73
"""

# Rust tag with cross_lang_canonical_bug_classes additive field
RUST_TAG_CANONICAL_FIELD_YAML = """verdict_id: wave8-canonical-field-test/rust-upstream-fix.md
target_repo: buildonspark/spark
audit_pin_sha: "0000000"
language: rust
verdict_class: FILED
bug_class: upstream-fix-not-backported
cross_lang_canonical_bug_classes:
  - fork-divergence-blocksync-gap
attack_classes_to_try:
  - upstream-fix-not-backported
  - fork-lag-divergence
sites:
  - file_path: crates/types/src/spark/mod.rs
    line_start: 213
"""


def _write_tmp(content: str, suffix: str = ".yaml") -> Path:
    fd, p = tempfile.mkstemp(suffix=suffix, prefix="wave8_syn_test_")
    Path(p).write_text(content, encoding="utf-8")
    return Path(p)


def _write_fixture_tags_dir(*yaml_contents: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="wave8_tags_"))
    for i, content in enumerate(yaml_contents):
        (tmp / f"fixture_{i:02d}.yaml").write_text(content, encoding="utf-8")
    return tmp


class TestSynonymMapLoads(unittest.TestCase):

    def test_t1_file_exists_and_loads(self):
        """T1 -- load_cross_lang_synonyms() loads the real production file."""
        self.assertTrue(SYNONYMS_PATH.exists(), f"Synonyms file not found: {SYNONYMS_PATH}")
        idx = RA.load_cross_lang_synonyms(SYNONYMS_PATH)
        self.assertIsInstance(idx, dict)
        self.assertGreater(len(idx), 0, "Expected non-empty synonym index from production file")

    def test_t2_anchor_signer_check_resolves(self):
        """T2 -- anchor-signer-check-missing resolves to missing-authority-check-on-msg-server."""
        idx = RA.load_cross_lang_synonyms(SYNONYMS_PATH)
        self.assertIn(
            "anchor-signer-check-missing", idx,
            "anchor-signer-check-missing not in synonym index",
        )
        self.assertEqual(
            idx["anchor-signer-check-missing"],
            "missing-authority-check-on-msg-server",
        )

    def test_t3_signature_validation_gap_resolves(self):
        """T3 -- signature-validation-gap resolves to missing-authority-check-on-msg-server."""
        idx = RA.load_cross_lang_synonyms(SYNONYMS_PATH)
        self.assertIn(
            "signature-validation-gap", idx,
            "signature-validation-gap not in synonym index",
        )
        self.assertEqual(
            idx["signature-validation-gap"],
            "missing-authority-check-on-msg-server",
        )

    def test_missing_file_returns_empty(self):
        """load_cross_lang_synonyms returns {} for a missing file."""
        ghost = REPO_ROOT / "reference" / "_does_not_exist_synonyms.yaml"
        idx = RA.load_cross_lang_synonyms(ghost)
        self.assertEqual(idx, {})


class TestS5SynonymContribution(unittest.TestCase):

    def _run_s5(self, tags, cl_map, synonyms):
        return RA.score_s5_cross_lang_transfer(
            target_language="go",
            target_shape="",
            target_shape_fine="",
            tags=tags,
            cross_lang_map=cl_map,
            synonyms=synonyms,
        )

    def test_t4_synonym_rust_tag_contributes_to_go_target(self):
        """T4 -- Rust tag bug_class=signature-validation-gap contributes
        to Go target for canonical missing-authority-check-on-msg-server
        via synonym match."""
        map_path = _write_tmp(FIXTURE_MAP_YAML)
        syn_path = _write_tmp(FIXTURE_SYNONYMS_YAML)
        tags_dir = _write_fixture_tags_dir(RUST_TAG_SYNONYM_YAML)

        cl_map = RA.load_cross_lang_map(map_path)
        synonyms = RA.load_cross_lang_synonyms(syn_path)
        tags = RA.load_tags(tags_dir=tags_dir)

        out = self._run_s5(tags, cl_map, synonyms)

        # Both attack classes from the Rust tag should appear in S5 output
        self.assertIn(
            "signature-forgery", out,
            "Expected signature-forgery in S5 output via synonym match",
        )
        self.assertIn(
            "admin-bypass", out,
            "Expected admin-bypass in S5 output via synonym match",
        )

    def test_t7_synonym_match_kind_is_synonym(self):
        """T7 -- synonym-matched evidence carries match_kind == 'synonym'."""
        map_path = _write_tmp(FIXTURE_MAP_YAML)
        syn_path = _write_tmp(FIXTURE_SYNONYMS_YAML)
        tags_dir = _write_fixture_tags_dir(RUST_TAG_SYNONYM_YAML)

        cl_map = RA.load_cross_lang_map(map_path)
        synonyms = RA.load_cross_lang_synonyms(syn_path)
        tags = RA.load_tags(tags_dir=tags_dir)

        out = self._run_s5(tags, cl_map, synonyms)

        transfer_evs = [
            e for e in out.get("signature-forgery", [])
            if e.get("subkind") != "empirical_anchor_bonus"
        ]
        self.assertTrue(
            any(e.get("match_kind") == "synonym" for e in transfer_evs),
            f"Expected match_kind=synonym in evidence; got: {transfer_evs}",
        )

    def test_t5_canonical_field_tag_contributes(self):
        """T5 -- tag with cross_lang_canonical_bug_classes contributes
        to Go target for fork-divergence-blocksync-gap."""
        map_path = _write_tmp(FIXTURE_MAP_YAML)
        syn_path = _write_tmp(FIXTURE_SYNONYMS_YAML)
        tags_dir = _write_fixture_tags_dir(RUST_TAG_CANONICAL_FIELD_YAML)

        cl_map = RA.load_cross_lang_map(map_path)
        synonyms = RA.load_cross_lang_synonyms(syn_path)
        tags = RA.load_tags(tags_dir=tags_dir)

        out = self._run_s5(tags, cl_map, synonyms)

        # The canonical_field tag should contribute fork-lag-divergence and
        # upstream-fix-not-backported as attack classes
        self.assertTrue(
            "upstream-fix-not-backported" in out or "fork-lag-divergence" in out,
            f"Expected fork-divergence-blocksync-gap canonical_field contribution; got keys: {list(out.keys())}",
        )

    def test_t8_canonical_field_match_kind(self):
        """T8 -- canonical_field-matched evidence carries match_kind == 'canonical_field'."""
        map_path = _write_tmp(FIXTURE_MAP_YAML)
        syn_path = _write_tmp(FIXTURE_SYNONYMS_YAML)
        tags_dir = _write_fixture_tags_dir(RUST_TAG_CANONICAL_FIELD_YAML)

        cl_map = RA.load_cross_lang_map(map_path)
        synonyms = RA.load_cross_lang_synonyms(syn_path)
        tags = RA.load_tags(tags_dir=tags_dir)

        out = self._run_s5(tags, cl_map, synonyms)

        all_evs = []
        for evs in out.values():
            all_evs.extend(evs)
        transfer_evs = [e for e in all_evs if e.get("subkind") != "empirical_anchor_bonus"]
        self.assertTrue(
            any(e.get("match_kind") == "canonical_field" for e in transfer_evs),
            f"Expected match_kind=canonical_field; got: {transfer_evs}",
        )


class TestS5PurePassRealCorpus(unittest.TestCase):

    def test_t6_real_corpus_nonzero_s5_for_go_target(self):
        """T6 -- With real corpus tags + real synonym map, at least one
        attack_class gets non-zero S5 contribution for a Go target."""
        tags = RA.load_tags()  # real corpus tags dir
        cl_map = RA.load_cross_lang_map()  # real cross_lang_detector_map.yaml
        synonyms = RA.load_cross_lang_synonyms()  # real synonyms map

        out = RA.score_s5_cross_lang_transfer(
            target_language="go",
            target_shape="",          # no shape hash; falls back to 0.2 partial credit
            target_shape_fine="",
            tags=tags,
            cross_lang_map=cl_map,
            synonyms=synonyms,
        )

        # At least one AC should have non-zero S5 contribution.
        nonzero = {
            ac: evs for ac, evs in out.items()
            if any(e.get("contribution", 0) > 0 for e in evs)
        }
        self.assertGreater(
            len(nonzero), 0,
            "Expected >=1 non-zero S5 AC contribution from real corpus + synonym map; got 0. "
            "Check that Rust tags have been re-tagged with cross_lang_canonical_bug_classes "
            "or that synonym map covers their bug_class strings.",
        )


if __name__ == "__main__":
    unittest.main()
