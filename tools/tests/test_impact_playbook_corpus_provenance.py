#!/usr/bin/env python3
"""Tests for the PLAYBOOK-CORPUS xref/index provenance check added to
tools/impact-methodology-corpus-provenance-check.py (--playbook-corpus mode).

Closes the wiring hole where the impact playbooks cite a kill_rubric_xref
(commit 69ec80c7b9) and index_key/index_keys with counts (commit 3208e3abf4),
but nothing asserted those citations still RESOLVE on disk:
  (a) every kill_rubric_xref resolves to a real KILL_RUBRIC_LIBRARY.md section
      (slug anchor under `## N. Title`, or a cited `sec N`);
  (b) every index_key/index_keys + index_file points at an existing index file
      whose `key` column actually contains the cited key.
Numeric member-count drift is a WARN, an unresolved key/file is the defect; the
check fails only when >10% of references are unresolved.

Proves: a resolving xref + present index key -> PASS; a dangling xref + absent
index key past the 10% floor -> DEFECT (fail). Also runs against the REAL
in-repo corpus and asserts it does not regress (xrefs all resolve, fraction <=10%).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_T = (Path(__file__).resolve().parent.parent
      / "impact-methodology-corpus-provenance-check.py")
_s = importlib.util.spec_from_file_location("impact_corpus_prov_pb", _T)
mod = importlib.util.module_from_spec(_s)
sys.modules["impact_corpus_prov_pb"] = mod
_s.loader.exec_module(mod)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _mk_repo(playbooks: list[dict], library: str,
             index_files: dict[str, list[dict]]) -> Path:
    """Build a throwaway repo root with the corpus YAML, the kill-rubric
    library, and by_*.jsonl index files."""
    import yaml as _yaml
    root = Path(tempfile.mkdtemp())
    ct = root / "audit" / "corpus_tags"
    (ct / "index").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    (ct / "impact_hunting_methodology.yaml").write_text(
        _yaml.safe_dump({"schema": "test", "playbooks": playbooks}),
        encoding="utf-8")
    (root / "docs" / "KILL_RUBRIC_LIBRARY.md").write_text(library, encoding="utf-8")
    for name, rows in index_files.items():
        (ct / "index" / name).write_text(
            "\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return root


# A minimal but real-shaped kill-rubric library: two numbered sections, one of
# which carries a kill_rubric_slug anchor.
_LIBRARY = (
    "# Kill Rubric Library\n\n"
    "## 1. AMM Rounding\n"
    "<!-- kill_rubric_slug: amm-rounding -->\n"
    "**R-AMM-1** rounding always against the user.\n\n"
    "## 2. Reentrancy\n"
    "<!-- kill_rubric_slug: reentrancy -->\n"
    "**R-RE-1** CEI ordering.\n"
)


class PlaybookCorpusProvenanceTest(unittest.TestCase):

    def test_pass_resolving_xref_and_present_index_key(self):
        # Slug xref resolves; prose xref resolves; index key present.
        playbooks = [
            {"impact_id": "p-slug", "kill_rubric_xref": "amm-rounding"},
            {"impact_id": "p-prose",
             "kill_rubric_xref": "reuse sec 1 (AMM Rounding), sec 2 (Reentrancy)",
             "corpus_anchors": [
                 {"id": "A", "label": "class foo (3 members)",
                  "index_key": "foo", "index_file":
                  "audit/corpus_tags/index/by_attack_class.jsonl"}]},
        ]
        idx = {"by_attack_class.jsonl": [
            {"key": "foo"}, {"key": "foo"}, {"key": "foo"}, {"key": "bar"}]}
        root = _mk_repo(playbooks, _LIBRARY, idx)
        res = mod.check_playbook_corpus(root / "tools" / "x.py")
        self.assertEqual(res["verdict"], mod.VERDICT_PB_PASS, res.get("detail"))
        self.assertEqual(res["detail"]["xref_unresolved"], [])
        self.assertEqual(res["detail"]["index_unresolved"], [])

    def test_count_drift_is_warn_not_fail(self):
        # Label cites 99 members but on-disk count is 3 -> WARN, still PASS.
        playbooks = [
            {"impact_id": "p", "kill_rubric_xref": "amm-rounding",
             "corpus_anchors": [
                 {"id": "A", "label": "class foo (99 members)",
                  "index_key": "foo", "index_file":
                  "audit/corpus_tags/index/by_attack_class.jsonl"}]},
        ]
        idx = {"by_attack_class.jsonl": [{"key": "foo"}] * 3}
        root = _mk_repo(playbooks, _LIBRARY, idx)
        res = mod.check_playbook_corpus(root / "tools" / "x.py")
        self.assertEqual(res["verdict"], mod.VERDICT_PB_PASS)
        self.assertTrue(any("foo" in w for w in res["detail"]["count_warnings"]))

    def test_defect_dangling_xref_and_absent_index_key(self):
        # Both refs unresolved -> 2/2 = 100% > 10% floor -> FAIL.
        playbooks = [
            {"impact_id": "p-dangling",
             "kill_rubric_xref": "totally-bogus-slug-xyz",
             "corpus_anchors": [
                 {"id": "A", "label": "class ghost",
                  "index_key": "ghost-key", "index_file":
                  "audit/corpus_tags/index/by_attack_class.jsonl"}]},
        ]
        idx = {"by_attack_class.jsonl": [{"key": "foo"}, {"key": "bar"}]}
        root = _mk_repo(playbooks, _LIBRARY, idx)
        res = mod.check_playbook_corpus(root / "tools" / "x.py")
        self.assertEqual(res["verdict"], mod.VERDICT_PB_FAIL)
        self.assertIn("p-dangling", res["detail"]["xref_unresolved"])
        self.assertTrue(any("ghost-key" in u
                            for u in res["detail"]["index_unresolved"]))

    def test_defect_missing_index_file(self):
        playbooks = [
            {"impact_id": "p", "kill_rubric_xref": "amm-rounding",
             "corpus_anchors": [
                 {"id": "A", "index_key": "foo", "index_file":
                  "audit/corpus_tags/index/does_not_exist.jsonl"}]},
            # pad with resolving refs so a single missing file stays under 10%? No:
            # we WANT this to fail, so keep it the only index ref (1/2 = 50%).
        ]
        root = _mk_repo(playbooks, _LIBRARY, {})
        res = mod.check_playbook_corpus(root / "tools" / "x.py")
        self.assertEqual(res["verdict"], mod.VERDICT_PB_FAIL)
        self.assertTrue(any("missing file" in u
                            for u in res["detail"]["index_unresolved"]))

    def test_under_floor_passes(self):
        # 9 resolving xrefs + 1 dangling = 1/10 = 10% (not > 10%) -> PASS.
        playbooks = [
            {"impact_id": f"ok{i}", "kill_rubric_xref": "amm-rounding"}
            for i in range(9)
        ] + [{"impact_id": "bad", "kill_rubric_xref": "no-such-slug"}]
        root = _mk_repo(playbooks, _LIBRARY, {})
        res = mod.check_playbook_corpus(root / "tools" / "x.py")
        self.assertEqual(res["verdict"], mod.VERDICT_PB_PASS)
        self.assertEqual(res["detail"]["unresolved_fraction"], 0.1)

    def test_na_when_corpus_has_no_playbooks(self):
        # A corpus file that parses but carries no playbooks -> NA (nothing to
        # validate). Note: an EMPTY dir is NOT NA because the check falls back to
        # the tool's own repo root so the no-arg CLI works; that fallback is
        # tested via test_real_repo_corpus_does_not_regress.
        import yaml as _yaml
        root = Path(tempfile.mkdtemp())
        ct = root / "audit" / "corpus_tags"
        ct.mkdir(parents=True)
        (ct / "impact_hunting_methodology.yaml").write_text(
            _yaml.safe_dump({"schema": "test", "playbooks": []}), encoding="utf-8")
        res = mod.check_playbook_corpus(root / "tools" / "x.py")
        self.assertEqual(res["verdict"], mod.VERDICT_NA)

    def test_cli_playbook_mode_rc(self):
        # FAIL -> rc 1.
        playbooks = [{"impact_id": "p", "kill_rubric_xref": "bogus-slug"}]
        root = _mk_repo(playbooks, _LIBRARY, {})
        rc = mod.main(["--playbook-corpus", str(root / "x.py"), "--json"])
        self.assertEqual(rc, 1)

    def test_real_repo_corpus_does_not_regress(self):
        # The shipped corpus (post G6/G7) must keep all xrefs resolving and stay
        # at or under the 10% unresolved floor.
        res = mod.check_playbook_corpus(REPO_ROOT / "tools" / "x.py")
        self.assertIn(res["verdict"], (mod.VERDICT_PB_PASS, mod.VERDICT_NA))
        if res["verdict"] == mod.VERDICT_PB_PASS:
            self.assertEqual(res["detail"]["xref_unresolved"], [],
                             "a real playbook kill_rubric_xref no longer resolves")
            self.assertLessEqual(res["detail"]["unresolved_fraction"],
                                 mod._PLAYBOOK_UNRESOLVED_FLOOR)


if __name__ == "__main__":
    unittest.main()
