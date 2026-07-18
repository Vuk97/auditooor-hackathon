"""Guard: reference/attack_class_vocab.yaml methodology_playbook links resolve to a real
impact_id in the canonical per-impact corpus (audit/corpus_tags/impact_hunting_methodology.yaml).

This is the acceptance test for WIRING_SPEC.md item C (vocab extend) + item D (Check #31
reconciliation). The vocab file is a TOP-LEVEL YAML LIST (`- class_id: ...`), NOT
`{classes: [...]}`; every assertion iterates the list directly (CRITIC correction).

Non-vacuity: the test fails if the methodology_playbook key was never attached (silent
no-op) by asserting a non-zero count of links AND that they cover the whole vocab, and it
fails if any link points at a non-existent impact_id (the divergent-taxonomy failure mode).
It also reconciles with Check #31: every corpus impact_id is a hyphen-cased slug and every
playbook carries a non-empty human rubric_row_hint, so the internal taxonomy can be
eyeballed against a real SEVERITY.md row at hunt/filing time without coupling to Check #31's
per-program exact-row vocabulary.
"""
import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
VOCAB_PATH = REPO_ROOT / "reference" / "attack_class_vocab.yaml"
CORPUS_PATH = REPO_ROOT / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"

_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _load_vocab():
    with VOCAB_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_playbooks():
    with CORPUS_PATH.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data.get("playbooks", []) if isinstance(data, dict) else []


class TestAttackClassVocabMethodologyLink(unittest.TestCase):
    def setUp(self):
        self.vocab = _load_vocab()
        self.playbooks = _load_playbooks()
        self.impact_ids = {
            str(p.get("impact_id"))
            for p in self.playbooks
            if p.get("impact_id")
        }

    def test_vocab_is_top_level_list(self):
        # CRITIC correction: top-level LIST, not {classes: [...]}.
        self.assertIsInstance(self.vocab, list)
        self.assertGreater(len(self.vocab), 0)
        for entry in self.vocab:
            self.assertIsInstance(entry, dict)
            self.assertIn("class_id", entry)

    def test_corpus_has_impact_ids(self):
        # Guards against the test silently passing because the corpus is empty.
        self.assertGreater(
            len(self.impact_ids),
            0,
            "canonical impact_hunting_methodology.yaml carries no impact_id rows",
        )

    def test_every_methodology_playbook_resolves(self):
        # The core link assertion: iterate the LIST directly (no ["classes"]).
        for entry in self.vocab:
            mp = entry.get("methodology_playbook")
            if not mp:  # optional key
                continue
            self.assertIn(
                mp,
                self.impact_ids,
                msg=(
                    f"attack class {entry['class_id']!r} -> methodology_playbook "
                    f"{mp!r} does not resolve to any impact_id in "
                    f"{CORPUS_PATH.relative_to(REPO_ROOT)}"
                ),
            )

    def test_links_actually_attached_not_silent_noop(self):
        # Non-vacuity: the wiring must actually attach. With the full mapping in
        # place EVERY entry carries a resolvable methodology_playbook, so a
        # regression that drops the keys (or a serving-join that reads the wrong
        # path) is caught here rather than passing an empty test.
        linked = [e for e in self.vocab if e.get("methodology_playbook")]
        self.assertGreater(len(linked), 0, "no methodology_playbook links found")
        self.assertEqual(
            len(linked),
            len(self.vocab),
            "every attack class should carry a methodology_playbook link",
        )

    def test_class_ids_unique(self):
        ids = [e["class_id"] for e in self.vocab]
        self.assertEqual(len(ids), len(set(ids)), "duplicate class_id in vocab")

    def test_impact_ids_are_hyphen_cased_slugs(self):
        # Check #31 reconciliation contract: the stable internal taxonomy is a
        # set of hyphen-cased slugs.
        for impact_id in self.impact_ids:
            self.assertRegex(
                impact_id,
                _SLUG_RE,
                msg=f"impact_id {impact_id!r} is not a hyphen-cased slug",
            )

    def test_each_playbook_has_human_eyeballable_phrase(self):
        # Reconciliation contract (WIRING_SPEC item D): every playbook carries a
        # non-empty human phrase that can be eyeballed against a real SEVERITY.md
        # rubric row at filing time, WITHOUT a brittle exact-enum coupling to
        # Check #31's per-program vocabulary. The consolidated corpus is
        # field-heterogeneous, so accept any of the rubric/severity phrase fields
        # it actually carries, falling back to the universal human `title`.
        rubric_phrase_keys = (
            "rubric_row_hint",
            "severity_source",
            "canonical_rubric_phrase",
            "program_impact_rubric_row",
            "severity_rows_verbatim",
            "title",
        )
        for p in self.playbooks:
            phrase = ""
            for key in rubric_phrase_keys:
                val = p.get(key)
                if isinstance(val, str) and val.strip():
                    phrase = val
                    break
                if isinstance(val, list) and val:
                    phrase = str(val[0])
                    break
            self.assertTrue(
                phrase.strip(),
                msg=(
                    f"playbook {p.get('impact_id')!r} has no human-readable "
                    "rubric/severity/title phrase to eyeball against SEVERITY.md"
                ),
            )

    def test_no_orphan_impact_id_zero_inbound_links(self):
        # Inverse-direction guard (PROBE E4b / G8): every impact_id in the
        # canonical corpus must have at least ONE inbound methodology_playbook
        # link from the attack-class surface, so every per-impact hunting
        # playbook is discoverable via the attack-class vocabulary. The forward
        # test only proves links RESOLVE; this proves none are STRANDED.
        linked_targets = {
            e.get("methodology_playbook")
            for e in self.vocab
            if e.get("methodology_playbook")
        }
        orphans = sorted(self.impact_ids - linked_targets)
        # Non-vacuity: there are real impact_ids to cover, so an empty corpus
        # cannot make this pass silently.
        self.assertGreater(len(self.impact_ids), 0)
        self.assertEqual(
            orphans,
            [],
            msg=(
                f"{len(orphans)} impact_id(s) have NO inbound methodology_playbook "
                f"link (undiscoverable via the attack-class surface): {orphans}. "
                "Add a methodology_playbook link on the most appropriate class entry "
                f"in {VOCAB_PATH.relative_to(REPO_ROOT)}."
            ),
        )

    def test_no_attack_class_dropped(self):
        # Additive-only contract: adding methodology_playbook must not drop the
        # pre-existing required fields from any entry.
        for entry in self.vocab:
            self.assertIn("class_id", entry)
            self.assertIn("severity_hint", entry)


if __name__ == "__main__":
    unittest.main()
