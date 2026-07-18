# <!-- r36-rebuttal: lane impact-methodology registered in .auditooor/agent_pathspec.json -->
"""Grounding + completeness gate for the per-impact hunting-methodology corpus.

Target file: audit/corpus_tags/impact_hunting_methodology.yaml
(schema auditooor.impact_hunting_methodology.v1; 32 per-impact playbooks merged
from the 32 IMPACT_*.yaml / *.methodology.yaml siblings in
agent_outputs/impact_methodology_full_2026-06-28/).

This is the REVISE-2 grounding gate for the impact-methodology wiring lane. It is
an anti-hallucination gate: a hunting agent is handed these playbooks for the
impact class it is chasing, so every block MUST carry real hunting content and
every corpus-key citation MUST resolve to a real key in the indexed corpus.

Assertions:

(a) Structural completeness - all 32 blocks parse and EACH carries:
      * non-empty `critical_paths`
      * non-empty `hacker_questions`, every question a dict with a non-empty `q`
        AND a non-empty `kill_condition` (the question is useless to a hunter
        without a falsification criterion)
      * at least one `incident_anchor` (>=1 element in `incident_anchors`)

(b) Grounding (anti-hallucination) - every `incident_anchor` that cites a corpus
    key of the form `name=NNN` (where `name` is a corpus-slug, i.e. hyphenated)
    has that `name` present as a `key` in the indexed corpus
    (audit/corpus_tags/index/by_attack_class.jsonl OR by_bug_class.jsonl). A
    hallucinated attack-class slug fails this gate.

The grounding index is read from the canonical live repo
(/Users/wolf/auditooor-mcp/audit/corpus_tags/index/) - that is the index the
citations were authored against - UNIONed with this worktree's own index so the
test stays green whichever snapshot is on disk. Presence (not the NNN count) is
the anti-hallucination guarantee; counts drift between corpus snapshots.

If a key is genuinely absent from every index, the FIX is to re-key or drop the
citation in the YAML - never weaken this test.
"""
import re
import unittest
from pathlib import Path

import yaml

# tools/tests/ -> tools/ -> repo-root
REPO_ROOT = Path(__file__).resolve().parents[2]
YAML_PATH = REPO_ROOT / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"

# Canonical (authoritative) corpus index location + this worktree's own copy.
_INDEX_BASES = [
    Path("/Users/wolf/auditooor-mcp/audit/corpus_tags/index"),
    REPO_ROOT / "audit" / "corpus_tags" / "index",
]
_INDEX_FILES = ("by_attack_class.jsonl", "by_bug_class.jsonl")

EXPECTED_PLAYBOOKS = 32

# A corpus-key citation: a hyphenated slug (attack-class / bug-class shape)
# immediately followed by =NNN. Anchored to require >=1 hyphen so source-code
# attribute tokens like `max_loss=0` are NOT treated as corpus-key citations.
_CITE_RE = re.compile(r"\b([A-Za-z][\w./+]*-[\w./+-]*)=(\d+)\b")


def _load_yaml():
    with YAML_PATH.open() as f:
        return yaml.safe_load(f)


def _load_index_keys():
    """Union of `key` fields across both class indexes, both index bases."""
    import json

    keys = set()
    loaded_any = False
    for base in _INDEX_BASES:
        for name in _INDEX_FILES:
            fp = base / name
            if not fp.exists():
                continue
            loaded_any = True
            with fp.open() as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    k = rec.get("key")
                    if k:
                        keys.add(k)
    return keys, loaded_any


def _anchor_strings(anchor):
    """Flatten an incident_anchor (str or dict) into its text fragments."""
    if isinstance(anchor, str):
        return [anchor]
    if isinstance(anchor, dict):
        out = []
        for v in anchor.values():
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, list):
                out.extend(x for x in v if isinstance(x, str))
        return out
    return []


class ImpactMethodologyCorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert YAML_PATH.exists(), f"missing canonical yaml: {YAML_PATH}"
        cls.data = _load_yaml()
        cls.playbooks = cls.data.get("playbooks")

    def test_schema_header(self):
        self.assertEqual(
            self.data.get("schema"), "auditooor.impact_hunting_methodology.v1"
        )
        self.assertIsInstance(self.playbooks, list)

    def test_32_blocks_parse(self):
        self.assertEqual(
            len(self.playbooks),
            EXPECTED_PLAYBOOKS,
            f"expected {EXPECTED_PLAYBOOKS} playbooks, got {len(self.playbooks)}",
        )
        # declared count must match the actual list (catches a stale header)
        self.assertEqual(self.data.get("playbooks_count"), EXPECTED_PLAYBOOKS)
        # impact_ids unique + non-empty
        ids = [p.get("impact_id") for p in self.playbooks]
        self.assertTrue(all(ids), "every playbook needs an impact_id")
        self.assertEqual(len(ids), len(set(ids)), "impact_id values must be unique")

    def test_every_block_has_critical_paths(self):
        offenders = [
            p["impact_id"]
            for p in self.playbooks
            if not (isinstance(p.get("critical_paths"), list) and p["critical_paths"])
        ]
        self.assertEqual(
            offenders, [], f"playbooks with empty critical_paths: {offenders}"
        )

    def test_every_hacker_question_has_kill_condition(self):
        offenders = []
        for p in self.playbooks:
            hq = p.get("hacker_questions")
            if not (isinstance(hq, list) and hq):
                offenders.append((p["impact_id"], "no hacker_questions"))
                continue
            for i, q in enumerate(hq):
                if not isinstance(q, dict):
                    offenders.append((p["impact_id"], f"hq[{i}] not a mapping"))
                    continue
                if not (isinstance(q.get("q"), str) and q["q"].strip()):
                    offenders.append((p["impact_id"], f"hq[{i}] empty q"))
                if not (
                    isinstance(q.get("kill_condition"), str)
                    and q["kill_condition"].strip()
                ):
                    offenders.append((p["impact_id"], f"hq[{i}] empty kill_condition"))
        self.assertEqual(offenders, [], f"hacker_question defects: {offenders}")

    def test_every_block_has_an_incident_anchor(self):
        offenders = [
            p["impact_id"]
            for p in self.playbooks
            if not (
                isinstance(p.get("incident_anchors"), list) and p["incident_anchors"]
            )
        ]
        self.assertEqual(
            offenders, [], f"playbooks with no incident_anchors: {offenders}"
        )

    def test_corpus_key_citations_are_grounded(self):
        index_keys, loaded_any = _load_index_keys()
        self.assertTrue(
            loaded_any,
            "no corpus index file readable from any base; cannot run the "
            f"grounding gate (bases tried: {[str(b) for b in _INDEX_BASES]})",
        )
        # Non-vacuity: the corpus index must be substantial, else the grounding
        # check could pass trivially against an empty key set.
        self.assertGreater(
            len(index_keys), 100, "corpus index suspiciously small; refusing to ground"
        )

        ungrounded = []
        cited_total = 0
        for p in self.playbooks:
            for anchor in p.get("incident_anchors", []) or []:
                for frag in _anchor_strings(anchor):
                    for m in _CITE_RE.finditer(frag):
                        name = m.group(1)
                        cited_total += 1
                        if name not in index_keys:
                            ungrounded.append((p["impact_id"], m.group(0)))

        # Non-vacuity: at least one real corpus-key citation must exist, else the
        # anti-hallucination gate would be a no-op tautology.
        self.assertGreater(
            cited_total,
            0,
            "no `name=NNN` corpus-key citations found in any incident_anchor; "
            "the grounding gate would be vacuous",
        )
        self.assertEqual(
            ungrounded,
            [],
            "hallucinated corpus-key citations (name=NNN absent from "
            f"by_attack_class.jsonl/by_bug_class.jsonl): {ungrounded}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
