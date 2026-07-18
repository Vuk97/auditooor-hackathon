# <!-- r36-rebuttal: lane kill-rubric-xref registered in .auditooor/agent_pathspec.json -->
"""Resolution gate for the kill_rubric xref of every impact-hunting playbook.

Target files:
  audit/corpus_tags/impact_hunting_methodology.yaml  (the playbook xrefs)
  docs/KILL_RUBRIC_LIBRARY.md                        (the section library)

LANE G7 invariant: every one of the 32 playbooks carries a single normalized
`kill_rubric_xref` field, and EVERY xref resolves to a real KILL_RUBRIC_LIBRARY.md
section. Two resolvable forms are accepted:

  * slug form  - the value is a hyphenated slug (e.g. `liquidation-abuse`). It
    resolves iff some section declares it via a `<!-- kill_rubric_slug: SLUG -->`
    anchor immediately under its `## N. Title` header.
  * prose form - the value references one or more existing sections by number
    ("reuse sec 1 (AMM Rounding), 3 (Oracle); ..."). It resolves iff at least
    one cited `sec N` / `section N` is a real numbered section header.

This is the anti-dangling-slug gate. Before this lane, ~9 playbook slugs pointed
at sections that did not exist and 5 numbered sections were missing. If a slug is
genuinely orphaned, the FIX is to (a) repoint the playbook xref at the correct
existing section slug, or (b) append a new numbered section to
KILL_RUBRIC_LIBRARY.md with a matching `kill_rubric_slug` anchor - never weaken
this test.

The library-section-id parser is the SAME regex the live reader uses
(VaultQuery.vault_kill_rubric_context: `^## \\d+\\. ...`), so the test cannot
pass with a section header shape the production reader would not see.
"""
import re
import unittest
from pathlib import Path

import yaml

# tools/tests/ -> tools/ -> repo-root
REPO_ROOT = Path(__file__).resolve().parents[2]
YAML_PATH = REPO_ROOT / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"
LIBRARY_PATH = REPO_ROOT / "docs" / "KILL_RUBRIC_LIBRARY.md"

EXPECTED_PLAYBOOKS = 32

# Same numbered-section regex the production reader keys on.
SECTION_RE = re.compile(r"^## (\d+)\.\s+(.+)$", re.MULTILINE)
SLUG_ANCHOR_RE = re.compile(r"^<!--\s*kill_rubric_slug:\s*([a-z0-9-]+)\s*-->\s*$", re.MULTILINE)
SLUG_VALUE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
# prose references like "sec 1", "section 3", "sec 13"
SEC_REF_RE = re.compile(r"\b(?:sec|section)\s+(\d+)\b", re.IGNORECASE)


def _load_library_text() -> str:
    return LIBRARY_PATH.read_text(encoding="utf-8")


def _section_numbers(text: str) -> set[int]:
    return {int(m.group(1)) for m in SECTION_RE.finditer(text)}


def _section_slugs(text: str) -> set[str]:
    """Map every declared kill_rubric_slug to the section it sits under.

    A slug only counts if it appears AFTER a numbered section header and BEFORE
    the next one (so an anchor stranded outside any section is not credited).
    """
    headers = list(SECTION_RE.finditer(text))
    slugs: set[str] = set()
    for i, h in enumerate(headers):
        start = h.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        body = text[start:end]
        for sm in SLUG_ANCHOR_RE.finditer(body):
            slugs.add(sm.group(1))
    return slugs


def _load_playbooks() -> list:
    data = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
    return data["playbooks"]


def _xref_resolves(value: str, sec_nums: set[int], sec_slugs: set[str]) -> bool:
    value = value.strip()
    if SLUG_VALUE_RE.match(value):
        return value in sec_slugs
    # prose form: at least one cited section number must exist
    cited = {int(n) for n in SEC_REF_RE.findall(value)}
    return bool(cited) and cited.issubset(sec_nums) and len(cited) > 0


class TestKillRubricXrefResolves(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text = _load_library_text()
        cls.sec_nums = _section_numbers(cls.text)
        cls.sec_slugs = _section_slugs(cls.text)
        cls.playbooks = _load_playbooks()

    # ------------------------------------------------------------------
    # 1. Field-name normalization: exactly one xref field name across all 32.
    # ------------------------------------------------------------------
    def test_single_normalized_field_name(self):
        self.assertEqual(len(self.playbooks), EXPECTED_PLAYBOOKS)
        legacy_variants = ("kill_rubric", "kill_rubric_ref")
        for i, pb in enumerate(self.playbooks):
            self.assertIn(
                "kill_rubric_xref", pb,
                msg=f"playbook[{i}] ({pb.get('impact_id')}) missing kill_rubric_xref",
            )
            for legacy in legacy_variants:
                self.assertNotIn(
                    legacy, pb,
                    msg=(f"playbook[{i}] ({pb.get('impact_id')}) still carries the "
                         f"un-normalized field {legacy!r}; rename to kill_rubric_xref"),
                )

    # ------------------------------------------------------------------
    # 2. Every playbook xref resolves to a real section.
    # ------------------------------------------------------------------
    def test_every_xref_resolves(self):
        unresolved = []
        for i, pb in enumerate(self.playbooks):
            value = pb.get("kill_rubric_xref")
            if not isinstance(value, str) or not value.strip():
                unresolved.append((i, pb.get("impact_id"), repr(value)))
                continue
            if not _xref_resolves(value, self.sec_nums, self.sec_slugs):
                unresolved.append((i, pb.get("impact_id"), value[:60]))
        self.assertEqual(
            unresolved, [],
            msg=("kill_rubric_xref values that do not resolve to a "
                 "KILL_RUBRIC_LIBRARY.md section (slug anchor or sec-N ref): "
                 f"{unresolved}"),
        )

    # ------------------------------------------------------------------
    # 3. Slug anchors are unique (no two sections claim the same slug).
    # ------------------------------------------------------------------
    def test_slug_anchors_unique(self):
        headers = list(SECTION_RE.finditer(self.text))
        seen: dict[str, int] = {}
        for i, h in enumerate(headers):
            start = h.end()
            end = headers[i + 1].start() if i + 1 < len(headers) else len(self.text)
            body = self.text[start:end]
            for sm in SLUG_ANCHOR_RE.finditer(body):
                slug = sm.group(1)
                self.assertNotIn(
                    slug, seen,
                    msg=(f"slug {slug!r} declared in section {h.group(1)} AND "
                         f"section {seen.get(slug)}"),
                )
                seen[slug] = int(h.group(1))

    # ------------------------------------------------------------------
    # 4. Sections are contiguously numbered 1..N (no renumber gap / dup).
    # ------------------------------------------------------------------
    def test_sections_contiguous(self):
        nums = sorted(self.sec_nums)
        self.assertEqual(
            nums, list(range(1, len(nums) + 1)),
            msg=f"section numbers not contiguous 1..N: {nums}",
        )

    # ------------------------------------------------------------------
    # 5. Negative control - the resolver is non-vacuous: a bogus slug and a
    #    bogus prose ref must NOT resolve, and a real one must.
    # ------------------------------------------------------------------
    def test_resolver_non_vacuous(self):
        self.assertFalse(
            _xref_resolves("totally-bogus-slug-xyz", self.sec_nums, self.sec_slugs)
        )
        self.assertFalse(
            _xref_resolves("reuse sec 999 (does not exist)", self.sec_nums, self.sec_slugs)
        )
        self.assertFalse(
            _xref_resolves("", self.sec_nums, self.sec_slugs)
        )
        # a real slug and a real prose ref DO resolve
        self.assertTrue(
            _xref_resolves("amm-rounding", self.sec_nums, self.sec_slugs)
        )
        self.assertTrue(
            _xref_resolves("reuse sec 1 (AMM Rounding)", self.sec_nums, self.sec_slugs)
        )

    # ------------------------------------------------------------------
    # 6. The previously-dangling slugs are now all resolvable (regression
    #    lock for LANE G7 - these are the 9 slugs that had no section).
    # ------------------------------------------------------------------
    def test_previously_dangling_slugs_resolve(self):
        dangling = {
            "liquidation-abuse",
            "promised-returns-accounting",
            "bc-direct-loss-conservation",
            "node-resource-exhaustion",
            "chain-split-fork-divergence",
            "rpc-api-crash-undefined-behavior",
            "gas-fee-vault",
            "operability-depletion-vs-freeze-and-accounting-gap",
            "signature-replay-forgery",
        }
        missing = sorted(dangling - self.sec_slugs)
        self.assertEqual(
            missing, [],
            msg=f"previously-dangling slugs still lack a section anchor: {missing}",
        )


if __name__ == "__main__":
    unittest.main()
