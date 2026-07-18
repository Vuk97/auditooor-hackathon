#!/usr/bin/env python3
"""PR 211 — Regression test for docs/FAILURE_MODES.md and 10_OF_10_PLAYBOOK.md.

This test asserts structural truths about the failure catalog:

  1. At least 17 FM-### rows are present.
  2. Every row has all seven required fields.
  3. Every "Status vocabulary affected" value is drawn from the locked
     vocabulary set documented at the top of FAILURE_MODES.md and in
     10_OF_10_PLAYBOOK.md §5.
  4. Every "What prevents regression now" field references an actual test
     function name (`::test_something`), a commit hash, or a doctrine-rule
     anchor (a phrase naming a real roadmap section / file).
  5. The playbook has all eight required sections.

The test is offline and parses markdown with plain regex — no network, no
subprocess beyond opening the files.

It is the regression-test answer to truth-audit question 5 for PR 211:
"Which test would have caught the PR #102-style mistake?" — here,
specifically, a row being added without a prevention citation (which is how
FM rows stop being useful).
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FM_PATH = ROOT / "docs" / "FAILURE_MODES.md"
PB_PATH = ROOT / "docs" / "10_OF_10_PLAYBOOK.md"

# Required fields on every FM-### row. These are the bold labels that the
# Makefile `docs-check-playbook` target also greps for; keep the two in sync.
REQUIRED_FIELDS = (
    "**First seen:**",
    "**What happened:**",
    "**Why it was possible:**",
    "**How it was caught:**",
    "**What prevents regression now:**",
    "**Status vocabulary affected:**",
    "**Artifact classification affected:**",
)

# Locked status vocabulary. Must match the §5 table in 10_OF_10_PLAYBOOK.md
# and the "Locked status vocabulary" section at the top of FAILURE_MODES.md.
# The row's value may be a comma-separated combination of these; or the
# literal "none" when the row is not a status-vocabulary regression.
LOCKED_STATUS_VOCAB = {
    "fork-replay.sh:status",
    "fork-replay-assert.py:assertion.status",
    "pre-submit-check.sh:Check22",
    "submission-packager.py:evidence-matrix.verdict",
    "fuzz-runner.sh:status",
    "symbolic-runner.sh:status",
    "ci-preflight.sh",
    "outcome-reweight.py:outcome",
    "roadmap-slice.status",
    "none",
}

# Artifact classification values.
LOCKED_ARTIFACT_CLASSES = {"proof", "advisory", "planning", "none"}

# Playbook section headings to assert present.
PLAYBOOK_SECTIONS = (
    "## 1. ",
    "## 2. ",
    "## 3. ",
    "## 4. ",
    "## 5. ",
    "## 6. ",
    "## 7. ",
    "## 8. ",
)

FM_ROW_HEADING = re.compile(r"^### (FM-\d{3}) —", re.MULTILINE)
COMMIT_HASH = re.compile(r"\b[0-9a-f]{7,40}\b")
TEST_FUNC = re.compile(r"::test_[A-Za-z0-9_]+")
DOCTRINE_ANCHORS = (
    # Non-exhaustive but concrete: any of these phrases is a real cite.
    "docs/ROADMAP_10_OF_10_V2.md",
    "docs/ROADMAP_10_OF_10.md",
    "Anti-Patterns",
    "Claude Execution Rules",
    "doctrine rule",
    "`tools/",
    "docs/CI_SETUP.md",
    "docs/FAILURE_MODES.md",
)


def _iter_fm_rows(text: str):
    """Yield (fm_id, body) pairs for every FM-### row."""
    matches = list(FM_ROW_HEADING.finditer(text))
    for idx, m in enumerate(matches):
        start = m.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        yield m.group(1), text[start:end]


def _extract_field(body: str, label: str) -> str:
    """Return the value after '**Label:**' up to the end of line.

    Returns '' if the field is missing.
    """
    needle = label
    i = body.find(needle)
    if i < 0:
        return ""
    j = body.find("\n", i + len(needle))
    val = body[i + len(needle) : j if j > 0 else len(body)].strip()
    return val


class TestFailureModesDocExists(unittest.TestCase):
    def test_failure_modes_file_exists(self) -> None:
        self.assertTrue(FM_PATH.is_file(), f"missing {FM_PATH}")

    def test_playbook_file_exists(self) -> None:
        self.assertTrue(PB_PATH.is_file(), f"missing {PB_PATH}")


class TestFailureModesStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fm_text = FM_PATH.read_text(encoding="utf-8")
        cls.rows = list(_iter_fm_rows(cls.fm_text))

    def test_at_least_17_rows(self) -> None:
        self.assertGreaterEqual(
            len(self.rows),
            17,
            msg=f"FAILURE_MODES.md must have >=17 FM-### rows; got {len(self.rows)}",
        )

    def test_fm_ids_are_unique(self) -> None:
        ids = [fm_id for fm_id, _ in self.rows]
        self.assertEqual(
            len(ids),
            len(set(ids)),
            msg=f"duplicate FM-### ids: {[i for i in ids if ids.count(i) > 1]}",
        )

    def test_every_row_has_all_required_fields(self) -> None:
        missing = []
        for fm_id, body in self.rows:
            for field in REQUIRED_FIELDS:
                if field not in body:
                    missing.append((fm_id, field))
        self.assertFalse(
            missing,
            msg=f"rows missing required fields: {missing[:10]}{'...' if len(missing) > 10 else ''}",
        )

    def test_every_status_vocab_is_from_locked_set(self) -> None:
        """FM rows may name any combination of locked vocabulary values,
        separated by commas. 'none' is allowed and means the row is not a
        status-vocabulary regression."""
        offenders = []
        for fm_id, body in self.rows:
            raw = _extract_field(body, "**Status vocabulary affected:**")
            if not raw:
                offenders.append((fm_id, "MISSING"))
                continue
            # Strip trailing period, surrounding backticks, split on commas.
            values = [
                v.strip().rstrip(".").strip("`")
                for v in raw.split(",")
                if v.strip()
            ]
            for v in values:
                if v not in LOCKED_STATUS_VOCAB:
                    offenders.append((fm_id, v))
        self.assertFalse(
            offenders,
            msg=(
                f"rows with non-locked status vocabulary values: {offenders}\n"
                f"locked set: {sorted(LOCKED_STATUS_VOCAB)}"
            ),
        )

    def test_every_artifact_class_is_from_locked_set(self) -> None:
        offenders = []
        for fm_id, body in self.rows:
            raw = _extract_field(
                body, "**Artifact classification affected:**"
            )
            if not raw:
                offenders.append((fm_id, "MISSING"))
                continue
            val = raw.rstrip(".").strip().strip("`")
            if val not in LOCKED_ARTIFACT_CLASSES:
                offenders.append((fm_id, val))
        self.assertFalse(
            offenders,
            msg=(
                f"rows with non-locked artifact classification: {offenders}\n"
                f"locked set: {sorted(LOCKED_ARTIFACT_CLASSES)}"
            ),
        )

    def test_every_fm_has_prevention_field(self) -> None:
        """Truth-audit q5 regression test (see PR 211 commit body).

        If a row lacks an actual test function name, commit hash, or doctrine
        anchor, it is a cannot-judge row and fails the build.
        """
        weak = []
        for fm_id, body in self.rows:
            prevention = _extract_field(
                body, "**What prevents regression now:**"
            )
            if not prevention:
                weak.append((fm_id, "missing prevention field"))
                continue
            has_test = bool(TEST_FUNC.search(prevention))
            has_commit = bool(COMMIT_HASH.search(prevention))
            has_anchor = any(anchor in prevention for anchor in DOCTRINE_ANCHORS)
            if not (has_test or has_commit or has_anchor):
                weak.append((fm_id, prevention[:120]))
        self.assertFalse(
            weak,
            msg=(
                "rows without a cited test function, commit hash, or "
                f"doctrine anchor: {weak}"
            ),
        )

    def test_first_seen_cites_a_commit_or_pr(self) -> None:
        """First-seen must be something concrete: a commit hash or a PR
        reference. Rules out vague 'circa March' language."""
        weak = []
        for fm_id, body in self.rows:
            raw = _extract_field(body, "**First seen:**")
            if not raw:
                weak.append((fm_id, "missing"))
                continue
            has_commit = bool(COMMIT_HASH.search(raw))
            has_pr_ref = "PR #" in raw or "PR 2" in raw or "commit " in raw
            if not (has_commit or has_pr_ref):
                weak.append((fm_id, raw[:120]))
        self.assertFalse(
            weak, msg=f"rows with vague First seen: {weak}"
        )


class TestPlaybookStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pb_text = PB_PATH.read_text(encoding="utf-8")

    def test_has_eight_sections(self) -> None:
        missing = [s for s in PLAYBOOK_SECTIONS if s not in self.pb_text]
        self.assertFalse(
            missing, msg=f"playbook missing section headings: {missing}"
        )

    def test_status_vocabulary_table_present(self) -> None:
        """§5 must name the same vocabulary producers as the locked set."""
        # Each producer name must appear somewhere in the playbook.
        for producer in (
            "fork-replay.sh",
            "fork-replay-assert.py",
            "pre-submit-check.sh",
            "submission-packager.py",
            "fuzz-runner.sh",
            "symbolic-runner.sh",
            "ci-preflight.sh",
            "outcome_reweight.py",
        ):
            self.assertIn(
                producer, self.pb_text, msg=f"playbook §5 must name {producer}"
            )

    def test_truth_audit_five_questions_present(self) -> None:
        for phrase in (
            "What could this PR accidentally overclaim",
            "What status values",
            "Which artifacts are proof",
            "What happens when the tool cannot judge",
            "Which test would have caught",
        ):
            self.assertIn(
                phrase, self.pb_text, msg=f"playbook §6 missing: {phrase}"
            )

    def test_single_entry_point_is_make_audit(self) -> None:
        self.assertIn(
            "make audit WS=", self.pb_text,
            msg="playbook must advertise `make audit WS=<workspace>`",
        )


if __name__ == "__main__":
    unittest.main()
