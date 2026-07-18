"""Unit tests for Rule 39 attack-class-orphan preflight (Check #74).

Source: docs/WAVE2_W29_NEW_GATES_SPEC_2026-05-16.md §5.2.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "attack_class_orphan_check",
    ROOT / "tools" / "attack-class-orphan-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r39_orphan_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    return root


def _write_draft(body: str, *, filename: str = "draft-HIGH.md", root: Path | None = None) -> Path:
    root = root or _workspace()
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _write_distribution(matrix: dict[str, dict[str, int]]) -> Path:
    """Write a hackerman-attack-class-distribution.py-shaped JSON file."""
    fd, path_str = tempfile.mkstemp(suffix=".json", prefix="dist_")
    os.close(fd)
    path = Path(path_str)
    classes = sorted({ac for cells in matrix.values() for ac in cells})
    payload = {
        "schema": "auditooor.hackerman_attack_class_distribution.v1",
        "subtrees": sorted(matrix.keys()),
        "classes": classes,
        "matrix": matrix,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_taxonomy(classes: list[str]) -> Path:
    fd, path_str = tempfile.mkstemp(suffix=".json", prefix="tax_")
    os.close(fd)
    path = Path(path_str)
    payload = {"classes": [{"attack_class": c} for c in classes]}
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _run(draft: Path, **kwargs):
    return mod.run(draft, **kwargs)


_CANONICAL_DIST = {
    "contest_platform_findings": {
        "oracle-price-manipulation": 150,
        "oracle-price-injection-via-pendle-pt-mint-discount": 3,
        "reentrancy-readonly": 8,
    },
    "immunefi": {
        "oracle-price-manipulation": 90,
        "reentrancy-readonly": 5,
    },
    "audit_firm_public_reports": {
        "oracle-price-manipulation": 80,
        "well-distributed-class": 25,
    },
    "mev_exploits": {
        "well-distributed-class": 30,
    },
}


class R39ScopeTests(unittest.TestCase):
    def test_severity_medium_skips(self) -> None:
        dist = _write_distribution(_CANONICAL_DIST)
        body = "Severity: Medium\nattack_class: oracle-price-injection-via-pendle-pt-mint-discount\n"
        draft = _write_draft(body)
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_unreadable_path_returns_error(self) -> None:
        rc, payload = _run(Path("/no/such/file.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


class R39OrphanTests(unittest.TestCase):
    def test_canonical_class_passes(self) -> None:
        dist = _write_distribution(_CANONICAL_DIST)
        tax = _write_taxonomy(["oracle-price-manipulation"])
        body = "Severity: High\nSelected impact: price drift\nattack_class: oracle-price-manipulation\n"
        draft = _write_draft(body)
        rc, payload = _run(draft, distribution_index=dist, taxonomy_index=tax)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-canonical")
        self.assertGreaterEqual(payload["corpus_record_count"], 20)
        self.assertGreaterEqual(payload["corpus_subtree_count"], 2)

    def test_orphan_single_subtree_fails(self) -> None:
        dist = _write_distribution(_CANONICAL_DIST)
        tax = _write_taxonomy(["oracle-price-manipulation"])
        body = (
            "Severity: High\nSelected impact: oracle drift\n"
            "attack_class: oracle-price-injection-via-pendle-pt-mint-discount\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, distribution_index=dist, taxonomy_index=tax)
        self.assertEqual(rc, 1, payload)
        # 3 records AND 1 subtree -> both thresholds breached -> orphan-both.
        self.assertEqual(payload["verdict"], "fail-orphan-both")
        self.assertEqual(payload["corpus_subtree_count"], 1)

    def test_orphan_low_record_count_fails(self) -> None:
        # subtree_count=2 but record_count=13 (<20).
        dist = _write_distribution(_CANONICAL_DIST)
        tax = _write_taxonomy(["oracle-price-manipulation"])
        body = (
            "Severity: High\nSelected impact: read-only reentrancy in view\n"
            "attack_class: reentrancy-readonly\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, distribution_index=dist, taxonomy_index=tax)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-orphan-low-record-count")

    def test_orphan_single_subtree_only_with_enough_records(self) -> None:
        # 1 subtree but 100 records: should still fail orphan-single-subtree.
        dist = _write_distribution({
            "subtree_a": {"sole-class": 100},
            "subtree_b": {"other-class": 50},
        })
        tax = _write_taxonomy(["sole-class"])
        body = "Severity: High\nSelected impact: griefing\nattack_class: sole-class\n"
        draft = _write_draft(body)
        rc, payload = _run(draft, distribution_index=dist, taxonomy_index=tax)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-orphan-single-subtree")

    def test_orphan_with_rebuttal_passes(self) -> None:
        dist = _write_distribution(_CANONICAL_DIST)
        body = (
            "Severity: High\nSelected impact: oracle drift\n"
            "attack_class: oracle-price-injection-via-pendle-pt-mint-discount\n"
            "<!-- r39-rebuttal: novel-class; operator-approved via audit/operator_overrides/wave2-novel-classes.yaml -->\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_oversize_rebuttal_ignored(self) -> None:
        dist = _write_distribution(_CANONICAL_DIST)
        big = "x" * 250
        body = (
            "Severity: High\nSelected impact: oracle drift\n"
            "attack_class: oracle-price-injection-via-pendle-pt-mint-discount\n"
            f"<!-- r39-rebuttal: {big} -->\n"
        )
        draft = _write_draft(body)
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 1, payload)
        self.assertTrue(payload.get("rebuttal_oversize"))

    def test_supported_non_canonical_passes(self) -> None:
        # well-distributed-class: 25+30=55 records, 2 subtrees. Not in taxonomy.
        dist = _write_distribution(_CANONICAL_DIST)
        tax = _write_taxonomy(["oracle-price-manipulation"])
        body = "Severity: High\nSelected impact: undistributed\nattack_class: well-distributed-class\n"
        draft = _write_draft(body)
        rc, payload = _run(draft, distribution_index=dist, taxonomy_index=tax)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-attack-class-supported-non-canonical")
        self.assertFalse(payload["is_in_canonical_taxonomy"])


class R39EnvOverrideTests(unittest.TestCase):
    def test_env_min_records_override(self) -> None:
        # well-distributed-class has 55 records; env lifts threshold to 100.
        dist = _write_distribution(_CANONICAL_DIST)
        body = "Severity: High\nSelected impact: x\nattack_class: well-distributed-class\n"
        draft = _write_draft(body)
        os.environ["AUDITOOOR_R39_MIN_RECORDS"] = "100"
        try:
            rc, payload = _run(draft, distribution_index=dist)
        finally:
            os.environ.pop("AUDITOOOR_R39_MIN_RECORDS", None)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-orphan-low-record-count")

    def test_env_min_subtrees_override(self) -> None:
        # well-distributed-class present in 2 subtrees; lift to 3 -> orphan.
        dist = _write_distribution(_CANONICAL_DIST)
        body = "Severity: High\nSelected impact: x\nattack_class: well-distributed-class\n"
        draft = _write_draft(body)
        os.environ["AUDITOOOR_R39_MIN_SUBTREES"] = "3"
        try:
            rc, payload = _run(draft, distribution_index=dist)
        finally:
            os.environ.pop("AUDITOOOR_R39_MIN_SUBTREES", None)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-orphan-single-subtree")

    def test_nearest_canonical_resolver(self) -> None:
        dist = _write_distribution({
            "contest_platform_findings": {"read-only-reentrancy": 2},
            "immunefi": {"reentrancy-readonly": 50},
            "audit_firm_public_reports": {"reentrancy-readonly": 80},
        })
        tax = _write_taxonomy(["reentrancy-readonly"])
        body = "Severity: High\nSelected impact: x\nattack_class: read-only-reentrancy\n"
        draft = _write_draft(body)
        os.environ["AUDITOOOR_R39_CANONICAL_ALIASES"] = "read-only-reentrancy=>reentrancy-readonly"
        try:
            rc, payload = _run(draft, distribution_index=dist, taxonomy_index=tax)
        finally:
            os.environ.pop("AUDITOOOR_R39_CANONICAL_ALIASES", None)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["nearest_canonical_class"], "reentrancy-readonly")


class R39IndexHandlingTests(unittest.TestCase):
    def test_distribution_index_missing_fails(self) -> None:
        body = "Severity: High\nSelected impact: x\nattack_class: anything\n"
        draft = _write_draft(body)
        rc, payload = _run(draft, distribution_index=Path("/no/such/dist.json"))
        self.assertEqual(rc, 2, payload)
        self.assertEqual(payload["verdict"], "error")

    def test_distribution_index_missing_with_allow_passes(self) -> None:
        body = "Severity: High\nSelected impact: x\nattack_class: anything\n"
        draft = _write_draft(body)
        rc, payload = _run(
            draft,
            distribution_index=Path("/no/such/dist.json"),
            allow_missing_index=True,
        )
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")
        self.assertTrue(payload.get("distribution_index_missing"))


# ---------------------------------------------------------------------------
# Wave-2 PR-A fixture expansion (per Wave-2 W29 brief, 2026-05-16).
# synthetic_fixture: true
#
# Adds cases for: 1-record orphan, 2-record borderline, 3+-record borderline
# (still fails default min_records=20 but pins behavior at min_records=3),
# quarantine subtree (pinning current "loader does not filter" behavior),
# new-class within 30-day grace window (pinned as fail today; future grace
# support will flip this), cross-firm aggregation, and rebuttal marker
# integration. Fixture envelopes mirror
# auditooor.hackerman_attack_class_distribution.v1.
# ---------------------------------------------------------------------------


class R39RecordCountBoundaryTests(unittest.TestCase):
    """Record-count boundary fixtures: 1 / 2 / 3+ records.

    Default thresholds: ``min_records=20``, ``min_subtrees=2``.
    synthetic_fixture: true
    """

    def test_attack_class_with_1_record_total_fails_orphan(self) -> None:
        dist = _write_distribution({
            "contest_platform_findings": {"unicorn-class": 1},
            "immunefi": {"oracle-price-manipulation": 50},
        })
        body = (
            "Severity: High\nSelected impact: theft via novel angle\n"
            "attack_class: unicorn-class\n"
            "# synthetic_fixture: true (1-record orphan)\n"
        )
        draft = _write_draft(body, filename="unicorn-1rec-HIGH.md")
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-orphan-both")
        self.assertEqual(payload["corpus_record_count"], 1)
        self.assertEqual(payload["corpus_subtree_count"], 1)

    def test_attack_class_with_2_records_borderline_advisory_under_default(self) -> None:
        """Borderline at default threshold: 2 records in 1 subtree -> orphan-both."""
        dist = _write_distribution({
            "contest_platform_findings": {"emerging-class": 2},
            "immunefi": {"oracle-price-manipulation": 50},
        })
        body = (
            "Severity: High\nSelected impact: theft via emerging-class\n"
            "attack_class: emerging-class\n"
            "# synthetic_fixture: true (2-record borderline)\n"
        )
        draft = _write_draft(body, filename="emerging-2rec-HIGH.md")
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-orphan-both")
        self.assertEqual(payload["corpus_record_count"], 2)

    def test_attack_class_with_3_records_advisory_under_lowered_threshold(self) -> None:
        """Pin advisory behavior: under min_records=3 + min_subtrees=2, a
        3-record-in-2-subtree class passes; under defaults it fails.
        synthetic_fixture: true"""
        dist = _write_distribution({
            "contest_platform_findings": {"borderline-class": 2},
            "immunefi": {"borderline-class": 1, "oracle-price-manipulation": 50},
        })
        body = (
            "Severity: High\nSelected impact: theft via borderline-class\n"
            "attack_class: borderline-class\n"
            "# synthetic_fixture: true (3-record borderline)\n"
        )
        draft = _write_draft(body, filename="borderline-3rec-HIGH.md")
        # With default thresholds -> still fails (3 < 20 records).
        rc_default, payload_default = _run(draft, distribution_index=dist)
        self.assertEqual(rc_default, 1, payload_default)
        self.assertEqual(payload_default["verdict"], "fail-orphan-low-record-count")
        # With min_records lowered to 3 and min_subtrees=2 -> passes.
        rc_low, payload_low = _run(
            draft, distribution_index=dist, min_records=3, min_subtrees=2
        )
        self.assertEqual(rc_low, 0, payload_low)
        self.assertIn(payload_low["verdict"], {
            "pass-attack-class-canonical",
            "pass-attack-class-supported-non-canonical",
        })


class R39QuarantineSubtreeTests(unittest.TestCase):
    """Quarantine subtree handling.

    The current loader does NOT special-case a ``_quarantine_*`` subtree
    prefix; the records under a quarantine subtree are still counted. This
    pins the behavior so a future "exclude quarantine from count" feature
    is detected by a test flip.
    synthetic_fixture: true
    """

    def test_quarantine_subtree_records_counted_today(self) -> None:
        dist = _write_distribution({
            "_quarantine_contest_platform_findings": {"qsec-class": 99},
            "audit_firm_public_reports": {"qsec-class": 1, "oracle-price-manipulation": 80},
        })
        # qsec-class: 99 + 1 = 100 records across 2 subtrees -> currently passes.
        body = (
            "Severity: High\nSelected impact: theft via qsec-class\n"
            "attack_class: qsec-class\n"
            "# synthetic_fixture: true (quarantine-counted-today)\n"
        )
        draft = _write_draft(body, filename="qsec-quarantine-HIGH.md")
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["corpus_record_count"], 100)
        self.assertEqual(payload["corpus_subtree_count"], 2)

    def test_quarantine_only_subtree_fails_single_subtree(self) -> None:
        """A class present ONLY in a quarantine subtree fails the single-
        subtree check exactly the same as any other 1-subtree class.
        Pinning: gate does not give quarantine-only classes a special pass.
        """
        dist = _write_distribution({
            "_quarantine_contest_platform_findings": {"q-only-class": 50},
            "immunefi": {"oracle-price-manipulation": 50},
        })
        body = (
            "Severity: High\nSelected impact: theft via q-only-class\n"
            "attack_class: q-only-class\n"
            "# synthetic_fixture: true (quarantine-only-class)\n"
        )
        draft = _write_draft(body, filename="q-only-class-HIGH.md")
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-orphan-single-subtree")


class R39NewClassGracePinTests(unittest.TestCase):
    """30-day grace window for newly-introduced attack_class identifiers.

    Spec mentions a 30-day grace; the implementation today does NOT branch
    on a ``first_seen_at`` timestamp - the class is treated like any other
    orphan. These fixtures pin the current behavior so that a future
    grace-window implementation is detected by a test flip.
    synthetic_fixture: true
    """

    def test_new_class_in_grace_window_currently_fails(self) -> None:
        dist = _write_distribution({
            "contest_platform_findings": {"wave-2-new-class": 4},
            "immunefi": {"oracle-price-manipulation": 50},
        })
        body = (
            "Severity: High\nSelected impact: theft via novel class\n"
            "attack_class: wave-2-new-class\n"
            "first_seen_at: 2026-05-15  # synthetic_fixture: true, within 30d\n"
        )
        draft = _write_draft(body, filename="wave2-new-class-HIGH.md")
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 1, payload)
        # Either orphan-both (1 subtree) or orphan-low-record-count.
        self.assertIn(payload["verdict"], {
            "fail-orphan-both",
            "fail-orphan-single-subtree",
            "fail-orphan-low-record-count",
        })

    def test_new_class_with_rebuttal_grace_pass(self) -> None:
        """Pending native grace-window support, operator can pass a new
        class via the standard r39-rebuttal marker citing the grace
        rationale.
        """
        dist = _write_distribution({
            "contest_platform_findings": {"wave-2-grace-class": 1},
            "immunefi": {"oracle-price-manipulation": 50},
        })
        body = (
            "Severity: High\nSelected impact: theft via grace-class\n"
            "attack_class: wave-2-grace-class\n"
            "<!-- r39-rebuttal: new attack_class introduced 2026-05-15, "
            "within 30d grace window per Wave-2 W29 spec -->\n"
        )
        draft = _write_draft(body, filename="wave2-grace-HIGH.md")
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "ok-rebuttal")


class R39CrossFirmAggregationTests(unittest.TestCase):
    """Cross-firm attack_class aggregation.

    Counts are summed across subtrees in the matrix-shape loader. Even if
    no single subtree has >= min_records, the class passes if the aggregate
    record_count and subtree_count clear the thresholds.
    synthetic_fixture: true
    """

    def test_cross_firm_aggregation_meets_threshold(self) -> None:
        """6 firms * 4 records each = 24 records across 6 subtrees. Each
        firm individually is below min_records=20 but the aggregate clears.
        """
        dist = _write_distribution({
            f"firm_{i}": {"cross-firm-class": 4, "oracle-price-manipulation": 50}
            for i in range(6)
        })
        body = (
            "Severity: High\nSelected impact: theft via cross-firm-class\n"
            "attack_class: cross-firm-class\n"
            "# synthetic_fixture: true (cross-firm aggregation)\n"
        )
        draft = _write_draft(body, filename="cross-firm-HIGH.md")
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["corpus_record_count"], 24)
        self.assertEqual(payload["corpus_subtree_count"], 6)
        # Class is not in taxonomy => non-canonical pass.
        self.assertEqual(payload["verdict"], "pass-attack-class-supported-non-canonical")

    def test_cross_firm_aggregation_two_firms_one_record_each_still_fails(self) -> None:
        """2 firms * 1 record each = 2 records / 2 subtrees - clears the
        subtree threshold but fails the record-count threshold."""
        dist = _write_distribution({
            "firm_a": {"sparse-cross-firm-class": 1, "oracle-price-manipulation": 50},
            "firm_b": {"sparse-cross-firm-class": 1},
        })
        body = (
            "Severity: High\nSelected impact: theft via sparse-cross-firm-class\n"
            "attack_class: sparse-cross-firm-class\n"
            "# synthetic_fixture: true (sparse cross-firm)\n"
        )
        draft = _write_draft(body, filename="sparse-cross-firm-HIGH.md")
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 1, payload)
        self.assertEqual(payload["verdict"], "fail-orphan-low-record-count")
        self.assertEqual(payload["corpus_subtree_count"], 2)
        self.assertEqual(payload["corpus_record_count"], 2)


class R39RebuttalIntegrationTests(unittest.TestCase):
    """Cross-cutting rebuttal-marker integration for R39.

    Verifies rebuttal overrides each fail-orphan-* verdict and that the
    sibling R38 rebuttal marker does NOT silence R39 (cross-gate
    independence; spec §4.1 Risk #3).
    synthetic_fixture: true
    """

    def test_rebuttal_overrides_orphan_low_record_count(self) -> None:
        dist = _write_distribution({
            "contest_platform_findings": {"rare-class": 3},
            "immunefi": {"rare-class": 4, "oracle-price-manipulation": 50},
        })
        body = (
            "Severity: High\nSelected impact: theft via rare-class\n"
            "attack_class: rare-class\n"
            "<!-- r39-rebuttal: rare-class is documented in wave2 novel-class registry -->\n"
        )
        draft = _write_draft(body, filename="rare-rebuttal-HIGH.md")
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_r38_rebuttal_marker_does_not_silence_r39(self) -> None:
        """The R38 marker only suppresses R38; R39 must still see the
        attack_class orphan condition. Mirrors spec §4.1 Risk #3.
        """
        dist = _write_distribution({
            "contest_platform_findings": {"isolated-class": 1},
            "immunefi": {"oracle-price-manipulation": 50},
        })
        body = (
            "Severity: High\nSelected impact: theft via isolated-class\n"
            "attack_class: isolated-class\n"
            "<!-- r38-rebuttal: drift-acknowledged; r38-only -->\n"
        )
        draft = _write_draft(body, filename="r38-only-rebuttal-HIGH.md")
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 1, payload)
        self.assertIn(payload["verdict"], {
            "fail-orphan-both",
            "fail-orphan-single-subtree",
            "fail-orphan-low-record-count",
        })

    def test_rebuttal_exactly_200_chars_accepted(self) -> None:
        dist = _write_distribution({
            "contest_platform_findings": {"long-rebuttal-class": 1},
            "immunefi": {"oracle-price-manipulation": 50},
        })
        reason = "y" * 200
        body = (
            "Severity: High\nSelected impact: theft via long-rebuttal-class\n"
            "attack_class: long-rebuttal-class\n"
            f"<!-- r39-rebuttal: {reason} -->\n"
        )
        draft = _write_draft(body, filename="r39-rebuttal-200-HIGH.md")
        rc, payload = _run(draft, distribution_index=dist)
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertEqual(len(payload["rebuttal"]), 200)


if __name__ == "__main__":
    unittest.main()
