"""Cross-gate integration tests: R38 + R39 (Checks #73 + #74).

Source: docs/WAVE2_W29_NEW_GATES_SPEC_2026-05-16.md §5.3.

These tests verify the independent-rebuttal behaviour: each marker
covers exactly one rule, and a draft can fail both gates simultaneously.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

_r38_spec = importlib.util.spec_from_file_location(
    "bug_class_shift_check",
    ROOT / "tools" / "bug-class-shift-check.py",
)
r38_mod = importlib.util.module_from_spec(_r38_spec)
_r38_spec.loader.exec_module(r38_mod)  # type: ignore[union-attr]

_r39_spec = importlib.util.spec_from_file_location(
    "attack_class_orphan_check",
    ROOT / "tools" / "attack-class-orphan-check.py",
)
r39_mod = importlib.util.module_from_spec(_r39_spec)
_r39_spec.loader.exec_module(r39_mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r38_r39_cross_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    return root


def _write_draft(body: str, *, filename: str = "draft-HIGH.md") -> Path:
    root = _workspace()
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _write_distribution(matrix: dict[str, dict[str, int]]) -> Path:
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


# Distribution where "governance-takeover-via-admin-key" is a true orphan
# (1 subtree, 2 records) AND not the canonical class for the "permanent
# freezing" rubric phrase used in the draft.
_DIST = {
    "contest_platform_findings": {
        "governance-takeover-via-admin-key": 2,
        "freeze-via-pause": 60,
    },
    "immunefi": {
        "freeze-via-pause": 80,
    },
}


class R38R39CrossGateTests(unittest.TestCase):
    def test_r38_r39_both_fire_simultaneously(self) -> None:
        """Draft with mismatched rubric AND orphan attack_class fails both gates."""
        body = (
            "Severity: High\n"
            "Selected impact: permanent freezing of user collateral\n"
            "attack_class: governance-takeover-via-admin-key\n"
        )
        draft = _write_draft(body)
        dist = _write_distribution(_DIST)

        r38_rc, r38_payload = r38_mod.run(draft, allow_missing_index=True)
        self.assertEqual(r38_rc, 1, r38_payload)
        self.assertEqual(r38_payload["verdict"], "fail-rubric-attack-class-mismatch")

        r39_rc, r39_payload = r39_mod.run(draft, distribution_index=dist)
        self.assertEqual(r39_rc, 1, r39_payload)
        # 2 records AND 1 subtree -> orphan-both.
        self.assertEqual(r39_payload["verdict"], "fail-orphan-both")

    def test_r38_passes_r39_fires(self) -> None:
        """Rubric-aligned but orphan attack_class: R38 passes, R39 fails."""
        # "permanent freezing" expects {freeze}; freeze-via-cap matches; but
        # freeze-via-cap is an orphan in our dist.
        dist_orphan = _write_distribution({
            "contest_platform_findings": {
                "freeze-via-cap": 1,
                "freeze-via-pause": 80,
            },
            "immunefi": {
                "freeze-via-pause": 80,
            },
        })
        body = (
            "Severity: High\n"
            "Selected impact: permanent freezing of user collateral\n"
            "attack_class: freeze-via-cap\n"
        )
        draft = _write_draft(body)

        r38_rc, r38_payload = r38_mod.run(draft, allow_missing_index=True)
        self.assertEqual(r38_rc, 0, r38_payload)
        self.assertEqual(r38_payload["verdict"], "pass-attack-class-matches-rubric")

        r39_rc, r39_payload = r39_mod.run(draft, distribution_index=dist_orphan)
        self.assertEqual(r39_rc, 1, r39_payload)
        self.assertEqual(r39_payload["verdict"], "fail-orphan-both")

    def test_both_rebutted_passes_independently(self) -> None:
        """Each rebuttal marker silences exactly one rule; both can coexist."""
        body = (
            "Severity: High\n"
            "Selected impact: permanent freezing of user collateral\n"
            "attack_class: governance-takeover-via-admin-key\n"
            "<!-- r38-rebuttal: admin-key seizure intersects freeze+governance; cite operator_overrides/wave2.yaml -->\n"
            "<!-- r39-rebuttal: novel-class; operator-approved via audit/operator_overrides/wave2-novel-classes.yaml -->\n"
        )
        draft = _write_draft(body)
        dist = _write_distribution(_DIST)

        r38_rc, r38_payload = r38_mod.run(draft, allow_missing_index=True)
        self.assertEqual(r38_rc, 0, r38_payload)
        self.assertEqual(r38_payload["verdict"], "ok-rebuttal")
        self.assertIn("admin-key seizure", r38_payload["rebuttal"])

        r39_rc, r39_payload = r39_mod.run(draft, distribution_index=dist)
        self.assertEqual(r39_rc, 0, r39_payload)
        self.assertEqual(r39_payload["verdict"], "ok-rebuttal")
        self.assertIn("operator-approved", r39_payload["rebuttal"])

    def test_r38_rebuttal_does_not_silence_r39(self) -> None:
        """Only r38-rebuttal: R38 passes, but R39 still fails for the orphan class."""
        body = (
            "Severity: High\n"
            "Selected impact: permanent freezing of user collateral\n"
            "attack_class: governance-takeover-via-admin-key\n"
            "<!-- r38-rebuttal: admin-key seizure intersects freeze+governance -->\n"
        )
        draft = _write_draft(body)
        dist = _write_distribution(_DIST)

        r38_rc, _ = r38_mod.run(draft, allow_missing_index=True)
        self.assertEqual(r38_rc, 0)

        r39_rc, r39_payload = r39_mod.run(draft, distribution_index=dist)
        self.assertEqual(r39_rc, 1, r39_payload)
        # No transitive override: R39 still blocks.
        self.assertTrue(r39_payload["verdict"].startswith("fail-orphan"))


if __name__ == "__main__":
    unittest.main()
