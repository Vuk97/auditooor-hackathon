"""Tests for ``tools/hackerman-bug-class-shift-detector.py``.

Coverage (>=8 cases):

1.  ``extract_prior_attack_classes`` reads
    ``record_extensions.prior_attack_class`` (string form).
2.  ``extract_prior_attack_classes`` reads ``record_extensions.prior_attack_class``
    (list form) preserving order and de-duplicating.
3.  ``extract_prior_attack_classes`` reads ``function_shape.shape_tags``
    entries prefixed ``prior:`` / ``was:`` / ``previously:``.
4.  ``detect_prior_attack_class_drift`` returns ``None`` when the only
    prior_attack_class equals the current ``attack_class`` (no drift).
5.  ``detect_prior_attack_class_drift`` returns a drift descriptor when a
    prior_attack_class differs from current.
6.  ``detect_rubric_row_vs_impact_class_mismatch`` returns ``None`` when
    the rubric phrase matches the current ``impact_class`` (e.g. rubric
    cites ``Direct loss of funds`` and ``impact_class=theft``).
7.  ``detect_rubric_row_vs_impact_class_mismatch`` returns a mismatch
    descriptor when rubric says ``Direct loss of funds`` but
    ``impact_class=dos``.
8.  ``detect_rubric_row_vs_impact_class_mismatch`` returns a mismatch
    descriptor when ``rubric_row`` is absent but
    ``attacker_action_sequence`` embeds the rubric phrase.
9.  ``detect_rubric_row_vs_impact_class_mismatch`` returns ``None`` when
    no scanned rubric phrase is present anywhere in the record.
10. ``iter_records`` walks all three shapes (record.json wins over yaml;
    record.yaml fallback when no json sibling; flat ``tags/<n>.yaml``).
11. ``build_candidates`` orders results by (drift_category asc, path asc).
12. End-to-end CLI run writes both artifacts and emits a stable summary
    JSON.
13. Determinism: two CLI runs over the same tree produce byte-identical
    docs and JSONL when ``--generated-at`` is pinned.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-bug-class-shift-detector.py"


def _load_tool() -> Any:
    name = "_hackerman_bug_class_shift_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write_record_json(tags_dir: Path, subtree: str, slug: str, body: dict) -> Path:
    rec_dir = tags_dir / subtree / slug
    rec_dir.mkdir(parents=True, exist_ok=True)
    path = rec_dir / "record.json"
    path.write_text(json.dumps(body, sort_keys=True), encoding="utf-8")
    return path


def _write_record_yaml(tags_dir: Path, subtree: str, slug: str, body: dict) -> Path:
    rec_dir = tags_dir / subtree / slug
    rec_dir.mkdir(parents=True, exist_ok=True)
    path = rec_dir / "record.yaml"
    # Minimal YAML emitter that avoids depending on pyyaml in tests; the
    # tool's own loader has both pyyaml and a regex fallback.
    lines: list[str] = []
    for k, v in body.items():
        if isinstance(v, list):
            lines.append(f"{k}:")
            for item in v:
                lines.append(f"  - {json.dumps(item)}")
        elif isinstance(v, dict):
            lines.append(f"{k}:")
            for sk, sv in v.items():
                if isinstance(sv, list):
                    lines.append(f"  {sk}:")
                    for item in sv:
                        lines.append(f"    - {json.dumps(item)}")
                else:
                    lines.append(f"  {sk}: {json.dumps(sv)}")
        else:
            lines.append(f"{k}: {json.dumps(v)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_flat_yaml(tags_dir: Path, name: str, body: dict) -> Path:
    tags_dir.mkdir(parents=True, exist_ok=True)
    path = tags_dir / f"{name}.yaml"
    lines = [f"{k}: {json.dumps(v)}" for k, v in body.items() if not isinstance(v, (list, dict))]
    for k, v in body.items():
        if isinstance(v, list):
            lines.append(f"{k}:")
            for item in v:
                lines.append(f"  - {json.dumps(item)}")
        elif isinstance(v, dict):
            lines.append(f"{k}:")
            for sk, sv in v.items():
                lines.append(f"  {sk}: {json.dumps(sv)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class TestPriorAttackClassExtraction(unittest.TestCase):
    def test_string_form(self) -> None:
        rec = {
            "attack_class": "reentrancy-cross-function",
            "record_extensions": {
                "prior_attack_class": "missing-modifier-on-state-write",
            },
        }
        priors = tool.extract_prior_attack_classes(rec)
        self.assertEqual(priors, ["missing-modifier-on-state-write"])

    def test_list_form_dedup_and_order(self) -> None:
        rec = {
            "attack_class": "twap-tick-manipulation",
            "record_extensions": {
                "prior_attack_class": [
                    "external-call-reentrancy",
                    "external-call-reentrancy",  # dup
                    "Missing_Range_Check",  # normalised -> missing-range-check
                ],
            },
        }
        priors = tool.extract_prior_attack_classes(rec)
        self.assertEqual(
            priors,
            ["external-call-reentrancy", "missing-range-check"],
        )

    def test_shape_tag_prefixes(self) -> None:
        rec = {
            "attack_class": "diff-derived-pattern",
            "function_shape": {
                "shape_tags": [
                    "lending-protocols-solidity",
                    "prior:double-initialization",
                    "was:precision-loss",
                    "previously:flashloan-callback-mismatch",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
            },
        }
        priors = tool.extract_prior_attack_classes(rec)
        self.assertEqual(
            sorted(priors),
            sorted(
                [
                    "double-initialization",
                    "precision-loss",
                    "flashloan-callback-mismatch",
                ]
            ),
        )


class TestPriorAttackClassDriftDetector(unittest.TestCase):
    def test_no_drift_when_prior_equals_current(self) -> None:
        rec = {
            "attack_class": "access-control-missing-modifier",
            "record_extensions": {
                # underscore form normalises to hyphen form
                "prior_attack_class": "access_control_missing_modifier",
            },
        }
        self.assertIsNone(tool.detect_prior_attack_class_drift(rec))

    def test_drift_when_prior_differs(self) -> None:
        rec = {
            "attack_class": "external-call-reentrancy",
            "record_extensions": {
                "prior_attack_class": "missing-modifier-on-state-write",
            },
        }
        out = tool.detect_prior_attack_class_drift(rec)
        self.assertIsNotNone(out)
        assert out is not None  # mypy
        self.assertEqual(out["drift_category"], tool.DRIFT_PRIOR_ATTACK_CLASS)
        self.assertEqual(
            out["drifted_priors"], ["missing-modifier-on-state-write"]
        )
        self.assertEqual(out["current_attack_class"], "external-call-reentrancy")


class TestRubricVsImpactClass(unittest.TestCase):
    def test_match_returns_none(self) -> None:
        rec = {
            "rubric_row": "Direct loss of funds",
            "impact_class": "theft",
        }
        self.assertIsNone(tool.detect_rubric_row_vs_impact_class_mismatch(rec))

    def test_mismatch_direct_loss_vs_dos(self) -> None:
        rec = {
            "rubric_row": "Direct loss of funds",
            "impact_class": "dos",
        }
        out = tool.detect_rubric_row_vs_impact_class_mismatch(rec)
        self.assertIsNotNone(out)
        assert out is not None
        self.assertEqual(out["drift_category"], tool.DRIFT_RUBRIC_MISMATCH)
        self.assertIn("direct loss of funds", out["rubric_phrases_matched"])
        self.assertEqual(out["current_impact_class"], "dos")
        self.assertEqual(out["expected_impact_class_any_of"], ["theft"])

    def test_match_via_attacker_action_sequence(self) -> None:
        rec = {
            "attacker_action_sequence": (
                "Attacker triggers permanent freezing of funds by burning"
                " the only admin key."
            ),
            "impact_class": "theft",  # mismatch: rubric implies freeze
        }
        out = tool.detect_rubric_row_vs_impact_class_mismatch(rec)
        self.assertIsNotNone(out)
        assert out is not None
        self.assertIn("permanent freezing", out["rubric_phrases_matched"])
        self.assertEqual(out["expected_impact_class_any_of"], ["freeze"])

    def test_no_rubric_phrase_no_mismatch(self) -> None:
        rec = {
            "rubric_row": "Smart contract bug",
            "impact_class": "theft",
        }
        self.assertIsNone(tool.detect_rubric_row_vs_impact_class_mismatch(rec))

    def test_governance_takeover_via_shape_tag(self) -> None:
        rec = {
            "function_shape": {
                "shape_tags": ["rubric:governance-takeover"],
            },
            "impact_class": "theft",  # mismatch: expected governance-takeover
        }
        out = tool.detect_rubric_row_vs_impact_class_mismatch(rec)
        self.assertIsNotNone(out)
        assert out is not None
        self.assertEqual(
            out["expected_impact_class_any_of"], ["governance-takeover"]
        )


class TestIterRecordsWalker(unittest.TestCase):
    def test_walks_three_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            # subtree JSON-wins-over-YAML
            _write_record_json(
                tags_dir, "sub_a", "slug1",
                {"attack_class": "x", "record_id": "json-wins"},
            )
            _write_record_yaml(
                tags_dir, "sub_a", "slug1",
                {"attack_class": "y", "record_id": "yaml-loses"},
            )
            # subtree YAML-only fallback
            _write_record_yaml(
                tags_dir, "sub_b", "slug2",
                {"attack_class": "z", "record_id": "yaml-only"},
            )
            # flat tags/<name>.yaml
            _write_flat_yaml(
                tags_dir, "flat_pattern",
                {"attack_class": "f", "record_id": "flat"},
            )
            seen_ids: list[str] = []
            for subtree, path, data in tool.iter_records(tags_dir):
                seen_ids.append(data.get("record_id", path.name))
            self.assertIn("json-wins", seen_ids)
            self.assertIn("yaml-only", seen_ids)
            self.assertIn("flat", seen_ids)
            self.assertNotIn("yaml-loses", seen_ids)


class TestBuildCandidatesOrdering(unittest.TestCase):
    def test_orders_by_category_then_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            # Two prior-drift records, one rubric-mismatch.
            _write_record_json(
                tags_dir, "sub_b", "rec1",
                {
                    "record_id": "rec1",
                    "attack_class": "twap-tick-manipulation",
                    "record_extensions": {
                        "prior_attack_class": "external-call-reentrancy",
                    },
                    "impact_class": "theft",
                },
            )
            _write_record_json(
                tags_dir, "sub_a", "rec2",
                {
                    "record_id": "rec2",
                    "attack_class": "double-initialization",
                    "record_extensions": {
                        "prior_attack_class": "missing-modifier-on-state-write",
                    },
                    "impact_class": "theft",
                },
            )
            _write_record_json(
                tags_dir, "sub_c", "rec3",
                {
                    "record_id": "rec3",
                    "attack_class": "x",
                    "rubric_row": "Permanent freezing of funds",
                    "impact_class": "theft",
                },
            )
            records = list(tool.iter_records(tags_dir))
            cands = tool.build_candidates(records)
            cats = [c["drift_category"] for c in cands]
            # category asc -> prior_attack_class_drift < rubric_row_vs_impact_class_mismatch
            self.assertEqual(
                cats,
                [
                    tool.DRIFT_PRIOR_ATTACK_CLASS,
                    tool.DRIFT_PRIOR_ATTACK_CLASS,
                    tool.DRIFT_RUBRIC_MISMATCH,
                ],
            )
            # Within prior_attack_class_drift, paths sorted asc -> sub_a < sub_b
            prior_paths = [
                c["path"] for c in cands
                if c["drift_category"] == tool.DRIFT_PRIOR_ATTACK_CLASS
            ]
            self.assertEqual(prior_paths, sorted(prior_paths))


class TestCliEndToEndAndDeterminism(unittest.TestCase):
    def _run(self, tags_dir: Path, out_dir: Path) -> dict[str, Any]:
        jsonl_out = out_dir / "bug_class_shift.jsonl"
        docs_out = out_dir / "preview.md"
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--tags-dir",
                str(tags_dir),
                "--jsonl-out",
                str(jsonl_out),
                "--docs-out",
                str(docs_out),
                "--generated-at",
                "2026-05-16T00:00:00Z",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return {
            "stdout": result.stdout,
            "jsonl": jsonl_out.read_text(encoding="utf-8"),
            "docs": docs_out.read_text(encoding="utf-8"),
        }

    def _seed(self, tags_dir: Path) -> None:
        _write_record_json(
            tags_dir, "lending_protocols", "rec_drift",
            {
                "record_id": "lending:drift-1",
                "attack_class": "twap-tick-manipulation",
                "record_extensions": {
                    "prior_attack_class": "external-call-reentrancy",
                },
                "impact_class": "theft",
            },
        )
        _write_record_json(
            tags_dir, "bridge_incidents", "rec_rubric",
            {
                "record_id": "bridge:rubric-1",
                "attack_class": "x",
                "rubric_row": "Direct loss of funds",
                "impact_class": "dos",
            },
        )
        _write_record_json(
            tags_dir, "bridge_incidents", "rec_clean",
            {
                "record_id": "bridge:clean",
                "attack_class": "x",
                "rubric_row": "Direct loss of funds",
                "impact_class": "theft",
            },
        )

    def test_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            tags_dir.mkdir(parents=True, exist_ok=True)
            self._seed(tags_dir)
            out_dir = Path(td) / "out"
            out_dir.mkdir(parents=True, exist_ok=True)
            artifacts = self._run(tags_dir, out_dir)
            summary = json.loads(artifacts["stdout"].strip())
            self.assertEqual(summary["candidate_count"], 2)
            self.assertEqual(
                summary["by_drift_category"],
                {
                    tool.DRIFT_PRIOR_ATTACK_CLASS: 1,
                    tool.DRIFT_RUBRIC_MISMATCH: 1,
                },
            )
            # JSONL header + 2 candidate rows.
            jsonl_lines = [
                line for line in artifacts["jsonl"].splitlines() if line
            ]
            self.assertEqual(len(jsonl_lines), 3)
            self.assertIn("schema_version", jsonl_lines[0])
            # Docs file mentions both categories and the gitignored path.
            self.assertIn(tool.DRIFT_PRIOR_ATTACK_CLASS, artifacts["docs"])
            self.assertIn(tool.DRIFT_RUBRIC_MISMATCH, artifacts["docs"])
            self.assertIn(".auditooor/bug_class_shift.jsonl", artifacts["docs"])

    def test_determinism(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tags_dir = Path(td) / "tags"
            tags_dir.mkdir(parents=True, exist_ok=True)
            self._seed(tags_dir)
            out_dir_a = Path(td) / "out_a"
            out_dir_b = Path(td) / "out_b"
            out_dir_a.mkdir(parents=True, exist_ok=True)
            out_dir_b.mkdir(parents=True, exist_ok=True)
            run_a = self._run(tags_dir, out_dir_a)
            run_b = self._run(tags_dir, out_dir_b)
            self.assertEqual(run_a["jsonl"], run_b["jsonl"])
            self.assertEqual(run_a["docs"], run_b["docs"])


if __name__ == "__main__":
    unittest.main()
