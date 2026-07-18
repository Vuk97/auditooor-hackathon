"""Tests for tools/analogue-provenance.py (J3c: evidence-aware analogue provenance)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Import hyphen-named module via importlib (filename contains a hyphen)
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    "analogue_provenance", REPO_ROOT / "tools" / "analogue-provenance.py"
)
ap = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(ap)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(obj, fh)


_MINED_ANALOGUE = {
    "analogue_record_id": "corpus-txt:ref:L1:S1:aabbcc",
    "attack_class": "reentrancy",
    "confidence": 0.95,
    "pattern_translation": "solidity->go: reentrant call guard -> mutex guard",
    "reason": "shared attack_class=reentrancy",
    "source_language": "solidity",
    "source_record_id": "corpus-mined:code4arena_slice_aa.md:L100:S69:73863d4152bc",
    "target_language": "go",
}

_TEMPLATE_ANALOGUE = {
    "analogue_record_id": "template:oracle:L1:S1:ddeeff",
    "attack_class": "stale-oracle",
    "confidence": 0.82,
    "pattern_translation": "solidity->rust: stale price guard -> freshness check",
    "reason": "template expansion from oracle family",
    "source_language": "solidity",
    "source_record_id": "template:oracle:family:001",
    "target_language": "rust",
}

_CRITICAL_ANALOGUE = {
    "analogue_record_id": "corpus-txt:ref:L2:S2:112233",
    "attack_class": "access-control",
    "confidence": 0.98,
    "pattern_translation": "solidity->go: role gate -> authority check",
    "reason": "shared attack_class=access-control",
    "source_language": "solidity",
    "source_record_id": "critical:cantina:40241:1d0436bfe933",
    "target_language": "go",
}

_PRED_MINED = {
    "record_id": "corpus-mined:code4arena_slice_aa.md:L100:S69:73863d4152bc",
    "record_tier": "public-corpus",
    "source_audit_ref": "https://code4rena.com/reports/2023-01",
    "attack_class": "reentrancy",
    "target_language": "solidity",
}

_PRED_CRITICAL = {
    "record_id": "critical:cantina:40241:1d0436bfe933",
    "record_tier": "submission-derived",
    "source_audit_ref": "https://solodit.cyfrin.io/issues/some-issue",
    "attack_class": "access-control",
    "target_language": "solidity",
}

_TAXONOMY = {
    "schema": "auditooor.hackerman.attack_class_taxonomy.v1",
    "total_records": 100,
    "subtrees": ["subtree_a", "subtree_b"],
    "classes": [
        {
            "attack_class": "reentrancy",
            "subtrees": ["subtree_a", "subtree_b"],
            "total_records": 50,
            "tier12_count": 40,
        },
        {
            "attack_class": "access-control",
            "subtrees": ["subtree_a", "subtree_b", "subtree_c"],
            "total_records": 30,
            "tier12_count": 25,
        },
        {
            "attack_class": "stale-or-manipulated-oracle",
            "subtrees": ["subtree_a", "subtree_b"],
            "total_records": 25,
            "tier12_count": 20,
        },
    ],
    "per_subtree": {},
}


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestEmptyInput(unittest.TestCase):
    """Empty analogue file produces zero counts without crashing."""

    def test_empty_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            analogue_path = td / "analogues.jsonl"
            analogue_path.write_text("")

            rc = ap.process(
                analogue_path=analogue_path,
                predicates_path=td / "missing_predicates.jsonl",
                taxonomy_path=td / "missing_taxonomy.json",
                out_path=None,
                limit=None,
                json_mode=False,
                strict=False,
            )
            self.assertEqual(rc, 0)


class TestMissingFile(unittest.TestCase):
    """Absent analogue file returns 0 (defensive) without crash."""

    def test_missing_analogue_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            rc = ap.process(
                analogue_path=td / "nonexistent.jsonl",
                predicates_path=td / "nonexistent_pred.jsonl",
                taxonomy_path=td / "nonexistent_tax.json",
                out_path=None,
                limit=None,
                json_mode=False,
                strict=False,
            )
            self.assertEqual(rc, 0)

    def test_missing_file_json_mode(self) -> None:
        """JSON mode on missing file emits a valid JSON object with status=missing."""
        import io
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = ap.process(
                    analogue_path=td / "nonexistent.jsonl",
                    predicates_path=td / "nonexistent_pred.jsonl",
                    taxonomy_path=td / "nonexistent_tax.json",
                    out_path=None,
                    limit=None,
                    json_mode=True,
                    strict=False,
                )
            data = json.loads(buf.getvalue())
            self.assertEqual(data["status"], "missing")
            self.assertEqual(data["schema"], ap.SCHEMA)
            self.assertEqual(rc, 0)


class TestSourceRecordTierDerivation(unittest.TestCase):
    """source_record_tier is mapped from exploit_predicates record_tier."""

    def test_mined_record_maps_to_tier2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_jsonl(td / "analogues.jsonl", [_MINED_ANALOGUE])
            _write_jsonl(td / "predicates.jsonl", [_PRED_MINED])
            _write_json(td / "taxonomy.json", _TAXONOMY)

            out_path = td / "out.jsonl"
            ap.process(
                analogue_path=td / "analogues.jsonl",
                predicates_path=td / "predicates.jsonl",
                taxonomy_path=td / "taxonomy.json",
                out_path=out_path,
                limit=None,
                json_mode=False,
                strict=False,
            )
            with out_path.open() as fh:
                row = json.loads(fh.readline())
            self.assertEqual(row["source_record_tier"], "tier-2-verified-public-archive")

    def test_critical_record_maps_to_tier1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_jsonl(td / "analogues.jsonl", [_CRITICAL_ANALOGUE])
            _write_jsonl(td / "predicates.jsonl", [_PRED_CRITICAL])
            _write_json(td / "taxonomy.json", _TAXONOMY)

            out_path = td / "out.jsonl"
            ap.process(
                analogue_path=td / "analogues.jsonl",
                predicates_path=td / "predicates.jsonl",
                taxonomy_path=td / "taxonomy.json",
                out_path=out_path,
                limit=None,
                json_mode=False,
                strict=False,
            )
            with out_path.open() as fh:
                row = json.loads(fh.readline())
            self.assertEqual(row["source_record_tier"], "tier-1-verified-realtime-api")

    def test_unknown_source_id_gives_none_tier(self) -> None:
        analogue = dict(_MINED_ANALOGUE, source_record_id="corpus-mined:unknown:L9:S9:000000")
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_jsonl(td / "analogues.jsonl", [analogue])
            _write_jsonl(td / "predicates.jsonl", [_PRED_MINED])
            _write_json(td / "taxonomy.json", _TAXONOMY)

            out_path = td / "out.jsonl"
            ap.process(
                analogue_path=td / "analogues.jsonl",
                predicates_path=td / "predicates.jsonl",
                taxonomy_path=td / "taxonomy.json",
                out_path=out_path,
                limit=None,
                json_mode=False,
                strict=False,
            )
            with out_path.open() as fh:
                row = json.loads(fh.readline())
            self.assertIsNone(row["source_record_tier"])


class TestSourceProofAvailable(unittest.TestCase):
    """source_proof_available reflects whether source_audit_ref is non-empty."""

    def test_proof_available_when_ref_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_jsonl(td / "analogues.jsonl", [_MINED_ANALOGUE])
            _write_jsonl(td / "predicates.jsonl", [_PRED_MINED])
            _write_json(td / "taxonomy.json", _TAXONOMY)

            out_path = td / "out.jsonl"
            ap.process(
                analogue_path=td / "analogues.jsonl",
                predicates_path=td / "predicates.jsonl",
                taxonomy_path=td / "taxonomy.json",
                out_path=out_path,
                limit=None,
                json_mode=False,
                strict=False,
            )
            with out_path.open() as fh:
                row = json.loads(fh.readline())
            self.assertTrue(row["source_proof_available"])

    def test_proof_unavailable_when_ref_missing(self) -> None:
        pred_no_ref = dict(_PRED_MINED, source_audit_ref="")
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_jsonl(td / "analogues.jsonl", [_MINED_ANALOGUE])
            _write_jsonl(td / "predicates.jsonl", [pred_no_ref])
            _write_json(td / "taxonomy.json", _TAXONOMY)

            out_path = td / "out.jsonl"
            ap.process(
                analogue_path=td / "analogues.jsonl",
                predicates_path=td / "predicates.jsonl",
                taxonomy_path=td / "taxonomy.json",
                out_path=out_path,
                limit=None,
                json_mode=False,
                strict=False,
            )
            with out_path.open() as fh:
                row = json.loads(fh.readline())
            self.assertFalse(row["source_proof_available"])


class TestAnalogueOriginClassification(unittest.TestCase):
    """analogue_origin correctly classifies mined_report vs template_expansion."""

    def test_corpus_mined_is_mined_report(self) -> None:
        origin = ap._derive_origin("corpus-mined:code4arena_slice_aa.md:L100:S69:abc")
        self.assertEqual(origin, "mined_report")

    def test_corpus_txt_is_mined_report(self) -> None:
        origin = ap._derive_origin("corpus-txt:reference-corpus:L1:S1:abc")
        self.assertEqual(origin, "mined_report")

    def test_critical_prefix_is_mined_report(self) -> None:
        origin = ap._derive_origin("critical:cantina:40241:1d0436bfe933")
        self.assertEqual(origin, "mined_report")

    def test_template_prefix_is_template_expansion(self) -> None:
        origin = ap._derive_origin("template:oracle:family:001")
        self.assertEqual(origin, "template_expansion")

    def test_empty_source_id_is_template_expansion(self) -> None:
        origin = ap._derive_origin("")
        self.assertEqual(origin, "template_expansion")


class TestUsageClassVerdicts(unittest.TestCase):
    """usage_class is correctly assigned for all three categories."""

    def _run_single(
        self, analogue: dict, pred_rows: list[dict], taxonomy: dict
    ) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_jsonl(td / "analogues.jsonl", [analogue])
            _write_jsonl(td / "predicates.jsonl", pred_rows)
            _write_json(td / "taxonomy.json", taxonomy)
            out_path = td / "out.jsonl"
            ap.process(
                analogue_path=td / "analogues.jsonl",
                predicates_path=td / "predicates.jsonl",
                taxonomy_path=td / "taxonomy.json",
                out_path=out_path,
                limit=None,
                json_mode=False,
                strict=False,
            )
            with out_path.open() as fh:
                return json.loads(fh.readline())

    def test_mined_report_is_usable_detector_seed(self) -> None:
        row = self._run_single(_MINED_ANALOGUE, [_PRED_MINED], _TAXONOMY)
        self.assertEqual(row["usage_class"], "usable_detector_seed")

    def test_template_with_strong_tier_is_hacker_question(self) -> None:
        # template_expansion origin but predicates has a tier-2 entry
        pred = dict(_PRED_MINED)
        pred["record_id"] = _TEMPLATE_ANALOGUE["source_record_id"]
        pred["record_tier"] = "public-corpus"
        pred["source_audit_ref"] = "https://example.com/report"
        row = self._run_single(_TEMPLATE_ANALOGUE, [pred], _TAXONOMY)
        self.assertEqual(row["usage_class"], "usable_hacker_question")

    def test_template_with_weak_tier_is_blocked(self) -> None:
        # template_expansion origin AND no predicates entry -> tier=None -> blocked
        row = self._run_single(_TEMPLATE_ANALOGUE, [], _TAXONOMY)
        self.assertEqual(row["usage_class"], "blocked_no_provenance")


class TestCannotUpgradeFlag(unittest.TestCase):
    """cannot_upgrade_severity_or_proof reflects the J3c acceptance rule."""

    def _run_single(
        self, analogue: dict, pred_rows: list[dict], taxonomy: dict
    ) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_jsonl(td / "analogues.jsonl", [analogue])
            _write_jsonl(td / "predicates.jsonl", pred_rows)
            _write_json(td / "taxonomy.json", taxonomy)
            out_path = td / "out.jsonl"
            ap.process(
                analogue_path=td / "analogues.jsonl",
                predicates_path=td / "predicates.jsonl",
                taxonomy_path=td / "taxonomy.json",
                out_path=out_path,
                limit=None,
                json_mode=False,
                strict=False,
            )
            with out_path.open() as fh:
                return json.loads(fh.readline())

    def test_mined_with_proof_can_upgrade(self) -> None:
        row = self._run_single(_MINED_ANALOGUE, [_PRED_MINED], _TAXONOMY)
        self.assertFalse(row["cannot_upgrade_severity_or_proof"])

    def test_template_with_no_proof_cannot_upgrade(self) -> None:
        row = self._run_single(_TEMPLATE_ANALOGUE, [], _TAXONOMY)
        self.assertTrue(row["cannot_upgrade_severity_or_proof"])

    def test_mined_but_no_audit_ref_cannot_upgrade(self) -> None:
        pred_no_ref = dict(_PRED_MINED, source_audit_ref="")
        row = self._run_single(_MINED_ANALOGUE, [pred_no_ref], _TAXONOMY)
        self.assertTrue(row["cannot_upgrade_severity_or_proof"])


class TestStrictModeExit(unittest.TestCase):
    """--strict exits non-zero when any analogue cannot_upgrade_severity_or_proof."""

    def test_strict_mode_exits_nonzero_on_violation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            # Template analogue with no predicates entry -> cannot_upgrade=True
            _write_jsonl(td / "analogues.jsonl", [_TEMPLATE_ANALOGUE])
            _write_jsonl(td / "predicates.jsonl", [])
            _write_json(td / "taxonomy.json", _TAXONOMY)

            rc = ap.process(
                analogue_path=td / "analogues.jsonl",
                predicates_path=td / "predicates.jsonl",
                taxonomy_path=td / "taxonomy.json",
                out_path=None,
                limit=None,
                json_mode=False,
                strict=True,
            )
            self.assertEqual(rc, 1)

    def test_strict_mode_ok_when_all_provenance_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_jsonl(td / "analogues.jsonl", [_MINED_ANALOGUE])
            _write_jsonl(td / "predicates.jsonl", [_PRED_MINED])
            _write_json(td / "taxonomy.json", _TAXONOMY)

            rc = ap.process(
                analogue_path=td / "analogues.jsonl",
                predicates_path=td / "predicates.jsonl",
                taxonomy_path=td / "taxonomy.json",
                out_path=None,
                limit=None,
                json_mode=False,
                strict=True,
            )
            self.assertEqual(rc, 0)


class TestLimitBound(unittest.TestCase):
    """--limit stops processing after N rows."""

    def test_limit_respected(self) -> None:
        import io
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            # Write 5 analogue rows
            rows = [dict(_MINED_ANALOGUE, analogue_record_id=f"id:{i}") for i in range(5)]
            _write_jsonl(td / "analogues.jsonl", rows)
            _write_jsonl(td / "predicates.jsonl", [_PRED_MINED])
            _write_json(td / "taxonomy.json", _TAXONOMY)

            out_path = td / "out.jsonl"
            buf = io.StringIO()
            with redirect_stdout(buf):
                ap.process(
                    analogue_path=td / "analogues.jsonl",
                    predicates_path=td / "predicates.jsonl",
                    taxonomy_path=td / "taxonomy.json",
                    out_path=out_path,
                    limit=2,
                    json_mode=False,
                    strict=False,
                )
            lines = [l for l in out_path.read_text().splitlines() if l.strip()]
            self.assertEqual(len(lines), 2)


class TestJsonSchemaSummary(unittest.TestCase):
    """JSON mode emits a valid summary with all required schema fields."""

    def test_json_summary_fields(self) -> None:
        import io
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_jsonl(td / "analogues.jsonl", [_MINED_ANALOGUE, _TEMPLATE_ANALOGUE])
            _write_jsonl(td / "predicates.jsonl", [_PRED_MINED])
            _write_json(td / "taxonomy.json", _TAXONOMY)

            buf = io.StringIO()
            with redirect_stdout(buf):
                ap.process(
                    analogue_path=td / "analogues.jsonl",
                    predicates_path=td / "predicates.jsonl",
                    taxonomy_path=td / "taxonomy.json",
                    out_path=None,
                    limit=None,
                    json_mode=True,
                    strict=False,
                )
            data = json.loads(buf.getvalue())

            required_fields = [
                "schema",
                "version",
                "status",
                "total_analogues",
                "usage_class_counts",
                "cannot_upgrade_count",
                "orphan_class_count",
                "origin_counts",
                "tier_counts",
            ]
            for field in required_fields:
                self.assertIn(field, data, f"Missing field: {field}")
            self.assertEqual(data["schema"], ap.SCHEMA)
            self.assertEqual(data["total_analogues"], 2)


class TestConfidenceBounding(unittest.TestCase):
    """analogue_confidence is clamped to [0.0, 1.0]."""

    def test_over_1_is_clamped(self) -> None:
        result = ap._normalize_confidence(1.5)
        self.assertEqual(result, 1.0)

    def test_negative_is_clamped(self) -> None:
        result = ap._normalize_confidence(-0.1)
        self.assertEqual(result, 0.0)

    def test_valid_value_preserved(self) -> None:
        result = ap._normalize_confidence(0.87)
        self.assertAlmostEqual(result, 0.87)

    def test_none_gives_zero(self) -> None:
        result = ap._normalize_confidence(None)
        self.assertEqual(result, 0.0)


class TestOrphanClassDetection(unittest.TestCase):
    """is_orphan_attack_class reflects taxonomy single-subtree / low-count detection."""

    def test_known_class_with_two_subtrees_is_not_orphan(self) -> None:
        idx = ap._build_taxonomy_index.__func__ if hasattr(ap._build_taxonomy_index, "__func__") else None
        # Build index directly from dict
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_json(td / "taxonomy.json", _TAXONOMY)
            tax_idx = ap._build_taxonomy_index(td / "taxonomy.json")

        self.assertFalse(ap._is_orphan_class("reentrancy", tax_idx))

    def test_unknown_class_is_orphan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_json(td / "taxonomy.json", _TAXONOMY)
            tax_idx = ap._build_taxonomy_index(td / "taxonomy.json")

        self.assertTrue(ap._is_orphan_class("totally-unknown-class-xyz", tax_idx))

    def test_orphan_class_gets_canonical_suggestion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            _write_json(td / "taxonomy.json", _TAXONOMY)
            tax_idx = ap._build_taxonomy_index(td / "taxonomy.json")

        # "stale-oracle" should suggest "stale-or-manipulated-oracle" via token overlap
        suggestion = ap._canonical_family_suggestion("stale-oracle", tax_idx)
        self.assertEqual(suggestion, "stale-or-manipulated-oracle")


if __name__ == "__main__":
    unittest.main()
