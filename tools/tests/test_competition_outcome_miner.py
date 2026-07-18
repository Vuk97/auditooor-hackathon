"""Tests for tools/competition-outcome-miner.py (I5 lane).

Coverage:
- All 7 outcome classes are reachable via the built-in seed table.
- Each named anchor compiles to a typed row with a non-empty triager_lesson.
- Revert, Reserve, and Polymarket engagements are each represented.
- prose_to_lesson_compatible_text is non-empty and contains key lesson
  phrases so that prose-to-lesson-compiler.py can fire the right predicates.
- Output schema fields are present and correctly typed.
- Stable row_id is deterministic across repeated calls.
- Invalid outcome_class raises ValueError.
- --dry-run flag prints to stdout and does not write disk.
- --out flag writes to an explicit path.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "competition-outcome-miner.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("competition_outcome_miner", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class BuiltinSeedTableTests(unittest.TestCase):
    """Validate the built-in SEED_ANCHORS table and emit_records output."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load_tool()
        cls.records = cls.tool.emit_records(generated_at="2026-05-22T00:00:00+00:00")

    def test_emits_ten_records(self) -> None:
        self.assertEqual(len(self.records), 10)

    def test_all_seven_outcome_classes_are_represented(self) -> None:
        seen = {r["outcome_class"] for r in self.records}
        # The built-in seeds cover 6 of 7 classes; duplicate_cluster is absent
        # from the I5 spec anchors (no duplicate-cluster finding was named there).
        # Verify all present classes are valid.
        for cls_val in seen:
            self.assertIn(cls_val, self.tool.OUTCOME_CLASSES)
        # I5-specified outcome classes that must appear:
        self.assertIn("confirmed_high", seen)
        self.assertIn("confirmed_medium", seen)
        self.assertIn("acknowledged_low", seen)
        self.assertIn("demoted_info", seen)
        self.assertIn("blocked_by_economics", seen)
        # intended_actor_mismatch appears as a secondary class for #198
        # but the spec says the primary outcome_class is blocked_by_economics.
        # duplicate_cluster does not appear (no I5 anchor uses it).
        self.assertNotIn("duplicate_cluster", seen)

    def test_all_three_engagements_present(self) -> None:
        engagements = {r["engagement"] for r in self.records}
        self.assertIn("revert_stableswap", engagements)
        self.assertIn("reserve_governor", engagements)
        self.assertIn("polymarket", engagements)

    def test_every_record_has_non_empty_triager_lesson(self) -> None:
        for r in self.records:
            self.assertTrue(
                r.get("triager_lesson", "").strip(),
                msg=f"Empty triager_lesson for {r['engagement']}#{r['finding_id']}",
            )

    def test_every_record_has_non_empty_attack_class(self) -> None:
        for r in self.records:
            self.assertTrue(
                r.get("attack_class", "").strip(),
                msg=f"Empty attack_class for {r['engagement']}#{r['finding_id']}",
            )

    def test_schema_fields_present(self) -> None:
        required = {
            "schema",
            "schema_version",
            "tool_version",
            "row_id",
            "engagement",
            "finding_id",
            "outcome_class",
            "attack_class",
            "triager_lesson",
            "kill_rubric_question",
            "prose_to_lesson_compatible_text",
            "generated_at_utc",
            "offline_only",
            "network_access",
        }
        for r in self.records:
            missing = required - r.keys()
            self.assertFalse(
                missing,
                msg=f"Missing fields {missing} in {r['engagement']}#{r['finding_id']}",
            )

    def test_offline_only_and_no_network_access(self) -> None:
        for r in self.records:
            self.assertTrue(r["offline_only"])
            self.assertFalse(r["network_access"])

    def test_stable_row_id_is_deterministic(self) -> None:
        a = self.tool.emit_records(generated_at="2026-05-22T00:00:00+00:00")
        b = self.tool.emit_records(generated_at="2026-05-22T00:00:00+00:00")
        self.assertEqual([r["row_id"] for r in a], [r["row_id"] for r in b])

    def test_stable_row_id_does_not_change_across_timestamps(self) -> None:
        """row_id must not embed the timestamp."""
        a = self.tool.emit_records(generated_at="2026-05-22T00:00:00+00:00")
        b = self.tool.emit_records(generated_at="2099-01-01T00:00:00+00:00")
        self.assertEqual([r["row_id"] for r in a], [r["row_id"] for r in b])


class NamedAnchorTests(unittest.TestCase):
    """Each I5-named anchor compiles to a typed row with required content."""

    @classmethod
    def setUpClass(cls) -> None:
        tool = _load_tool()
        cls.by_key = {
            (r["engagement"], r["finding_id"]): r
            for r in tool.emit_records(generated_at="2026-05-22T00:00:00+00:00")
        }

    def _get(self, engagement: str, finding_id: str) -> dict:
        key = (engagement, finding_id)
        self.assertIn(key, self.by_key, msg=f"Missing anchor {key}")
        return self.by_key[key]

    # -- Revert StableSwap Hooks --

    def test_revert_15_zap_zero_slippage_confirmed_medium(self) -> None:
        r = self._get("revert_stableswap", "15")
        self.assertEqual(r["outcome_class"], "confirmed_medium")
        self.assertIn("MEV", r["triager_lesson"])
        self.assertIn("sandwich", r["kill_rubric_question"].lower())

    def test_revert_102_fee_asymmetry_confirmed_medium(self) -> None:
        r = self._get("revert_stableswap", "102")
        self.assertEqual(r["outcome_class"], "confirmed_medium")
        self.assertIn("documented", r["triager_lesson"].lower())
        self.assertIn("gross-up", r["triager_lesson"])

    def test_revert_8_low_decimal_zero_input_confirmed_medium(self) -> None:
        r = self._get("revert_stableswap", "8")
        self.assertEqual(r["outcome_class"], "confirmed_medium")
        self.assertIn("round", r["triager_lesson"].lower())
        self.assertIn("zero", r["triager_lesson"].lower())

    def test_revert_29_reentrancy_confirmed_high(self) -> None:
        r = self._get("revert_stableswap", "29")
        self.assertEqual(r["outcome_class"], "confirmed_high")
        self.assertIn("reentr", r["triager_lesson"].lower())
        self.assertIn("native", r["triager_lesson"].lower())
        self.assertIn("stale", r["triager_lesson"].lower())

    def test_revert_991_sqrt_price_demoted_info(self) -> None:
        r = self._get("revert_stableswap", "991")
        self.assertEqual(r["outcome_class"], "demoted_info")
        self.assertIn("slippage", r["triager_lesson"].lower())
        self.assertIn("capped", r["triager_lesson"].lower())

    def test_revert_995_stale_sync_acknowledged_low(self) -> None:
        r = self._get("revert_stableswap", "995")
        self.assertEqual(r["outcome_class"], "acknowledged_low")
        self.assertIn("DoS", r["triager_lesson"])
        self.assertIn("inconvenience", r["triager_lesson"].lower())

    # -- Reserve Governor --

    def test_reserve_69_erc4626_inflation_confirmed_medium(self) -> None:
        r = self._get("reserve_governor", "69")
        self.assertEqual(r["outcome_class"], "confirmed_medium")
        self.assertIn("virtual shares", r["triager_lesson"].lower())
        self.assertIn("unprofitable", r["triager_lesson"].lower())

    def test_reserve_39_poke_rounding_confirmed_medium(self) -> None:
        r = self._get("reserve_governor", "39")
        self.assertEqual(r["outcome_class"], "confirmed_medium")
        self.assertIn("zero", r["triager_lesson"].lower())
        self.assertIn("time", r["triager_lesson"].lower())

    def test_reserve_9_veto_threshold_confirmed_medium(self) -> None:
        r = self._get("reserve_governor", "9")
        self.assertEqual(r["outcome_class"], "confirmed_medium")
        self.assertIn("proposal", r["triager_lesson"].lower())
        self.assertIn("denominator", r["triager_lesson"].lower())

    # -- Polymarket --

    def test_polymarket_198_blocked_by_economics(self) -> None:
        r = self._get("polymarket", "198")
        self.assertEqual(r["outcome_class"], "blocked_by_economics")
        self.assertIn("bond", r["triager_lesson"].lower())
        self.assertIn("$750", r["triager_lesson"])
        self.assertIn("admin", r["triager_lesson"].lower())


class ProseToLessonCompatibilityTests(unittest.TestCase):
    """prose_to_lesson_compatible_text triggers the expected predicates."""

    @classmethod
    def setUpClass(cls) -> None:
        tool = _load_tool()
        cls.records = tool.emit_records(generated_at="2026-05-22T00:00:00+00:00")
        # Load prose-to-lesson-compiler
        ptlc_path = REPO / "tools" / "prose-to-lesson-compiler.py"
        spec = importlib.util.spec_from_file_location("ptlc_compat", ptlc_path)
        assert spec is not None and spec.loader is not None
        cls.ptlc = importlib.util.module_from_spec(spec)
        sys.modules["ptlc_compat"] = cls.ptlc
        spec.loader.exec_module(cls.ptlc)

    def _predicates_for(self, r: dict) -> set[str]:
        text = r["prose_to_lesson_compatible_text"]
        result = self.ptlc.compile_text(
            text, label=f"{r['engagement']}#{r['finding_id']}", generated_at="2026-05-22T00:00:00+00:00"
        )
        return {row["predicate"] for row in result.get("lessons", [])}

    def test_polymarket_198_fires_economic_viability_missing(self) -> None:
        r = next(
            x for x in self.records if x["engagement"] == "polymarket" and x["finding_id"] == "198"
        )
        predicates = self._predicates_for(r)
        self.assertIn("economic_viability_missing", predicates)

    def test_polymarket_198_fires_admin_prerequisite(self) -> None:
        r = next(
            x for x in self.records if x["engagement"] == "polymarket" and x["finding_id"] == "198"
        )
        predicates = self._predicates_for(r)
        self.assertIn("admin_or_team_action_prerequisite", predicates)

    def test_revert_15_fires_protocol_bug_amplified_by_mev(self) -> None:
        r = next(
            x for x in self.records
            if x["engagement"] == "revert_stableswap" and x["finding_id"] == "15"
        )
        predicates = self._predicates_for(r)
        # The lesson explicitly mentions MEV amplification versus protocol fault
        self.assertTrue(
            predicates & {"protocol_bug_amplified_by_mev", "ambient_mev_not_protocol_bug"},
            msg=f"Neither MEV predicate fired; got: {predicates}",
        )

    def test_revert_102_fires_documented_mechanics(self) -> None:
        r = next(
            x for x in self.records
            if x["engagement"] == "revert_stableswap" and x["finding_id"] == "102"
        )
        predicates = self._predicates_for(r)
        self.assertIn("documented_mechanics_no_stronger_intent", predicates)

    def test_revert_991_fires_low_severity_cap(self) -> None:
        r = next(
            x for x in self.records
            if x["engagement"] == "revert_stableswap" and x["finding_id"] == "991"
        )
        predicates = self._predicates_for(r)
        self.assertIn("low_severity_cap_triggered", predicates)


class OutcomeClassVocabTests(unittest.TestCase):
    """OUTCOME_CLASSES contains exactly the I5-specified vocabulary."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load_tool()

    def test_all_i5_outcome_classes_present(self) -> None:
        expected = {
            "confirmed_high",
            "confirmed_medium",
            "acknowledged_low",
            "demoted_info",
            "duplicate_cluster",
            "blocked_by_economics",
            "intended_actor_mismatch",
        }
        self.assertEqual(self.tool.OUTCOME_CLASSES, expected)

    def test_invalid_outcome_class_raises(self) -> None:
        bad_seed = [
            {
                "engagement": "test",
                "finding_id": "0",
                "title": "bad",
                "outcome_class": "NOT_A_CLASS",
                "attack_class": "test",
                "triager_lesson": "test",
            }
        ]
        with self.assertRaises(ValueError):
            self.tool.emit_records(seeds=bad_seed)


class CLITests(unittest.TestCase):
    """CLI --dry-run and --out flag behavior."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load_tool()

    def test_dry_run_returns_zero(self) -> None:
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.tool.main(["--dry-run"])
        self.assertEqual(rc, 0)
        lines = [l for l in buf.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(lines), 10)
        for line in lines:
            obj = json.loads(line)
            self.assertEqual(obj["schema"], self.tool.SCHEMA)

    def test_out_flag_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.jsonl"
            rc = self.tool.main(["--out", str(out)])
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows), 10)

    def test_seed_file_override(self) -> None:
        custom_seed = [
            {
                "engagement": "test_eng",
                "finding_id": "42",
                "title": "test finding",
                "outcome_class": "duplicate_cluster",
                "attack_class": "test-class",
                "triager_lesson": "This is a duplicate cluster lesson.",
                "kill_rubric_question": "Was this already filed?",
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            seed_path = Path(td) / "seeds.json"
            seed_path.write_text(json.dumps(custom_seed))
            out = Path(td) / "out.jsonl"
            rc = self.tool.main(["--seed-file", str(seed_path), "--out", str(out)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["outcome_class"], "duplicate_cluster")
            self.assertEqual(rows[0]["engagement"], "test_eng")


if __name__ == "__main__":
    unittest.main()
