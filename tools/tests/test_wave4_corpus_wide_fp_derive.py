"""Wave-4 corpus-wide FP derive: unit tests.

These tests exercise the canonical fingerprinting algorithm and the
walker on synthetic in-tmpdir fixtures so they run fast and avoid
contaminating the real corpus. Fixture documents are clearly marked
``synthetic_fixture: true`` per the Wave-4 capability-lane brief.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import importlib.util


def _load_module():
    here = Path(__file__).resolve().parent.parent / "wave4-corpus-wide-fp-derive.py"
    spec = importlib.util.spec_from_file_location("_w4fp", here)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_module()


class CanonicalFingerprintTests(unittest.TestCase):
    """The Wave-3 canonical-fingerprint algorithm verbatim."""

    def test_simple_attack_class(self) -> None:
        fp = _MOD.canonical_fingerprint("missing-validation-on-state-mutation")
        self.assertEqual(fp, "missing-mutation-state-validation")

    def test_lowercase(self) -> None:
        fp = _MOD.canonical_fingerprint("Reentrancy-On-External-Call")
        self.assertEqual(fp, "call-external-reentrancy")

    def test_stopwords_dropped(self) -> None:
        fp = _MOD.canonical_fingerprint("the missing validation for state and storage mutation")
        self.assertNotIn("the", (fp or "").split("-"))
        self.assertNotIn("and", (fp or "").split("-"))
        self.assertNotIn("for", (fp or "").split("-"))

    def test_short_tokens_dropped(self) -> None:
        fp = _MOD.canonical_fingerprint("a b c d e f reentrancy oracle staleness manipulation drift")
        self.assertNotIn("a", (fp or "").split("-"))
        self.assertNotIn("b", (fp or "").split("-"))

    def test_empty_input(self) -> None:
        self.assertIsNone(_MOD.canonical_fingerprint(""))
        self.assertIsNone(_MOD.canonical_fingerprint(None or ""))

    def test_top_k_truncation(self) -> None:
        fp = _MOD.canonical_fingerprint(
            "alpha bravo charlie delta echo foxtrot golf hotel"
        )
        self.assertEqual(len((fp or "").split("-")), 5)

    def test_punctuation_stripped(self) -> None:
        fp = _MOD.canonical_fingerprint("missing!!! validation??? state... mutation")
        for tok in (fp or "").split("-"):
            self.assertTrue(tok.isalnum() or "-" in tok)

    def test_deterministic_lex_tiebreak(self) -> None:
        fp1 = _MOD.canonical_fingerprint("zebra apple banana cherry kiwi mango papaya")
        fp2 = _MOD.canonical_fingerprint("papaya mango kiwi cherry banana apple zebra")
        self.assertEqual(fp1, fp2)


class FpInputExtractionTests(unittest.TestCase):

    def test_attack_class_preferred(self) -> None:
        doc = {"attack_class": "reentrancy", "bug_class": "X", "attacker_action_sequence": "Y"}
        text = _MOD._extract_fp_input(doc)
        self.assertIn("reentrancy", text)

    def test_falls_back_to_aas(self) -> None:
        doc = {
            "attacker_action_sequence": "Attacker called fn with malicious payload",
        }
        text = _MOD._extract_fp_input(doc)
        self.assertIn("attacker", text.lower())

    def test_aas_truncated_at_200(self) -> None:
        doc = {"attacker_action_sequence": "x" * 1000}
        text = _MOD._extract_fp_input(doc)
        self.assertLessEqual(len(text), 200)

    def test_no_usable_input(self) -> None:
        doc = {"unrelated_field": "foo"}
        self.assertEqual(_MOD._extract_fp_input(doc), "")


class WalkerTests(unittest.TestCase):

    def _make_fixture(self, root: Path) -> None:
        (root / "subtree_a" / "rec1").mkdir(parents=True)
        (root / "subtree_a" / "rec1" / "record.yaml").write_text(
            "synthetic_fixture: true\n"
            "schema_version: auditooor.hackerman_record.v1.1\n"
            "record_id: synth:a:1\n"
            "attack_class: reentrancy-on-external-call\n"
            "target_repo: synthetic/repo-a\n"
        )
        (root / "subtree_a" / "rec2").mkdir(parents=True)
        (root / "subtree_a" / "rec2" / "record.yaml").write_text(
            "synthetic_fixture: true\n"
            "schema_version: auditooor.hackerman_record.v1.1\n"
            "record_id: synth:a:2\n"
            "attack_class: missing-validation-on-state-mutation\n"
            "target_repo: synthetic/repo-a\n"
        )
        (root / "subtree_b" / "rec1").mkdir(parents=True)
        (root / "subtree_b" / "rec1" / "record.yaml").write_text(
            "synthetic_fixture: true\n"
            "schema_version: auditooor.hackerman_record.v1.1\n"
            "record_id: synth:b:1\n"
            "attack_class: reentrancy-on-external-call\n"
            "target_repo: synthetic/repo-b\n"
        )
        (root / "subtree_c" / "rec1").mkdir(parents=True)
        (root / "subtree_c" / "rec1" / "record.yaml").write_text(
            "synthetic_fixture: true\n"
            "schema_version: auditooor.hackerman_record.v1.1\n"
            "record_id: synth:c:1\n"
            "attack_class: reentrancy-on-external-call\n"
            "target_repo: synthetic/repo-c\n"
        )
        (root / "flat_record.yaml").write_text(
            "synthetic_fixture: true\n"
            "schema_version: auditooor.hackerman_record.v1.1\n"
            "record_id: synth:flat:1\n"
            "attack_class: precision-loss-rounding-error\n"
            "target_repo: synthetic/repo-flat\n"
        )
        (root / "subtree_d" / "rec1").mkdir(parents=True)
        (root / "subtree_d" / "rec1" / "record.json").write_text(json.dumps({
            "synthetic_fixture": True,
            "schema_version": "auditooor.hackerman_record.v1.1",
            "record_id": "synth:d:1",
            "attack_class": "reentrancy-on-external-call",
            "target_repo": "synthetic/repo-d",
        }))

    def test_walker_finds_all_records(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._make_fixture(root)
            paths = list(_MOD._iter_record_paths(root))
            self.assertEqual(len(paths), 6)

    def test_walker_skips_excluded_subtrees(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "_QUARANTINE_FABRICATED_CVE" / "rec1").mkdir(parents=True)
            (root / "_QUARANTINE_FABRICATED_CVE" / "rec1" / "record.yaml").write_text(
                "synthetic_fixture: true\nattack_class: reentrancy\n"
            )
            (root / "subtree_a" / "rec1").mkdir(parents=True)
            (root / "subtree_a" / "rec1" / "record.yaml").write_text(
                "synthetic_fixture: true\nattack_class: reentrancy\n"
            )
            paths = list(_MOD._iter_record_paths(root))
            subtrees = {p[1] for p in paths}
            self.assertNotIn("_QUARANTINE_FABRICATED_CVE", subtrees)
            self.assertIn("subtree_a", subtrees)


class DeriveEndToEndTests(unittest.TestCase):

    def test_end_to_end_universal_detection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for sub in ("ws_a", "ws_b", "ws_c"):
                (root / sub / "rec1").mkdir(parents=True)
                (root / sub / "rec1" / "record.yaml").write_text(
                    "synthetic_fixture: true\n"
                    f"record_id: synth:{sub}:1\n"
                    "attack_class: reentrancy-on-external-call\n"
                    f"target_repo: synthetic/{sub}\n"
                )
            (root / "ws_a" / "rec2").mkdir(parents=True)
            (root / "ws_a" / "rec2" / "record.yaml").write_text(
                "synthetic_fixture: true\n"
                "record_id: synth:ws_a:2\n"
                "attack_class: precision-loss-rounding\n"
                "target_repo: synthetic/ws_a\n"
            )
            rows, total, skipped, errors = _MOD.derive(root)
            self.assertEqual(total, 4)
            self.assertEqual(skipped, 0)
            self.assertEqual(errors, 0)
            self.assertEqual(len(rows), 2)
            universals = [r for r in rows if r.is_universal]
            self.assertEqual(len(universals), 1)
            self.assertEqual(universals[0].distinct_workspace_count, 3)

    def test_universal_by_target_repo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for i, repo in enumerate(("r1", "r2", "r3")):
                (root / "ws_a" / f"rec{i}").mkdir(parents=True)
                (root / "ws_a" / f"rec{i}" / "record.yaml").write_text(
                    "synthetic_fixture: true\n"
                    f"record_id: synth:rec{i}\n"
                    "attack_class: reentrancy-callback\n"
                    f"target_repo: synthetic/{repo}\n"
                )
            rows, _, _, _ = _MOD.derive(root)
            self.assertEqual(len(rows), 1)
            r = rows[0]
            self.assertEqual(r.distinct_workspace_count, 1)
            self.assertEqual(r.distinct_target_repo_count, 3)
            self.assertFalse(r.is_universal)
            self.assertTrue(r.is_universal_by_repo)


class FpIdAssignmentTests(unittest.TestCase):

    def test_refinement_match_on_existing(self) -> None:
        row = _MOD.FingerprintRow("missing-mutation-state-validation")
        row.add({"target_repo": "x/y"}, "ws_a")
        row.add({"target_repo": "x/z"}, "ws_b")
        row.add({"target_repo": "x/w"}, "ws_c")
        ids = _MOD.assign_fp_ids([row], _MOD.EXISTING_FP_IDS, _MOD.NEXT_FP_NUM)
        self.assertIn("FP-01", ids["missing-mutation-state-validation"])
        self.assertIn("refinement", ids["missing-mutation-state-validation"])

    def test_net_new_assignment(self) -> None:
        row = _MOD.FingerprintRow("brand-new-shape-never-seen")
        row.add({"target_repo": "x/y"}, "ws_a")
        row.add({"target_repo": "x/z"}, "ws_b")
        row.add({"target_repo": "x/w"}, "ws_c")
        ids = _MOD.assign_fp_ids([row], _MOD.EXISTING_FP_IDS, _MOD.NEXT_FP_NUM)
        self.assertEqual(ids["brand-new-shape-never-seen"], f"FP-{_MOD.NEXT_FP_NUM:02d}")


if __name__ == "__main__":
    unittest.main()
