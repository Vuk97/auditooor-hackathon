#!/usr/bin/env python3
"""Tests for tools/originality-before-proof-gate.py.

Coverage:
  - Strong duplicate/prior-disclosure indicators produce fail.
  - Missing prior-audit corpus is warn, not error.
  - No-hit scans produce pass.
  - Draft-based keyword extraction populates keywords.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "originality-before-proof-gate.py"
HIGH_PLUS_TOOL = REPO_ROOT / "tools" / "high-plus-submission-gate.py"


def _load_gate_module():
    spec = importlib.util.spec_from_file_location("originality_before_proof_gate", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GATE = _load_gate_module()
HIGH_PLUS = None


class FakeDedup:
    def __init__(self, result):
        self._result = result

    def grep_prior_audits(self, _workspace, _keywords):
        return self._result


class FakeVaultQuery:
    def __init__(self, payload):
        self.payload = payload

    def vault_originality_context(self, **_kwargs):
        return self.payload


class OriginalityBeforeProofGateTest(unittest.TestCase):
    def test_strong_prior_disclosure_indicator_causes_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orig-gate-fail-") as tmp:
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            with mock.patch.object(
                GATE,
                "_load_dedup",
                return_value=FakeDedup({
                    "files_scanned_count": 1,
                    "hits": [],
                }),
            ):
                with mock.patch.object(
                    GATE,
                    "_load_vault_query",
                    return_value=(FakeVaultQuery({
                        "degraded": False,
                        "hits": [
                            {
                                "source_ref": "vault://external-audits-extracts/ws/demo.md",
                                "finding_id": "M-01",
                                "status": "ACK",
                                "score": 10,
                                "matched_terms": ["affiliate", "blocked"],
                                "snippet": "affiliate blocked from recipient",
                            },
                        ],
                    }), "note"),
                ):
                    result = GATE._run(workspace, keywords=["affiliate", "blocked"])
            self.assertEqual(result["status"], "fail", result)
            self.assertEqual(result["counts"]["strong_hits"], 1)
            self.assertTrue(
                any(
                    entry["source"] == "prior_audit_extract" and entry["strength"] == "strong"
                    for entry in result["evidence"]
                )
            )

    def test_missing_corpus_warns_not_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orig-gate-missing-") as tmp:
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            with mock.patch.object(
                GATE,
                "_load_dedup",
                return_value=FakeDedup({
                    "files_scanned_count": 0,
                    "hits": [],
                }),
            ):
                with mock.patch.object(
                    GATE,
                    "_load_vault_query",
                    return_value=(FakeVaultQuery({
                        "degraded": True,
                        "reason": "section_missing",
                        "hits": [],
                    }), "note"),
                ):
                    result = GATE._run(workspace, keywords=["affiliate"])
            self.assertEqual(result["status"], "warn", result)
            self.assertTrue(any(w["code"] == "corpus_missing" for w in result["warnings"]), result)
            self.assertFalse(result["errors"])

    def test_no_hits_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orig-gate-pass-") as tmp:
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            with mock.patch.object(
                GATE,
                "_load_dedup",
                return_value=FakeDedup({
                    "files_scanned_count": 2,
                    "hits": [],
                }),
            ):
                with mock.patch.object(
                    GATE,
                    "_load_vault_query",
                    return_value=(FakeVaultQuery({
                        "degraded": False,
                        "hits": [],
                    }), None),
                ):
                    result = GATE._run(workspace, keywords=["affiliate"])
            self.assertEqual(result["status"], "pass", result)
            self.assertEqual(result["counts"]["strong_hits"], 0)
            self.assertEqual(result["counts"]["weak_hits"], 0)
            self.assertFalse(result["warnings"])
            self.assertFalse(result["errors"])

    def test_recorded_fail_blocks_high_plus_wrapper(self) -> None:
        global HIGH_PLUS
        if HIGH_PLUS is None:
            spec = importlib.util.spec_from_file_location("high_plus_submission_gate_for_originality_test", HIGH_PLUS_TOOL)
            if spec is None or spec.loader is None:
                raise RuntimeError(f"could not load {HIGH_PLUS_TOOL}")
            HIGH_PLUS = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(HIGH_PLUS)  # type: ignore[union-attr]

        with tempfile.TemporaryDirectory(prefix="orig-gate-recorded-fail-") as tmp:
            draft = Path(tmp) / "fail.md"
            draft.write_text(
                "\n".join(
                    [
                        "# Duplicate posture",
                        "",
                        "**Severity:** High",
                        "selected_impact: Direct theft of any user funds",
                        "production_reachability: production-profile lab path",
                        "",
                        "## Originality / Duplicate Review",
                        "",
                        "- Originality-before-proof: FAIL",
                        "- duplicate of prior report R-17.",
                    ]
                ),
                encoding="utf-8",
            )
            packet = GATE.build_packet(draft, severity="High")
            self.assertEqual(packet["verdict"], "fail")
            wrapped = HIGH_PLUS.evaluate(draft, severity="High", run_pre_submit=False)
            self.assertEqual(wrapped["originality_gate"]["verdict"], "fail")
            self.assertTrue(
                any(blocker["code"] == "high_plus_originality_fail_closed" for blocker in wrapped["blockers"]),
                wrapped,
            )

    def test_recorded_mixed_duplicate_override_is_warn(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orig-gate-recorded-mixed-") as tmp:
            draft = Path(tmp) / "mixed.md"
            draft.write_text(
                "\n".join(
                    [
                        "# Novel vector override",
                        "",
                        "**Severity:** Critical",
                        "",
                        "## Originality / Duplicate Review",
                        "",
                        "- duplicate-posture: dupe override / novel vector in a distinct call path.",
                        "- This is a novel vector within the same class, not a dupe of the prior fix.",
                    ]
                ),
                encoding="utf-8",
            )
            packet = GATE.build_packet(draft, severity="Critical")
            self.assertEqual(packet["verdict"], "warn")
            self.assertEqual(packet["code"], "mixed-duplicate-posture")

    def test_recorded_no_hits_is_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orig-gate-recorded-pass-") as tmp:
            draft = Path(tmp) / "pass.md"
            draft.write_text(
                "\n".join(
                    [
                        "# Clean originality",
                        "",
                        "**Severity:** High",
                        "",
                        "## Originality / Duplicate Review",
                        "",
                        "- Originality grep: zero hits across prior audit corpus.",
                        "- locally novel with no local submitted duplicate.",
                    ]
                ),
                encoding="utf-8",
            )
            packet = GATE.build_packet(draft, severity="High")
            self.assertEqual(packet["verdict"], "pass")

    def test_draft_path_extracts_keywords(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orig-gate-draft-") as tmp:
            workspace = Path(tmp) / "ws"
            (workspace / "prior_audits").mkdir(parents=True)
            (workspace / "prior_audits" / "baseline.txt").write_text(
                "This file discusses a historical storage optimisation with unrelated language.",
                encoding="utf-8",
            )
            draft = workspace / "candidate.md"
            draft.write_text(
                "# Candidate with `disputeId`\n\n"
                "Mechanism references `_fisherman` and `createIndexingDispute(...)`.",
                encoding="utf-8",
            )

            with mock.patch.object(
                GATE,
                "_load_vault_query",
                return_value=(FakeVaultQuery({
                    "degraded": False,
                    "hits": [],
                }), None),
            ):
                result = GATE._run(workspace, keywords=[], draft=draft)
            self.assertIn("disputeid", result["keywords"])
            self.assertTrue(any("fisherman" in kw for kw in result["keywords"]), result["keywords"])
            self.assertEqual(result["status"], "pass", result)

    def test_mezo_style_fingerprint_extracts_root_cause_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orig-gate-mezo-fingerprint-") as tmp:
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            draft = workspace / "candidate.md"
            draft.write_text(
                "StabilityPool.withdrawFromSP(uint256) relies on "
                "_requireNoUnderCollateralizedTroves() and sortedTroves.getLast() "
                "as if tail order were a live ICR sentinel.\n"
                "Once principal-order and interest-accrual diverge, the invariant fails "
                "and withdrawal bypasses intended controls.\n"
                "Fix: replace the sortedTroves.getLast() proxy with a live ICR health check.",
                encoding="utf-8",
            )
            with mock.patch.object(
                GATE,
                "_load_dedup",
                return_value=FakeDedup({
                    "files_scanned_count": 1,
                    "hits": [],
                }),
            ):
                with mock.patch.object(
                    GATE,
                    "_load_vault_query",
                    return_value=(FakeVaultQuery({
                        "degraded": False,
                        "hits": [],
                    }), None),
                ):
                    result = GATE._run(workspace, keywords=[], draft=draft)

            fingerprint = result["root_cause_fingerprint"]
            self.assertEqual(result["status"], "pass", result)
            self.assertIn("StabilityPool.withdrawFromSP(uint256)", fingerprint["entrypoints"])
            self.assertIn("_requireNoUnderCollateralizedTroves()", fingerprint["helpers"])
            self.assertIn("sortedTroves.getLast()", fingerprint["helpers"])
            self.assertIn("invariant", fingerprint["invariant_terms"])
            self.assertTrue(
                any("bypass" in term for term in fingerprint["impact_terms"]),
                fingerprint["impact_terms"],
            )
            self.assertIn("replace", fingerprint["fix_terms"])

    def test_realistic_rate_delta_does_not_change_status(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orig-gate-rate-delta-") as tmp:
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            draft_a = workspace / "draft-a.md"
            draft_b = workspace / "draft-b.md"
            shared = (
                "StabilityPool.withdrawFromSP(uint256) depends on "
                "_requireNoUnderCollateralizedTroves() for the same ordering invariant.\n"
                "The same withdrawal bypass follows from sortedTroves.getLast().\n"
            )
            draft_a.write_text(shared, encoding="utf-8")
            draft_b.write_text(
                shared
                + "Rate realism delta: reproduction now uses a tighter 2.5 percent accrual assumption only.\n",
                encoding="utf-8",
            )

            with mock.patch.object(
                GATE,
                "_load_dedup",
                return_value=FakeDedup({
                    "files_scanned_count": 1,
                    "hits": [],
                }),
            ):
                with mock.patch.object(
                    GATE,
                    "_load_vault_query",
                    return_value=(FakeVaultQuery({
                        "degraded": False,
                        "hits": [],
                    }), None),
                ):
                    result_a = GATE._run(workspace, keywords=[], draft=draft_a)
                    result_b = GATE._run(workspace, keywords=[], draft=draft_b)

            self.assertEqual(result_a["status"], "pass", result_a)
            self.assertEqual(result_b["status"], "pass", result_b)

    def test_generic_withdraw_admin_draft_has_no_code_like_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orig-gate-fp-generic-draft-") as tmp:
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            draft = workspace / "generic.md"
            draft.write_text(
                "Admin oversight: users discuss withdrawal and admin authority in abstract terms.\n"
                "No specific contract function, helper, or invariant callsite is identified.\n",
                encoding="utf-8",
            )
            with mock.patch.object(
                GATE,
                "_load_dedup",
                return_value=FakeDedup({
                    "files_scanned_count": 1,
                    "hits": [],
                }),
            ):
                with mock.patch.object(
                    GATE,
                    "_load_vault_query",
                    return_value=(FakeVaultQuery({
                        "degraded": False,
                        "hits": [],
                    }), None),
                ):
                    result = GATE._run(workspace, keywords=[], draft=draft)

            fingerprint = result["root_cause_fingerprint"]
            self.assertEqual(result["status"], "pass", result)
            self.assertEqual(fingerprint["entrypoints"], [])
            self.assertEqual(fingerprint["helpers"], [])

    def test_generic_withdraw_admin_keywords_have_no_code_like_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory(prefix="orig-gate-fp-generic-keywords-") as tmp:
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            with mock.patch.object(
                GATE,
                "_load_dedup",
                return_value=FakeDedup({
                    "files_scanned_count": 1,
                    "hits": [],
                }),
            ):
                with mock.patch.object(
                    GATE,
                    "_load_vault_query",
                    return_value=(FakeVaultQuery({
                        "degraded": False,
                        "hits": [],
                    }), None),
                ):
                    result = GATE._run(workspace, keywords=["withdrawal", "admin", "owner"])

            fingerprint = result["root_cause_fingerprint"]
            self.assertEqual(result["status"], "pass", result)
            self.assertEqual(fingerprint["entrypoints"], [])
            self.assertEqual(fingerprint["helpers"], [])


if __name__ == "__main__":
    unittest.main()
