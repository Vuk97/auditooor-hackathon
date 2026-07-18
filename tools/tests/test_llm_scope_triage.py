#!/usr/bin/env python3
"""Tests for tools/llm-scope-triage.py — dual-LLM OOS triage pipeline.

Hermetic: no live API, no calibration-ledger writes against the real
JSONL file. Every test that exercises the pipeline patches
``subprocess.run`` to inject neutral, synthesised LLM responses. Test
fixtures are NEUTRAL (no leaked PR comment text, no real-finding
draft contents) so artefact replay is safe.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch, MagicMock

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "llm-scope-triage.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("llm_scope_triage", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class EngagementKeyTest(unittest.TestCase):
    """engagement_key produces stable, short, uppercase shortcodes."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_single_token_falls_back_to_first_two(self) -> None:
        self.assertEqual(self.mod.engagement_key("polymarket"), "PO")
        self.assertEqual(self.mod.engagement_key("morpho"), "MO")

    def test_hyphenated_token_takes_initials(self) -> None:
        self.assertEqual(self.mod.engagement_key("centrifuge-v3"), "CV")
        self.assertEqual(self.mod.engagement_key("kiln-v1"), "KV")

    def test_empty_falls_back_to_X(self) -> None:
        self.assertEqual(self.mod.engagement_key(""), "X")

    def test_stable_for_same_input(self) -> None:
        a = self.mod.engagement_key("snowbridge")
        b = self.mod.engagement_key("snowbridge")
        self.assertEqual(a, b)


class PromptBuildTest(unittest.TestCase):
    """build_prompt is deterministic so prompt_hash is a usable dedupe key."""

    def setUp(self) -> None:
        self.mod = _load_module()
        self.kwargs = dict(
            engagement="neutral-eng",
            draft_path="/tmp/neutral-finding.md",
            draft_text="title\n\nbody body body.",
            oos_text="- OOS-1: bullet one\n- OOS-2: bullet two",
            caps_text="(no caps)",
        )

    def test_prompt_is_byte_stable(self) -> None:
        a = self.mod.build_prompt(**self.kwargs)
        b = self.mod.build_prompt(**self.kwargs)
        self.assertEqual(a, b)

    def test_prompt_includes_engagement_and_key_and_oos(self) -> None:
        out = self.mod.build_prompt(**self.kwargs)
        self.assertIn("Engagement: neutral-eng", out)
        self.assertIn("Engagement key:", out)
        self.assertIn("OOS-1: bullet one", out)
        self.assertIn("/tmp/neutral-finding.md", out)


class VerdictParserTest(unittest.TestCase):
    """parse_triage_verdict handles IN_SCOPE, OOS_*_N, and partial input."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_parse_in_scope_high(self) -> None:
        text = (
            "SCOPE: IN_SCOPE\n"
            "SEVERITY: Medium\n"
            "CONFIDENCE: HIGH\n"
            "RATIONALE: novel vector, not in any OOS bullet."
        )
        v = self.mod.parse_triage_verdict(text)
        self.assertEqual(v["scope"], "IN_SCOPE")
        self.assertEqual(v["severity"], "Medium")
        self.assertEqual(v["confidence"], "HIGH")
        self.assertIn("novel vector", v["rationale"])

    def test_parse_oos_tag_with_underscore(self) -> None:
        text = (
            "SCOPE: OOS_PO_3\n"
            "SEVERITY: Informational\n"
            "CONFIDENCE: HIGH\n"
            "RATIONALE: matches OOS-3 prior-audit clause."
        )
        v = self.mod.parse_triage_verdict(text)
        self.assertEqual(v["scope"], "OOS_PO_3")
        self.assertTrue(self.mod.is_oos_tag(v["scope"]))

    def test_parse_oos_tag_with_hyphen_normalised(self) -> None:
        # Some models return OOS-PO-1 with hyphens; we normalise to underscores.
        text = (
            "SCOPE: OOS-PO-1\n"
            "SEVERITY: Low\n"
            "CONFIDENCE: MEDIUM\n"
            "RATIONALE: prior audit finding."
        )
        v = self.mod.parse_triage_verdict(text)
        self.assertEqual(v["scope"], "OOS_PO_1")

    def test_parse_lowercase_normalised(self) -> None:
        text = (
            "scope: in_scope\n"
            "severity: high\n"
            "confidence: medium\n"
            "rationale: ok."
        )
        v = self.mod.parse_triage_verdict(text)
        self.assertEqual(v["scope"], "IN_SCOPE")
        self.assertEqual(v["severity"], "High")
        self.assertEqual(v["confidence"], "MEDIUM")

    def test_parse_missing_fields_returns_none(self) -> None:
        text = "I am not following the schema today."
        v = self.mod.parse_triage_verdict(text)
        self.assertIsNone(v["scope"])
        self.assertIsNone(v["severity"])
        self.assertIsNone(v["confidence"])

    def test_parse_empty_returns_none(self) -> None:
        v = self.mod.parse_triage_verdict("")
        self.assertIsNone(v["scope"])


class ConsensusTest(unittest.TestCase):
    """compute_consensus reduces two parsed verdicts to a confidence label."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def _v(self, scope, severity, confidence) -> dict:
        return {"scope": scope, "severity": severity,
                "confidence": confidence, "rationale": "n/a"}

    def test_both_high_agree_full(self) -> None:
        c = self.mod.compute_consensus(
            self._v("IN_SCOPE", "Medium", "HIGH"),
            self._v("IN_SCOPE", "Medium", "HIGH"),
        )
        self.assertEqual(c["confidence"], "HIGH")
        self.assertEqual(c["scope"], "IN_SCOPE")
        self.assertEqual(c["severity"], "Medium")

    def test_scope_mismatch_disagrees(self) -> None:
        c = self.mod.compute_consensus(
            self._v("IN_SCOPE", "Medium", "HIGH"),
            self._v("OOS_PO_1", "Informational", "HIGH"),
        )
        self.assertEqual(c["confidence"], "DISAGREED")

    def test_severity_off_by_one_drops_to_medium(self) -> None:
        c = self.mod.compute_consensus(
            self._v("IN_SCOPE", "High", "HIGH"),
            self._v("IN_SCOPE", "Medium", "HIGH"),
        )
        self.assertEqual(c["confidence"], "MEDIUM")
        self.assertIsNone(c["severity"])  # tier mismatch -> not asserted

    def test_severity_two_tiers_drops_to_low(self) -> None:
        c = self.mod.compute_consensus(
            self._v("IN_SCOPE", "Critical", "HIGH"),
            self._v("IN_SCOPE", "Medium", "HIGH"),
        )
        self.assertEqual(c["confidence"], "LOW")

    def test_low_confidence_anywhere_caps_at_low(self) -> None:
        c = self.mod.compute_consensus(
            self._v("IN_SCOPE", "Medium", "HIGH"),
            self._v("IN_SCOPE", "Medium", "LOW"),
        )
        self.assertEqual(c["confidence"], "LOW")

    def test_medium_confidence_caps_at_medium(self) -> None:
        c = self.mod.compute_consensus(
            self._v("IN_SCOPE", "Medium", "MEDIUM"),
            self._v("IN_SCOPE", "Medium", "HIGH"),
        )
        self.assertEqual(c["confidence"], "MEDIUM")

    def test_missing_scope_one_side_disagrees(self) -> None:
        c = self.mod.compute_consensus(
            self._v(None, None, None),
            self._v("IN_SCOPE", "Medium", "HIGH"),
        )
        self.assertEqual(c["confidence"], "DISAGREED")


class ProviderAbstractionTest(unittest.TestCase):
    """kimi_triage / minimax_triage shell out to llm-dispatch correctly."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def _ok_proc(self, stdout: str) -> MagicMock:
        rv = MagicMock()
        rv.returncode = 0
        rv.stdout = stdout
        rv.stderr = ""
        return rv

    def _fail_proc(self, stderr: str) -> MagicMock:
        rv = MagicMock()
        rv.returncode = 3
        rv.stdout = ""
        rv.stderr = stderr
        return rv

    def test_kimi_triage_passes_provider_flag(self) -> None:
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = self._ok_proc(
                "SCOPE: IN_SCOPE\nSEVERITY: Low\nCONFIDENCE: HIGH\nRATIONALE: ok.\n"
            )
            text = self.mod.kimi_triage("prompt-body", max_tokens=50, timeout=5.0)
            self.assertIn("IN_SCOPE", text)
            args, _ = run.call_args
            cmd = args[0]
            self.assertEqual(cmd[cmd.index("--provider") + 1], "kimi")

    def test_minimax_triage_passes_provider_flag(self) -> None:
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = self._ok_proc(
                "SCOPE: OOS_MO_2\nSEVERITY: Informational\nCONFIDENCE: HIGH\nRATIONALE: oos.\n"
            )
            text = self.mod.minimax_triage("prompt-body", max_tokens=50, timeout=5.0)
            self.assertIn("OOS_MO_2", text)
            args, _ = run.call_args
            cmd = args[0]
            self.assertEqual(cmd[cmd.index("--provider") + 1], "minimax")

    def test_provider_failure_raises(self) -> None:
        with patch.object(self.mod.subprocess, "run") as run:
            run.return_value = self._fail_proc("dispatch-failed: no-api-key")
            with self.assertRaises(RuntimeError):
                self.mod.kimi_triage("prompt", max_tokens=10, timeout=2.0)

    def test_provider_env_includes_consent(self) -> None:
        env = self.mod._build_provider_env("kimi")
        self.assertEqual(env.get("AUDITOOOR_LLM_NETWORK_CONSENT"), "1")


class TriageOnePipelineTest(unittest.TestCase):
    """triage_one wires loader -> prompt -> dispatch -> parse -> consensus."""

    def setUp(self) -> None:
        self.mod = _load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.eng_dir = self.root / "neutral-eng"
        self.eng_dir.mkdir()
        (self.eng_dir / "OOS_CHECKLIST.md").write_text(
            "- OOS-1: prior audits\n- OOS-2: known centralization\n",
            encoding="utf-8",
        )
        (self.eng_dir / "SEVERITY_CAPS.md").write_text(
            "(no caps)\n", encoding="utf-8",
        )
        # Synthesised neutral draft — no real PR/finding text.
        self.draft = self.root / "neutral-draft.md"
        self.draft.write_text(
            "# Neutral finding\n\nGeneric body referencing function f().\n",
            encoding="utf-8",
        )
        self.out_dir = self.root / "artefacts"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run_with_responses(self, kimi_resp: str, minimax_resp: str):
        # We patch the high-level runner functions so we don't need to
        # mock subprocess for two providers separately.
        with patch.object(self.mod, "kimi_triage", return_value=kimi_resp), \
             patch.object(self.mod, "minimax_triage", return_value=minimax_resp):
            return self.mod.triage_one(
                self.draft,
                engagement="neutral-eng",
                engage_root=self.root,
                providers=["kimi", "minimax"],
                max_tokens=100,
                timeout=5.0,
                output_dir=self.out_dir,
                log_to_calibration=False,
            )

    def test_pipeline_agreement_writes_artefact(self) -> None:
        good = (
            "SCOPE: IN_SCOPE\nSEVERITY: Medium\nCONFIDENCE: HIGH\n"
            "RATIONALE: novel vector.\n"
        )
        rec = self._run_with_responses(good, good)
        self.assertEqual(rec["consensus"]["confidence"], "HIGH")
        self.assertEqual(rec["consensus"]["scope"], "IN_SCOPE")
        # Artefact file exists and is JSON-parseable.
        self.assertIn("artefact_path", rec)
        path = pathlib.Path(rec["artefact_path"])
        self.assertTrue(path.is_file())
        replay = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(replay["consensus"]["confidence"], "HIGH")

    def test_pipeline_disagreement_marked(self) -> None:
        kimi = (
            "SCOPE: IN_SCOPE\nSEVERITY: Medium\nCONFIDENCE: HIGH\n"
            "RATIONALE: novel.\n"
        )
        minimax = (
            "SCOPE: OOS_NE_1\nSEVERITY: Informational\nCONFIDENCE: HIGH\n"
            "RATIONALE: prior audit overlap.\n"
        )
        rec = self._run_with_responses(kimi, minimax)
        self.assertEqual(rec["consensus"]["confidence"], "DISAGREED")

    def test_missing_engagement_returns_error_record(self) -> None:
        # No engagement directory created at this name.
        rec = self.mod.triage_one(
            self.draft,
            engagement="does-not-exist",
            engage_root=self.root,
            providers=["kimi", "minimax"],
            max_tokens=10,
            timeout=2.0,
            output_dir=self.out_dir,
            log_to_calibration=False,
        )
        self.assertTrue(any("engagement-load-failed" in e for e in rec["errors"]))

    def test_prompt_hash_recorded_and_stable(self) -> None:
        good = (
            "SCOPE: IN_SCOPE\nSEVERITY: Low\nCONFIDENCE: HIGH\n"
            "RATIONALE: ok.\n"
        )
        rec1 = self._run_with_responses(good, good)
        rec2 = self._run_with_responses(good, good)
        self.assertEqual(rec1["prompt_hash"], rec2["prompt_hash"])
        self.assertEqual(len(rec1["prompt_hash"]), 64)  # sha256 hex


class CliParsingTest(unittest.TestCase):
    """Argparse rejects unknown providers and requires a target."""

    def setUp(self) -> None:
        self.mod = _load_module()

    def test_target_required(self) -> None:
        p = self.mod.build_arg_parser()
        with self.assertRaises(SystemExit):
            p.parse_args([])

    def test_unknown_provider_rejected(self) -> None:
        p = self.mod.build_arg_parser()
        with self.assertRaises(SystemExit):
            p.parse_args([
                "/tmp/x.md", "--engagement", "polymarket",
                "--providers", "openai",
            ])

    def test_single_finding_target_parses(self) -> None:
        p = self.mod.build_arg_parser()
        ns = p.parse_args([
            "/tmp/x.md", "--engagement", "polymarket",
        ])
        self.assertEqual(str(ns.finding), "/tmp/x.md")
        self.assertEqual(ns.engagement, "polymarket")
        self.assertEqual(ns.providers, ["kimi", "minimax"])


if __name__ == "__main__":
    unittest.main()
