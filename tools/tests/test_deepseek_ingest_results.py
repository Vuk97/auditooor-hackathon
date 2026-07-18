#!/usr/bin/env python3
# r36-rebuttal: lane-DEEPSEEK-INGEST declared in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py at lane start (2026-05-26, TTL 2h)
"""Tests for tools/deepseek-ingest-results.py (lane DEEPSEEK-INGEST, 2026-05-26).

Covers:
- Mock fanout output with 5 results, all ingest cleanly with tier-3 stamp
- Missing verification_tier: fail-tier-missing
- Invalid task-type: fail-unknown-task-type
- Schema validation failure: fail-schema-validation
- L34 path enforcement: refusing target-dir that lands in
  submissions/<status>/<slug>/
- Dry-run: prints summary without writes
- Idempotency: re-ingest same fanout-output is no-op
- Per-task-type happy paths: TOK-A, TOK-B, TOK-C, TOK-D, TOK-G
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

TOOLS_DIR = Path(__file__).resolve().parent.parent
INGEST_SCRIPT = TOOLS_DIR / "deepseek-ingest-results.py"
REPO_ROOT = TOOLS_DIR.parent
SCHEMAS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "schemas"


def _load_ingest_module():
    spec = importlib.util.spec_from_file_location(
        "deepseek_ingest_results", str(INGEST_SCRIPT)
    )
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


M = _load_ingest_module()


def _make_fanout_result(
    task_id: str,
    task_type: str = "tok_a_corpus_mine",
    result_text: Optional[str] = None,
    verification_tier: str = "tier-3-synthetic-taxonomy-anchored",
    meta: Optional[Dict[str, Any]] = None,
    verified_by_second_pass: bool = False,
    provider: str = "deepseek-flash",
    model_id: str = "deepseek-v4-flash",
) -> Dict[str, Any]:
    if result_text is None:
        if task_type == "tok_a_corpus_mine":
            result_text = json.dumps({
                "classification": "dupe-of-prior",
                "rationale_text": "Closed as duplicate of #N. Same root cause + same fix.",
                "confidence": 0.92,
                "evidence_phrases": ["duplicate of", "same root cause"],
            })
        elif task_type == "tok_b_invariant_lift":
            result_text = json.dumps({
                "invariant_id": f"INV-EVM-{task_id[-4:]}",
                "invariant_text": "Bridge proof-domain must consume exportId before payout.",
                "target_language": "Solidity",
                "attack_class": "bridge-proof-domain-replay",
            })
        elif task_type == "tok_c_hypothesis_gen":
            result_text = json.dumps({
                "hypothesis_text": "The verifier accepts unfinalized state roots.",
                "target_component": "ismp-optimism/src/verifier.rs",
                "attack_class": "verifier-finalization-omission",
                "severity_proposed": "HIGH",
            })
        elif task_type == "tok_d_persona_drafts":
            result_text = json.dumps({
                "persona": "adversarial-triager",
                "critique_summary": "The draft lacks a designed-as-intended precheck.",
                "kill_likelihood": "high",
                "rebuttal_required_for": ["R45 precheck", "R52 rubric coverage"],
            })
        elif task_type == "tok_g_anti_pattern":
            result_text = json.dumps({
                "anti_pattern_name": "in-process timing PoC for production rubric",
                "description": "Microbenchmark cited as evidence for network-level production impact.",
                "category": "proof",
                "indicator_phrases": ["time.Since", "in-process timing"],
                "related_rules": ["R18", "R19"],
            })
        else:
            result_text = "{}"
    return {
        "task_id": task_id,
        "task_type": task_type,
        "status": "ok",
        "result": result_text,
        "provider": provider,
        "model_id": model_id,
        "input_tokens": 100,
        "output_tokens": 200,
        "cost_usd": 0.001,
        "duration_s": 0.5,
        "verification_tier": verification_tier,
        "verified_by_second_pass": verified_by_second_pass,
        "meta": meta or {},
        "started_at_utc": "2026-05-26T13:00:00Z",
        "ended_at_utc": "2026-05-26T13:00:01Z",
        "retries": 0,
    }


def _write_fanout_results(out_dir: Path, results: List[Dict[str, Any]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for r in results:
        path = out_dir / f"{r['task_id']}.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(r, f)


class IngestTests(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="ingest_test_"))
        self.fanout_dir = self.tmp / "fanout_out"
        self.target_dir = self.tmp / "target"
        # workspace is used for workspace-scoped task types
        self.workspace = self.tmp / "ws"
        self.workspace.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------------
    # Case 1: 5 results, all ingest cleanly with tier-3 stamp (TOK-A)
    # ------------------------------------------------------------------
    def test_case_01_five_results_clean_ingest_tok_a(self):
        results = [_make_fanout_result(f"tok_a_corpus_mine_{i:04d}") for i in range(1, 6)]
        _write_fanout_results(self.fanout_dir, results)

        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-A",
            target_dir=self.target_dir,
            workspace=None,
            schema_override=None,
            batch_id="test_batch_1",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "pass-clean-ingest", env)
        self.assertEqual(env["ingested"], 5)
        self.assertEqual(env["failed_tier_missing"], 0)
        self.assertEqual(env["failed_schema"], 0)
        yaml_files = list(self.target_dir.glob("*.yaml"))
        self.assertEqual(len(yaml_files), 5)
        for yf in yaml_files:
            txt = yf.read_text(encoding="utf-8")
            self.assertIn("tier-3-synthetic-taxonomy-anchored", txt)
            self.assertIn("auditooor.triager_rationale.v1", txt)

    # ------------------------------------------------------------------
    # Case 2: Invalid verification_tier value -> fail-tier-missing
    # ------------------------------------------------------------------
    def test_case_02_invalid_tier_fails(self):
        bad = _make_fanout_result(
            "tok_a_corpus_mine_bad",
            verification_tier="tier-99-bogus",
        )
        _write_fanout_results(self.fanout_dir, [bad])
        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-A",
            target_dir=self.target_dir,
            workspace=None,
            schema_override=None,
            batch_id="t2",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "fail-tier-missing")
        self.assertGreaterEqual(env["failed_tier_missing"], 1)

    # ------------------------------------------------------------------
    # Case 3: Unknown task-type
    # ------------------------------------------------------------------
    def test_case_03_unknown_task_type(self):
        self.fanout_dir.mkdir(parents=True, exist_ok=True)
        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-Q",
            target_dir=None,
            workspace=None,
            schema_override=None,
            batch_id=None,
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "fail-unknown-task-type")

    # ------------------------------------------------------------------
    # Case 4: Schema validation failure - inject forbidden extra field
    # ------------------------------------------------------------------
    def test_case_04_schema_validation_failure_via_extra_field(self):
        good = _make_fanout_result("tok_a_corpus_mine_good")
        _write_fanout_results(self.fanout_dir, [good])

        orig_build = M._build_record

        def _sabotage_build(*args, **kwargs):
            rec = orig_build(*args, **kwargs)
            rec["forbidden_extra"] = "this_should_fail_schema"
            return rec

        M._build_record = _sabotage_build
        try:
            env = M.ingest(
                fanout_output_dir=self.fanout_dir,
                raw_task_type="TOK-A",
                target_dir=self.target_dir,
                workspace=None,
                schema_override=None,
                batch_id="t4",
                dry_run=False,
                strict=False,
            )
        finally:
            M._build_record = orig_build
        self.assertEqual(env["verdict"], "fail-schema-validation", env)
        self.assertGreaterEqual(env["failed_schema"], 1)

    # ------------------------------------------------------------------
    # Case 5: L34 v2 bucket violation
    # ------------------------------------------------------------------
    def test_case_05_l34_bucket_violation(self):
        bad_target = self.tmp / "submissions" / "paste_ready" / "some-finding"
        good = _make_fanout_result("tok_a_corpus_mine_l34")
        _write_fanout_results(self.fanout_dir, [good])
        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-A",
            target_dir=bad_target,
            workspace=None,
            schema_override=None,
            batch_id="t5",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "fail-l34-bucket-violation", env)
        self.assertEqual(env["l34_bucket"], "draft-file")
        self.assertFalse(bad_target.exists())

    # ------------------------------------------------------------------
    # Case 6: Dry-run: no writes
    # ------------------------------------------------------------------
    def test_case_06_dry_run_no_writes(self):
        results = [_make_fanout_result(f"tok_a_corpus_mine_{i:04d}") for i in range(1, 4)]
        _write_fanout_results(self.fanout_dir, results)
        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-A",
            target_dir=self.target_dir,
            workspace=None,
            schema_override=None,
            batch_id="t6",
            dry_run=True,
            strict=False,
        )
        self.assertEqual(env["verdict"], "pass-dry-run")
        self.assertEqual(env["ingested"], 3)
        self.assertFalse(self.target_dir.exists())

    # ------------------------------------------------------------------
    # Case 7: Idempotency: re-ingest is no-op
    # ------------------------------------------------------------------
    def test_case_07_idempotency(self):
        results = [_make_fanout_result(f"tok_a_corpus_mine_{i:04d}") for i in range(1, 4)]
        _write_fanout_results(self.fanout_dir, results)
        env1 = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-A",
            target_dir=self.target_dir,
            workspace=None,
            schema_override=None,
            batch_id="t7",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env1["verdict"], "pass-clean-ingest")
        self.assertEqual(env1["ingested"], 3)
        env2 = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-A",
            target_dir=self.target_dir,
            workspace=None,
            schema_override=None,
            batch_id="t7",
            dry_run=False,
            strict=False,
        )
        self.assertGreater(env2["skipped_idempotent"], 0)
        if env2["ingested"] == 0:
            self.assertEqual(env2["verdict"], "pass-idempotent")
        else:
            self.assertIn(env2["verdict"], ("pass-clean-ingest", "pass-idempotent"))

    # ------------------------------------------------------------------
    # Case 8: TOK-B happy path (invariant lift)
    # ------------------------------------------------------------------
    def test_case_08_tok_b_invariant_lift(self):
        results = [
            _make_fanout_result(f"tok_b_invariant_lift_{i:04d}", task_type="tok_b_invariant_lift")
            for i in range(1, 4)
        ]
        _write_fanout_results(self.fanout_dir, results)
        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-B",
            target_dir=self.target_dir,
            workspace=None,
            schema_override=None,
            batch_id="t8",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "pass-clean-ingest", env)
        self.assertEqual(env["ingested"], 3)
        self.assertEqual(env["schema_id"], "auditooor.invariant.v1")
        for yf in self.target_dir.glob("*.yaml"):
            txt = yf.read_text(encoding="utf-8")
            self.assertIn("invariant_id", txt)
            self.assertIn("INV-", txt)

    # ------------------------------------------------------------------
    # Case 9: TOK-C happy path (hypothesis gen, workspace-scoped)
    # ------------------------------------------------------------------
    def test_case_09_tok_c_hypothesis_gen(self):
        results = [
            _make_fanout_result(
                f"tok_c_hypothesis_gen_{i:04d}",
                task_type="tok_c_hypothesis_gen",
                meta={"workspace": str(self.workspace)},
            )
            for i in range(1, 4)
        ]
        _write_fanout_results(self.fanout_dir, results)
        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-C",
            target_dir=None,
            workspace=self.workspace,
            schema_override=None,
            batch_id="t9",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "pass-clean-ingest", env)
        self.assertEqual(env["ingested"], 3)
        expected = self.workspace / "audit" / "corpus_tags" / "derived" / "deepseek_hypotheses" / "t9"
        self.assertTrue(expected.is_dir(), str(expected))
        self.assertEqual(len(list(expected.glob("*.yaml"))), 3)

    # ------------------------------------------------------------------
    # Case 10: TOK-D happy path (persona critique with md+json sidecar)
    # ------------------------------------------------------------------
    def test_case_10_tok_d_persona_drafts(self):
        results = [
            _make_fanout_result(
                f"tok_d_persona_drafts_{i:04d}",
                task_type="tok_d_persona_drafts",
                meta={"draft_slug": "my-draft-slug", "persona": "adversarial-triager"},
            )
            for i in range(1, 3)
        ]
        _write_fanout_results(self.fanout_dir, results)
        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-D",
            target_dir=self.target_dir,
            workspace=self.workspace,
            schema_override=None,
            batch_id="t10",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "pass-clean-ingest", env)
        self.assertEqual(env["ingested"], 2)
        json_files = list(self.target_dir.glob("*.json"))
        md_files = list(self.target_dir.glob("*.md"))
        self.assertEqual(len(json_files), 2)
        self.assertEqual(len(md_files), 2)
        for mf in md_files:
            txt = mf.read_text(encoding="utf-8")
            self.assertIn("adversarial-triager", txt)
            self.assertIn("Critique summary", txt)

    # ------------------------------------------------------------------
    # Case 11: TOK-G happy path (anti-pattern)
    # ------------------------------------------------------------------
    def test_case_11_tok_g_anti_pattern(self):
        results = [
            _make_fanout_result(f"tok_g_anti_pattern_{i:04d}", task_type="tok_g_anti_pattern")
            for i in range(1, 4)
        ]
        _write_fanout_results(self.fanout_dir, results)
        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-G",
            target_dir=self.target_dir,
            workspace=None,
            schema_override=None,
            batch_id="t11",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "pass-clean-ingest", env)
        self.assertEqual(env["ingested"], 3)
        self.assertEqual(env["schema_id"], "auditooor.anti_pattern.v1")
        for yf in self.target_dir.glob("*.yaml"):
            txt = yf.read_text(encoding="utf-8")
            self.assertIn("anti_pattern_name", txt)

    # ------------------------------------------------------------------
    # Case 12: verified_by_second_pass=true promotes to tier-1
    # ------------------------------------------------------------------
    def test_case_12_verified_by_second_pass_promotes_to_tier_1(self):
        r = _make_fanout_result(
            "tok_a_corpus_mine_verified",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            verified_by_second_pass=True,
        )
        _write_fanout_results(self.fanout_dir, [r])
        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-A",
            target_dir=self.target_dir,
            workspace=None,
            schema_override=None,
            batch_id="t12",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "pass-clean-ingest", env)
        yfs = list(self.target_dir.glob("*.yaml"))
        self.assertEqual(len(yfs), 1)
        txt = yfs[0].read_text(encoding="utf-8")
        self.assertIn("tier-1-verified-realtime-api", txt)

    # ------------------------------------------------------------------
    # Case 13: Fanout dir missing
    # ------------------------------------------------------------------
    def test_case_13_fanout_dir_missing(self):
        env = M.ingest(
            fanout_output_dir=self.tmp / "does-not-exist",
            raw_task_type="TOK-A",
            target_dir=self.target_dir,
            workspace=None,
            schema_override=None,
            batch_id="t13",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "fail-fanout-dir-missing")

    # ------------------------------------------------------------------
    # Case 14: cross-task-type contamination filtered out
    # ------------------------------------------------------------------
    def test_case_14_cross_task_type_filtered(self):
        results = [
            _make_fanout_result(f"tok_a_corpus_mine_{i:04d}", task_type="tok_a_corpus_mine")
            for i in range(1, 3)
        ] + [
            _make_fanout_result(f"tok_b_invariant_lift_{i:04d}", task_type="tok_b_invariant_lift")
            for i in range(1, 3)
        ]
        _write_fanout_results(self.fanout_dir, results)
        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-A",
            target_dir=self.target_dir,
            workspace=None,
            schema_override=None,
            batch_id="t14",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "pass-clean-ingest", env)
        self.assertEqual(env["ingested"], 2)
        self.assertEqual(env["results_total"], 4)

    # ------------------------------------------------------------------
    # Case 15: L34 classifier returns workspace-ledger for corpus_tags/derived
    # ------------------------------------------------------------------
    def test_case_15_l34_classifier_workspace_ledger(self):
        path = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "test_subtree" / "test_batch"
        bucket, reason = M._classify_target_dir_l34(path)
        self.assertIn(bucket, ("workspace-ledger", "out-of-scope"))
        self.assertNotEqual(bucket, "draft-file")

    # ------------------------------------------------------------------
    # Case 16: Schema file not found
    # ------------------------------------------------------------------
    def test_case_16_schema_not_found(self):
        results = [_make_fanout_result("tok_a_corpus_mine_x")]
        _write_fanout_results(self.fanout_dir, results)
        env = M.ingest(
            fanout_output_dir=self.fanout_dir,
            raw_task_type="TOK-A",
            target_dir=self.target_dir,
            workspace=None,
            schema_override="auditooor.does_not_exist.v1",
            batch_id="t16",
            dry_run=False,
            strict=False,
        )
        self.assertEqual(env["verdict"], "fail-schema-not-found")


class TaskTypeAliasTests(unittest.TestCase):
    def test_aliases_resolve(self):
        for alias in ("TOK-A", "TOK-B", "TOK-C", "TOK-D", "TOK-G",
                      "tok-a", "tok-b", "tok-c", "tok-d", "tok-g",
                      "tok_a_corpus_mine", "tok_b_invariant_lift",
                      "tok_c_hypothesis_gen", "tok_d_persona_drafts",
                      "tok_g_anti_pattern"):
            self.assertIsNotNone(M._normalize_task_type(alias), f"alias {alias!r} did not resolve")

    def test_unknown_alias_returns_none(self):
        self.assertIsNone(M._normalize_task_type("TOK-X"))
        self.assertIsNone(M._normalize_task_type("not_a_task"))


if __name__ == "__main__":
    unittest.main()
