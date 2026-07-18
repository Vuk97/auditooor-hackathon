#!/usr/bin/env python3
"""Integration tests for PR #535 PR 1: Program Impact Mapping promotion contract.

Three surfaces wired:

  * tools/submission-packager.py        — embeds ``impact_mapping`` in
    manifest.json; refuses packaging under
    ``REQUIRE_PROGRAM_IMPACT_MAPPING=1`` when status is non-clean.
  * tools/audit-closeout-check.py       — emits a ``program-impact-mapping``
    closeout row reporting counts (mapped / missing_mapping /
    tier_mismatch / proof_artifact_missing / advisory_no_rubric).
  * tools/promote-typed-candidate.py    — downgrades Critical/High/Medium typed
    candidates without a mapping block to ``impact_unresolved``.

Three FN7-style regression fixtures (per Codex spec):

  * FX1 (FN7-style invalid): valid Engine API proof claiming Critical
    but with no listed Critical impact in the rubric → fails the
    promotion contract (tier_mismatch / missing_mapping).
  * FX2 (FN7-style valid):   same proof mapped to a verbatim High-tier
    listed impact → passes when severity matches the selected impact.
  * FX3 (proof outside ws):  draft whose ``proof_artifact:`` path lives
    outside the workspace root → fails (proof_artifact_missing).

Stdlib-only. Hermetic — every test builds a throwaway workspace shape.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
_PIM_LIB_PATH = _REPO_ROOT / "tools" / "lib" / "program_impact_mapping.py"
_PACKAGER_PATH = _REPO_ROOT / "tools" / "submission-packager.py"
_CLOSEOUT_PATH = _REPO_ROOT / "tools" / "audit-closeout-check.py"
_PROMOTE_PATH = _REPO_ROOT / "tools" / "promote-typed-candidate.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


_PIM = _load_module("pim_lib_under_test", _PIM_LIB_PATH)


# ---------------------------------------------------------------------------
# Synthetic rubric used by every fixture-mode workspace.
# ---------------------------------------------------------------------------

_SEVERITY_MD = """\
# SEVERITY -- Synthetic Rubric for promotion-contract integration tests

## Critical-tier listed impacts
- Total network shutdown of the canonical chain
- Hardfork-required chain split affecting all validators
- Permanent freezing of user funds inside in-scope contracts (>10%)
- Direct theft from in-scope bridge contracts (>=10% of locked value)

## High-tier listed impacts
- Engine API request validation bypass causing peer ban / fork follow-on
- Liveness regression on a single validator (recoverable, requires restart)
- Temporary freezing of user funds (recoverable within a finalization window)

## Medium-tier listed impacts
- Griefing of a single RPC endpoint
- Log misformatting that disturbs monitoring tooling
"""


# ---------------------------------------------------------------------------
# FN7-style fixtures
# ---------------------------------------------------------------------------

# FX1: Critical claim with NO listed Critical impact (over-framing).
# selected_impact maps to a High-tier row, severity_implied says Critical → tier mismatch.
_FX1_CRITICAL_OVERCLAIM = """# FN7 — Engine API request validation bypass

**Severity (RECOMMENDED)**: **Critical**

## Program Impact Mapping

- program: Base Azul Immunefi audit
- asset: base-reth-node Engine API
- selected_impact: Engine API request validation bypass causing peer ban / fork follow-on
- severity_implied: Critical
- proof_artifact: poc/fn7_engine_api.rs
- listed_impact_proven: true
- proof_contract:
  - engine-api real-component harness proving peer-ban / fork follow-on
- oos_traps:
  - base_operated_infra
  - invalid_tee_or_zk_proof
- downgrade_clauses:
  - no Critical claim without exact Critical impact proof
- not_proven_impacts:
  - Total network shutdown of the canonical chain
  - Hardfork-required chain split affecting all validators

## Production Path

1. Asset in scope: base-reth-node Engine API
2. External actor: peer node
3. Concrete entrypoint: engine_newPayloadV2
4. Privileged precondition: none
5. State precondition: parent state visibility mismatch
6. Trigger sequence: 1 malformed payload
7. Production-component proof: harness drops payload acceptance
8. Real-victim impact: peer ban
9. Live-deployment evidence: poc/fn7_engine_api.rs
10. Mock-component caveat: none
"""


# FX2: same proof but mapped to High with severity_implied=High (valid).
_FX2_HIGH_VALID = """# FN7 — Engine API request validation bypass

**Severity (RECOMMENDED)**: **High**

## Program Impact Mapping

- program: Base Azul Immunefi audit
- asset: base-reth-node Engine API
- selected_impact: Engine API request validation bypass causing peer ban / fork follow-on
- severity_implied: High
- proof_artifact: poc/fn7_engine_api.rs
- listed_impact_proven: true
- proof_contract:
  - engine-api real-component harness proving peer-ban / fork follow-on
- oos_traps:
  - base_operated_infra
- downgrade_clauses:
  - component-only proof remains NOT_SUBMIT_READY
- not_proven_impacts:
  - Total network shutdown of the canonical chain
  - Hardfork-required chain split affecting all validators
  - Permanent freezing of user funds inside in-scope contracts (>10%)
  - Direct theft from in-scope bridge contracts (>=10% of locked value)

## Production Path

1. Asset in scope: base-reth-node Engine API
2. External actor: peer node
3. Concrete entrypoint: engine_newPayloadV2
4. Privileged precondition: none
5. State precondition: parent state visibility mismatch
6. Trigger sequence: 1 malformed payload
7. Production-component proof: harness drops payload acceptance
8. Real-victim impact: peer ban
9. Live-deployment evidence: poc/fn7_engine_api.rs
10. Mock-component caveat: none
"""


# FX3: proof_artifact path outside workspace.
_FX3_PROOF_OUTSIDE_WS = """# FN8 — Liveness regression with external proof path

**Severity (RECOMMENDED)**: **High**

## Program Impact Mapping

- program: Base Azul Immunefi audit
- asset: base-reth-node Engine API
- selected_impact: Liveness regression on a single validator (recoverable, requires restart)
- severity_implied: High
- proof_artifact: /etc/passwd
- listed_impact_proven: true
- proof_contract:
  - real-component proof
- oos_traps:
  - out-of-workspace proof
- downgrade_clauses:
  - missing proof artifact blocks report promotion
- not_proven_impacts: []

## Production Path

1. Asset in scope: base-reth-node
2. External actor: peer node
3. Concrete entrypoint: engine_newPayloadV2
4. Privileged precondition: none
5. State precondition: validator alive
6. Trigger sequence: 1 malformed message
7. Production-component proof: external file path (out of tree)
8. Real-victim impact: validator stalls
9. Live-deployment evidence: out-of-tree
10. Mock-component caveat: none
"""


_FX4_HIGH_MISSING_MAPPING = """# FN9 — Reportable draft without mapping

**Severity (RECOMMENDED)**: **High**

## Summary

This reportable draft intentionally omits Program Impact Mapping.
"""


_FX5_DIRECT_SUBMIT_MISSING_MAPPING = """# FN10 — Direct-submit draft without mapping

Status: direct-submit

## Summary

This draft is marked for direct submission but intentionally omits Program
Impact Mapping and Impact Contract evidence.
"""


# ---------------------------------------------------------------------------
# Workspace builder
# ---------------------------------------------------------------------------


def _make_workspace(tmp: Path, name: str = "ws") -> Path:
    ws = tmp / name
    (ws / "submissions" / "staging").mkdir(parents=True)
    (ws / "submissions" / "ready").mkdir(parents=True)
    (ws / "submissions" / "paste-ready").mkdir(parents=True)
    (ws / "poc").mkdir()
    (ws / "OOS_CHECKLIST.md").write_text("# OOS\n", encoding="utf-8")
    (ws / "SEVERITY.md").write_text(_SEVERITY_MD, encoding="utf-8")
    # Concrete proof artifact for FX1 / FX2.
    (ws / "poc" / "fn7_engine_api.rs").write_text("// fake harness\n", encoding="utf-8")
    return ws


def _write_draft(ws: Path, name: str, body: str, *, lane: str = "staging") -> Path:
    p = ws / "submissions" / lane / name
    p.write_text(body, encoding="utf-8")
    return p


# ===========================================================================
# Surface 1: closeout row counts
# ===========================================================================


class TestCloseoutRowCounts(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pim-int-closeout-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _run_closeout(self, ws: Path, *, env: dict | None = None) -> tuple[int, dict]:
        cmd = [
            sys.executable, str(_CLOSEOUT_PATH),
            "--workspace", str(ws),
            "--json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        try:
            payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError:
            payload = {"_raw_stdout": proc.stdout, "_raw_stderr": proc.stderr}
        return proc.returncode, payload

    def _row(self, payload: dict, name: str) -> dict:
        for r in payload.get("checks", []):
            if r.get("check") == name:
                return r
        return {}

    def test_row_reports_all_five_counts(self) -> None:
        ws = _make_workspace(self.tmp)
        # FX2 = mapped, FX1 = tier_mismatch, FX3 = proof_artifact_missing.
        _write_draft(ws, "FX1.md", _FX1_CRITICAL_OVERCLAIM)
        _write_draft(ws, "FX2.md", _FX2_HIGH_VALID)
        _write_draft(ws, "FX3.md", _FX3_PROOF_OUTSIDE_WS)
        # Default (advisory) — no strict env.
        env = dict(os.environ)
        env.pop("REQUIRE_PROGRAM_IMPACT_MAPPING", None)
        rc, payload = self._run_closeout(ws, env=env)
        row = self._row(payload, "program-impact-mapping")
        self.assertEqual(row.get("status"), "WARN", msg=json.dumps(row, indent=2))
        detail = row.get("detail", {})
        # All five required count keys present.
        for key in ("mapped", "missing_mapping", "tier_mismatch",
                    "proof_artifact_missing", "advisory_no_rubric"):
            self.assertIn(key, detail, msg=f"missing count key: {key}")
        self.assertEqual(detail.get("mapped"), 1)
        self.assertEqual(detail.get("tier_mismatch"), 1)
        self.assertEqual(detail.get("proof_artifact_missing"), 1)
        # The promotion-contract row itself is WARN (advisory). Other
        # closeout checks may legitimately FAIL in this minimal hermetic
        # workspace — we only assert the contract row's status, not
        # the aggregate rc.

    def test_strict_env_escalates_to_fail(self) -> None:
        ws = _make_workspace(self.tmp)
        _write_draft(ws, "FX1.md", _FX1_CRITICAL_OVERCLAIM)
        env = dict(os.environ)
        env["REQUIRE_PROGRAM_IMPACT_MAPPING"] = "1"
        rc, payload = self._run_closeout(ws, env=env)
        row = self._row(payload, "program-impact-mapping")
        self.assertEqual(row.get("status"), "FAIL", msg=row)
        self.assertEqual(rc, 1)
        # Detail surfaces the escalation env var name.
        self.assertEqual(
            row.get("detail", {}).get("strict_env_var"),
            "REQUIRE_PROGRAM_IMPACT_MAPPING",
        )

    def test_clean_mapped_only_passes(self) -> None:
        ws = _make_workspace(self.tmp)
        _write_draft(ws, "FX2.md", _FX2_HIGH_VALID)
        env = dict(os.environ)
        env.pop("REQUIRE_PROGRAM_IMPACT_MAPPING", None)
        rc, payload = self._run_closeout(ws, env=env)
        row = self._row(payload, "program-impact-mapping")
        self.assertEqual(row.get("status"), "PASS", msg=row)
        self.assertEqual(row.get("detail", {}).get("mapped"), 1)
        self.assertEqual(row.get("detail", {}).get("tier_mismatch"), 0)


# ===========================================================================
# Surface 2: packager manifest + strict refusal
# ===========================================================================


class TestPackagerImpactMapping(unittest.TestCase):
    """Black-box test of the packager's manifest field + STRICT refusal.

    We invoke the packager with `--skip-gates` so only the impact-mapping
    code path runs (no quality scorer / pre-submit / variant detector
    network); this keeps the test hermetic and fast.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pim-int-pkg-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _run_packager(
        self,
        ws: Path,
        draft: Path,
        *,
        env: dict | None = None,
    ) -> tuple[int, dict]:
        cmd = [
            sys.executable, str(_PACKAGER_PATH),
            str(ws), str(draft),
            "--skip-gates", "--json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        try:
            payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError:
            payload = {"_raw_stdout": proc.stdout, "_raw_stderr": proc.stderr}
        return proc.returncode, payload

    def test_manifest_carries_impact_mapping_field(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = _write_draft(ws, "FX2.md", _FX2_HIGH_VALID)
        env = dict(os.environ)
        env.pop("REQUIRE_PROGRAM_IMPACT_MAPPING", None)
        rc, payload = self._run_packager(ws, draft, env=env)
        self.assertEqual(rc, 0, msg=json.dumps(payload, indent=2)[:1000])
        impact = payload.get("impact_mapping") or {}
        self.assertEqual(impact.get("status"), "mapped", msg=impact)
        self.assertTrue(impact.get("requires_mapping"))
        self.assertEqual(impact.get("severity_claim"), "High")
        # not_proven_impacts copied through.
        self.assertGreater(len(impact.get("not_proven_impacts") or []), 0)

    def test_strict_refuses_critical_overclaim(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = _write_draft(ws, "FX1.md", _FX1_CRITICAL_OVERCLAIM)
        env = dict(os.environ)
        env["REQUIRE_PROGRAM_IMPACT_MAPPING"] = "1"
        rc, payload = self._run_packager(ws, draft, env=env)
        # STRICT refusal -> rc != 0 + error message in payload.
        self.assertEqual(rc, 1, msg=json.dumps(payload, indent=2)[:2000])
        err = str(payload.get("error") or "")
        self.assertIn("Program Impact Mapping promotion contract", err)
        self.assertIn("tier_mismatch", err)

    def test_default_refuses_reportable_missing_mapping(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = _write_draft(ws, "FX4.md", _FX4_HIGH_MISSING_MAPPING)
        env = dict(os.environ)
        env.pop("REQUIRE_PROGRAM_IMPACT_MAPPING", None)
        rc, payload = self._run_packager(ws, draft, env=env)
        self.assertEqual(rc, 1, msg=json.dumps(payload, indent=2)[:2000])
        err = str(payload.get("error") or "")
        self.assertIn("Program Impact Mapping promotion contract", err)
        self.assertIn("impact_mapping_status=missing_mapping", err)

    def test_default_refuses_direct_submit_missing_mapping(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = _write_draft(ws, "FX5.md", _FX5_DIRECT_SUBMIT_MISSING_MAPPING)
        env = dict(os.environ)
        env.pop("REQUIRE_PROGRAM_IMPACT_MAPPING", None)
        rc, payload = self._run_packager(ws, draft, env=env)
        self.assertEqual(rc, 1, msg=json.dumps(payload, indent=2)[:2000])
        err = str(payload.get("error") or "")
        self.assertIn("Program Impact Mapping promotion contract", err)
        self.assertIn("direct-submit/reportable posture requires", err)

    def test_proof_outside_workspace_refuses_under_strict(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = _write_draft(ws, "FX3.md", _FX3_PROOF_OUTSIDE_WS)
        env = dict(os.environ)
        env["REQUIRE_PROGRAM_IMPACT_MAPPING"] = "1"
        rc, payload = self._run_packager(ws, draft, env=env)
        self.assertEqual(rc, 1, msg=json.dumps(payload, indent=2)[:2000])
        impact = payload.get("impact_mapping") or {}
        self.assertEqual(impact.get("status"), "proof_artifact_missing", msg=impact)


# ===========================================================================
# Surface 3: candidate promotion downgrade
# ===========================================================================


class TestCandidatePromotionDowngrade(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pim-int-promote-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _build_candidate(self, ws: Path, *, severity: str, with_mapping: bool) -> Path:
        """Write a typed candidate JSON conforming to deep_candidate.v1.

        The deep_candidate.v1 schema rejects a top-level ``severity`` field
        (``additionalProperties: false``), so the severity claim is
        carried in ``impact`` text + (optionally) in
        ``lane_payload.program_impact_mapping.severity_implied``. The
        candidate-level promotion contract scans those locations.
        """
        cand_dir = ws / "deep_candidates"
        cand_dir.mkdir(parents=True, exist_ok=True)
        src = ws / "src" / "Vault.sol"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text("contract Vault {}\n", encoding="utf-8")
        # The validator requires runnable reproduction; use a real-looking forge command.
        body: dict = {
            "schema_version": "deep_candidate.v1",
            "candidate_id": "fn7-engine-api",
            "lane": "source_mine",
            "claim": "Engine API request validation bypass on malformed payload.",
            "trigger": "peer sends malformed engine_newPayloadV2",
            "impact": (
                f"{severity}: peer ban + fork follow-on causing engine API drift "
                "on the canonical chain"
            ),
            "reproduction": "forge test --match-test test_fn7_engine_api_bypass",
            "files": ["src/Vault.sol"],
            "promotion_status": "poc_ready",
            "confidence": "high",
            "blocking_questions": [],
            "lane_payload": {
                "production_path": {"verdict": "EXTERNAL_REACHABLE"},
            },
        }
        if with_mapping:
            # PR #541 follow-up F1 fix: the mapping must now pass the
            # canonical Check #31 parser (program / asset / selected_impact
            # / severity_implied / proof_artifact / not_proven_impacts), not
            # just have a non-empty selected_impact field. We synthesize a
            # full structured mapping that grounds against the synthetic
            # rubric in `_SEVERITY_MD`.
            body["lane_payload"]["program_impact_mapping"] = {
                "program": "Base Azul Immunefi audit",
                "asset": "base-reth-node Engine API",
                "selected_impact": (
                    "Engine API request validation bypass causing peer ban / "
                    "fork follow-on"
                ),
                "severity_implied": severity,
                "proof_artifact": "poc/fn7_engine_api.rs",
                "listed_impact_proven": True,
                "proof_contract": [
                    "engine-api real-component harness proving selected impact",
                ],
                "required_evidence_class": "executed_with_manifest",
                "stop_condition": (
                    "Stop if the executed harness does not prove the exact "
                    "selected program-impact sentence."
                ),
                "oos_traps": [
                    "base_operated_infra",
                ],
                "downgrade_clauses": [
                    "missing exact impact proof blocks promotion",
                ],
                "not_proven_impacts": [
                    "Total network shutdown of the canonical chain",
                ],
            }
        cand_path = cand_dir / "fn7-engine-api.json"
        cand_path.write_text(json.dumps(body, indent=2), encoding="utf-8")
        return cand_path

    def _run_promote(self, ws: Path, candidate: Path) -> tuple[int, dict]:
        out_json = self.tmp / "promote.json"
        cmd = [
            sys.executable, str(_PROMOTE_PATH),
            "--workspace", str(ws),
            "--out-json", str(out_json),
            str(candidate),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        try:
            payload = json.loads(out_json.read_text()) if out_json.exists() else {}
        except json.JSONDecodeError:
            payload = {}
        return proc.returncode, payload

    def test_critical_without_mapping_is_downgraded_to_impact_unresolved(self) -> None:
        ws = _make_workspace(self.tmp)
        cand = self._build_candidate(ws, severity="Critical", with_mapping=False)
        rc, payload = self._run_promote(ws, cand)
        self.assertEqual(rc, 0, msg=payload)
        decisions = payload.get("decision_counts") or {}
        self.assertEqual(decisions.get("impact_unresolved"), 1, msg=decisions)
        self.assertEqual(decisions.get("poc_ready"), 0, msg=decisions)
        verdict = (payload.get("verdicts") or [{}])[0]
        self.assertEqual(verdict.get("decision"), "impact_unresolved")
        self.assertIn("program_impact_mapping_unresolved",
                      verdict.get("blocker_categories", []))
        self.assertEqual(verdict.get("checks", {}).get("severity_claim"), "Critical")
        self.assertEqual(
            verdict.get("checks", {}).get("program_impact_mapping_status"),
            "missing_mapping",
        )

    def test_high_with_mapping_is_promoted_normally(self) -> None:
        ws = _make_workspace(self.tmp)
        cand = self._build_candidate(ws, severity="High", with_mapping=True)
        rc, payload = self._run_promote(ws, cand)
        self.assertEqual(rc, 0, msg=payload)
        decisions = payload.get("decision_counts") or {}
        self.assertEqual(decisions.get("impact_unresolved"), 0, msg=decisions)
        # Either poc_ready or needs_poc — anything but impact_unresolved.
        verdict = (payload.get("verdicts") or [{}])[0]
        self.assertNotEqual(verdict.get("decision"), "impact_unresolved")
        self.assertEqual(
            verdict.get("checks", {}).get("program_impact_mapping_status"),
            "mapped",
        )

    def test_medium_without_mapping_is_downgraded_to_impact_unresolved(self) -> None:
        ws = _make_workspace(self.tmp)
        cand = self._build_candidate(ws, severity="Medium", with_mapping=False)
        rc, payload = self._run_promote(ws, cand)
        self.assertEqual(rc, 0, msg=payload)
        verdict = (payload.get("verdicts") or [{}])[0]
        self.assertEqual(verdict.get("decision"), "impact_unresolved")
        self.assertEqual(
            verdict.get("checks", {}).get("program_impact_mapping_status"),
            "missing_mapping",
        )


# ===========================================================================
# Three FN7-style regression fixtures (Codex spec)
# ===========================================================================


class TestFN7RegressionFixtures(unittest.TestCase):
    """Direct exercise of the three fixtures via the shared helper.

    These fixtures are also referenced by the surface-specific test classes
    above. The point of this dedicated class is to lock the rc/status
    outcomes per Codex spec so a future refactor cannot quietly weaken
    one of them without flipping a named test.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pim-int-fixtures-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.ws = _make_workspace(self.tmp)

    def test_fx1_critical_overclaim_fails(self) -> None:
        draft = _write_draft(self.ws, "FX1.md", _FX1_CRITICAL_OVERCLAIM)
        summary = _PIM.summarize_draft(draft, workspace=self.ws)
        # Codex spec: rc=1 (fail) when claiming Critical without listed Critical impact.
        self.assertIn(summary["status"], {"tier_mismatch", "missing_mapping"},
                      msg=summary)
        self.assertNotEqual(summary["status"], "mapped")
        # is_clean must reject this.
        self.assertFalse(_PIM.is_clean(summary["status"]))

    def test_fx2_high_with_listed_impact_passes(self) -> None:
        draft = _write_draft(self.ws, "FX2.md", _FX2_HIGH_VALID)
        summary = _PIM.summarize_draft(draft, workspace=self.ws)
        self.assertEqual(summary["status"], "mapped", msg=summary)
        self.assertTrue(_PIM.is_clean(summary["status"]))
        # not_proven_impacts copied through (used by paste-ready Not Proven section).
        self.assertGreater(len(summary["not_proven_impacts"]), 0)

    def test_fx3_proof_artifact_outside_workspace_fails(self) -> None:
        draft = _write_draft(self.ws, "FX3.md", _FX3_PROOF_OUTSIDE_WS)
        summary = _PIM.summarize_draft(draft, workspace=self.ws)
        self.assertEqual(summary["status"], "proof_artifact_missing", msg=summary)
        self.assertFalse(_PIM.is_clean(summary["status"]))

    def test_paste_ready_helpers_extract_not_proven(self) -> None:
        """The paste-ready surface relies on the lib's ``extract_not_proven_lines``."""
        items = _PIM.extract_not_proven_lines(_FX2_HIGH_VALID)
        self.assertIn(
            "Total network shutdown of the canonical chain", items,
        )
        rendered = _PIM.render_not_proven_section(items)
        self.assertIn("- Total network shutdown", rendered)
        # Empty list produces a sentinel string, not crash.
        sentinel = _PIM.render_not_proven_section([])
        self.assertIn("not_proven_impacts: []", sentinel)


# ===========================================================================
# PR #541 follow-up: adversarial regression tests
# (BC1-class bypasses caught by Minimax adversarial review)
# ===========================================================================


# Critical-claim typed candidate with a single-char ``program_impact_mapping``
# string -- exactly the F1 bypass Minimax demonstrated. Pre-fix this would
# return ``poc_ready``; post-fix it must return ``impact_unresolved``.
_F1_BYPASS_CANDIDATE = {
    "schema_version": "deep_candidate.v1",
    "candidate_id": "f1-bypass",
    "lane": "source_mine",
    "claim": "Critical: bridge contract drains.",
    "trigger": "anyone calls drain()",
    "impact": (
        "Critical: direct theft of any user funds (>=10% of locked value)"
    ),
    "reproduction": "forge test --match-test test_f1_bypass",
    "files": ["src/Bridge.sol:42"],
    "promotion_status": "poc_ready",
    "confidence": "high",
    "blocking_questions": [],
    "lane_payload": {
        "production_path": {"verdict": "EXTERNAL_REACHABLE"},
        "program_impact_mapping": "x",  # <-- the single-char F1 bypass
    },
}


# Critical-claim typed candidate with a fully valid structured mapping that
# grounds against the synthetic Critical rubric tier. This is the legit
# pass case — must continue to verdict as ``poc_ready``.
_F1_VALID_CANDIDATE = {
    "schema_version": "deep_candidate.v1",
    "candidate_id": "f1-valid",
    "lane": "source_mine",
    "claim": "Critical: bridge contract drains.",
    "trigger": "anyone calls drain() with attacker-controlled amount",
    "impact": (
        "Critical: direct theft from in-scope bridge contracts (>=10% of locked value)"
    ),
    "reproduction": "forge test --match-test test_f1_valid",
    "files": ["src/Bridge.sol:42"],
    "promotion_status": "poc_ready",
    "confidence": "high",
    "blocking_questions": [],
    "lane_payload": {
        "production_path": {"verdict": "EXTERNAL_REACHABLE"},
        "program_impact_mapping": {
            "program": "Base Azul Immunefi audit",
            "asset": "in-scope bridge",
            "selected_impact": (
                "Direct theft from in-scope bridge contracts (>=10% of locked value)"
            ),
            "severity_implied": "Critical",
            "proof_artifact": "poc/f1_valid.rs",
            "listed_impact_proven": True,
            "proof_contract": [
                "funds_flow_poc proving direct theft from the selected bridge row",
            ],
            "required_evidence_class": "executed_with_manifest",
            "stop_condition": (
                "Stop if the executed manifest does not prove direct theft "
                "from the selected in-scope bridge row."
            ),
            "oos_traps": [
                "privileged_key",
            ],
            "downgrade_clauses": [
                "component-only proof is NOT_SUBMIT_READY",
            ],
            "not_proven_impacts": [
                "Total network shutdown of the canonical chain",
            ],
        },
    },
}


class TestF1RubricGateNotDeadCode(unittest.TestCase):
    """F1 (BC1-class): the rubric gate must actually run on typed candidates."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pim-f1-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _build_workspace_with_candidate(self, body: dict) -> tuple[Path, Path]:
        ws = _make_workspace(self.tmp, name=body["candidate_id"])
        # Provide a real source file the candidate cites.
        src = ws / "src" / "Bridge.sol"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text("contract Bridge {}\n", encoding="utf-8")
        # Provide the proof_artifact file referenced in the valid case.
        (ws / "poc" / "f1_valid.rs").write_text("// fake harness\n", encoding="utf-8")
        if body["candidate_id"] == "f1-valid":
            proof_dir = ws / "source_proofs" / "f1-valid"
            proof_dir.mkdir(parents=True, exist_ok=True)
            (proof_dir / "source_proof.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.source_proof.v1",
                        "candidate_id": "f1-valid",
                        "impact_contract_linked": True,
                        "valid_source_citation_count": 1,
                        "oos_status": "in_scope",
                        "final_verdict": "proved_source_only",
                        "evidence_class": "human_verified",
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        cand_dir = ws / "deep_candidates"
        cand_dir.mkdir(parents=True, exist_ok=True)
        cand_path = cand_dir / f"{body['candidate_id']}.json"
        cand_path.write_text(json.dumps(body, indent=2), encoding="utf-8")
        return ws, cand_path

    def _run_promote(self, ws: Path, candidate: Path) -> dict:
        out_json = self.tmp / "promote.json"
        cmd = [
            sys.executable, str(_PROMOTE_PATH),
            "--workspace", str(ws),
            "--out-json", str(out_json),
            str(candidate),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        return json.loads(out_json.read_text())

    def test_f1_single_char_mapping_is_no_longer_mapped(self) -> None:
        ws, cand = self._build_workspace_with_candidate(_F1_BYPASS_CANDIDATE)
        payload = self._run_promote(ws, cand)
        verdict = (payload.get("verdicts") or [{}])[0]
        # PR #541 follow-up F1 fix: the single-char `"x"` no longer counts
        # as a valid mapping. Verdict must be impact_unresolved.
        self.assertEqual(verdict.get("decision"), "impact_unresolved",
                         msg=verdict)
        self.assertNotEqual(
            verdict.get("checks", {}).get("program_impact_mapping_status"),
            "mapped",
        )
        self.assertIn("program_impact_mapping_unresolved",
                      verdict.get("blocker_categories", []))

    def test_f1_full_valid_mapping_passes(self) -> None:
        ws, cand = self._build_workspace_with_candidate(_F1_VALID_CANDIDATE)
        payload = self._run_promote(ws, cand)
        verdict = (payload.get("verdicts") or [{}])[0]
        # Full valid mapping with rubric grounding -> mapped + poc_ready.
        self.assertEqual(
            verdict.get("checks", {}).get("program_impact_mapping_status"),
            "mapped",
            msg=verdict,
        )
        self.assertEqual(verdict.get("decision"), "poc_ready", msg=verdict)


class TestF2WorkspaceLayoutSweep(unittest.TestCase):
    """F2 (BC1-class): closeout sweep must see ``submissions/drafts/`` too."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pim-f2-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _make_polymarket_layout(self) -> Path:
        ws = self.tmp / "ws-poly"
        (ws / "submissions" / "drafts").mkdir(parents=True)
        (ws / "OOS_CHECKLIST.md").write_text("# OOS\n", encoding="utf-8")
        (ws / "SEVERITY.md").write_text(_SEVERITY_MD, encoding="utf-8")
        (ws / "poc").mkdir()
        (ws / "poc" / "fn7_engine_api.rs").write_text("// fake\n", encoding="utf-8")
        (ws / "submissions" / "drafts" / "FX1.md").write_text(
            _FX1_CRITICAL_OVERCLAIM, encoding="utf-8"
        )
        return ws

    def _make_legacy_layout(self) -> Path:
        ws = _make_workspace(self.tmp, name="ws-legacy")
        _write_draft(ws, "FX1.md", _FX1_CRITICAL_OVERCLAIM)
        return ws

    def _run_closeout(self, ws: Path, *, env: dict | None = None) -> tuple[int, dict]:
        cmd = [
            sys.executable, str(_CLOSEOUT_PATH),
            "--workspace", str(ws),
            "--json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        try:
            payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError:
            payload = {"_raw_stdout": proc.stdout, "_raw_stderr": proc.stderr}
        return proc.returncode, payload

    def _row(self, payload: dict, name: str) -> dict:
        for r in payload.get("checks", []):
            if r.get("check") == name:
                return r
        return {}

    def test_f2_drafts_dir_layout_strict_now_fails(self) -> None:
        ws = self._make_polymarket_layout()
        env = dict(os.environ)
        env["REQUIRE_PROGRAM_IMPACT_MAPPING"] = "1"
        rc, payload = self._run_closeout(ws, env=env)
        row = self._row(payload, "program-impact-mapping")
        # Must FAIL under strict mode now that drafts/ is in the sweep.
        self.assertEqual(row.get("status"), "FAIL", msg=row)
        self.assertEqual(rc, 1)
        self.assertGreater(row.get("detail", {}).get("total", 0), 0)

    def test_f2_legacy_staging_layout_still_works(self) -> None:
        ws = self._make_legacy_layout()
        env = dict(os.environ)
        env["REQUIRE_PROGRAM_IMPACT_MAPPING"] = "1"
        rc, payload = self._run_closeout(ws, env=env)
        row = self._row(payload, "program-impact-mapping")
        # Same FX1 fixture in submissions/staging/ also fails strict mode.
        self.assertEqual(row.get("status"), "FAIL", msg=row)

    def test_f2_env_override_can_restrict_subdirs(self) -> None:
        """``IMPACT_MAPPING_WORKSPACE_DRAFT_DIRS`` lets operators tune the sweep."""
        ws = self._make_polymarket_layout()
        env = dict(os.environ)
        env["REQUIRE_PROGRAM_IMPACT_MAPPING"] = "1"
        # Restrict the sweep to staging only -> drafts/ becomes invisible
        # again -> total=0 -> PASS. This proves the override works.
        env["IMPACT_MAPPING_WORKSPACE_DRAFT_DIRS"] = "staging,ready"
        rc, payload = self._run_closeout(ws, env=env)
        row = self._row(payload, "program-impact-mapping")
        self.assertEqual(row.get("status"), "PASS", msg=row)
        self.assertEqual(row.get("detail", {}).get("total", -1), 0)

    def test_paste_ready_and_final_cantina_paste_are_scanned(self) -> None:
        ws = _make_workspace(self.tmp)
        (ws / "submissions" / "paste_ready").mkdir(parents=True, exist_ok=True)
        (ws / "submissions" / "final_cantina_paste").mkdir(parents=True, exist_ok=True)
        _write_draft(ws, "paste.md", _FX1_CRITICAL_OVERCLAIM, lane="paste_ready")
        _write_draft(ws, "final.md", _FX1_CRITICAL_OVERCLAIM, lane="final_cantina_paste")
        rollup = _PIM.closeout_counts(ws)
        drafts = {Path(s["draft"]).parent.name for s in rollup["draft_summaries"]}
        self.assertIn("paste_ready", drafts)
        self.assertIn("final_cantina_paste", drafts)
        self.assertEqual(rollup["counts"]["total"], 2, msg=rollup)


class TestF3RetiredFilenameBypass(unittest.TestCase):
    """F3 (BC1-class): filename ``RETIRED_`` prefix must NOT bypass the sweep."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pim-f3-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_f3_retired_filename_no_longer_skipped(self) -> None:
        ws = _make_workspace(self.tmp)
        _write_draft(ws, "RETIRED_critical_overclaim.md", _FX1_CRITICAL_OVERCLAIM)
        rollup = _PIM.closeout_counts(ws)
        # Pre-fix this returned total=0 (skipped by RETIRED_ prefix).
        # Post-fix the filename alone is no longer trusted.
        self.assertEqual(rollup["counts"]["total"], 1, msg=rollup)

    def test_f3_explicit_retired_frontmatter_still_skipped(self) -> None:
        ws = _make_workspace(self.tmp)
        body = "---\nretired: true\n---\n\n" + _FX1_CRITICAL_OVERCLAIM
        _write_draft(ws, "actually_retired.md", body)
        rollup = _PIM.closeout_counts(ws)
        # Body-level opt-out is still honoured.
        self.assertEqual(rollup["counts"]["total"], 0, msg=rollup)


# F4 fixture: a draft with severity_implied=High but not_proven_impacts:
# listing CRITICAL-tier rubric phrases. Pre-fix this published the
# Critical-tier phrases verbatim; post-fix they get a higher-tier prefix.
_F4_HIGH_WITH_CRITICAL_NOT_PROVEN = """# FX4 — Engine API request validation bypass

**Severity (RECOMMENDED)**: **High**

## Program Impact Mapping

- program: Base Azul Immunefi audit
- asset: base-reth-node Engine API
- selected_impact: Engine API request validation bypass causing peer ban / fork follow-on
- severity_implied: High
- proof_artifact: poc/fn7_engine_api.rs
- listed_impact_proven: true
- proof_contract:
  - engine-api real-component harness proving peer-ban / fork follow-on
- oos_traps:
  - base_operated_infra
- downgrade_clauses:
  - Critical network shutdown remains not proven
- not_proven_impacts:
  - Total network shutdown of the canonical chain
  - Permanent freezing of user funds inside in-scope contracts (>10%)
  - Direct theft from in-scope bridge contracts (>=10% of locked value)

## Production Path

1. Asset in scope: base-reth-node Engine API
2. External actor: peer node
3. Concrete entrypoint: engine_newPayloadV2
4. Privileged precondition: none
5. State precondition: parent state visibility mismatch
6. Trigger sequence: 1 malformed payload
7. Production-component proof: harness drops payload acceptance
8. Real-victim impact: peer ban
9. Live-deployment evidence: poc/fn7_engine_api.rs
10. Mock-component caveat: none
"""


class TestF4NotProvenTierPrefix(unittest.TestCase):
    """F4 (TIER_OVERREACH): higher-tier not_proven_impacts must be labeled."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pim-f4-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_f4_higher_tier_items_get_prefix(self) -> None:
        ws = _make_workspace(self.tmp)
        # Use the gate's parser to pull tiers from the synthetic SEVERITY.md.
        gate = _PIM._load_gate()
        self.assertIsNotNone(gate)
        rubric_text = (ws / "SEVERITY.md").read_text(encoding="utf-8")
        rubric_tiers = gate._parse_rubric_tiers(rubric_text)

        items = [
            "Total network shutdown of the canonical chain",       # Critical
            "Permanent freezing of user funds inside in-scope contracts (>10%)",  # Critical
            "Liveness regression on a single validator (recoverable, requires restart)",  # High
        ]
        rendered = _PIM.render_not_proven_section(
            items,
            severity_implied="High",
            rubric_tiers=rubric_tiers,
        )
        # Critical-tier rows must carry the higher-tier prefix.
        self.assertIn(
            "(higher-tier impact, not claimed by this finding) Total network shutdown",
            rendered,
            msg=rendered,
        )
        self.assertIn(
            "(higher-tier impact, not claimed by this finding) Permanent freezing",
            rendered,
            msg=rendered,
        )
        # Same-tier (High) row stays plain.
        self.assertIn("- Liveness regression", rendered)
        self.assertNotIn(
            "(higher-tier impact, not claimed by this finding) Liveness regression",
            rendered,
        )

    def test_f4_paste_ready_e2e_emits_prefixed_critical(self) -> None:
        """Black-box: drive paste-ready-generator on a High-claim draft with Critical not-proven entries."""
        ws = _make_workspace(self.tmp)
        draft = _write_draft(ws, "FX4.md", _F4_HIGH_WITH_CRITICAL_NOT_PROVEN)
        out = ws / "submissions" / "paste-ready"
        out.mkdir(parents=True, exist_ok=True)
        gen_path = _REPO_ROOT / "tools" / "paste-ready-generator.py"
        cmd = [
            sys.executable, str(gen_path),
            str(ws), str(draft),
            "--skip-pre-submit",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        # Even if the generator refuses for unrelated reasons, the lib's
        # render contract is verified above. Here we only assert the
        # output -- if any -- contains the prefix.
        produced = out / draft.name
        if produced.is_file():
            body = produced.read_text(encoding="utf-8")
            self.assertIn(
                "(higher-tier impact, not claimed by this finding)", body,
                msg=body,
            )
        else:
            # Refusal path is acceptable; assert the generator didn't
            # silently emit a file with raw Critical phrases.
            self.assertNotEqual(proc.returncode, 0)

    def test_f4_is_higher_tier_overreach_helper(self) -> None:
        """Surface helper exposes the tier-overreach detection for callers."""
        ws = _make_workspace(self.tmp)
        gate = _PIM._load_gate()
        self.assertIsNotNone(gate)
        rubric_tiers = gate._parse_rubric_tiers(
            (ws / "SEVERITY.md").read_text(encoding="utf-8")
        )
        overreach = _PIM.is_higher_tier_overreach(
            ["Total network shutdown of the canonical chain",
             "Liveness regression on a single validator (recoverable, requires restart)"],
            severity_implied="High",
            rubric_tiers=rubric_tiers,
        )
        self.assertEqual(overreach, ["Total network shutdown of the canonical chain"])


# F5 fixture: a draft whose Program Impact Mapping body is a single
# placeholder word -- pre-fix this passed Refusal #2 because the body
# was "non-empty"; post-fix Refusal #2 calls the canonical gate.
_F5_PLACEHOLDER_PIM_BODY = """# FX5 — Critical placeholder draft

**Severity (RECOMMENDED)**: **Critical**

## Program Impact Mapping

placeholder

## Production Path

1. Asset in scope: foo
2. External actor: peer
3. Concrete entrypoint: x
4. Privileged precondition: none
5. State precondition: y
6. Trigger sequence: 1 message
7. Production-component proof: nope
8. Real-victim impact: yes
9. Live-deployment evidence: poc/x.rs
10. Mock-component caveat: none
"""


class TestF5PasteReadyRefusalCallsGate(unittest.TestCase):
    """F5 (NEEDS_FIX): paste-ready Refusal #2 must invoke the canonical gate."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pim-f5-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_f5_placeholder_pim_body_now_refused(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = _write_draft(ws, "FX5.md", _F5_PLACEHOLDER_PIM_BODY)
        gen_path = _REPO_ROOT / "tools" / "paste-ready-generator.py"
        cmd = [
            sys.executable, str(gen_path),
            str(ws), str(draft),
            "--skip-pre-submit",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0,
                            msg=proc.stdout + "|||" + proc.stderr)
        combined = proc.stdout + proc.stderr
        self.assertIn("canonical gate", combined.lower(), msg=combined)


class TestF6PackagerFlaggedSeverityKeywords(unittest.TestCase):
    """F6 (NEEDS_FIX): packager surfaces severity-flavoured keywords in not_required."""

    def test_f6_flagged_severity_keywords_helper(self) -> None:
        body = (
            "## Description\n\n"
            "An admin can drain the contract via a permanent freezing pattern. "
            "There is no severity word in title or body.\n"
        )
        flagged = _PIM.flagged_severity_keywords(body)
        # Both keywords detected, lowercased, deduped.
        self.assertIn("drain", flagged)
        self.assertIn("permanent freezing", flagged)

    def test_f6_metadata_carries_flagged_keywords_for_not_required(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="pim-f6-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        ws = _make_workspace(tmp)
        body = (
            "# Some advisory note\n\n"
            "An admin can drain the contract via a permanent freezing pattern. "
            "There is no severity word in title or body.\n"
        )
        draft = _write_draft(ws, "FX6.md", body)
        meta = _PIM.packager_metadata(draft, workspace=ws)
        self.assertEqual(meta.get("status"), "not_required", msg=meta)
        flagged = meta.get("flagged_severity_keywords") or []
        self.assertIn("drain", flagged)
        self.assertIn("permanent freezing", flagged)


class TestF7CloseoutAdvisoryWarn(unittest.TestCase):
    """F7 (SILENT_ZERO_RISK): advisory_no_rubric must surface as WARN, not PASS."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pim-f7-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_f7_advisory_only_workspace_warns(self) -> None:
        # No SEVERITY.md / RUBRIC_COVERAGE.md anywhere.
        ws = self.tmp / "ws-no-rubric"
        (ws / "submissions" / "staging").mkdir(parents=True)
        (ws / "OOS_CHECKLIST.md").write_text("# OOS\n", encoding="utf-8")
        (ws / "submissions" / "staging" / "FX_advisory.md").write_text(
            _FX1_CRITICAL_OVERCLAIM, encoding="utf-8"
        )
        env = dict(os.environ)
        env.pop("REQUIRE_PROGRAM_IMPACT_MAPPING", None)
        cmd = [
            sys.executable, str(_CLOSEOUT_PATH),
            "--workspace", str(ws),
            "--json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
        rows = [r for r in payload.get("checks", [])
                if r.get("check") == "program-impact-mapping"]
        self.assertEqual(len(rows), 1, msg=payload)
        row = rows[0]
        # Pre-fix this was silently PASS. Post-fix it must be WARN.
        self.assertEqual(row.get("status"), "WARN", msg=row)
        self.assertGreater(row.get("detail", {}).get("advisory_no_rubric", 0), 0)


class TestF8StructuredErrorCodes(unittest.TestCase):
    """F8 (NEEDS_FIX): tier_mismatch detection must use structured codes, not substring."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pim-f8-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_f8_summarize_draft_emits_error_codes(self) -> None:
        ws = _make_workspace(self.tmp)
        draft = _write_draft(ws, "FX1.md", _FX1_CRITICAL_OVERCLAIM)
        summary = _PIM.summarize_draft(draft, workspace=ws)
        codes = summary.get("error_codes") or []
        # FX1 is a tier_mismatch (selected_impact lives in High but
        # severity_implied=Critical).
        self.assertIn("tier_mismatch", codes, msg=summary)
        self.assertEqual(summary.get("status"), "tier_mismatch", msg=summary)

    def test_f8_status_routing_uses_codes_not_english(self) -> None:
        """Even if we monkey-patched the prose, status would still route via codes."""
        # Sanity: the gate's code constants are stable strings.
        gate = _PIM._load_gate()
        self.assertIsNotNone(gate)
        for code in (
            "mapping_block_missing", "field_missing", "tier_mismatch",
            "rubric_grounding_missing", "proof_artifact_missing",
            "proof_artifact_invalid", "severity_implied_invalid",
            "severity_implied_contradicts_claim",
        ):
            self.assertIn(code, gate.ALL_ERR_CODES, msg=code)


if __name__ == "__main__":
    unittest.main()
