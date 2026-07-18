# <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
"""Tests for tools/audit-completeness-check.py (L37 audit-completeness gate).

Each test builds a tmp fixture workspace and asserts the verdict + exit code
for every branch of the verdict vocabulary:
  pass-audit-complete / fail-no-tier6-mining / fail-hunt-incomplete /
  fail-no-live-engines / fail-engines-not-run-for-language /
  fail-engine-false-pass / fail-no-audit-preflight / fail-no-exploit-queue /
  fail-no-chain-synth / fail-conversion-loop-not-run /
  fail-prove-top-leads-not-run / fail-no-originality /
  fail-advisory-corpus-incomplete / fail-no-learning / fail-mined-not-landed /
  fail-no-cross-ws-seed / fail-fork-divergence-not-run / error
plus the l37-rebuttal override paths.

The hunt-complete signal delegates to hunt-completeness-check.evaluate, so
the "all-pass" fixture builds a real git clone + all hunt artifacts too.
<!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "audit-completeness-check.py"
COV_TOOL = Path(__file__).resolve().parents[1] / "workspace-coverage-heatmap.py"


def _resolve_real_git() -> str:
    """Return a git binary that is NOT the auditooor MCP-gate wrapper."""
    cand = os.environ.get("AUDITOOOR_REAL_GIT")
    if cand and os.access(cand, os.X_OK):
        return cand
    if os.access("/usr/bin/git", os.X_OK):
        return "/usr/bin/git"
    found = shutil.which("git")
    if found and ".auditooor" not in str(Path(found).resolve()):
        return found
    return found or "git"


_GIT = _resolve_real_git()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        [_GIT, "-C", str(repo), *args],
        check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"},
    )


def _write_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def _load_coverage_module():
    spec = importlib.util.spec_from_file_location("_cov_for_l37_test", COV_TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_cov_for_l37_test"] = mod
    spec.loader.exec_module(mod)
    return mod


_COV = _load_coverage_module()


def _coverage_report(ws: Path, list_cap: int = 500) -> dict:
    return _COV.build_coverage_report(ws, list_cap=list_cap)


def _refresh_coverage_report(ws: Path, list_cap: int = 500) -> None:
    _write_json(ws / ".auditooor" / "coverage_report.json", _coverage_report(ws, list_cap=list_cap))


def _write_audit_run_start(
    ws: Path,
    *,
    run_id: str = "auditrun-current",
    timestamp: str = "2026-05-30T10:00:00Z",
) -> None:
    _write_jsonl = ws / ".auditooor" / "audit_run_full_manifest.jsonl"
    _write_jsonl.parent.mkdir(parents=True, exist_ok=True)
    _write_jsonl.write_text(
        json.dumps({
            "schema": "auditooor.audit_run_full_manifest.v1",
            "event": "start",
            "run_id": run_id,
            "workspace": str(ws),
            "timestamp_utc": timestamp,
        }, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_fresh_audit_deep_manifest(
    ws: Path,
    *,
    run_id: str = "auditrun-current",
    generated_at: str = "2026-05-30T10:01:00Z",
) -> None:
    logs = ws / ".audit_logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "audit_deep_report.md").write_text("audit deep report\n", encoding="utf-8")
    (logs / "audit_deep_default.log").write_text("profile default ok\n", encoding="utf-8")
    _write_json(logs / "audit_deep_all_manifest.json", {
        "schema": "auditooor.audit_deep_all.v1",
        "workspace": str(ws),
        "run_id": run_id,
        "generated_at": generated_at,
        "expected_profiles": ["default"],
        "report": "audit_deep_report.md",
        "profiles": [
            {
                "profile": "default",
                "status": "success",
                "exit_code": 0,
                "log": "audit_deep_default.log",
            }
        ],
    })


def _write_fresh_per_function_halmos_manifest(
    ws: Path,
    *,
    run_id: str = "auditrun-current",
    generated_at: str = "2026-05-30T10:01:00Z",
    expected_invocation_count: int = 1,
    ok_invocation_count: int = 1,
) -> None:
    """Emit the per-function Halmos proof artifacts the tightened live-engines gate
    requires for the solidity-deep-audit row's execution_ok.

    The post-27471f4e35/6fd91d62aa gate (tools/audit-deep-manifest.py
    ``_manifest_execution_assessment``) credits execution_ok via the FULL
    ``per_function_halmos_proof_ok`` path, which needs BOTH:
      (1) ``_with_per_function_halmos_denominator`` to parse a clean manifest at
          ``.audit_logs/solidity_per_function_halmos_manifest.json`` (schema
          ``auditooor.solidity_per_function_halmos.v1``, status ok,
          expected==executed==ok, every invocation backed by a fresh,
          run-id-matching, halmos-engine deep_engine_artifact.v1 artifact +
          an on-disk, gate-classifiable harness file), and
      (2) ``engine-harness-proof-check.py`` ``evaluate`` to return verdict
          ``pass-engine-harness-proof`` with a ``solidity-per-function-halmos:``
          proven label (the manifest's ``good`` path).

    The harness referenced is the SAME real ``.auditooor/echidna/VaultHarness.sol``
    the fixture already authors (a genuine, non-advisory, classify_path-passing
    real-property harness), so this is honest proof evidence, not a stub.
    """
    aud = ws / ".auditooor"
    logs = ws / ".audit_logs"
    logs.mkdir(parents=True, exist_ok=True)
    halmos_dir = aud / "solidity-deep-audit" / "per_function_halmos"
    halmos_dir.mkdir(parents=True, exist_ok=True)
    harness_rel = ".auditooor/echidna/VaultHarness.sol"
    invocations: list[dict] = []
    for idx in range(expected_invocation_count):
        invocation_ok = idx < ok_invocation_count
        artifact_rel = f".auditooor/solidity-deep-audit/per_function_halmos/inv_{idx}.json"
        _write_json(ws / artifact_rel, {
            "schema_version": "auditooor.deep_engine_artifact.v1",
            "engine": "halmos",
            "workspace": str(ws),
            "status": "ok" if invocation_ok else "fail",
            "returncode": 0 if invocation_ok else 1,
            "generated_at": generated_at,
            "run_id": run_id,
            "selector": f"echidna_property_balance_{idx}()",
        })
        invocations.append({
            "index": idx,
            "selector": f"echidna_property_balance_{idx}()",
            "harness_contract": "VaultHarness",
            "harness_path": harness_rel,
            "status": "ok" if invocation_ok else "fail",
            "returncode": 0 if invocation_ok else 1,
            "artifact": artifact_rel,
        })
    _write_json(logs / "solidity_per_function_halmos_manifest.json", {
        "schema": "auditooor.solidity_per_function_halmos.v1",
        "workspace": str(ws),
        "generated_at": generated_at,
        "run_id": run_id,
        "status": "ok" if ok_invocation_count == expected_invocation_count else "blocked",
        "expected_invocation_count": expected_invocation_count,
        "executed_invocation_count": expected_invocation_count,
        "ok_invocation_count": ok_invocation_count,
        "invocations": invocations,
    })


def _write_fresh_solidity_deep_manifest(
    ws: Path,
    *,
    run_id: str = "auditrun-current",
    generated_at: str = "2026-05-30T10:01:00Z",
    generated_per_function_harness_count: int = 1,
    executed_generated_harness_count: int | None = 1,
    available_engine_harness_count: int = 1,
    executed_engine_harness_count: int | None = 1,
) -> None:
    aud = ws / ".auditooor"
    eng = aud / "solidity-deep-audit"
    eng.mkdir(parents=True, exist_ok=True)
    _write_json(eng / "echidna-campaign.json", {
        "schema": "auditooor.solidity_deep_audit.step.v1",
        "tool": "echidna-campaign",
        "status": "ok",
        "returncode": 0,
        "generated_at": generated_at,
        "run_id": run_id,
        "stdout_tail": "echidna_property_balance: passing (256 calls)",
    })
    echidna = aud / "echidna"
    echidna.mkdir(parents=True, exist_ok=True)
    # A valid deep_engine_artifact.v1 runner artifact so the tightened gate's
    # runner_artifact_errors stays empty (a bare {status,returncode} object trips
    # schema_mismatch -> "runner artifacts did not all succeed").
    _write_json(echidna / "artifact.json", {
        "schema_version": "auditooor.deep_engine_artifact.v1",
        "engine": "echidna",
        "workspace": str(ws),
        "status": "ok",
        "returncode": 0,
        "generated_at": generated_at,
        "run_id": run_id,
    })
    manifest = {
        "schema": "auditooor.solidity_deep_audit.v1",
        "workspace": str(ws),
        "generated_at": generated_at,
        "run_id": run_id,
        "generated_per_function_harness_count": generated_per_function_harness_count,
        "available_engine_harness_count": available_engine_harness_count,
        "artifacts": [
            {
                "tool": "echidna-campaign",
                "status": "ok",
                "artifact": "echidna-campaign.json",
            }
        ],
    }
    if executed_generated_harness_count is not None:
        manifest["executed_generated_harness_count"] = executed_generated_harness_count
    if executed_engine_harness_count is not None:
        manifest["executed_engine_harness_count"] = executed_engine_harness_count
    _write_json(eng / "manifest.json", manifest)
    # Per-function Halmos proof artifacts: the full execution_ok credit path the
    # tightened live-engines gate requires. Tie the expected invocation count to
    # the manifest's generated_per_function_harness_count so a default (1/1) call
    # yields a complete proof, and the negative-test downgrade (generated=2,
    # executed=1) yields an INCOMPLETE per-function proof - though that negative
    # test fails earlier on the manifest's denominator delta (2 > 1) regardless.
    _write_fresh_per_function_halmos_manifest(
        ws,
        run_id=run_id,
        generated_at=generated_at,
        expected_invocation_count=generated_per_function_harness_count,
        ok_invocation_count=(
            executed_generated_harness_count
            if executed_generated_harness_count is not None
            else generated_per_function_harness_count
        ),
    )


def _write_typed_deep_skip(
    ws: Path,
    *,
    run_id: str = "auditrun-current",
    timestamp: str = "2026-05-30T10:01:00Z",
) -> None:
    _write_json(ws / ".auditooor" / "stage_skips.json", {
        "NO_AUDIT_DEEP_REASON": {
            "reason": "no supported deep engine for this workspace",
            "run_id": run_id,
            "timestamp_utc": timestamp,
        }
    })


def _convert_complete_ws_to_go(ws: Path) -> None:
    for p in (ws / "src").glob("*.sol"):
        p.unlink()
    (ws / "src" / "main.go").write_text("package main\n", encoding="utf-8")
    shutil.rmtree(ws / ".auditooor" / "solidity-deep-audit")


def _build_complete_ws(root: Path) -> Path:
    """Build a workspace that passes ALL L37 signals (incl. the hunt gate).

    The source tree is Solidity so live-engines requires the solidity engine.
    """
    ws = root / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)

    # --- in-scope Solidity source under <ws>/src ---
    src = ws / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "Vault.sol").write_text(
        "contract Vault {\n"
        "    function foo() external {}\n"
        "}\n",
        encoding="utf-8",
    )
    _write_audit_run_start(ws)

    # --- (a) tier6-mining: a GENUINE-ran round dir (a git-commits-mining output
    # with >0 scanned commits), so the signal passes even under the strict
    # ENFORCE_AUTONOMOUS_PROOF_CONVERSION umbrella (a hollow file-presence-only
    # round WARN-passes off-strict but hard-fails under strict). ---
    _round = ws / "mining_rounds" / "round1"
    _round.mkdir(parents=True, exist_ok=True)
    _write_json(_round / "round1_git_commits_mining.json", {
        "commits_scanned": 3,
        "security_fix_count": 1,
        "commits": [{"sha": "a" * 40, "subject": "fix: guard reentrancy"}],
    })

    # --- (b) hunt-complete: satisfy every hunt-completeness signal ---
    _write_json(aud / "hunt_skip_set.json", {
        "schema": "auditooor.l36_hunt_skip_set.v1",
        "source_counts": {"total_after_dedup": 0},
    })
    # full clone (a git repo at the workspace root itself with >1 commit)
    (ws / "A.sol").write_text("contract A {}\n", encoding="utf-8")
    _git(ws, "init", "-q")
    _git(ws, "add", "A.sol")
    _git(ws, "commit", "-q", "-m", "c1")
    (ws / "C.sol").write_text("contract C {}\n", encoding="utf-8")
    _git(ws, "add", "C.sol")
    _git(ws, "commit", "-q", "-m", "c2")
    # audit-deep manifest
    (ws / ".audit_logs").mkdir(parents=True, exist_ok=True)
    _write_json(ws / ".audit_logs" / "audit_deep_all_manifest.json", {
        "schema": "auditooor.audit_deep_all.v1",
        "profiles": [{"profile": "default", "status": "success", "exit_code": 0}],
    })
    # coverage matrix with no DARK rows + cluster coverage + sidecars
    (ws / "vault_CAPABILITY_COVERAGE_MATRIX.md").write_text(
        "| # | family | Verdict | Evidence |\n"
        "|---|--------|---------|----------|\n"
        "| 1 | reentrancy | covered | sidecar |\n",
        encoding="utf-8",
    )
    (ws / "SCOPE.md").write_text("- reentrancy\n", encoding="utf-8")
    sidecars = ws / "hunt_findings_sidecars"
    sidecars.mkdir(parents=True, exist_ok=True)
    # A GENUINE finding sidecar: it (a) carries real finding content so the
    # mined-landed parity gate counts it (matches the landed==1 ledger below),
    # and (b) span-cites the single in-scope external fn (Vault.foo) with a
    # terminal finding verdict, so function-coverage-completeness credits foo as
    # a real per-function attack. Crediting via a hunt_findings_sidecar (not a
    # `per_function_*` record) keeps it from colliding with the audit-preflight
    # signal's `per_function`-prefixed artifact match.
    _write_json(sidecars / "reentrancy.json", {
        "verdict": "finding",
        "title": "reentrancy in Vault.foo",
        "file_line": "src/Vault.sol:2",
        "function": "foo",
    })
    # artifact-mining learn report (hunt gate signal (e))
    (ws / "reports").mkdir(parents=True, exist_ok=True)
    _write_json(ws / "reports" / "agent_learning_report.json", {"ok": True})

    # --- (c) live-engines (solidity) ---
    # <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
    eng = aud / "solidity-deep-audit"
    eng.mkdir(parents=True, exist_ok=True)
    # (c2) engine-harness: a REAL engine step that executed >0 properties.
    _write_json(eng / "echidna-campaign.json", {
        "status": "ok", "returncode": 0, "tool": "echidna-campaign",
        "properties": 7, "stdout_tail": "echidna_property_balance: passing (256 calls)",
    })
    harness_dir = aud / "echidna"
    harness_dir.mkdir(parents=True, exist_ok=True)
    (harness_dir / "VaultHarness.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract TargetVault {\n"
        "    uint256 public balance = 1;\n"
        "    function bump() external { balance += 1; }\n"
        "}\n"
        "contract VaultHarness {\n"
        "    TargetVault internal target = new TargetVault();\n"
        "    function cleanPathBaseline() public view returns (bool) {\n"
        "        return target.balance() >= 1;\n"
        "    }\n"
        "    function echidna_property_balance() public returns (bool) {\n"
        "        uint256 beforeValue = target.balance();\n"
        "        target.bump();\n"
        "        uint256 afterValue = target.balance();\n"
        "        return afterValue > beforeValue;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    _write_json(aud / "evm_engine_proof" / "engine_harness_proof.json", {
        "schema": "auditooor.evm_engine_harness_proof.v1",
        "verdict": "pass-engine-harness-proof",
        "proven": [".auditooor/echidna/VaultHarness.sol"],
        "unproven": [],
    })
    _write_fresh_solidity_deep_manifest(ws)

    # --- (d) audit-preflight: a per-function pack manifest with genuine processed
    # content (a non-empty functions list), so the signal passes under strict. ---
    _write_json(aud / "per_function_invariants" / "manifest.json", {
        "function_count": 1,
        "functions": ["foo"],
    })

    # --- (e) exploit-queue: a non-hollow queue that processed >=1 candidate row
    # (check_exploit_queue rejects a file-present-only artifact as HOLLOW). ---
    _write_json(aud / "exploit_queue.json", {
        "queue": [{"file": "src/Vault.sol", "function": "foo", "verdict": "evaluated"}],
        "total_candidates": 1,
    })

    # --- (s) function-coverage: Vault.foo is credited real-attack by the genuine
    # finding sidecar written above (hunt_findings_sidecars/reentrancy.json). ---

    # --- depth-certificate (R81): a fresh, depth-audited per-unit cert. Both
    # depth passes ran with evidence and the 0-findings smell is cleared. ---
    _write_json(aud / "depth_certificate.json", {
        "schema": "auditooor.depth_certificate.v1",
        "build_schema": "auditooor.depth_certificate_build.v1",
        "verdict": "depth-audited",
        "negative_space_ran": True,
        "sibling_diff_ran": True,
        "guards_enumerated": 1,
        "sibling_pairs_enumerated": 1,
        "findings_count": 0,
        "incomplete_guard_deltas": [],
        "sibling_asymmetries": [],
        "zero_findings_smell_cleared": True,
    })

    # --- exploit-class coverage: every canonical exploit class carries a backed
    # disposition. This minimal vault has none of the surfaces, so each class is
    # not-applicable with a source-file basis (src/Vault.sol). ---
    _write_json(aud / "exploit_class_coverage.json", {
        "classes": [
            {
                "class": cls,
                "status": "not-applicable",
                "rationale": "no such surface in this minimal single-function vault",
                "evidence_ref": "src/Vault.sol",
            }
            for cls in (
                "multi-step-economic", "system-invariant", "stateful-history",
                "cross-chain-messaging", "upgradability", "oracle-manipulation",
                "governance-timelock", "donation-inflation", "rounding-accumulation",
                "access-control-composition",
            )
        ],
    })

    # --- (f) chain-synth: a verdict-bearing report (genuine under strict). ---
    cs = aud / "chain_synthesis"
    cs.mkdir(parents=True, exist_ok=True)
    _write_json(cs / "chain_synthesis_report.json", {"ok": True})
    _write_json(aud / "chain_synthesis_report.json", {
        "schema": "auditooor.chain_synthesis_report.v1",
        "status": "complete",
        "applicability_verdict": "pass-not-applicable",
        "chains_synthesized": 1,
    })

    # --- (g) exploit-conversion + prove-top-leads. The conversion gate is genuine
    # (adjudicated bool + positive sidecar work) so it passes under the strict
    # ENFORCE_AUTONOMOUS_PROOF_CONVERSION umbrella. prove-top-leads is deliberately
    # left as a bare (weak) artifact: under ENFORCE it is the ONLY failing signal,
    # which the dedicated prove-top-leads tests supply/exercise. ---
    _write_json(aud / "current_to_exploit_conversion_gate.json", {
        "start_exploit_conversion_allowed": True,
        "sidecar_freshness": {"total": 1},
    })
    _write_json(aud / "prove_top_leads_candidate_judgment_packet.json", {"ok": True})

    # --- (h) originality: a scan that genuinely ran (keyword_count>0 + corpus compared). ---
    _write_json(aud / "originality_report.json", {
        "schema": "auditooor.originality_before_proof_gate.v1",
        "counts": {"keyword_count": 3, "local_files_scanned": 5},
        "evidence": [],
    })

    # --- (i) learning: agent-artifact-miner ran (genuine schema, 0-artifacts honest). ---
    _write_json(aud / "agent_artifact_mining_report.json", {
        "schema_version": "auditooor.agent_artifact_mining.v2",
        "total_artifacts": 0,
        "no_learning_reason": True,
    })

    # --- (j) cross-ws-seed: the seed stage ran (schema + generated_at_utc + totals). ---
    _write_json(aud / "cross_workspace_seed.json", {
        "schema": "auditooor.cross_workspace_seed.v1",
        "generated_at_utc": "2026-05-30T10:00:00Z",
        "totals": {"seeded": 1},
    })

    # --- (j2) brain-prime (ADD-D): a genuine intake report (>=500 bytes + a
    # 'Phase A' marker), so the signal passes under strict. The dedicated
    # brain-prime tests remove this .md (and cover the receipt path separately). ---
    (ws / "BRAIN_PRIMING_REPORT.md").write_text(
        "# Brain Priming Report\n\n## Phase A - intake\n\n"
        + ("Primed the engagement context from prior same-family knowledge. "
           * 12)
        + "\n",
        encoding="utf-8",
    )

    # --- (q) hunt-trust: a healthy hunt-run-health report so the hunt-trust meta
    # signal passes under the strict umbrella (the HuntTrust tests overwrite this). ---
    _write_json(aud / "hunt_run_health_report.json", {
        "schema": "auditooor.hunt_run_health.v1",
        "kind": "hunt_run_health",
        "workspace": str(ws),
        "ws_name": ws.name,
        "hunt_dirs_scanned": [f"mimo_harness_{ws.name}"],
        "verdict": "healthy",
        "needs_re_hunt": False,
        "total_records": 200,
        "success": 160,
        "rate_limited": 5,
        "success_fraction": 0.80,
    })

    # --- (j3) per-function hacker-questions (ADD-D) ---
    (aud / "per_fn_hacker_questions.jsonl").write_text(
        '{"schema":"auditooor.per_fn_hacker_questions.v1"}\n', encoding="utf-8",
    )

    # <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
    # --- (h2) advisory-corpus parity (published == corpus) ---
    _write_json(aud / "advisory_corpus_parity.json", {
        "published_advisory_count": 3, "corpus_advisory_record_count": 3,
    })

    # --- (i2) mined-landed parity (sidecar_count == landed) ---
    # The hunt fixture writes 1 sidecar (hunt_findings_sidecars/reentrancy.json),
    # so the landed ledger must assert landed == 1.
    _write_json(aud / "mined_landed_parity.json", {
        "sidecar_count": 1, "landed_count": 1,
    })

    # --- (l) novel-vector (PR9/PR10): invariant miner output ---
    _write_json(aud / "novel_vector_invariants.json", {
        "schema": "auditooor.novel_vector_invariant.v1", "invariants": [],
    })

    # --- (o) coverage-map: SWEPT-SURFACE coverage report present + full ---
    # The single src/Vault.sol has no functions, so it enumerates to 1 file-unit
    # ("Vault.sol"). A coverage token referencing it makes coverage_fraction=1.0.
    _write_json(aud / "coverage_report.json", _coverage_report(ws))

    # --- (p) rubric-coverage: RUBRIC coverage report present + full ---
    # The complementary axis to (o). A 2/2-rows report keeps the fixture green.
    _write_json(aud / "rubric_coverage_report.json", {
        "schema": "auditooor.workspace_rubric_coverage.v1",
        "workspace": "ws", "total_rows": 2, "rows_with_candidate": 2,
        "rows_uncovered": 0, "rubric_coverage_fraction": 1.0,
        "candidates_scanned": 3, "uncovered_rows": [], "covered_rows": [],
        "rows": [],
    })

    # --- (m) adversarial-panel (PR8 ADD-B / PR10): N/A by default (no
    # FINAL_LEADS set). The all-pass fixture deliberately has no FINAL_LEADS
    # so the panel signal passes as N/A. A dedicated test covers the gated path.

    # --- (n) evm-0day-proof (PR5a): the all-pass fixture's exploit_queue.json
    # above has no Medium+ EVM candidate, so the signal passes as N/A. A
    # dedicated test covers the qualifying (fail/pass) paths.

    return ws


def _run(ws: Path):
    proc = subprocess.run(
        [sys.executable, str(TOOL), str(ws), "--json"],
        capture_output=True, text=True,
    )
    return proc.returncode, json.loads(proc.stdout)


class AuditCompletenessTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    # ---- pass ----
    def test_pass_audit_complete(self):
        ws = _build_complete_ws(self._tmp)
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        self.assertEqual(out["failures"], [])

    # ---- (a) tier6 ----
    def test_fail_no_tier6_mining(self):
        ws = _build_complete_ws(self._tmp)
        shutil.rmtree(ws / "mining_rounds")
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-tier6-mining", out)
        self.assertEqual(rc, 1)

    # ---- (b) hunt-complete ----
    def test_fail_hunt_incomplete(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "hunt_skip_set.json").unlink()
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-hunt-incomplete", out)
        self.assertEqual(rc, 1)

    # ---- (c) live-engines: none at all ----
    def test_fail_no_live_engines(self):
        # r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json
        ws = _build_complete_ws(self._tmp)
        shutil.rmtree(ws / ".auditooor" / "solidity-deep-audit")
        shutil.rmtree(ws / ".audit_logs")
        shutil.rmtree(ws / "src")
        # remove root .sol files (git fixture) so NO language is detected at all
        for p in ws.glob("*.sol"):
            p.unlink()
        # rebuttal hunt-complete (which needs audit-deep) to isolate live-engines
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: hunt-complete: isolating live-engines for test\n",
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-live-engines", out)
        self.assertEqual(rc, 1)

    # ---- (c) live-engines: language mismatch ----
    def test_fail_engines_not_run_for_language(self):
        ws = _build_complete_ws(self._tmp)
        shutil.rmtree(ws / ".auditooor" / "solidity-deep-audit")
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-engines-not-run-for-language", out)
        self.assertEqual(rc, 1)
        le = [s for s in out["signals"] if s["signal"] == "live-engines"][0]
        self.assertEqual(le["verdict"], "fail-engines-not-run-for-language")

    # ---- (d) audit-preflight ----
    def test_fail_no_audit_preflight(self):
        ws = _build_complete_ws(self._tmp)
        shutil.rmtree(ws / ".auditooor" / "per_function_invariants")
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-audit-preflight", out)
        self.assertEqual(rc, 1)

    # ---- (e) exploit-queue ----
    def test_fail_no_exploit_queue(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "exploit_queue.json").unlink()
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-exploit-queue", out)
        self.assertEqual(rc, 1)

    # ---- (f) chain-synth ----
    def test_fail_no_chain_synth(self):
        ws = _build_complete_ws(self._tmp)
        shutil.rmtree(ws / ".auditooor" / "chain_synthesis")
        (ws / ".auditooor" / "chain_synthesis_report.json").unlink()
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-chain-synth", out)
        self.assertEqual(rc, 1)

    # ---- (g) exploit-conversion: missing is advisory unless env-enforced ----
    # <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
    def test_missing_conversion_loop_advisory_by_default(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "current_to_exploit_conversion_gate.json").unlink()
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": ""}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        ec = [s for s in out["signals"] if s["signal"] == "exploit-conversion"][0]
        self.assertTrue(ec["detail"]["advisory_autonomous_proof_conversion"])
        self.assertEqual(ec["verdict"], "advisory-without-artifact")
        self.assertEqual(ec["policy"], "advisory")
        self.assertFalse(ec["hard_required"])
        self.assertFalse(ec["artifact_present"])
        self.assertEqual(ec["artifact_requirement"], "advisory-without-artifact")

    def test_conversion_loop_env_values_other_than_one_remain_advisory(self):
        for value in ("true", "yes", "on", "2", "garbage"):
            with self.subTest(value=value):
                ws = _build_complete_ws(self._tmp / value)
                (ws / ".auditooor" / "current_to_exploit_conversion_gate.json").unlink()
                with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": value}):
                    rc, out = _run(ws)
                self.assertEqual(out["verdict"], "pass-audit-complete", out)
                self.assertEqual(rc, 0)
                ec = [s for s in out["signals"] if s["signal"] == "exploit-conversion"][0]
                self.assertFalse(ec["detail"]["enforce_autonomous_proof_conversion"])
                self.assertEqual(ec["verdict"], "advisory-without-artifact")

    def test_l37_present_advisory_proof_artifacts_stay_advisory(self):
        ws = _build_complete_ws(self._tmp)
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        for name in ("exploit-conversion", "prove-top-leads"):
            sig = [s for s in out["signals"] if s["signal"] == name][0]
            self.assertEqual(sig["verdict"], "advisory-artifact-present")
            self.assertEqual(sig["policy"], "advisory")
            self.assertFalse(sig["hard_required"])
            self.assertTrue(sig["artifact_present"])
            self.assertEqual(sig["artifact_requirement"], "advisory-artifact-present")

    def test_l37_human_output_marks_missing_advisory_not_pass(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "current_to_exploit_conversion_gate.json").unlink()
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(ws)],
            capture_output=True,
            text=True,
            env={**os.environ, "ENFORCE_AUTONOMOUS_PROOF_CONVERSION": ""},
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[ADVISORY] exploit-conversion", proc.stdout)
        self.assertNotIn("[PASS] exploit-conversion", proc.stdout)

    def test_enforced_conversion_loop_missing_fails(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "current_to_exploit_conversion_gate.json").unlink()
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-conversion-loop-not-run", out)
        self.assertEqual(rc, 1)

    # ---- (g2) prove-top-leads missing is advisory unless env-enforced ----
    def test_missing_prove_top_leads_advisory_by_default(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "prove_top_leads_candidate_judgment_packet.json").unlink()
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": ""}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        ec = [s for s in out["signals"] if s["signal"] == "prove-top-leads"][0]
        self.assertIn("prove_top_leads", ec["reason"])
        self.assertEqual(ec["verdict"], "advisory-without-artifact")
        self.assertEqual(ec["policy"], "advisory")
        self.assertFalse(ec["hard_required"])
        self.assertFalse(ec["artifact_present"])
        self.assertEqual(ec["artifact_requirement"], "advisory-without-artifact")

    def test_enforced_prove_top_leads_missing_fails(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "prove_top_leads_candidate_judgment_packet.json").unlink()
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-prove-top-leads-not-run", out)
        self.assertEqual(rc, 1)

    def test_enforced_prove_top_leads_weak_file_only_fails(self):
        ws = _build_complete_ws(self._tmp)
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-prove-top-leads-not-run", out)
        self.assertEqual(rc, 1)
        sig = [s for s in out["signals"] if s["signal"] == "prove-top-leads"][0]
        self.assertFalse(sig["detail"]["artifact_set_complete"])
        self.assertIn("source_mine", sig["detail"]["missing_required_groups"])
        self.assertIn("source_mined_impact_contracts", sig["detail"]["missing_required_groups"])
        self.assertIn("bare prove_top_leads", sig["reason"])

    def test_enforced_prove_top_leads_stale_reports_fallback_fails(self):
        ws = _build_complete_ws(self._tmp)
        aud = ws / ".auditooor"
        reports = ws / "reports"
        (aud / "prove_top_leads_candidate_judgment_packet.json").unlink()
        _write_json(aud / "prove_top_leads_outcome_lesson_gate.json", {"ok": True})
        _write_json(reports / "prove_top_leads_source_mine.json", {"ok": True})
        _write_json(reports / "prove_top_leads_prefiling_stress_test.json", {"ok": True})
        _write_json(reports / "harness_binding_manifest_from_exploit_queue.json", {"ok": True})
        _write_json(reports / "harness_execution_queue_from_exploit_queue.json", {"ok": True})
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-prove-top-leads-not-run", out)
        self.assertEqual(rc, 1)
        sig = [s for s in out["signals"] if s["signal"] == "prove-top-leads"][0]
        self.assertIn("candidate_judgment", sig["detail"]["missing_required_groups"])
        self.assertIn("source_mined_impact_contracts", sig["detail"]["missing_required_groups"])

    def test_enforced_prove_top_leads_outcome_is_not_candidate_packet(self):
        ws = _build_complete_ws(self._tmp)
        aud = ws / ".auditooor"
        (aud / "prove_top_leads_candidate_judgment_packet.json").unlink()
        _write_json(aud / "prove_top_leads_source_mine.json", {"ok": True})
        _write_json(aud / "prove_top_leads_source_mined_impact_contracts.json", {"ok": True})
        _write_json(aud / "prove_top_leads_prefiling_stress_test.json", {"ok": True})
        _write_json(aud / "prove_top_leads_outcome_lesson_gate.json", {"ok": True})
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-prove-top-leads-not-run", out)
        self.assertEqual(rc, 1)
        sig = [s for s in out["signals"] if s["signal"] == "prove-top-leads"][0]
        self.assertIn("candidate_judgment", sig["detail"]["missing_required_groups"])

    def test_enforced_prove_top_leads_impact_contracts_required(self):
        ws = _build_complete_ws(self._tmp)
        aud = ws / ".auditooor"
        _write_json(aud / "prove_top_leads_source_mine.json", {"ok": True})
        _write_json(aud / "prove_top_leads_prefiling_stress_test.json", {"ok": True})
        _write_json(aud / "prove_top_leads_outcome_lesson_gate.json", {"ok": True})
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-prove-top-leads-not-run", out)
        self.assertEqual(rc, 1)
        sig = [s for s in out["signals"] if s["signal"] == "prove-top-leads"][0]
        self.assertIn("source_mined_impact_contracts", sig["detail"]["missing_required_groups"])

    def test_enforced_prove_top_leads_full_artifact_set_passes(self):
        ws = _build_complete_ws(self._tmp)
        aud = ws / ".auditooor"
        _write_json(aud / "prove_top_leads_source_mine.json", {
            "schema": "auditooor.exploit_queue_source_miner.v1",
            "selected_rows": 1,
            "source_found": 1,
        })
        _write_json(aud / "prove_top_leads_source_mined_impact_contracts.json", {
            "contracts": [{"candidate_id": "EQ-001"}],
        })
        _write_json(aud / "prove_top_leads_prefiling_stress_test.json", {
            "results": [{"candidate_id": "EQ-001"}],
        })
        _write_json(aud / "prove_top_leads_candidate_judgment_packet.json", {
            "packets": [{"candidate_id": "EQ-001"}],
        })
        _write_json(aud / "prove_top_leads_outcome_lesson_gate.json", {
            "schema": "auditooor.outcome_lesson_gate.v1",
            "status": "pass",
        })
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        sig = [s for s in out["signals"] if s["signal"] == "prove-top-leads"][0]
        self.assertTrue(sig["detail"]["artifact_set_complete"])
        self.assertEqual(sig["detail"]["missing_required_groups"], [])

    def test_enforced_prove_top_leads_placeholder_artifact_set_fails(self):
        ws = _build_complete_ws(self._tmp)
        aud = ws / ".auditooor"
        _write_json(aud / "prove_top_leads_source_mine.json", {"ok": True})
        _write_json(aud / "prove_top_leads_source_mined_impact_contracts.json", {"ok": True})
        _write_json(aud / "prove_top_leads_prefiling_stress_test.json", {"ok": True})
        _write_json(aud / "prove_top_leads_candidate_judgment_packet.json", {"ok": True})
        _write_json(aud / "prove_top_leads_outcome_lesson_gate.json", {"ok": True})
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-prove-top-leads-not-run", out)
        self.assertEqual(rc, 1)
        sig = [s for s in out["signals"] if s["signal"] == "prove-top-leads"][0]
        self.assertFalse(sig["detail"]["artifact_set_complete"])
        self.assertIn("candidate_judgment", sig["detail"]["invalid_required_groups"])

    def test_enforced_prove_top_leads_structured_no_leads_manifest_passes(self):
        ws = _build_complete_ws(self._tmp)
        aud = ws / ".auditooor"
        (aud / "prove_top_leads_candidate_judgment_packet.json").unlink()
        _write_json(aud / "exploit_queue.json", {"items": []})
        _write_json(aud / "exploit_queue.source_mined.json", {"items": []})
        # A genuinely-empty queue is HONEST here: record the survivors sidecar the
        # exploit-queue gate requires so an empty queue reads as an evaluated
        # no-leads result rather than a hollow file-presence-only artifact.
        _write_json(aud / "exploit_queue.survivors.json", {
            "note": "source-mining evaluated the candidate surface; no leads survived",
            "survivors": [],
            "candidates_evaluated": 1,
        })
        agent_outputs = ws / "agent_outputs"
        agent_outputs.mkdir(parents=True, exist_ok=True)
        (agent_outputs / "coverage.md").write_text("Covered src/Vault.sol:1\n", encoding="utf-8")
        _refresh_coverage_report(ws)
        _write_json(aud / "prove_top_leads_no_leads.json", {
            "schema": "auditooor.prove_top_leads_no_leads.v1",
            "status": "no-leads",
            "no_leads": True,
            "lead_count": 0,
            "current_queue_rows": {
                ".auditooor/exploit_queue.json": 0,
                ".auditooor/exploit_queue.source_mined.json": 0,
            },
        })
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        sig = [s for s in out["signals"] if s["signal"] == "prove-top-leads"][0]
        self.assertTrue(sig["detail"]["no_leads_manifest_complete"])

    def test_enforced_prove_top_leads_no_leads_manifest_fails_with_queue_rows(self):
        ws = _build_complete_ws(self._tmp)
        aud = ws / ".auditooor"
        (aud / "prove_top_leads_candidate_judgment_packet.json").unlink()
        _write_json(aud / "prove_top_leads_no_leads.json", {
            "schema": "auditooor.prove_top_leads_no_leads.v1",
            "status": "no-leads",
            "no_leads": True,
            "lead_count": 0,
            "current_queue_rows": {
                ".auditooor/exploit_queue.json": 1,
                ".auditooor/exploit_queue.source_mined.json": 0,
            },
        })
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-prove-top-leads-not-run", out)
        self.assertEqual(rc, 1)
        sig = [s for s in out["signals"] if s["signal"] == "prove-top-leads"][0]
        self.assertFalse(sig["detail"]["no_leads_manifest_complete"])

    # ---- (h) originality ----
    def test_fail_no_originality(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "originality_report.json").unlink()
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-originality", out)
        self.assertEqual(rc, 1)

    def test_fail_originality_artifact_with_fail_status(self):
        ws = _build_complete_ws(self._tmp)
        _write_json(ws / ".auditooor" / "originality_report.json", {"status": "fail"})
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-originality", out)
        self.assertEqual(rc, 1)
        sig = [s for s in out["signals"] if s["signal"] == "originality"][0]
        self.assertIn("fail/error", sig["reason"])

    def test_originality_blocker_diagnosis_does_not_satisfy_originality(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "originality_report.json").unlink()
        _write_json(ws / ".auditooor" / "originality_blocker_diagnosis.json", {
            "schema": "auditooor.originality_blocker_diagnosis.v1",
            "strict_audit_completeness_blocker": "fail-no-originality",
        })
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-originality", out)
        self.assertEqual(rc, 1)
        sig = [s for s in out["signals"] if s["signal"] == "originality"][0]
        self.assertNotIn("originality_blocker_diagnosis.json", " ".join(sig["artifacts"]))

    # ---- (i) learning ----
    def test_fail_no_learning(self):
        # r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json
        ws = _build_complete_ws(self._tmp)
        # The learning signal accepts EITHER the .auditooor report OR a
        # reports/ learn report. The reports/ one also feeds the hunt gate's
        # artifact-mining signal, so removing both means we must rebuttal
        # hunt-complete to isolate the learning fail.
        (ws / ".auditooor" / "agent_artifact_mining_report.json").unlink()
        (ws / "reports" / "agent_learning_report.json").unlink()
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: hunt-complete: isolating learning signal for test\n",
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-learning", out)
        self.assertEqual(rc, 1)

    # ---- (j) cross-ws-seed ----
    def test_fail_no_cross_ws_seed(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "cross_workspace_seed.json").unlink()
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-cross-ws-seed", out)
        self.assertEqual(rc, 1)

    def test_differential_seed_satisfies_cross_ws_seed(self):
        # ADD-A: the differential_seed_queue.json artifact (emitted by
        # cross-workspace-differential-seed.py) is a first-class cross-ws-seed
        # artifact and must satisfy signal (j) on its own.
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "cross_workspace_seed.json").unlink()
        _write_json(
            ws / ".auditooor" / "differential_seed_queue.json",
            {"schema": "auditooor.cross_workspace_differential_seed.v1",
             "hypotheses": []},
        )
        rc, out = _run(ws)
        self.assertNotEqual(out["verdict"], "fail-no-cross-ws-seed", out)

    def test_corpus_hunt_fuel_satisfies_cross_ws_seed(self):
        # PR7a: corpus-driven-hunt --emit-proof-queue writes corpus-hunt-fuel
        # rows into exploit_queue.json. Those rows are evidence the cross-ws
        # invariant corpus seeded this workspace's proof obligations, so they
        # satisfy signal (j) even with every other seed artifact removed.
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "cross_workspace_seed.json").unlink()
        _write_json(
            ws / ".auditooor" / "exploit_queue.json",
            {"schema": "auditooor.exploit_queue.v1", "queue": [
                {"lead_id": "F-CORPUS-INV-1", "source": "corpus-hunt-fuel",
                 "proof_status": "open", "broken_invariant_ids": ["INV-1"]}]},
        )
        _refresh_coverage_report(ws)
        rc, out = _run(ws)
        self.assertNotEqual(out["verdict"], "fail-no-cross-ws-seed", out)

    def test_corpus_hunt_hacker_q_satisfies_cross_ws_seed(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "cross_workspace_seed.json").unlink()
        _write_json(
            ws / ".auditooor" / "exploit_queue.json",
            {"schema": "auditooor.exploit_queue.v1", "queue": [
                {"lead_id": "F-CORPUS-HQ-1", "source": "corpus-hunt-hacker-q",
                 "proof_status": "open"}]},
        )
        _refresh_coverage_report(ws)
        rc, out = _run(ws)
        self.assertNotEqual(out["verdict"], "fail-no-cross-ws-seed", out)

    def test_non_corpus_exploit_queue_does_not_satisfy_cross_ws_seed(self):
        # A plain exploit_queue with only non-corpus rows must NOT satisfy the
        # cross-seed signal (no corpus provenance).
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "cross_workspace_seed.json").unlink()
        _write_json(
            ws / ".auditooor" / "exploit_queue.json",
            {"schema": "auditooor.exploit_queue.v1", "queue": [
                {"lead_id": "REAL-1", "source": "source-mined",
                 "proof_status": "proven"}]},
        )
        _refresh_coverage_report(ws)
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-cross-ws-seed", out)

    # ---- error ----
    def test_error_missing_workspace(self):
        rc, out = _run(self._tmp / "does-not-exist")
        self.assertEqual(out["verdict"], "error", out)
        self.assertEqual(rc, 2)

    # ---- rebuttal: single signal ----
    def test_rebuttal_single_signal(self):
        ws = _build_complete_ws(self._tmp)
        shutil.rmtree(ws / ".auditooor" / "chain_synthesis")
        (ws / ".auditooor" / "chain_synthesis_report.json").unlink()
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: chain-synth: non-chainable single-contract target\n",
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        cs = [s for s in out["signals"] if s["signal"] == "chain-synth"][0]
        self.assertEqual(cs["verdict"], "ok-rebuttal")

    # ---- rebuttal: all signals ----
    def test_rebuttal_all_signals(self):
        ws = self._tmp / "bare"
        ws.mkdir()
        (ws / ".auditooor").mkdir()
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: all: greenfield engagement, pipeline intentionally skipped\n",
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)

    # ---- rebuttal: empty reason ignored ----
    def test_rebuttal_empty_reason_ignored(self):
        ws = _build_complete_ws(self._tmp)
        shutil.rmtree(ws / ".auditooor" / "chain_synthesis")
        (ws / ".auditooor" / "chain_synthesis_report.json").unlink()
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: chain-synth: \n", encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-chain-synth", out)
        self.assertEqual(rc, 1)

    # ---- rebuttal: oversized reason ignored ----
    def test_rebuttal_oversized_reason_ignored(self):
        ws = _build_complete_ws(self._tmp)
        shutil.rmtree(ws / ".auditooor" / "chain_synthesis")
        (ws / ".auditooor" / "chain_synthesis_report.json").unlink()
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: chain-synth: " + ("x" * 250) + "\n", encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-chain-synth", out)
        self.assertEqual(rc, 1)

    # ---- go/rust workspace matches audit-deep engine (not solidity) ----
    def test_go_rust_ws_matches_audit_deep_engine(self):
        ws = _build_complete_ws(self._tmp)
        _convert_complete_ws_to_go(ws)
        _write_audit_run_start(ws)
        _write_fresh_audit_deep_manifest(ws)
        rc, out = _run(ws)
        le = [s for s in out["signals"] if s["signal"] == "live-engines"][0]
        self.assertTrue(le["ok"], le)
        self.assertEqual(le["detail"]["languages"], {"go": 1})
        self.assertEqual(
            le["detail"]["audit_deep_freshness"]["verdict"],
            "pass-fresh-deep-manifest",
        )

    def test_stale_audit_deep_manifest_does_not_satisfy_live_engine(self):
        ws = _build_complete_ws(self._tmp)
        _convert_complete_ws_to_go(ws)
        _write_audit_run_start(ws)
        # Genuinely STALE: a manifest from a PREVIOUS run (non-matching run_id) with
        # a timestamp before this run's start. A manifest tagged with the CURRENT
        # run_id but pre-dating run-start is classified as conflicting (self-
        # contradictory), not stale - that taxonomy is covered separately. This test
        # exercises the stale path, so it must use a prior run_id.
        _write_fresh_audit_deep_manifest(
            ws, run_id="auditrun-previous", generated_at="2026-05-30T09:59:00Z"
        )

        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-engines-not-run-for-language", out)
        self.assertEqual(rc, 1)
        le = [s for s in out["signals"] if s["signal"] == "live-engines"][0]
        self.assertFalse(le["ok"])
        self.assertFalse(le["detail"]["audit_deep"])
        self.assertEqual(
            le["detail"]["audit_deep_freshness"]["verdict"],
            "fail-stale-deep-manifest",
        )

    def test_typed_deep_skip_satisfies_non_solidity_live_engine(self):
        ws = _build_complete_ws(self._tmp)
        _convert_complete_ws_to_go(ws)
        for p in (ws / ".audit_logs").glob("audit_deep*"):
            p.unlink()
        _write_audit_run_start(ws)
        _write_typed_deep_skip(ws)

        rc, out = _run(ws)
        le = [s for s in out["signals"] if s["signal"] == "live-engines"][0]
        self.assertTrue(le["ok"], le)
        self.assertTrue(le["detail"]["audit_deep_skip"])
        self.assertEqual(
            le["detail"]["audit_deep_freshness"]["verdict"],
            "pass-explicit-deep-skip",
        )

    def test_placeholder_audit_deep_manifest_does_not_satisfy_live_engine(self):
        ws = _build_complete_ws(self._tmp)
        for p in (ws / "src").glob("*.sol"):
            p.unlink()
        (ws / "src" / "main.go").write_text("package main\n", encoding="utf-8")
        shutil.rmtree(ws / ".auditooor" / "solidity-deep-audit")
        for p in (ws / ".audit_logs").glob("audit_deep*"):
            p.unlink()
        _write_json(ws / ".audit_logs" / "audit_deep_x_manifest.json", {"ok": True})

        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-engines-not-run-for-language", out)
        self.assertEqual(rc, 1)
        le = [s for s in out["signals"] if s["signal"] == "live-engines"][0]
        self.assertFalse(le["ok"])
        self.assertFalse(le["detail"]["audit_deep"])

    def test_solidity_live_engine_does_not_accept_bare_directory_without_manifest(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "solidity-deep-audit" / "manifest.json").unlink()

        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-engines-not-run-for-language", out)
        self.assertEqual(rc, 1)
        le = [s for s in out["signals"] if s["signal"] == "live-engines"][0]
        self.assertFalse(le["ok"])
        self.assertTrue(le["detail"]["solidity_engine_dir"])
        self.assertFalse(le["detail"]["solidity_engine"])
        self.assertNotEqual(
            le["detail"]["audit_deep_freshness"]["verdict"],
            "pass-fresh-deep-manifest",
        )

    def test_solidity_live_engine_rejects_partial_invariant_denominator_execution(self):
        ws = _build_complete_ws(self._tmp)
        _write_fresh_solidity_deep_manifest(
            ws,
            generated_per_function_harness_count=2,
            executed_generated_harness_count=1,
            available_engine_harness_count=2,
            executed_engine_harness_count=1,
        )

        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-engines-not-run-for-language", out)
        self.assertEqual(rc, 1)
        le = [s for s in out["signals"] if s["signal"] == "live-engines"][0]
        self.assertFalse(le["ok"])
        self.assertFalse(le["detail"]["solidity_engine"])
        self.assertEqual(
            le["detail"]["audit_deep_freshness"]["verdict"],
            "fail-conflicting-deep-manifest",
        )
        source_rows = le["detail"]["audit_deep_freshness"]["source_manifests"]
        sol_row = [row for row in source_rows if row["kind"] == "solidity-deep-audit"][0]
        self.assertIn("invariant harness denominator exceeds executed counts", sol_row["execution_reason"])

    # ====================================================================
    # NEW fail-closing required-checks (this lane).
    # <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
    # ====================================================================

    # ---- (c2) engine-harness: the Morpho false-pass (rc=0 zero harnesses) ----
    def test_fail_engine_false_pass(self):
        ws = _build_complete_ws(self._tmp)
        # Rewrite the engine step to the false-pass shape: status=ok, rc=0,
        # EMPTY stdout, ZERO harness/property count - "ran" but executed nothing.
        eng = ws / ".auditooor" / "solidity-deep-audit" / "echidna-campaign.json"
        eng.write_text(json.dumps({
            "schema": "auditooor.solidity_deep_audit.step.v1",
            "status": "ok", "returncode": 0, "tool": "echidna-campaign",
            "generated_at": "2026-05-30T10:01:00Z",
            "run_id": "auditrun-current",
            "stdout_tail": "", "stdout_log": None,
        }), encoding="utf-8")
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-engine-false-pass", out)
        self.assertEqual(rc, 1)
        eh = [s for s in out["signals"] if s["signal"] == "engine-harness"][0]
        self.assertFalse(eh["ok"])
        self.assertIn("false-pass", eh["reason"])

    # ---- (h2) advisory-corpus incomplete (the Zebra 4-of-25 false-clean) ----
    def test_fail_advisory_corpus_incomplete(self):
        ws = _build_complete_ws(self._tmp)
        _write_json(ws / ".auditooor" / "advisory_corpus_parity.json", {
            "published_advisory_count": 25, "corpus_advisory_record_count": 4,
        })
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-advisory-corpus-incomplete", out)
        self.assertEqual(rc, 1)
        ac = [s for s in out["signals"] if s["signal"] == "advisory-corpus"][0]
        self.assertIn("4-of-25", ac["reason"])

    def test_advisory_corpus_accepts_tool_native_count_aliases(self):
        ws = _build_complete_ws(self._tmp)
        _write_json(ws / ".auditooor" / "advisory_corpus_parity.json", {
            "schema_version": "auditooor.advisory_corpus_completeness.v1",
            "repo": "leanEthereum/leanVM",
            "published_count": 0,
            "ingested_count": 0,
            "published_ghsa_ids": [],
            "missing_ghsa_ids": [],
            "verdict": "pass-advisory-corpus-complete",
        })
        rc, out = _run(ws)
        ac = [s for s in out["signals"] if s["signal"] == "advisory-corpus"][0]
        self.assertTrue(ac["ok"], ac)
        self.assertEqual(ac["detail"]["published"], 0)
        self.assertEqual(ac["detail"]["corpus"], 0)

        _write_json(ws / ".auditooor" / "advisory_corpus_parity.json", {
            "schema_version": "auditooor.advisory_corpus_completeness.v1",
            "repo": "nonEvm/example",
            "published_count": 3,
            "ingested_count": 1,
            "published_ghsa_ids": ["GHSA-1", "GHSA-2", "GHSA-3"],
            "missing_ghsa_ids": ["GHSA-2", "GHSA-3"],
            "verdict": "fail-advisory-corpus-incomplete",
        })
        rc, out = _run(ws)
        self.assertEqual(rc, 1)
        ac = [s for s in out["signals"] if s["signal"] == "advisory-corpus"][0]
        self.assertFalse(ac["ok"], ac)
        self.assertIn("1-of-3", ac["reason"])

    # ---- (h2) advisory-corpus: no ledger at all also fails ----
    def test_fail_advisory_corpus_no_ledger(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "advisory_corpus_parity.json").unlink()
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-advisory-corpus-incomplete", out)
        self.assertEqual(rc, 1)

    # ---- (i2) mined-landed: un-landed sidecars (LEARNING_DEBT) ----
    def test_fail_mined_not_landed_ledger_mismatch(self):
        ws = _build_complete_ws(self._tmp)
        # The fixture leaves exactly 1 finding sidecar on disk, so the ledger's
        # declared sidecar count must match it (1) for the landed<mined
        # LEARNING_DEBT path to fire (rather than the stale-count-mismatch path).
        _write_json(ws / ".auditooor" / "mined_landed_parity.json", {
            "sidecar_count": 1, "landed_count": 0,
        })
        with mock.patch.dict(os.environ, {"AUDITOOOR_L37_MINED_LANDED_STRICT": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-mined-not-landed", out)
        self.assertEqual(rc, 1)
        ml = [s for s in out["signals"] if s["signal"] == "mined-landed"][0]
        self.assertIn("LEARNING_DEBT", ml["reason"])

    # ---- (i2) mined-landed: sidecars present but no ledger ----
    def test_fail_mined_not_landed_no_ledger(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "mined_landed_parity.json").unlink()
        # the hunt fixture left 1 sidecar in hunt_findings_sidecars/
        with mock.patch.dict(os.environ, {"AUDITOOOR_L37_MINED_LANDED_STRICT": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-mined-not-landed", out)
        self.assertEqual(rc, 1)

    # ---- (i2) mined-landed: explicit sidecar-accounted parity passes ----
    def test_mined_landed_passes_with_explicit_sidecars_accounted(self):
        ws = _build_complete_ws(self._tmp)
        _write_json(ws / ".auditooor" / "mined_landed_parity.json", {
            "sidecar_count": 42,
            "corpus_record_count": 22,
            "sidecars_accounted": 42,
            "per_sidecar_disposition": {f"sidecar-{i}": "accounted" for i in range(42)},
        })
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        ml = [s for s in out["signals"] if s["signal"] == "mined-landed"][0]
        self.assertEqual(ml["detail"]["accounted"], 42)

    # ---- (i2) mined-landed: broad learning manifest record counts do not pass ----
    def test_learning_parity_record_count_does_not_imply_sidecar_parity(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "mined_landed_parity.json").unlink()
        _write_json(ws / ".auditooor" / "learning_parity_manifest.json", {
            "sidecar_count": 42,
            "corpus_record_count": 22,
            "sidecars_accounted": 42,
        })
        with mock.patch.dict(os.environ, {"AUDITOOOR_L37_MINED_LANDED_STRICT": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-mined-not-landed", out)
        self.assertEqual(rc, 1)
        ml = [s for s in out["signals"] if s["signal"] == "mined-landed"][0]
        self.assertEqual(ml["detail"]["landed"], 22)
        self.assertIsNone(ml["detail"]["accounted"])

    # ---- (i2) mined-landed: local learning artifacts need explicit parity ledger ----
    def test_local_learning_artifacts_without_parity_ledger_do_not_pass(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "mined_landed_parity.json").unlink()
        _write_json(ws / ".auditooor" / "invariant_ledger.json", {"sidecars_accounted": 1})
        _write_json(ws / ".auditooor" / "workspace_detector_seeds.json", {"sidecars_accounted": 1})
        (ws / "reports" / "known_dead_ends.jsonl").write_text(
            '{"sidecar":"reentrancy"}\n', encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {"AUDITOOOR_L37_MINED_LANDED_STRICT": "1"}):
            rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-mined-not-landed", out)
        self.assertEqual(rc, 1)

    # ---- (i2) mined-landed: explicit ledger takes precedence over broad manifest ----
    def test_explicit_mined_landed_parity_takes_precedence(self):
        ws = _build_complete_ws(self._tmp)
        _write_json(ws / ".auditooor" / "learning_parity_manifest.json", {
            "sidecar_count": 42,
            "corpus_record_count": 22,
        })
        _write_json(ws / ".auditooor" / "mined_landed_parity.json", {
            "sidecar_count": 42,
            "sidecars_accounted": 42,
        })
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        ml = [s for s in out["signals"] if s["signal"] == "mined-landed"][0]
        self.assertTrue(ml["artifacts"][0].endswith("mined_landed_parity.json"))

    # ---- (k) fork-divergence: fork target w/o probe artifact fails ----
    def test_fail_fork_divergence_not_run(self):
        ws = _build_complete_ws(self._tmp)
        # mark as a fork target via a pinned git rev in Cargo.toml
        (ws / "Cargo.toml").write_text(
            '[dependencies]\n'
            'upstream = { git = "https://github.com/x/y", '
            'rev = "deadbeefcafe1234" }\n',
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-fork-divergence-not-run", out)
        self.assertEqual(rc, 1)
        fd = [s for s in out["signals"] if s["signal"] == "fork-divergence"][0]
        self.assertTrue(fd["detail"]["is_fork"])

    # ---- (k) fork-divergence: fork target WITH probe artifact passes ----
    def test_pass_fork_divergence_with_artifact(self):
        ws = _build_complete_ws(self._tmp)
        (ws / "Cargo.toml").write_text(
            '[dependencies]\n'
            'upstream = { git = "https://github.com/x/y", '
            'rev = "deadbeefcafe1234" }\n',
            encoding="utf-8",
        )
        _write_json(ws / ".auditooor" / "fork_divergence_prober.json",
                    {"schema": "auditooor.fork_divergence_prober.v1", "leads": []})
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)

    def test_same_family_unproven_differential_seed_requires_fork_divergence(self):
        ws = _build_complete_ws(self._tmp)
        _write_json(
            ws / ".auditooor" / "differential_seed_queue.json",
            {
                "schema": "auditooor.cross_workspace_differential_seed.v1",
                "target_families": ["morpho-blue"],
                "selected_siblings": [
                    {"workspace": "morpho", "families": ["morpho-blue"]},
                    {"workspace": "zebra", "families": ["zcash"]},
                ],
                "hypotheses": [
                    {"hypothesis_id": "DIFF-1", "verdict": "unproven"},
                    {"hypothesis_id": "DIFF-2", "verdict": "falsified"},
                    {"hypothesis_id": "DIFF-3", "prior_workspace": "zebra", "verdict": "unproven"},
                ],
            },
        )
        rc, out = _run(ws)
        self.assertIn("fail-fork-divergence-not-run", out["failures"], out)
        self.assertEqual(rc, 1)
        fd = [s for s in out["signals"] if s["signal"] == "fork-divergence"][0]
        self.assertEqual(fd["verdict"], "fail-fork-divergence-not-run")
        self.assertTrue(fd["detail"]["is_fork"])
        self.assertTrue(any("same-family differential seed" in r for r in fd["detail"]["fork_reasons"]))
        self.assertTrue(any("unproven=1" in r for r in fd["detail"]["fork_reasons"]))

    # ====================================================================
    # ADD-A: cross-ws-seed sibling-aware enforcement.
    # <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
    # ====================================================================

    # ---- ADD-A: same-family sibling exists, no seed -> distinct fail ----
    def test_fail_cross_ws_seed_sibling_exists(self):
        ws = _build_complete_ws(self._tmp)
        # drop the seed artifact
        (ws / ".auditooor" / "cross_workspace_seed.json").unlink()
        # declare THIS workspace's family
        (ws / ".auditooor" / "engagement_family.txt").write_text(
            "morpho-blue\n", encoding="utf-8")
        # build a same-family SIBLING alongside ws (same parent = self._tmp)
        sib = self._tmp / "morpho-v2"
        (sib / ".auditooor").mkdir(parents=True, exist_ok=True)
        (sib / ".auditooor" / "engagement_family.txt").write_text(
            "morpho-blue\n", encoding="utf-8")
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-cross-ws-seed-sibling-exists", out)
        self.assertEqual(rc, 1)
        cw = [s for s in out["signals"] if s["signal"] == "cross-ws-seed"][0]
        self.assertEqual(cw["verdict"], "fail-cross-ws-seed-sibling-exists")
        self.assertEqual(cw["detail"]["family"], "morpho-blue")

    # ---- ADD-A: seed present -> pass even with a sibling ----
    def test_pass_cross_ws_seed_present_with_sibling(self):
        ws = _build_complete_ws(self._tmp)  # seed artifact present
        (ws / ".auditooor" / "engagement_family.txt").write_text(
            "morpho-blue\n", encoding="utf-8")
        sib = self._tmp / "morpho-v2"
        (sib / ".auditooor").mkdir(parents=True, exist_ok=True)
        (sib / ".auditooor" / "engagement_family.txt").write_text(
            "morpho-blue\n", encoding="utf-8")
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)

    # ---- ADD-A: NO same-family sibling -> generic fail-no-cross-ws-seed ----
    def test_fail_no_cross_ws_seed_no_sibling(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "cross_workspace_seed.json").unlink()
        (ws / ".auditooor" / "engagement_family.txt").write_text(
            "morpho-blue\n", encoding="utf-8")
        # a sibling of a DIFFERENT family must NOT trigger the sibling verdict
        sib = self._tmp / "aave-v3"
        (sib / ".auditooor").mkdir(parents=True, exist_ok=True)
        (sib / ".auditooor" / "engagement_family.txt").write_text(
            "aave\n", encoding="utf-8")
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-cross-ws-seed", out)
        self.assertEqual(rc, 1)

    # ---- ADD-A: sibling-exists fail is rebuttable ----
    def test_rebuttal_cross_ws_seed_sibling(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "cross_workspace_seed.json").unlink()
        (ws / ".auditooor" / "engagement_family.txt").write_text(
            "morpho-blue\n", encoding="utf-8")
        sib = self._tmp / "morpho-v2"
        (sib / ".auditooor").mkdir(parents=True, exist_ok=True)
        (sib / ".auditooor" / "engagement_family.txt").write_text(
            "morpho-blue\n", encoding="utf-8")
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: cross-ws-seed: sibling is a stale dupe, no shared knowledge\n",
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)

    # ====================================================================
    # ADD-D: brain-prime + per-function hacker-question required artifacts.
    # <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
    # ====================================================================

    # ---- (j2) brain-prime missing ----
    def test_fail_no_brain_prime(self):
        ws = _build_complete_ws(self._tmp)
        (ws / "BRAIN_PRIMING_REPORT.md").unlink()
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-brain-prime", out)
        self.assertEqual(rc, 1)
        bp = [s for s in out["signals"] if s["signal"] == "brain-prime"][0]
        self.assertFalse(bp["ok"])

    # ---- (j2) brain-prime via receipt also passes ----
    def test_pass_brain_prime_via_receipt(self):
        ws = _build_complete_ws(self._tmp)
        (ws / "BRAIN_PRIMING_REPORT.md").unlink()
        _write_json(ws / ".auditooor" / "brain_prime_receipt.json", {"ok": True})
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)

    # ---- (j3) hacker-questions missing ----
    def test_fail_no_hacker_questions(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "per_fn_hacker_questions.jsonl").unlink()
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-hacker-questions", out)
        self.assertEqual(rc, 1)
        hq = [s for s in out["signals"] if s["signal"] == "hacker-questions"][0]
        self.assertFalse(hq["ok"])

    # ---- (j3) hacker-questions via alt name pattern passes ----
    def test_pass_hacker_questions_alt_name(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "per_fn_hacker_questions.jsonl").unlink()
        (ws / "reports").mkdir(parents=True, exist_ok=True)
        (ws / "reports" / "vault_hacker_questions.json").write_text(
            "{}", encoding="utf-8")
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)

    # ---- ADD-D: both new signals rebuttable ----
    def test_rebuttal_brain_prime_and_hacker_questions(self):
        ws = _build_complete_ws(self._tmp)
        (ws / "BRAIN_PRIMING_REPORT.md").unlink()
        (ws / ".auditooor" / "per_fn_hacker_questions.jsonl").unlink()
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: brain-prime: greenfield, no priors\n"
            "l37-rebuttal: hacker-questions: trivial single-fn target\n",
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)

    # ---- rebuttal: a NEW signal can be rebutted (advisory-corpus) ----
    def test_rebuttal_new_signal_advisory_corpus(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "advisory_corpus_parity.json").unlink()
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: advisory-corpus: target has no published advisories\n",
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        ac = [s for s in out["signals"] if s["signal"] == "advisory-corpus"][0]
        self.assertEqual(ac["verdict"], "ok-rebuttal")


# --------------------------------------------------------------------------
# (c2) engine-harness PROOF-gate wiring (PR4b): L37 CALLS the proof gate.
# These tests load the module in-process so they can stub PR4a's proof gate
# (which lands in parallel and is not on disk here) and exercise the
# stub-vs-real harness decision: harness count > 0 AND every counted harness
# passes the proof gate => credit; any unproven counted harness => fail-closed.
# --------------------------------------------------------------------------
def _load_acc_module():
    spec = importlib.util.spec_from_file_location("_acc_under_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_acc_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


_ACC = _load_acc_module()


def _ws_with_one_real_engine_step(root: Path) -> Path:
    """Minimal workspace with exactly one engine step that executed a harness
    (positive property count). Enough to drive check_engine_harness directly.

    Lays down a real in-scope ``src/Vault.sol`` so the workspace is detected as
    a genuine EVM target (``_is_evm_workspace``). The engine-harness EVM proof
    gate must fire for a REAL EVM workspace; the non-EVM-source narrowing in
    ``_engine_step_requires_evm_proof`` only suppresses the gate when the
    workspace has NO Solidity/Vyper source (the near-intents Rust false-pass)."""
    ws = root / "eh_ws"
    eng = ws / ".auditooor" / "solidity-deep-audit"
    eng.mkdir(parents=True, exist_ok=True)
    src = ws / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    _write_json(eng / "echidna-campaign.json", {
        "status": "ok", "returncode": 0, "tool": "echidna-campaign",
        "properties": 7, "stdout_tail": "echidna_property_balance: passing (256 calls)",
    })
    return ws


def _ws_with_one_rust_proptest_step(root: Path) -> Path:
    """Minimal workspace with one Rust proptest manifest that executed tests."""
    ws = root / "rust_eh_ws"
    run = ws / "fuzz_runs" / "20260601T010203Z"
    run.mkdir(parents=True, exist_ok=True)
    _write_json(run / "manifest.json", {
        "status": "pass",
        "engine": "rust-proptest",
        "packages": "zebra-chain",
        "proptest_cases": "64",
        "notes": "all proptest properties held (12 tests passed, PROPTEST_CASES=64)",
    })
    return ws


class EngineHarnessProofGateWiringTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        # snapshot + clear the strict env so each test sets it explicitly
        self._saved_strict = os.environ.pop("AUDITOOOR_L37_ENGINE_PROOF_STRICT", None)
        self._saved_enforce = os.environ.pop("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", None)
        self._orig_call = _ACC._call_engine_proof_gate

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)
        _ACC._call_engine_proof_gate = self._orig_call
        os.environ.pop("AUDITOOOR_L37_ENGINE_PROOF_STRICT", None)
        os.environ.pop("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", None)
        if self._saved_strict is not None:
            os.environ["AUDITOOOR_L37_ENGINE_PROOF_STRICT"] = self._saved_strict
        if self._saved_enforce is not None:
            os.environ["ENFORCE_AUTONOMOUS_PROOF_CONVERSION"] = self._saved_enforce

    # --- proof gate present, REAL harness: PASS ---
    def test_proof_gate_real_harness_passes(self):
        ws = _ws_with_one_real_engine_step(self._tmp)
        _ACC._call_engine_proof_gate = lambda w: {
            "verdict": "pass-engine-harness-proof",
            "proven": ["echidna-campaign.json"], "unproven": [],
        }
        r = _ACC.check_engine_harness(ws)
        self.assertTrue(r.ok, r.reason)
        self.assertIn("PROVEN", r.reason)
        self.assertEqual(r.detail["proof_gate"], "ran")

    # --- proof gate present, FAKE/stub harness: FAIL-CLOSED ---
    def test_proof_gate_stub_harness_fails_closed(self):
        ws = _ws_with_one_real_engine_step(self._tmp)
        # count > 0 (the step executed 7 properties) but the proof gate says
        # the counted harness is a tautological stub.
        _ACC._call_engine_proof_gate = lambda w: {
            "verdict": "fail-tautological-harness",
            "proven": [], "unproven": ["echidna-campaign.json"],
            "reason": "echidna_property_x is assert(true) - touches no in-scope fn",
        }
        r = _ACC.check_engine_harness(ws)
        self.assertFalse(r.ok, r.reason)
        self.assertIn("proof gate", r.reason)
        self.assertIn("tautological", r.reason)
        self.assertEqual(r.detail["proof_gate"], "ran")
        self.assertEqual(r.detail["unproven"], ["echidna-campaign.json"])

    # --- proof gate present, pass verdict but a stray unproven => still fail ---
    def test_proof_gate_pass_verdict_with_unproven_fails(self):
        ws = _ws_with_one_real_engine_step(self._tmp)
        _ACC._call_engine_proof_gate = lambda w: {
            "verdict": "pass-engine-harness-proof",
            "proven": ["a.json"], "unproven": ["echidna-campaign.json"],
        }
        r = _ACC.check_engine_harness(ws)
        self.assertFalse(r.ok, r.reason)

    # --- proof gate ABSENT, non-strict: legacy positive-count credit ---
    def test_proof_gate_absent_nonstrict_legacy_credit(self):
        ws = _ws_with_one_real_engine_step(self._tmp)
        _ACC._call_engine_proof_gate = lambda w: None  # PR4a not on disk
        r = _ACC.check_engine_harness(ws)
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(r.detail["proof_gate"], "unavailable")
        self.assertFalse(r.detail["strict"])

    # --- proof gate ABSENT, STRICT: fail-closed (manifest required) ---
    def test_proof_gate_absent_strict_fails_closed(self):
        ws = _ws_with_one_real_engine_step(self._tmp)
        os.environ["AUDITOOOR_L37_ENGINE_PROOF_STRICT"] = "1"
        _ACC._call_engine_proof_gate = lambda w: None
        r = _ACC.check_engine_harness(ws)
        self.assertFalse(r.ok, r.reason)
        self.assertIn("strict", r.reason.lower())
        self.assertEqual(r.detail["proof_gate"], "manifest-missing")
        self.assertTrue(r.detail["strict"])

    def test_proof_gate_pass_no_engine_harness_fails_closed(self):
        ws = _ws_with_one_real_engine_step(self._tmp)
        (ws / ".auditooor" / "evm_engine_proof").mkdir(parents=True, exist_ok=True)
        _write_json(
            ws / ".auditooor" / "evm_engine_proof" / "engine_harness_proof.json",
            {"schema": "auditooor.evm_engine_harness_proof.v1"},
        )
        _ACC._call_engine_proof_gate = lambda w: {
            "verdict": "pass-no-engine-harness",
            "proven": [],
            "unproven": [],
        }
        r = _ACC.check_engine_harness(ws)
        self.assertFalse(r.ok, r.reason)
        self.assertEqual(r.detail["proof_verdict"], "pass-no-engine-harness")

    def test_advisory_only_generated_harnesses_pass_when_conversion_not_enforced(self):
        ws = _ws_with_one_real_engine_step(self._tmp)
        _ACC._call_engine_proof_gate = lambda w: {
            "verdict": "fail-no-proven-harness",
            "proven": [],
            "unproven": ["solidity-per-function-halmos:137/137"],
            "advisory_only": True,
            "reason": "generated advisory harnesses are not proof",
        }
        r = _ACC.check_engine_harness(ws)
        self.assertTrue(r.ok, r.reason)
        self.assertTrue(r.detail["advisory_autonomous_proof_conversion"])
        self.assertEqual(r.detail["proof_verdict"], "fail-no-proven-harness")

    def test_advisory_only_generated_harnesses_fail_when_conversion_enforced(self):
        ws = _ws_with_one_real_engine_step(self._tmp)
        os.environ["ENFORCE_AUTONOMOUS_PROOF_CONVERSION"] = "1"
        _ACC._call_engine_proof_gate = lambda w: {
            "verdict": "fail-no-proven-harness",
            "proven": [],
            "unproven": ["solidity-per-function-halmos:137/137"],
            "advisory_only": True,
            "reason": "generated advisory harnesses are not proof",
        }
        r = _ACC.check_engine_harness(ws)
        self.assertFalse(r.ok, r.reason)
        self.assertEqual(r.detail["proof_verdict"], "fail-no-proven-harness")

    def test_non_evm_rust_proptest_does_not_require_evm_proof(self):
        ws = _ws_with_one_rust_proptest_step(self._tmp)
        os.environ["AUDITOOOR_L37_ENGINE_PROOF_STRICT"] = "1"
        called = {"n": 0}

        def _spy(w):
            called["n"] += 1
            return {
                "verdict": "pass-no-engine-harness",
                "proven": [],
                "unproven": [],
            }

        _ACC._call_engine_proof_gate = _spy
        r = _ACC.check_engine_harness(ws)
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(called["n"], 0)
        self.assertEqual(r.detail["proof_gate"], "not-applicable-non-evm")
        self.assertEqual(len(r.detail["non_evm_executed"]), 1)
        self.assertEqual(r.detail["evm_executed"], [])

    # --- zero executed harnesses: proof gate not even reached (count==0) ---
    def test_zero_executed_harness_fails_before_proof_gate(self):
        ws = self._tmp / "zero_ws"
        eng = ws / ".auditooor" / "solidity-deep-audit"
        eng.mkdir(parents=True, exist_ok=True)
        _write_json(eng / "echidna-campaign.json", {
            "status": "ok", "returncode": 0, "tool": "echidna-campaign",
            "stdout_tail": "",  # false-pass shape, zero count
        })
        called = {"n": 0}
        def _spy(w):
            called["n"] += 1
            return {"verdict": "pass", "proven": [], "unproven": []}
        _ACC._call_engine_proof_gate = _spy
        r = _ACC.check_engine_harness(ws)
        self.assertFalse(r.ok, r.reason)
        self.assertIn("false-pass", r.reason)
        # count==0 precondition fails before the proof gate is consulted
        self.assertEqual(called["n"], 0)

    def test_scanner_stdout_is_not_harness_execution(self):
        ws = self._tmp / "scanner_ws"
        eng = ws / ".auditooor" / "solidity-deep-audit"
        eng.mkdir(parents=True, exist_ok=True)
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
        for tool in (
            "aderyn-solidity",
            "semgrep-solidity",
            "regex-detectors-solidity",
            "foundry-scaffold-verified-source",
        ):
            _write_json(eng / f"{tool}.json", {
                "status": "ok", "tool": tool, "stdout_tail": "scan complete: 12 checks",
            })
        r = _ACC.check_engine_harness(ws)
        self.assertFalse(r.ok, r.reason)
        self.assertEqual(r.detail["executed"], [])
        self.assertTrue(all("not harness execution" in row["why"] for row in r.detail["not_executed"]))

    def test_canonical_execution_manifest_requires_evm_proof(self):
        ws = self._tmp / "manifest_ws"
        ws.mkdir(parents=True, exist_ok=True)
        obj = {
            "schema": "auditooor.engine_harness_execution.v1",
            "executed_engine_harness_count": 2,
            "harnesses": [{"status": "pass"}, {"status": "pass"}],
        }
        self.assertTrue(_ACC._engine_step_requires_evm_proof("engine-harness-execution.json", obj, ws))

    # --- no engine steps at all: signal defers to live-engines (pass) ---
    def test_no_engine_steps_defers(self):
        ws = self._tmp / "empty_ws"
        ws.mkdir(parents=True, exist_ok=True)
        r = _ACC.check_engine_harness(ws)
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(r.detail["engine_steps"], 0)


class EngineStepEvmProofNonEvmWorkspaceTest(unittest.TestCase):
    """FIX A: a Solidity-named engine/detector step must NOT require the EVM
    harness proof gate on a workspace with NO in-scope Solidity/Vyper source
    (the near-intents Rust false-pass). It MUST still require proof on a real
    EVM workspace - the gate is not weakened for EVM targets."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _step(self, tool):
        return tool + ".json", {"status": "ok", "tool": tool, "stdout_tail": "x"}

    def test_solidity_detector_on_rust_workspace_not_required(self):
        # Rust source only (no .sol); a *-solidity detector / no-op foundry
        # scaffold step must not face the EVM proof gate.
        ws = self._tmp / "rust_ws"
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "lib.rs").write_text("pub fn f() {}\n", encoding="utf-8")
        for tool in ("aderyn-solidity", "semgrep-solidity",
                     "regex-detectors-solidity", "foundry-scaffold-verified-source"):
            label, obj = self._step(tool)
            self.assertFalse(
                _ACC._engine_step_requires_evm_proof(label, obj, ws),
                f"{tool} should NOT require EVM proof on a pure-Rust workspace",
            )

    def test_solidity_engine_on_real_evm_workspace_still_required(self):
        # Real Solidity source present -> the same step MUST require proof.
        ws = self._tmp / "evm_ws"
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
        for tool in ("aderyn-solidity", "echidna-campaign", "foundry-invariant-runner"):
            label, obj = self._step(tool)
            self.assertTrue(
                _ACC._engine_step_requires_evm_proof(label, obj, ws),
                f"{tool} MUST require EVM proof on a real EVM workspace",
            )

    def test_rust_engine_token_never_required(self):
        # Non-EVM engine tokens are always exempt regardless of source.
        ws = self._tmp / "any_ws"
        ws.mkdir(parents=True, exist_ok=True)
        for tool in ("rust-proptest", "bolero", "kani", "cargo-fuzz"):
            label, obj = self._step(tool)
            self.assertFalse(
                _ACC._engine_step_requires_evm_proof(label, obj, ws),
                f"{tool} is a non-EVM engine and must never require EVM proof",
            )

    def test_ws_none_preserves_legacy_evm_requirement(self):
        # Back-compat: when no workspace is supplied, an EVM-token step keeps
        # the legacy (pre-fix) "requires EVM proof" answer.
        label, obj = self._step("echidna-campaign")
        self.assertTrue(_ACC._engine_step_requires_evm_proof(label, obj, None))


class EngineProofGateLoaderTest(unittest.TestCase):
    """The loader must be a no-op (return None) until PR4a's tool is on disk."""
    def test_loader_returns_none_when_tool_absent(self):
        tool = TOOL.with_name("engine-harness-proof-check.py")
        if tool.is_file():
            self.skipTest("PR4a proof gate tool is on disk; loader will load it")
        self.assertIsNone(_ACC._load_engine_proof_gate_module())


class Pr10NovelVectorSignalTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_miner_output_passes(self):
        ws = self._tmp / "ws"
        (ws / ".auditooor").mkdir(parents=True)
        _write_json(ws / ".auditooor" / "novel_vector_invariants.json", {"invariants": []})
        r = _ACC.check_novel_vector(ws)
        self.assertTrue(r.ok, r.reason)

    def test_pr9_demo_summary_passes(self):
        ws = self._tmp / "ws2"
        d = ws / ".auditooor" / "pr9_0day_demo"
        d.mkdir(parents=True)
        _write_json(d / "pr9_0day_demo_summary.json", {"ok": True})
        r = _ACC.check_novel_vector(ws)
        self.assertTrue(r.ok, r.reason)

    def test_absent_fails(self):
        ws = self._tmp / "ws3"
        (ws / ".auditooor").mkdir(parents=True)
        r = _ACC.check_novel_vector(ws)
        self.assertFalse(r.ok)


class Pr10AdversarialPanelSignalTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_no_final_leads_na_passes(self):
        ws = self._tmp / "ws"
        (ws / ".auditooor").mkdir(parents=True)
        r = _ACC.check_adversarial_panel(ws)
        self.assertTrue(r.ok, r.reason)

    def test_final_leads_without_panel_fails(self):
        ws = self._tmp / "ws2"
        (ws / ".auditooor").mkdir(parents=True)
        (ws / ".auditooor" / "final_leads.json").write_text("{}", encoding="utf-8")
        r = _ACC.check_adversarial_panel(ws)
        self.assertFalse(r.ok)

    def test_final_leads_with_panel_passes(self):
        ws = self._tmp / "ws3"
        (ws / ".auditooor").mkdir(parents=True)
        (ws / ".auditooor" / "final_leads.json").write_text("{}", encoding="utf-8")
        _write_json(ws / ".auditooor" / "adversarial_panel.json", {"panel_verdict": "pass-survived-panel"})
        r = _ACC.check_adversarial_panel(ws)
        self.assertTrue(r.ok, r.reason)


class Pr10Evm0dayProofSignalTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _evm_ws(self, name):
        ws = self._tmp / name
        (ws / "src").mkdir(parents=True)
        (ws / "src" / "V.sol").write_text("contract V {}\n", encoding="utf-8")
        (ws / ".auditooor").mkdir(parents=True)
        return ws

    def test_non_evm_na_passes(self):
        ws = self._tmp / "go_ws"
        (ws / "src").mkdir(parents=True)
        (ws / "src" / "m.go").write_text("package main\n", encoding="utf-8")
        (ws / ".auditooor").mkdir(parents=True)
        _write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [{"severity": "High"}]})
        r = _ACC.check_evm_0day_proof(ws)
        self.assertTrue(r.ok, r.reason)
        self.assertFalse(r.detail["is_evm"])

    def test_evm_no_medium_plus_na_passes(self):
        ws = self._evm_ws("evm_low")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [{"severity": "Low"}]})
        r = _ACC.check_evm_0day_proof(ws)
        self.assertTrue(r.ok, r.reason)

    def test_evm_medium_plus_without_proof_advisory_by_default(self):
        ws = self._evm_ws("evm_high")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [{"severity": "Critical"}]})
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": ""}):
            r = _ACC.check_evm_0day_proof(ws)
        self.assertTrue(r.ok, r.reason)
        self.assertTrue(r.detail["advisory_autonomous_proof_conversion"])

    def test_evm_medium_plus_without_proof_fails_when_enforced(self):
        ws = self._evm_ws("evm_high_enforced")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [{"severity": "Critical"}]})
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            r = _ACC.check_evm_0day_proof(ws)
        self.assertFalse(r.ok)

    def test_evm_medium_plus_with_proof_passes(self):
        ws = self._evm_ws("evm_proven")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [{"severity": "High"}]})
        _write_json(ws / ".auditooor" / "evm_0day_proof.json", {"verdict": "proof-backed"})
        r = _ACC.check_evm_0day_proof(ws)
        self.assertTrue(r.ok, r.reason)
        self.assertTrue(r.detail["proof_valid"])

    def test_evm_likely_severity_requires_proof_when_enforced(self):
        ws = self._evm_ws("evm_likely_high")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [{"likely_severity": "High"}]})
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            r = _ACC.check_evm_0day_proof(ws)
        self.assertFalse(r.ok)
        self.assertTrue(r.detail["medium_plus_candidate"])

    def test_evm_malformed_proof_fails_when_enforced(self):
        ws = self._evm_ws("evm_malformed")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [{"severity": "High"}]})
        (ws / ".auditooor" / "evm_0day_proof.json").write_text("{not-json", encoding="utf-8")
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            r = _ACC.check_evm_0day_proof(ws)
        self.assertFalse(r.ok)
        self.assertFalse(r.detail["proof_valid"])

    def test_evm_scaffold_only_proof_fails_when_enforced(self):
        ws = self._evm_ws("evm_scaffold")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [{"severity": "High"}]})
        _write_json(ws / ".auditooor" / "evm_0day_proof.json", {"verdict": "scaffold-only-not-run"})
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            r = _ACC.check_evm_0day_proof(ws)
        self.assertFalse(r.ok)
        self.assertFalse(r.detail["proof_valid"])

    def test_evm_blocked_with_obligation_proof_fails_when_enforced(self):
        ws = self._evm_ws("evm_blocked")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [{"severity": "High"}]})
        _write_json(ws / ".auditooor" / "evm_0day_proof.json", {"status": "blocked-with-obligation"})
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            r = _ACC.check_evm_0day_proof(ws)
        self.assertFalse(r.ok)
        self.assertFalse(r.detail["proof_valid"])

    def test_evm_status_complete_is_not_proof_backed_when_enforced(self):
        ws = self._evm_ws("evm_status_complete")
        _write_json(ws / ".auditooor" / "exploit_queue.json", {"queue": [{"severity": "High"}]})
        _write_json(ws / ".auditooor" / "evm_0day_proof.json", {"status": "complete"})
        with mock.patch.dict(os.environ, {"ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}):
            r = _ACC.check_evm_0day_proof(ws)
        self.assertFalse(r.ok)
        self.assertFalse(r.detail["proof_valid"])


class TypedProofTerminalCloseoutTest(unittest.TestCase):
    """Admitted proof rows cannot close this final consumer by status alone."""

    def _queue(self) -> dict:
        parent = ["zdo_parent", "zdr_revision"]
        return {
            "schema": "auditooor.exploit_queue.v1",
            "queue_role": "proof_tasks",
            "queue": [{
                "lead_id": "zdpq_lead",
                "obligation_id": parent[0],
                "revision_id": parent[1],
                "proof_status": "closed_negative",
                "zero_day_proof_projection": {
                    "schema": "auditooor.zero_day_proof_queue_projection.v1",
                    "freeze_receipt_id": "a" * 64,
                    "freeze_input_fingerprint": "b" * 64,
                    "obligation_source_row_sha256": "c" * 64,
                    "parent_ids": parent,
                    "selection_ordinal": 1,
                    "question_evidence": [{"question_id": "q0"}],
                },
                "zero_day_proof_admission": {
                    "freeze_receipt_id": "a" * 64,
                    "input_fingerprint": "b" * 64,
                    "obligation_source_row_sha256": "c" * 64,
                    "parent_ids": parent,
                },
            }],
            "zero_day_proof_admission": {
                "schema": "auditooor.zero_day_proof_admission.v1",
                "queue_role": "proof_tasks",
                "admission_id": "zdpa_" + "d" * 64,
                "input_queue_sha256": "e" * 64,
                "freeze_receipt_id": "a" * 64,
                "freeze_input_fingerprint": "b" * 64,
                "admitted_count": 1,
                "admitted_parents": [{"obligation_id": parent[0], "revision_id": parent[1]}],
            },
        }

    def test_typed_terminal_status_requires_exact_source_cited_record(self):
        queue = self._queue()
        row = queue["queue"][0]
        entry = _ACC._typed_queue_entries(queue)[row["lead_id"]]
        self.assertFalse(_ACC._lead_is_terminal_work_backed(row, entry))
        row["terminal_join"] = {
            "schema": "auditooor.zero_day_proof_terminal_verdict.v1",
            "parent_ids": entry["parent_ids"],
            "envelope_id": entry["envelope_id"],
            "source_cite": "src/Vault.sol:L42",
        }
        self.assertTrue(_ACC._lead_is_terminal_work_backed(row, entry))

    def test_invalid_typed_queue_hard_fails_conversion_throughput(self):
        with tempfile.TemporaryDirectory() as temporary:
            ws = Path(temporary) / "ws"
            payload = self._queue()
            payload["entries"] = [{"legacy": "discovery-row"}]
            _write_json(ws / ".auditooor" / "exploit_queue.json", payload)
            result = _ACC.check_conversion_throughput(ws)
        self.assertFalse(result.ok)
        self.assertIn("typed proof queue is invalid", result.reason)

    def test_typed_terminal_closeout_requires_persisted_envelope(self):
        with tempfile.TemporaryDirectory() as temporary:
            ws = Path(temporary) / "ws"
            queue = self._queue()
            row = queue["queue"][0]
            entry = _ACC._typed_queue_entries(queue)[row["lead_id"]]
            row["terminal_join"] = {
                "schema": "auditooor.zero_day_proof_terminal_verdict.v1",
                "parent_ids": entry["parent_ids"],
                "envelope_id": entry["envelope_id"],
                "source_cite": "src/Vault.sol:L42",
            }
            queue_path = ws / ".auditooor" / "exploit_queue.zero_day_admitted.json"
            _write_json(queue_path, queue)
            present, terminal = _ACC._typed_prove_top_leads_all_terminal(ws)
            self.assertTrue(present)
            self.assertFalse(terminal)
            envelope_tool = _ACC._load_typed_envelope_tool()
            envelope_tool.materialize(
                ws, queue_path, ws / ".auditooor" / "zero_day_proof_envelope.json",
            )
            present, terminal = _ACC._typed_prove_top_leads_all_terminal(ws)
            self.assertTrue(present)
            self.assertTrue(terminal)

    def test_conversion_throughput_rejects_stale_persisted_typed_queue(self):
        with tempfile.TemporaryDirectory() as temporary:
            ws = Path(temporary) / "ws"
            queue = self._queue()
            row = queue["queue"][0]
            entry = _ACC._typed_queue_entries(queue)[row["lead_id"]]
            row["terminal_join"] = {
                "schema": "auditooor.zero_day_proof_terminal_verdict.v1",
                "parent_ids": entry["parent_ids"],
                "envelope_id": entry["envelope_id"],
                "source_cite": "src/Vault.sol:L42",
            }
            queue_path = ws / ".auditooor" / "exploit_queue.json"
            _write_json(queue_path, queue)
            envelope_tool = _ACC._load_typed_envelope_tool()
            envelope_tool.materialize(
                ws, queue_path, ws / ".auditooor" / "zero_day_proof_envelope.json",
            )
            queue["queue"][0]["zero_day_proof_projection"]["selection_ordinal"] = 2
            _write_json(queue_path, queue)
            result = _ACC.check_conversion_throughput(ws)
            self.assertFalse(result.ok)
            self.assertIn("typed proof queue is invalid", result.reason)
            self.assertIn("typed_proof_envelope_invalid", result.reason)


class Pr10ForkHuntStageEvidenceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_hunt_stage_queue_marker_credits_fork_divergence(self):
        ws = self._tmp / "fork_ws"
        (ws / ".auditooor").mkdir(parents=True)
        (ws / "Cargo.toml").write_text(
            '[dependencies]\nfoo = { git = "https://x/y", rev = "abcdef1234" }\n',
            encoding="utf-8")
        _write_json(ws / ".auditooor" / "proof_obligation_queue.json", {
            "queue": [], "fork_divergence_last_run": "2026-05-30T00:00:00Z",
        })
        r = _ACC.check_fork_divergence(ws)
        self.assertTrue(r.ok, r.reason)

    def test_hunt_stage_queue_without_marker_does_not_credit(self):
        ws = self._tmp / "fork_ws2"
        (ws / ".auditooor").mkdir(parents=True)
        (ws / "Cargo.toml").write_text(
            '[dependencies]\nfoo = { git = "https://x/y", rev = "abcdef1234" }\n',
            encoding="utf-8")
        _write_json(ws / ".auditooor" / "proof_obligation_queue.json", {"queue": []})
        r = _ACC.check_fork_divergence(ws)
        self.assertFalse(r.ok)


class CoverageMapSignalTest(unittest.TestCase):
    """Signal (o): SWEPT-SURFACE coverage map - first-class L37 signal."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    # ---- absence of the coverage report fails closed ----
    def test_fail_no_coverage_map(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "coverage_report.json").unlink()
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])

    # ---- malformed report (missing counts) fails closed ----
    def test_fail_malformed_coverage_report(self):
        ws = _build_complete_ws(self._tmp)
        _write_json(ws / ".auditooor" / "coverage_report.json",
                    {"schema": "auditooor.workspace_coverage_report.v1"})
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)

    # ---- (b) mostly-uncovered: the TRUE uncovered count is SURFACED in the
    #         gate output, and high-uncovered WARNS loudly but does NOT fail ----
    def test_high_uncovered_warns_and_surfaces_count(self):
        ws = _build_complete_ws(self._tmp)
        for i in range(742):
            (ws / "src" / f"Uncovered{i}.sol").write_text(
                f"contract Uncovered{i} {{}}\n",
                encoding="utf-8",
            )
        # Hyperbridge-shaped signal: 742 of 743 UNCOVERED.
        _write_json(
            ws / ".auditooor" / "coverage_report.json",
            _coverage_report(ws, list_cap=2),
        )
        rc, out = _run(ws)
        # WARN, not fail: the whole audit still passes.
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertTrue(cm["ok"])
        # the TRUE uncovered count is surfaced, not hidden
        self.assertEqual(cm["detail"]["uncovered"], 742)
        self.assertTrue(cm["detail"]["high_uncovered"])
        self.assertEqual(cm["detail"]["coverage_basis"], "source-unit")
        self.assertIn("742", cm["reason"])
        # top-level loud warn block carries the count too
        self.assertIsNotNone(out["coverage_warn"])
        self.assertIn("742", out["coverage_warn"])

    def test_fail_coverage_report_without_source_unit_basis(self):
        ws = _build_complete_ws(self._tmp)
        _write_json(ws / ".auditooor" / "coverage_report.json", {
            "schema": "auditooor.workspace_coverage_report.v1",
            "workspace_name": "ws", "total_units": 743, "covered": 743,
            "uncovered": 0, "coverage_fraction": 1.0,
            "uncovered_units": [],
            "uncovered_units_truncated": False, "uncovered_units_omitted": 0,
        })
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])
        self.assertEqual(cm["detail"]["coverage_basis"], "")

    def test_fail_stale_coverage_report_with_source_unit_basis(self):
        ws = _build_complete_ws(self._tmp)
        (ws / "src" / "NewSurface.sol").write_text(
            "contract NewSurface {}\n",
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])
        self.assertIn("out of sync", cm["reason"])
        self.assertEqual(
            cm["detail"]["mismatches"]["source_freshness.source_units_count"],
            {"stored": 1, "recomputed": 2},
        )

    def test_fail_coverage_report_from_different_workspace(self):
        ws = _build_complete_ws(self._tmp)
        report_path = ws / ".auditooor" / "coverage_report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["workspace"] = str(self._tmp / "other-ws")
        report["workspace_name"] = "other-ws"
        _write_json(report_path, report)

        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])
        self.assertIn("different workspace", cm["reason"])
        self.assertEqual(cm["detail"]["expected_workspace_name"], ws.name)

    def test_fail_zero_denominator_coverage_report(self):
        ws = _build_complete_ws(self._tmp)
        shutil.rmtree(ws / "src")
        (ws / "src").mkdir()
        _refresh_coverage_report(ws)

        result = _ACC.check_coverage_map(ws)
        self.assertFalse(result.ok)
        self.assertIn("zero source units", result.reason)
        self.assertEqual(result.detail["total_units"], 0)

    def test_fail_stale_coverage_report_when_source_content_changes_same_units(self):
        ws = _build_complete_ws(self._tmp)
        (ws / "src" / "Vault.sol").write_text(
            "contract Vault { /* same unit, changed bytes */ }\n",
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])
        self.assertIn("source_freshness.source_files_sha256", cm["detail"]["mismatches"])

    def test_fail_coverage_report_missing_denominator_honesty_freshness_field(self):
        ws = _build_complete_ws(self._tmp)
        report_path = ws / ".auditooor" / "coverage_report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["source_freshness"].pop("function_denominator_status")
        _write_json(report_path, report)
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])
        self.assertIn("function_denominator_status", cm["detail"]["source_freshness_error"])

    def test_fail_coverage_report_with_stale_top_level_denominator_honesty(self):
        ws = _build_complete_ws(self._tmp)
        report_path = ws / ".auditooor" / "coverage_report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["function_denominator_status"] = "source-unit-only"
        report["full_in_scope_function_denominator"] = False
        _write_json(report_path, report)
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])
        self.assertEqual(
            cm["detail"]["mismatches"]["coverage_report.function_denominator_status"],
            {"stored": "source-unit-only", "recomputed": "complete"},
        )

    def test_fail_coverage_report_top_level_numerator_drift(self):
        ws = _build_complete_ws(self._tmp)
        report_path = ws / ".auditooor" / "coverage_report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report.update({
            "covered": 0,
            "uncovered": 1,
            "coverage_fraction": 0.0,
            "uncovered_units": ["Vault.sol"],
            "uncovered_units_listed": 1,
            "uncovered_units_omitted": 0,
            "uncovered_units_truncated": False,
        })
        _write_json(report_path, report)
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])
        self.assertIn("stored coverage numerator fingerprint", cm["reason"])
        self.assertIn(
            "coverage_report.covered_vs_numerator_freshness.covered_units_count",
            cm["detail"]["mismatches"],
        )

    def test_fail_stale_coverage_report_when_numerator_artifact_changes_same_source_denominator(self):
        ws = _build_complete_ws(self._tmp)
        agent_outputs = ws / "agent_outputs"
        agent_outputs.mkdir(parents=True, exist_ok=True)
        (agent_outputs / "vault-review.md").write_text(
            "Additional source-backed review cites src/DefinitelyNew.sol:1\n",
            encoding="utf-8",
        )

        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])
        self.assertIn("numerator fingerprint is stale", cm["reason"])
        self.assertTrue(cm["detail"]["source_freshness_verified"])
        self.assertIn("numerator_freshness.coverage_tokens_sha256", cm["detail"]["mismatches"])

    def test_fail_stale_coverage_report_when_numerator_artifact_content_changes_same_tokens(self):
        ws = _build_complete_ws(self._tmp)
        artifact = ws / "agent_outputs" / "vault-review.md"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(
            "First source-backed review cites src/Vault.sol:1\n",
            encoding="utf-8",
        )
        _refresh_coverage_report(ws)

        artifact.write_text(
            "Changed prose still cites src/Vault.sol:1\n",
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])
        self.assertIn("numerator fingerprint is stale", cm["reason"])
        self.assertIn(
            "numerator_freshness.numerator_artifacts_sha256",
            cm["detail"]["mismatches"],
        )
        self.assertIn("numerator_freshness.numerator_sha256", cm["detail"]["mismatches"])
        self.assertNotIn(
            "numerator_freshness.coverage_tokens_sha256",
            cm["detail"]["mismatches"],
        )

    def test_fail_coverage_report_wrong_visible_uncovered_units_same_count(self):
        ws = _build_complete_ws(self._tmp)
        (ws / "src" / "Other.sol").write_text("contract Other {}\n", encoding="utf-8")
        _refresh_coverage_report(ws)
        report_path = ws / ".auditooor" / "coverage_report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["uncovered_units"], ["Other.sol"])
        report["uncovered_units"] = ["Vault.sol"]
        _write_json(report_path, report)

        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])
        self.assertIn("visible uncovered-unit list is stale", cm["reason"])
        self.assertIn("coverage_report.uncovered_units", cm["detail"]["mismatches"])

    def test_fail_truncated_coverage_report_wrong_visible_uncovered_units(self):
        ws = _build_complete_ws(self._tmp)
        for i in range(4):
            (ws / "src" / f"Other{i}.sol").write_text(
                f"contract Other{i} {{}}\n",
                encoding="utf-8",
            )
        _refresh_coverage_report(ws, list_cap=2)
        report_path = ws / ".auditooor" / "coverage_report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertTrue(report["uncovered_units_truncated"])
        self.assertEqual(report["uncovered_units_listed"], 2)
        report["uncovered_units"][0] = "Vault.sol"
        _write_json(report_path, report)

        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertFalse(cm["ok"])
        self.assertIn("visible uncovered-unit list is stale", cm["reason"])
        self.assertIn("coverage_report.uncovered_units", cm["detail"]["mismatches"])

    def test_fail_coverage_report_count_sum_mismatch_green_fraction(self):
        ws = _build_complete_ws(self._tmp)
        report_path = ws / ".auditooor" / "coverage_report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report.update({
            "covered": 1,
            "uncovered": 1,
            "coverage_fraction": 1.0,
            "uncovered_units": ["Vault.sol"],
            "uncovered_units_listed": 1,
            "uncovered_units_omitted": 0,
            "uncovered_units_truncated": False,
        })
        _write_json(report_path, report)
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertEqual(
            cm["detail"]["numerator_error"],
            "covered plus uncovered must equal total_units",
        )

    def test_fail_coverage_report_fraction_mismatch_green(self):
        ws = _build_complete_ws(self._tmp)
        report_path = ws / ".auditooor" / "coverage_report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report.update({
            "covered": 0,
            "uncovered": 1,
            "coverage_fraction": 1.0,
            "uncovered_units": ["Vault.sol"],
            "uncovered_units_listed": 1,
            "uncovered_units_omitted": 0,
            "uncovered_units_truncated": False,
        })
        _write_json(report_path, report)
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertEqual(
            cm["detail"]["numerator_error"],
            "coverage_fraction must match covered divided by total_units",
        )

    def test_fail_coverage_report_uncovered_units_mismatch_green(self):
        ws = _build_complete_ws(self._tmp)
        report_path = ws / ".auditooor" / "coverage_report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report.update({
            "covered": 1,
            "uncovered": 0,
            "coverage_fraction": 1.0,
            "uncovered_units": ["Vault.sol"],
            "uncovered_units_listed": 1,
            "uncovered_units_omitted": 0,
            "uncovered_units_truncated": False,
        })
        _write_json(report_path, report)
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "fail-no-coverage-map", out)
        self.assertEqual(rc, 1)
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        self.assertEqual(
            cm["detail"]["numerator_error"],
            "uncovered_units plus omitted count must equal uncovered",
        )

    # ---- (a) fully-covered passes with no warn ----
    def test_full_coverage_passes_no_warn(self):
        ws = _build_complete_ws(self._tmp)
        # the all-pass fixture already ships a 1/1 coverage report
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        self.assertIsNone(out["coverage_warn"])

    # ---- coverage-map fail is rebuttable (genuinely-N/A) ----
    def test_rebuttal_coverage_map(self):
        ws = _build_complete_ws(self._tmp)
        (ws / ".auditooor" / "coverage_report.json").unlink()
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: coverage-map: non-source target, no swept surface\n",
            encoding="utf-8",
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)


class HuntTrustSignalTest(unittest.TestCase):
    """Signal (q): HUNT-TRUST - the meta-caveat over the coverage axes.

    A coverage number is only real if the hunt behind it actually ran. When the
    workspace's per-function hunt was rate-limited into ~0 real anchored
    hypotheses (the dydx + morpho failed-run shape), the gate must LOUDLY caveat
    the coverage without failing certification. These tests drive the signal via
    the report-file path (<ws>/.auditooor/hunt_run_health_report.json) so they
    are deterministic and never touch the corpus derived-root.
    <!-- r36-rebuttal: lane-L37-AUDIT-COMPLETENESS registered in .auditooor/agent_pathspec.json -->
    """

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self._saved_hunt_trust_strict = os.environ.pop(
            "AUDITOOOR_L37_HUNT_TRUST_STRICT",
            None,
        )

    def tearDown(self):
        if self._saved_hunt_trust_strict is not None:
            os.environ["AUDITOOOR_L37_HUNT_TRUST_STRICT"] = self._saved_hunt_trust_strict
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_hunt_health(self, ws: Path, **fields) -> None:
        """Write a hunt-run-health report-file the (q) signal reads first."""
        payload = {
            "schema": "auditooor.hunt_run_health.v1",
            "kind": "hunt_run_health",
            "workspace": str(ws),
            "ws_name": ws.name,
            "hunt_dirs_scanned": [f"mimo_harness_{ws.name}"],
        }
        payload.update(fields)
        _write_json(ws / ".auditooor" / "hunt_run_health_report.json", payload)

    # ---- (a) failed-run: LOUD warn, but the signal PASSES (warn-not-fail) ----
    def test_failed_run_warns_but_passes(self):
        ws = _build_complete_ws(self._tmp)
        # dydx-shaped failed-run: 299 records, 0 anchored, all rate-limited.
        self._write_hunt_health(
            ws, verdict="failed-run", needs_re_hunt=True,
            total_records=299, success=0, rate_limited=299,
            success_fraction=0.0,
        )
        rc, out = _run(ws)
        # The whole audit still passes - hunt-trust never blocks certification.
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        ht = [s for s in out["signals"] if s["signal"] == "hunt-trust"][0]
        self.assertTrue(ht["ok"])
        self.assertEqual(ht["verdict"], "pass")
        # the re-hunt caveat is surfaced in the signal reason ...
        self.assertIn("re-hunt", ht["reason"].lower())
        self.assertIn("not trustworthy", ht["reason"].lower())
        # ... carries the true success_fraction + rate_limited count ...
        self.assertEqual(ht["detail"]["success_fraction"], 0.0)
        self.assertEqual(ht["detail"]["rate_limited"], 299)
        # ... and is ALSO surfaced as a top-level loud warn block.
        self.assertIsNotNone(out["hunt_trust_warn"])
        self.assertIn("re-hunt", out["hunt_trust_warn"].lower())
        self.assertIn("299", out["hunt_trust_warn"])

    # ---- needs_re_hunt=True alone (without verdict==failed-run) still warns ----
    def test_needs_re_hunt_flag_warns(self):
        ws = _build_complete_ws(self._tmp)
        self._write_hunt_health(
            ws, verdict="degraded", needs_re_hunt=True,
            total_records=120, success=2, rate_limited=110,
            success_fraction=0.0167,
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        self.assertIsNotNone(out["hunt_trust_warn"])
        self.assertIn("FAILED-RUN", out["hunt_trust_warn"])

    # ---- (b) healthy: NO hunt-trust warn, signal passes quiet ----
    def test_healthy_no_warn(self):
        ws = _build_complete_ws(self._tmp)
        self._write_hunt_health(
            ws, verdict="healthy", needs_re_hunt=False,
            total_records=200, success=160, rate_limited=5,
            success_fraction=0.80,
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        # no top-level hunt-trust warn for a healthy hunt
        self.assertIsNone(out["hunt_trust_warn"])
        ht = [s for s in out["signals"] if s["signal"] == "hunt-trust"][0]
        self.assertTrue(ht["ok"])
        self.assertNotIn("hunt_trust_warn", ht["detail"])
        self.assertEqual(ht["detail"]["hunt_run_health_verdict"], "healthy")

    # ---- degraded: a SOFTER warn, still passes ----
    def test_degraded_softer_warn(self):
        ws = _build_complete_ws(self._tmp)
        self._write_hunt_health(
            ws, verdict="degraded", needs_re_hunt=False,
            total_records=100, success=20, rate_limited=10,
            success_fraction=0.20,
        )
        rc, out = _run(ws)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        self.assertIsNotNone(out["hunt_trust_warn"])
        self.assertIn("DEGRADED", out["hunt_trust_warn"])

    # ---- (c) no regression: coverage-map / rubric-coverage still pass + the
    #         all-pass fixture (no hunt report-file, no derived-root match) is
    #         a quiet hunt-trust pass ----
    def test_no_regression_coverage_signals_and_quiet_hunt_trust(self):
        ws = _build_complete_ws(self._tmp)
        # Remove the fixture's default healthy report so this test exercises the
        # NO-report path. Point the import fallback at a NON-EXISTENT derived-root
        # so the test is hermetic (independent of whatever the host corpus
        # contains): an unreachable derived-root yields an `unavailable` hunt-trust
        # signal - a quiet pass with no caveat (distinct from a `no-records`
        # verdict, which is a real never-ran-with-evidence caveat and warns).
        (ws / ".auditooor" / "hunt_run_health_report.json").unlink()
        empty_derived = self._tmp / "empty_derived_does_not_exist"
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(ws), "--json"],
            capture_output=True, text=True,
            env={**os.environ, "AUDITOOOR_L37_DERIVED_ROOT": str(empty_derived)},
        )
        rc, out = proc.returncode, json.loads(proc.stdout)
        self.assertEqual(out["verdict"], "pass-audit-complete", out)
        self.assertEqual(rc, 0)
        # coverage-map and rubric-coverage still pass cleanly.
        cm = [s for s in out["signals"] if s["signal"] == "coverage-map"][0]
        rcv = [s for s in out["signals"] if s["signal"] == "rubric-coverage"][0]
        self.assertTrue(cm["ok"])
        self.assertTrue(rcv["ok"])
        self.assertIsNone(out["coverage_warn"])
        self.assertIsNone(out["rubric_coverage_warn"])
        # hunt-trust is a quiet pass (no caveat, no warn). With no report-file
        # the import fallback runs build_report for this tmp ws name; an unknown
        # name yields no-records / unavailable - either way a quiet pass with no
        # failed-run caveat. The invariant is: ok=True and no warn surfaced.
        ht = [s for s in out["signals"] if s["signal"] == "hunt-trust"][0]
        self.assertTrue(ht["ok"])
        self.assertIsNone(out["hunt_trust_warn"])
        self.assertNotIn("hunt_trust_warn", ht["detail"])
        # empty derived-root -> no-records verdict (or unavailable); never a
        # failed-run caveat.
        self.assertIn(
            ht["detail"].get("hunt_run_health_verdict", "unavailable"),
            ("no-records", "unavailable", ""),
        )

    # ---- failed-run is rebuttable via l37-rebuttal: hunt-trust: <reason> ----
    def test_failed_run_rebuttal_under_strict(self):
        # In strict mode a failed-run hunt-trust FAILS closed; the rebuttal
        # flips it back to ok-rebuttal (genuinely-N/A: e.g. non-LLM-hunt target).
        ws = _build_complete_ws(self._tmp)
        self._write_hunt_health(
            ws, verdict="failed-run", needs_re_hunt=True,
            total_records=299, success=0, rate_limited=299,
            success_fraction=0.0,
        )
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: hunt-trust: coverage from static engines, no LLM hunt\n",
            encoding="utf-8",
        )
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(ws), "--json", "--strict"],
            capture_output=True, text=True,
            env={**os.environ},
        )
        out = json.loads(proc.stdout)
        ht = [s for s in out["signals"] if s["signal"] == "hunt-trust"][0]
        self.assertEqual(ht["verdict"], "ok-rebuttal", out)
        self.assertNotIn("fail-hunt-untrustworthy", out["failures"])

    # ---- strict mode (opt-in) downgrades a failed-run to a hard fail ----
    def test_strict_failed_run_fails_closed(self):
        ws = _build_complete_ws(self._tmp)
        self._write_hunt_health(
            ws, verdict="failed-run", needs_re_hunt=True,
            total_records=299, success=0, rate_limited=299,
            success_fraction=0.0,
        )
        proc = subprocess.run(
            [sys.executable, str(TOOL), str(ws), "--json", "--strict"],
            capture_output=True, text=True,
            env={**os.environ},
        )
        out = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 1)
        # Assert on the hunt-trust SIGNAL + the failures list (mirroring the sibling
        # test_failed_run_rebuttal_under_strict): under the global --strict umbrella
        # other independent signals (e.g. completeness-matrix, which needs a full
        # in-scope enumeration this minimal fixture does not carry) also fail closed,
        # so the top-level verdict is the first-ordered failure - not necessarily
        # fail-hunt-untrustworthy. The invariant this test owns is that a failed-run
        # hunt makes hunt-trust FAIL CLOSED under strict.
        ht = [s for s in out["signals"] if s["signal"] == "hunt-trust"][0]
        self.assertFalse(ht["ok"])
        self.assertIn("fail-hunt-untrustworthy", out["failures"])


# r36-rebuttal: funnel-generic-fixes-wave3
# Bug A regression tests: pre_flight_packs/ (underscore) detection in check_audit_preflight.
# Uses _ACC.check_audit_preflight() directly to isolate the signal.
class TestPreFlightPacksUnderscoreDetection(unittest.TestCase):
    """Bug A regression: pre_flight_packs/ (underscore) was invisible to
    check_audit_preflight because the guard used ``"preflight" in nm`` which
    is NOT a substring of ``"pre_flight_packs"``.

    Fix: also match ``"pre_flight"`` (underscore variant).
    """

    def setUp(self):
        self._td = tempfile.mkdtemp()
        self.ws = Path(self._td) / "ws"
        self.ws.mkdir(parents=True)
        (self.ws / ".auditooor").mkdir()

    def tearDown(self):
        shutil.rmtree(self._td, ignore_errors=True)

    def _write_j(self, p: Path, obj) -> None:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj), encoding="utf-8")

    def _add_pfi_genuine(self) -> None:
        """per_function_invariants/ with a manifest (original passing path)."""
        self._write_j(
            self.ws / ".auditooor" / "per_function_invariants" / "manifest.json",
            {"ok": True},
        )

    def _add_pfp_genuine(self) -> None:
        """pre_flight_packs/ with manifest + pack files (canonical underscore form)."""
        pfp = self.ws / ".auditooor" / "pre_flight_packs"
        self._write_j(pfp / "manifest.json", {
            "schema": "auditooor.pre_flight_packs.v1",
            "pack_count": 2,
            "packs": ["pre_flight_pack_foo.json", "pre_flight_pack_bar.json"],
        })
        self._write_j(pfp / "pre_flight_pack_foo.json", {"fn": "foo", "verdict": "run"})
        self._write_j(pfp / "pre_flight_pack_bar.json", {"fn": "bar", "verdict": "run"})

    def _check(self):
        return _ACC.check_audit_preflight(self.ws.resolve())

    def test_pre_flight_packs_dir_detected_as_genuine(self):
        """pre_flight_packs/ with real content must produce ok=True.
        Was BUG: dir name ``pre_flight_packs`` does not contain substring
        ``preflight`` so it was invisible before the fix."""
        self._add_pfp_genuine()
        result = self._check()
        self.assertTrue(
            result.ok,
            f"audit-preflight NOT ok with pre_flight_packs/: {result.reason}",
        )
        pfp_path = str(self.ws.resolve() / ".auditooor" / "pre_flight_packs")
        self.assertIn(pfp_path, result.artifacts,
                      "pre_flight_packs/ must appear in genuine artifacts")

    def test_pre_flight_packs_dir_hollow_not_genuine(self):
        """Empty pre_flight_packs/ must not count as genuine."""
        pfp = self.ws / ".auditooor" / "pre_flight_packs"
        pfp.mkdir(parents=True, exist_ok=True)
        result = self._check()
        empty_pfp = str(self.ws.resolve() / ".auditooor" / "pre_flight_packs")
        self.assertNotIn(
            empty_pfp, result.detail.get("genuine_artifacts", []),
            "empty pre_flight_packs/ must not appear in genuine_artifacts",
        )

    def test_per_function_invariants_still_detected(self):
        """Original per_function_invariants/ path must still be detected."""
        self._add_pfi_genuine()
        result = self._check()
        self.assertTrue(result.ok,
                        f"per_function_invariants/ no longer detected: {result.reason}")

    def test_only_pre_flight_packs_no_pfi_passes(self):
        """pre_flight_packs/ as ONLY preflight artifact must pass."""
        self._add_pfp_genuine()
        result = self._check()
        self.assertTrue(result.ok, result.reason)

    def test_no_preflight_at_all_not_ok(self):
        """No preflight artifacts at all must give not-ok."""
        result = self._check()
        self.assertFalse(result.ok, "expected not-ok with no preflight artifacts")

    def test_pre_flight_underscore_and_classic_preflight_both_matched(self):
        """Both name variants must be matched: pre_flight_packs (underscore)
        and classic preflight_packs (no underscore in 'pre')."""
        # Variant 1: pre_flight_packs (underscore)
        pfp_u = self.ws / ".auditooor" / "pre_flight_packs"
        self._write_j(pfp_u / "manifest.json", {"pack_count": 1, "packs": ["x.json"]})
        r1 = self._check()
        self.assertTrue(r1.ok, f"pre_flight_packs/ (underscore) not matched: {r1.reason}")

        # Variant 2: classic preflight_packs (no underscore in 'pre')
        shutil.rmtree(pfp_u)
        pfp_c = self.ws / ".auditooor" / "preflight_packs"
        self._write_j(pfp_c / "manifest.json", {"pack_count": 1, "packs": ["x.json"]})
        r2 = self._check()
        self.assertTrue(r2.ok,
                        f"preflight_packs/ (no underscore) not matched: {r2.reason}")


if __name__ == "__main__":
    unittest.main()


class TestHuntTrustDegradedFailsClosedUnderStrict(unittest.TestCase):
    """Strata 2026-07-01: the hunt-trust `degraded` verdict (hunt-run-health
    ran_frac < healthy: the per-function hunt engaged <half its records with a
    real verdict, the rest empty) had NO strict-fail path - so a STRICT
    audit-complete certified honest-0 over a hunt that only engaged 18% of 814
    records (corpus-driven-hunt proof-queue hypotheses grounding-resolved but
    never individually verdicted). It now fails closed under the main L37 gate.
    healthy-clean (genuinely-engaged clean audit) still passes - only under-
    engagement is punished."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp()).resolve()
        (self.ws / ".auditooor").mkdir(parents=True)
        for k in ("AUDITOOOR_L37_STRICT", "AUDITOOOR_L37_HUNT_TRUST_STRICT"):
            os.environ.pop(k, None)

    def _write_report(self, verdict, total=814, success=146, rate_limited=0):
        (self.ws / ".auditooor" / "hunt_run_health_report.json").write_text(json.dumps({
            "schema": _ACC._HUNT_RUN_HEALTH_SCHEMA,
            "verdict": verdict, "total_records": total, "success": success,
            "rate_limited": rate_limited,
            "success_fraction": round(success / total, 4) if total else 0.0,
        }))

    def tearDown(self):
        for k in ("AUDITOOOR_L37_STRICT", "AUDITOOOR_L37_HUNT_TRUST_STRICT"):
            os.environ.pop(k, None)

    def test_degraded_warns_by_default(self):
        self._write_report("degraded")
        r = _ACC.check_hunt_trust(self.ws)
        self.assertTrue(r.ok, "degraded must be advisory WARN-pass by default")

    def test_degraded_fails_closed_under_main_l37_strict(self):
        self._write_report("degraded")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = _ACC.check_hunt_trust(self.ws)
        self.assertFalse(r.ok, "degraded must FAIL under AUDITOOOR_L37_STRICT=1")
        self.assertIn("STRICT: failing closed", r.reason)

    def test_healthy_clean_passes_even_under_strict(self):
        # a genuinely-engaged clean audit is healthy-clean, NOT degraded -> passes
        self._write_report("healthy-clean")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = _ACC.check_hunt_trust(self.ws)
        self.assertTrue(r.ok, "healthy-clean must pass even under strict")

    def test_failed_run_now_fails_under_main_l37_strict(self):
        # previously failed-run keyed only on the standalone flag; now the main
        # L37 gate triggers it too.
        self._write_report("failed-run", success=2)
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = _ACC.check_hunt_trust(self.ws)
        self.assertFalse(r.ok, "failed-run must FAIL under AUDITOOOR_L37_STRICT=1")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestCompletenessMatrixEnforceUnderMainStrict(unittest.TestCase):
    """Strata 2026-07-01 (sibling of the hunt-trust degraded-strict fix): the
    completeness-matrix `incomplete` verdict (an in-scope asset/function/invariant/
    impact cell NEVER ENUMERATED) was WARN-pass unless the dedicated
    AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE=1 was set - which `make audit-complete
    STRICT=1` does NOT set. So a STRICT audit certified over a matrix with
    never-enumerated cells (absence read as coverage). enforce now also triggers on
    the main L37 gate."""

    def test_l37_strict_flips_enforce_true(self):
        prev = {k: os.environ.get(k) for k in
                ("AUDITOOOR_COMPLETENESS_MATRIX_ENFORCE", "AUDITOOOR_L37_STRICT")}
        try:
            for k in prev:
                os.environ.pop(k, None)
            # default: no enforce
            self.assertFalse(_ACC._l37_gate_strict("COMPLETENESS_MATRIX"),
                             "no strict env -> matrix not enforced")
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            self.assertTrue(_ACC._l37_gate_strict("COMPLETENESS_MATRIX"),
                            "AUDITOOOR_L37_STRICT=1 must enable matrix enforcement")
        finally:
            for k, v in prev.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestPrefilingFreshnessContentFallback(unittest.TestCase):
    """Regression: the prove-top-leads no-leads corroboration must not false-red
    when audit-completeness-check REWRITES the queue in place (synthetic-drop /
    provenance-filter) on the SAME rows - bumping mtime past a still-valid prefiling
    - while STILL rejecting a queue REGENERATED with NEW obligations (axelar +7116).
    Root-caused 2026-07-14 (NUVA prove-top-leads green/red churn)."""
    def _setup(self, queue_rows: int, terminal_skipped: int, queue_newer: bool):
        import time
        d = Path(tempfile.mkdtemp()); (d / ".auditooor").mkdir()
        pf = d / ".auditooor" / "prove_top_leads_prefiling_stress_test.json"
        q = d / ".auditooor" / "exploit_queue.json"
        pf.write_text(json.dumps({"top_n": 10, "rows_assessed": 0,
                                  "terminal_rows_skipped": terminal_skipped}))
        q.write_text(json.dumps({"queue": [{"proof_status": "closed_negative"}
                                            for _ in range(queue_rows)]}))
        if queue_newer:
            old = pf.stat().st_mtime
            os.utime(q, (old + 100, old + 100))  # queue re-touched AFTER prefiling
        else:
            old = q.stat().st_mtime
            os.utime(pf, (old + 100, old + 100))
        return d

    def test_inplace_retouch_same_count_accepts(self):
        d = self._setup(queue_rows=4266, terminal_skipped=4266, queue_newer=True)
        self.assertTrue(_ACC._prefiling_confirms_all_terminal(d),
                        "in-place re-touch with unchanged row count must stay corroborated")

    def test_grown_queue_still_rejected(self):
        # queue regenerated with MORE rows than prefiling assessed => stale, reject
        d = self._setup(queue_rows=5000, terminal_skipped=4266, queue_newer=True)
        self.assertFalse(_ACC._prefiling_confirms_all_terminal(d),
                         "a queue grown with new obligations must remain stale-rejected")

    def test_fresh_prefiling_accepts(self):
        d = self._setup(queue_rows=4266, terminal_skipped=4266, queue_newer=False)
        self.assertTrue(_ACC._prefiling_confirms_all_terminal(d))
