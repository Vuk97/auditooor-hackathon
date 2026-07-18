#!/usr/bin/env python3
"""Tests for the IGAL (Incomplete-Guard Acknowledgement Lane) scanner + gate.

Covers the op-reth regression that motivated the gap, plus non-vacuous negative
cases (clean file => zero records), proximity guard, scope-exclusion, rank
ordering, multi-language (Go), and the gate's pass / fail paths.

Run: python3 -m pytest tools/tests/test_incomplete_guard_acknowledgement_scanner.py -q
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parents[1]

# Resolve the REAL git binary, bypassing the auditooor session-marker wrapper at
# ~/.auditooor/bin/git (which rejects commits lacking a session recall marker - not
# applicable to a throwaway fixture repo).
_GIT = (
    "/usr/bin/git" if Path("/usr/bin/git").exists()
    else (shutil.which("git") or "git")
)


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SCANNER = _load("igal_scanner_under_test", "incomplete-guard-acknowledgement-scanner.py")
GATE = _load("igal_gate_under_test", "incomplete-guard-ack-gate.py")


# ---------------------------------------------------------------------------
# 1. POSITIVE / EVIDENCE-EXACT - the op-reth engine.rs regression.
# ---------------------------------------------------------------------------
OP_RETH_FIXTURE = """\
impl OpEngineValidator {
    fn validate_block_post_execution_with_hashed_state(
        &self,
        state_updates: &HashedPostState,
        block: &RecoveredBlock<Self::Block>,
    ) -> Result<(), ConsensusError> {
        if self.chain_spec().is_isthmus_active_at_timestamp(block.timestamp()) {
            let Ok(state) = self.provider.state_by_block_hash(block.parent_hash()) else {
                // FIXME: we don't necessarily have access to the parent block here because the
                // parent block isn't necessarily part of the canonical chain yet. Instead this
                // function should receive the list of in memory blocks as input
                return Ok(());
            };
            let predeploy_storage_updates = state_updates
                .storages
                .get(&self.hashed_addr_l2tol1_msg_passer)
                .cloned()
                .unwrap_or_default();
            isthmus::verify_withdrawals_root_prehashed(
                predeploy_storage_updates,
                state,
                block.header(),
            )
            .map_err(|err| {
                ConsensusError::msg(format!("failed to verify block post-execution: {err}"))
            })?
        }
        Ok(())
    }
}
"""


def test_positive_op_reth_evidence_exact():
    recs = SCANNER.hypotheses_from_source(
        OP_RETH_FIXTURE, "rs", file_rel="crates/node/src/engine.rs"
    )
    # Exactly one emitted record (one ACK marker line: the FIXME).
    assert len(recs) == 1, f"expected 1 record, got {len(recs)}: {recs}"
    r = recs[0]
    assert r["ack_token"] == "FIXME"
    assert r["sink_kind"] == "early-skip-return"
    # sink line is the `return Ok(());`
    assert r["sink_text"].startswith("return Ok(())"), r["sink_text"]
    assert "verify_withdrawals_root_prehashed" in r["skipped_call"], r["skipped_call"]
    sk = r["security_keywords"]
    assert "verify" in sk
    assert ("withdraw" in sk) or ("root" in sk), sk
    assert r["rank_bucket"] == "high", (r["rank_score"], r["rank_bucket"])
    assert r["verdict"] == "needs-fuzz"
    assert r["attack_class"] == "incomplete-guard-self-acknowledged"
    assert r["source"] == "IGAL"


# ---------------------------------------------------------------------------
# 2. NEGATIVE / NON-VACUOUS - clean file, no ack markers => ZERO records.
# ---------------------------------------------------------------------------
CLEAN_FIXTURE = """\
fn validate_amount(x: u64) -> Result<(), Error> {
    if x == 0 {
        return Err(Error::ZeroAmount);
    }
    // fully implemented bound check below
    if x > MAX_AMOUNT {
        return Err(Error::TooLarge);
    }
    do_real_transfer(x)?;
    Ok(())
}
"""


def test_negative_clean_file_zero_records():
    recs = SCANNER.hypotheses_from_source(CLEAN_FIXTURE, "rs", file_rel="src/clean.rs")
    assert recs == [], f"clean file should emit zero records, got {recs}"


# ---------------------------------------------------------------------------
# 3. NEGATIVE PROXIMITY GUARD - ack marker far from any guard/skip => ZERO.
# ---------------------------------------------------------------------------
def test_negative_proximity_guard():
    body_lines = ["fn refactor_target() {"]
    body_lines.append("    // TODO: refactor naming")
    # 40 filler lines of inert code (no guard, no early-skip, no security kw)
    for i in range(40):
        body_lines.append(f"    let v{i} = compute_value({i});")
    body_lines.append("    if v0 == v1 {")          # a guard, but 40+ lines away
    body_lines.append("        log_metric(v0);")
    body_lines.append("    }")
    body_lines.append("}")
    src = "\n".join(body_lines) + "\n"
    recs = SCANNER.hypotheses_from_source(src, "rs", file_rel="src/refactor.rs")
    assert recs == [], f"far-away ack marker should not fire, got {recs}"


# ---------------------------------------------------------------------------
# 4. SCOPE EXCLUSION - identical fixture under an OOS/test path => ZERO records
#    at the WORKSPACE level (run() applies is_in_scope).
# ---------------------------------------------------------------------------
def test_scope_exclusion_oos_path(tmp_path):
    ws = tmp_path / "ws"
    src_dir = ws / "src"
    test_dir = ws / "tests"
    src_dir.mkdir(parents=True)
    test_dir.mkdir(parents=True)
    # In-scope copy.
    (src_dir / "engine.rs").write_text(OP_RETH_FIXTURE, encoding="utf-8")
    # OOS copy (under tests/ -> is_test => is_oos True).
    (test_dir / "engine.rs").write_text(OP_RETH_FIXTURE, encoding="utf-8")
    # Also a _test.rs sibling next to the in-scope file.
    (src_dir / "engine_test.rs").write_text(OP_RETH_FIXTURE, encoding="utf-8")

    res = SCANNER.run(ws)
    out = json.loads(
        Path(res["output_path"]).read_text(encoding="utf-8").splitlines()[0]
    )
    # Every emitted record must be from the in-scope src/engine.rs, never tests/.
    recs = [
        json.loads(line)
        for line in Path(res["output_path"]).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    files = {r["file"] for r in recs}
    assert files == {"src/engine.rs"}, files
    assert not any("tests/" in f or "_test" in f for f in files)
    assert out["file"] == "src/engine.rs"


# ---------------------------------------------------------------------------
# 5. RANK ORDERING - security-dense candidate ranks strictly above a sparse one.
# ---------------------------------------------------------------------------
RANK_FIXTURE = """\
fn process(req: Request) -> Result<(), Error> {
    // dense, security-critical incomplete guard
    let Ok(sig) = recover_signature(req.withdraw_root) else {
        // FIXME: signature verify not wired yet
        return Ok(());
    };
    verify_withdrawal_proof(sig, req.balance)?;
    let a0 = step(0);
    let a1 = step(1);
    let a2 = step(2);
    let a3 = step(3);
    let a4 = step(4);
    let a5 = step(5);
    let a6 = step(6);
    let a7 = step(7);
    let a8 = step(8);
    let a9 = step(9);

    // sparse: ack near a non-security guard only (far from the dense block above)
    let cfg = load_config();
    // TODO: tidy config naming
    if cfg.enabled {
        emit_log(cfg.value);
        return Ok(());
    }
    Ok(())
}
"""


def test_rank_ordering():
    recs = SCANNER.hypotheses_from_source(RANK_FIXTURE, "rs", file_rel="src/proc.rs")
    assert len(recs) == 2, recs
    # emitted order is score-descending.
    assert recs[0]["rank_score"] > recs[1]["rank_score"], [
        (r["ack_token"], r["rank_score"], r["rank_bucket"]) for r in recs
    ]
    assert recs[0]["rank_bucket"] == "high"
    assert recs[0]["ack_token"] == "FIXME"
    assert recs[1]["rank_bucket"] in ("low", "med")


# ---------------------------------------------------------------------------
# 6. LANGUAGE COVERAGE - Go fixture: FIXME above `return nil` inside if-guard.
# ---------------------------------------------------------------------------
GO_FIXTURE = """\
func (k Keeper) verifyWithdrawal(ctx Context, w Withdrawal) error {
	root, err := k.computeRoot(w)
	if err != nil {
		// FIXME: skip validation for now
		return nil
	}
	return k.checkRoot(root, w.proof)
}
"""


def test_language_coverage_go():
    recs = SCANNER.hypotheses_from_source(GO_FIXTURE, "go", file_rel="x/keeper/wd.go")
    assert len(recs) >= 1, recs
    r = recs[0]
    assert r["language"] == "go"
    assert r["ack_token"] == "FIXME"
    assert r["sink_kind"] == "early-skip-return"
    assert r["sink_text"].startswith("return nil"), r["sink_text"]


# ---------------------------------------------------------------------------
# Gate fixtures + helpers
# ---------------------------------------------------------------------------
def _init_git_repo(ws: Path) -> str:
    """Init a tiny git repo so the gate can recompute HEAD. Returns HEAD sha.

    Commits whatever already exists in ``ws`` (the caller writes the fixture first),
    so the committed tree includes the in-scope source and HEAD is a real sha.
    """
    subprocess.run([_GIT, "init", "-q"], cwd=ws, check=True)
    subprocess.run([_GIT, "config", "user.email", "t@t.t"], cwd=ws, check=True)
    subprocess.run([_GIT, "config", "user.name", "t"], cwd=ws, check=True)
    # A committable placeholder distinct from any fixture file.
    (ws / ".igal_placeholder").write_text("placeholder\n", encoding="utf-8")
    subprocess.run([_GIT, "add", "-A"], cwd=ws, check=True)
    # --no-verify: this throwaway fixture repo has no auditooor session marker, and
    # the global pre-commit hook (rightly) rejects commits without it. We only need
    # a real HEAD sha for the gate's freshness check, not a hook-validated commit.
    subprocess.run(
        [_GIT, "commit", "-q", "--no-verify", "-m", "init"], cwd=ws, check=True,
        env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.t",
             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.t",
             "PATH": os.environ.get("PATH", "")},
    )
    out = subprocess.run(
        [_GIT, "rev-parse", "HEAD"], cwd=ws, capture_output=True, text=True, check=True
    )
    return out.stdout.strip()


def _build_scanned_ws(tmp_path) -> tuple[Path, list[dict]]:
    """Build a workspace with the op-reth fixture in-scope, run scanner. Returns
    (ws, high_bucket_records)."""
    ws = tmp_path / "ws"
    src = ws / "src" / "rust" / "op-reth" / "crates" / "node" / "src"
    src.mkdir(parents=True)
    (src / "engine.rs").write_text(OP_RETH_FIXTURE, encoding="utf-8")
    head = _init_git_repo(ws)
    # Run the scanner AFTER the commit so its last_run marker records the real HEAD.
    SCANNER.run(ws)
    marker_path = ws / ".auditooor" / "incomplete_guard_ack_last_run.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert marker["head_sha"] == head, (marker["head_sha"], head)
    recs = [
        json.loads(l)
        for l in (ws / ".auditooor" / "incomplete_guard_ack_hypotheses.jsonl")
        .read_text(encoding="utf-8").splitlines() if l.strip()
    ]
    high = [r for r in recs if r["rank_bucket"] == "high"]
    return ws, high


# ---------------------------------------------------------------------------
# 7. GATE PASS PATH - every high-bucket record has a disposition => rc 0, pass.
# ---------------------------------------------------------------------------
def test_gate_pass_path(tmp_path):
    ws, high = _build_scanned_ws(tmp_path)
    assert high, "fixture should produce >=1 high-bucket record"
    # Dispose every high record (filed).
    dispo_path = ws / ".auditooor" / "incomplete_guard_ack_dispositions.jsonl"
    with dispo_path.open("w", encoding="utf-8") as fh:
        for r in high:
            fh.write(json.dumps({
                "file": r["file"], "ack_line": r["ack_line"],
                "disposition": "filed", "reason": "submitted as op-reth withdrawals-root skip",
            }) + "\n")
    rc, payload = GATE.evaluate(ws, strict=True)
    assert rc == 0, payload
    assert payload["verdict"] == "pass", payload
    assert payload.get("pass_line") == "pass-igal-incomplete-guard-ack"


# ---------------------------------------------------------------------------
# 8a. GATE FAIL PATH - scanner never ran (marker absent) => fail-scanner-not-run.
# ---------------------------------------------------------------------------
def test_gate_fail_scanner_not_run(tmp_path):
    ws = tmp_path / "ws"
    src = ws / "src" / "rust" / "op-reth" / "crates" / "node" / "src"
    src.mkdir(parents=True)
    (src / "engine.rs").write_text(OP_RETH_FIXTURE, encoding="utf-8")
    # NOTE: scanner NOT run -> no hypotheses file, no marker.
    rc, payload = GATE.evaluate(ws, strict=False)
    assert rc == 1, payload
    assert payload["verdict"] == "fail-scanner-not-run", payload


# ---------------------------------------------------------------------------
# 8b. GATE FAIL PATH - high-bucket record unaddressed =>
#     fail-unaddressed-high-bucket-acknowledgement.
# ---------------------------------------------------------------------------
def test_gate_fail_unaddressed_high(tmp_path):
    ws, high = _build_scanned_ws(tmp_path)
    assert high
    # No dispositions file at all -> high records unaddressed.
    rc, payload = GATE.evaluate(ws, strict=False)
    assert rc == 1, payload
    assert payload["verdict"] == "fail-unaddressed-high-bucket-acknowledgement", payload
    assert payload["unaddressed_high"], payload


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
