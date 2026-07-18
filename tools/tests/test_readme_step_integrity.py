"""Guards readme-step-integrity.py against the 6-day silent-degradation miss:
a commit-mining step that ran in local-git-only mode (no GitHub auth) must be
classified DEGRADED, not FULL, and must fail the STRICT gate."""
import json
import os
import subprocess
import sys
import tempfile

TOOL = os.path.join(os.path.dirname(__file__), "..", "readme-step-integrity.py")


def _run(ws, strict=True):
    cmd = [sys.executable, TOOL, "--workspace", ws, "--json"]
    if strict:
        cmd.append("--strict")
    return subprocess.run(cmd, capture_output=True, text=True)


def _write(ws, name, obj):
    os.makedirs(os.path.join(ws, ".auditooor"), exist_ok=True)
    with open(os.path.join(ws, ".auditooor", name), "w") as fh:
        json.dump(obj, fh)


def test_commit_mining_local_only_is_degraded_and_fails_strict():
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "git_commits_mining.json", {"fallback_mode": "local-git-only", "commits_scanned": 12})
        r = _run(ws, strict=True)
        out = json.loads(r.stdout)
        cm = next(s for s in out["steps"] if s["step"] == "commit-mining")
        assert cm["status"] == "DEGRADED", cm
        assert "commit-mining" in out["degraded_or_skipped"]
        assert r.returncode == 1, "STRICT must fail on a degraded step"


def test_commit_mining_full_upstream_is_full():
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "git_commits_mining_deep.json", {"commits_scanned": 977, "security_fix_count": 250})
        r = _run(ws, strict=False)
        out = json.loads(r.stdout)
        cm = next(s for s in out["steps"] if s["step"] == "commit-mining")
        assert cm["status"] == "FULL", cm


def test_commit_mining_found_in_mining_rounds_subdir():
    # The canonical artifact lands in mining_rounds/<date>/commit_mining_manifest.json
    # (two dirs deep), which the shallow _newest globs miss. The check must still
    # find it (FULL with real scanned count), not report a false SKIPPED.
    with tempfile.TemporaryDirectory() as ws:
        os.makedirs(os.path.join(ws, ".auditooor"), exist_ok=True)
        mr = os.path.join(ws, "mining_rounds", "2026-06-22-bidirectional-commit-mining")
        os.makedirs(mr, exist_ok=True)
        with open(os.path.join(mr, "commit_mining_manifest.json"), "w") as fh:
            json.dump({"commits_scanned": 95, "security_fix_count": 7}, fh)
        r = _run(ws, strict=False)
        out = json.loads(r.stdout)
        cm = next(s for s in out["steps"] if s["step"] == "commit-mining")
        assert cm["status"] == "FULL", cm
        assert "95" in cm["reason"], cm


def test_missing_commit_mining_is_skipped():
    with tempfile.TemporaryDirectory() as ws:
        os.makedirs(os.path.join(ws, ".auditooor"), exist_ok=True)
        r = _run(ws, strict=True)
        out = json.loads(r.stdout)
        cm = next(s for s in out["steps"] if s["step"] == "commit-mining")
        assert cm["status"] == "SKIPPED", cm
        assert r.returncode == 1


# --- hunt-stale-rerun-after-corpus-refresh guard ---------------------------
# The cross-workspace transfer machinery fires fresh, but a workspace whose
# persisted hunt artifacts predate the latest corpus ingest is corpus-blind: it
# greens the gate with 0 transferred patterns. A stale hunt artifact (mtime
# OLDER than the active corpus) must be DEGRADED; a fresh one must be FULL.

_CORPUS_REL = os.path.join("audit", "corpus_tags", "derived", "invariants_pilot_audited.jsonl")


def _seed_hunt(ws, hunt_mtime, corpus_mtime, rows=3):
    """Write a per_fn_hacker_questions.jsonl + a workspace-local corpus copy and
    pin their mtimes so the staleness comparison is deterministic (the local
    corpus copy is preferred over the tool's REPO_ROOT corpus)."""
    aud = os.path.join(ws, ".auditooor")
    os.makedirs(aud, exist_ok=True)
    qp = os.path.join(aud, "per_fn_hacker_questions.jsonl")
    with open(qp, "w") as fh:
        for i in range(rows):
            fh.write(json.dumps({"q": i}) + "\n")
    os.utime(qp, (hunt_mtime, hunt_mtime))
    corp = os.path.join(ws, _CORPUS_REL)
    os.makedirs(os.path.dirname(corp), exist_ok=True)
    with open(corp, "w") as fh:
        fh.write(json.dumps({"inv": "INV-1"}) + "\n")
    os.utime(corp, (corpus_mtime, corpus_mtime))
    return qp, corp


def test_stale_hunt_artifact_is_degraded():
    with tempfile.TemporaryDirectory() as ws:
        # hunt is OLDER than corpus -> corpus-blind -> DEGRADED
        _seed_hunt(ws, hunt_mtime=1000, corpus_mtime=2000)
        r = _run(ws, strict=True)
        out = json.loads(r.stdout)
        h = next(s for s in out["steps"] if s["step"] == "scoped-hunt")
        assert h["status"] == "DEGRADED", h
        assert "hunt-stale-rerun-after-corpus-refresh" in h["reason"], h
        assert "scoped-hunt" in out["degraded_or_skipped"]
        assert r.returncode == 1, "STRICT must fail on a stale corpus-blind hunt"


def test_fresh_hunt_artifact_is_full():
    with tempfile.TemporaryDirectory() as ws:
        # hunt is NEWER than corpus -> grounded -> FULL
        _seed_hunt(ws, hunt_mtime=3000, corpus_mtime=2000)
        r = _run(ws, strict=False)
        out = json.loads(r.stdout)
        h = next(s for s in out["steps"] if s["step"] == "scoped-hunt")
        assert h["status"] == "FULL", h
        assert "3 per-fn hacker-question rows" in h["reason"], h


def test_hunt_without_corpus_is_graceful_full():
    with tempfile.TemporaryDirectory() as ws:
        # rows present, NO local corpus copy: staleness must be skipped gracefully.
        # (REPO_ROOT fallback may exist; if so the stale check would fire, so set
        # the hunt artifact to "now" to stay FULL regardless of which corpus wins.)
        aud = os.path.join(ws, ".auditooor")
        os.makedirs(aud, exist_ok=True)
        qp = os.path.join(aud, "per_fn_hacker_questions.jsonl")
        with open(qp, "w") as fh:
            fh.write(json.dumps({"q": 0}) + "\n")
        import time as _t
        future = _t.time() + 10_000
        os.utime(qp, (future, future))
        r = _run(ws, strict=False)
        out = json.loads(r.stdout)
        h = next(s for s in out["steps"] if s["step"] == "scoped-hunt")
        assert h["status"] == "FULL", h


def test_empty_hunt_file_is_degraded():
    with tempfile.TemporaryDirectory() as ws:
        aud = os.path.join(ws, ".auditooor")
        os.makedirs(aud, exist_ok=True)
        open(os.path.join(aud, "per_fn_hacker_questions.jsonl"), "w").close()
        r = _run(ws, strict=True)
        out = json.loads(r.stdout)
        h = next(s for s in out["steps"] if s["step"] == "scoped-hunt")
        assert h["status"] == "DEGRADED", h
        assert "empty" in h["reason"], h


import importlib.util


def _load_module():
    spec = importlib.util.spec_from_file_location("readme_step_integrity", TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["readme_step_integrity"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_pin_read_from_repo_strategy_targets():
    # Serving-join fix: no SCOPE.md PINNED line, but repo_strategy.json
    # targets[].pin carries the SHA (the artifact commit-mining + the clone use).
    m = _load_module()
    with tempfile.TemporaryDirectory() as ws:
        _write(
            ws,
            "repo_strategy.json",
            {
                "owner_repo": "ssvlabs/ssv-network",
                "targets": [{"pin": "9bb7b21d4432f34f623bed3e0bb3fa77f1e5d2b9"}],
            },
        )
        pin, repo = m._read_pin_and_repo(ws)
        assert pin == "9bb7b21d4432f34f623bed3e0bb3fa77f1e5d2b9", pin
        assert repo == "ssvlabs/ssv-network", repo


def test_pin_read_top_level_audit_pin_sha():
    m = _load_module()
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "repo_strategy.json", {"repo": "a/b", "audit_pin_sha": "deadbeef" * 5})
        pin, repo = m._read_pin_and_repo(ws)
        assert pin == "deadbeef" * 5, pin
        assert repo == "a/b", repo


def test_scanners_detector_artifacts_are_full():
    # Serving-join fix: detector_action_graph IS slither output; recognise it.
    m = _load_module()
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "detector_action_graph.json", {"detector_hit": {}})
        status, reason = m.check_scanners(ws)
        assert status == "FULL", (status, reason)
        assert "scan artifact" in reason, reason


def test_scanners_truly_empty_still_skips():
    m = _load_module()
    with tempfile.TemporaryDirectory() as ws:
        os.makedirs(os.path.join(ws, ".auditooor"), exist_ok=True)
        status, reason = m.check_scanners(ws)
        assert status == "SKIPPED", (status, reason)


def test_remote_default_tip_slug_normalisation():
    m = _load_module()
    # malformed repo -> '' (no crash)
    assert m._remote_default_tip("") == ""
    assert isinstance(m._remote_default_tip("not-a-repo"), str)


def test_pin_freshness_full_when_pin_equals_tip():
    m = _load_module()
    sha = "9bb7b21d4432f34f623bed3e0bb3fa77f1e5d2b9"
    m._remote_default_tip = lambda repo: sha  # stub the network probe
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "repo_strategy.json", {"owner_repo": "ssvlabs/ssv-network", "targets": [{"pin": sha}]})
        status, reason = m.check_pin_freshness(ws)
        assert status == "FULL", (status, reason)
        assert "default-branch HEAD" in reason, reason


def test_pin_freshness_degraded_when_pin_behind():
    m = _load_module()
    m._remote_default_tip = lambda repo: "f" * 40  # different tip
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "repo_strategy.json", {"owner_repo": "a/b", "targets": [{"pin": "9bb7b21d4432f34f623bed3e0bb3fa77f1e5d2b9"}]})
        status, reason = m.check_pin_freshness(ws)
        assert status == "DEGRADED", (status, reason)
        assert "BEHIND" in reason, reason


def test_pin_policy_default_is_head():
    m = _load_module()
    with tempfile.TemporaryDirectory() as ws:
        assert m._pin_policy(ws) == "head"


def test_pin_policy_marker_overrides():
    m = _load_module()
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "pin_policy.json", {"policy": "release"})
        assert m._pin_policy(ws) == "release"


def test_pin_policy_autodetect_from_scope_prose():
    m = _load_module()
    with tempfile.TemporaryDirectory() as ws:
        with open(os.path.join(ws, "SCOPE.md"), "w") as fh:
            fh.write("Reports must be associated with RELEASES, NOT develop branches.\n"
                     "Pin each in-scope repo to its latest RELEASE tag.\n")
        assert m._pin_policy(ws) == "release"


def test_pin_freshness_release_policy_full_when_pin_equals_latest_release():
    # The Lido false-DEGRADED fix: pinned to latest stable release == FULL, even
    # though default-branch HEAD (develop) is ahead (HEAD findings are OOS here).
    m = _load_module()
    sha = "2a2210baa3939f8079c47e8b45656b9d40e90650"
    m._latest_stable_release_sha = lambda repo: ("v3.0.2", sha)
    m._remote_default_tip = lambda repo: "f" * 40  # HEAD ahead - must be IGNORED
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "pin_policy.json", {"policy": "release"})
        _write(ws, "repo_strategy.json", {"owner_repo": "lidofinance/core", "targets": [{"pin": sha}]})
        status, reason = m.check_pin_freshness(ws)
        assert status == "FULL", (status, reason)
        assert "RELEASE" in reason and "v3.0.2" in reason, reason


def test_pin_freshness_release_policy_degraded_when_behind_release():
    m = _load_module()
    m._latest_stable_release_sha = lambda repo: ("v4.0.0", "a" * 40)
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "pin_policy.json", {"policy": "release"})
        _write(ws, "repo_strategy.json", {"owner_repo": "lidofinance/core", "targets": [{"pin": "b" * 40}]})
        status, reason = m.check_pin_freshness(ws)
        assert status == "DEGRADED", (status, reason)
        assert "BEHIND latest stable RELEASE" in reason and "v4.0.0" in reason, reason


def test_read_targets_falls_back_to_targets_tsv():
    # Serving-join fix: pre-make-audit (no repo_strategy.json), pins live in targets.tsv.
    m = _load_module()
    with tempfile.TemporaryDirectory() as ws:
        with open(os.path.join(ws, "targets.tsv"), "w") as fh:
            fh.write("# repo_url\tpinned_commit\tlocal_name\n")
            fh.write("https://github.com/ProvLabs/vault.git\t" + "a" * 40 + "\tvault\n")
            fh.write("https://github.com/ProvLabs/nuva-evm-contracts.git\t" + "b" * 40 + "\tnuva-evm-contracts\n")
        t = m._read_targets(ws)
        assert ("ProvLabs/vault", "a" * 40, "vault") in t, t
        assert ("ProvLabs/nuva-evm-contracts", "b" * 40, "nuva-evm-contracts") in t, t


def test_read_targets_tsv_skips_comments_and_bad_rows():
    m = _load_module()
    with tempfile.TemporaryDirectory() as ws:
        with open(os.path.join(ws, "targets.tsv"), "w") as fh:
            fh.write("# header\n\nhttps://github.com/o/r.git\tnotasha\tr\n")  # bad pin -> skip
        assert m._read_targets_tsv(ws) == []


def test_pin_policy_deployed_recognized():
    m = _load_module()
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "pin_policy.json", {"policy": "deployed"})
        assert m._pin_policy(ws) == "deployed"


def test_pin_freshness_deployed_policy_is_full_not_behind_head():
    # NUVA deployed-only: a deployed pin is intentionally NOT latest HEAD/release;
    # pin-freshness must credit FULL, never false-DEGRADE "behind HEAD".
    m = _load_module()
    # stub the network probes - they must NOT be consulted under deployed policy
    m._remote_default_tip = lambda repo: "f" * 40
    m._latest_stable_release_sha = lambda repo: ("v9.9.9", "e" * 40)
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "pin_policy.json", {"policy": "deployed",
                                       "evm_deployed_pin": "7bcc72d2bb3f17551c387b0277a79cc4db480d62"})
        _write(ws, "repo_strategy.json", {"owner_repo": "ProvLabs/nuva-evm-contracts",
                                          "targets": [{"owner_repo": "ProvLabs/nuva-evm-contracts",
                                                       "pin": "7bcc72d2bb3f17551c387b0277a79cc4db480d62",
                                                       "local_name": "nuva-evm-contracts"}]})
        status, reason = m.check_pin_freshness(ws)
        assert status == "FULL", (status, reason)
        assert "deployed-pin policy" in reason and "BEHIND" not in reason, reason


def test_pin_freshness_release_policy_skips_when_no_release_resolvable():
    m = _load_module()
    m._latest_stable_release_sha = lambda repo: ("", "")
    with tempfile.TemporaryDirectory() as ws:
        _write(ws, "pin_policy.json", {"policy": "release"})
        _write(ws, "repo_strategy.json", {"owner_repo": "a/b", "targets": [{"pin": "c" * 40}]})
        status, reason = m.check_pin_freshness(ws)
        assert status == "SKIPPED", (status, reason)
        assert "release-pin policy" in reason, reason


if __name__ == "__main__":
    test_commit_mining_local_only_is_degraded_and_fails_strict()
    test_commit_mining_full_upstream_is_full()
    test_missing_commit_mining_is_skipped()
    test_stale_hunt_artifact_is_degraded()
    test_fresh_hunt_artifact_is_full()
    test_hunt_without_corpus_is_graceful_full()
    test_empty_hunt_file_is_degraded()
    test_pin_read_from_repo_strategy_targets()
    test_pin_read_top_level_audit_pin_sha()
    test_scanners_detector_artifacts_are_full()
    test_scanners_truly_empty_still_skips()
    test_remote_default_tip_slug_normalisation()
    test_pin_freshness_full_when_pin_equals_tip()
    test_pin_freshness_degraded_when_pin_behind()
    test_pin_policy_default_is_head()
    test_pin_policy_marker_overrides()
    test_pin_policy_autodetect_from_scope_prose()
    test_pin_freshness_release_policy_full_when_pin_equals_latest_release()
    test_pin_freshness_release_policy_degraded_when_behind_release()
    test_pin_freshness_release_policy_skips_when_no_release_resolvable()
    test_read_targets_falls_back_to_targets_tsv()
    test_read_targets_tsv_skips_comments_and_bad_rows()
    test_pin_policy_deployed_recognized()
    test_pin_freshness_deployed_policy_is_full_not_behind_head()
    print("ok")
