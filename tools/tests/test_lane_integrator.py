"""Unit tests for tools/lane-integrator.py (WF-7 #3 canonical integrator)."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "lane_integrator",
    ROOT / "tools" / "lane-integrator.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


# Bypass the auditooor MCP-gated `git` wrapper for the entire test process.
# The wrapper rejects `commit` / `push` when the workspace lacks a fresh
# `.auditooor/last_mcp_recall.json`, which is correct in production but
# unwanted in a hermetic unit-test temp dir.
def _scrubbed_path() -> str:
    parts = [
        p for p in os.environ.get("PATH", "").split(os.pathsep)
        if p and "auditooor" not in p.lower() and ".auditooor" not in p
    ]
    return os.pathsep.join(parts or ["/usr/bin", "/bin"])


def _repo_pythonpath() -> str:
    parts = [str(ROOT)]
    existing = os.environ.get("PYTHONPATH", "")
    if existing:
        parts.extend(p for p in existing.split(os.pathsep) if p)
    return os.pathsep.join(parts)


_BASE_ENV: dict[str, str] = {
    "PATH": _scrubbed_path(),
    "PYTHONPATH": _repo_pythonpath(),
    "GIT_AUTHOR_NAME": "lane-integrator-test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "lane-integrator-test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def _run(args: list[str], cwd: Path,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    e = os.environ.copy()
    e.update(_BASE_ENV)
    e.update(env or {})
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True,
                          env=e, check=False)


def _git(args: list[str], cwd: Path,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return _run(["git"] + args, cwd=cwd, env=env)


def _init_repo() -> Path:
    root = Path(tempfile.mkdtemp(prefix="lane_integrator_test_"))
    _git(["init", "-q", "-b", "main"], cwd=root)
    # Disable hooks (the live r36 hook would fight our temp test).
    (root / ".git" / "hooks").mkdir(exist_ok=True)
    # Initial empty commit so HEAD exists.
    (root / "README.md").write_text("# test repo\n")
    _git(["add", "README.md"], cwd=root)
    _git(["commit", "-q", "-m", "init"], cwd=root)
    return root


def _future_iso(seconds: int = 3600) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _past_iso(seconds: int = 3600) -> str:
    return (
        datetime.now(timezone.utc) - timedelta(seconds=seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_pathspec(repo: Path, agents: list[dict]) -> Path:
    pdir = repo / ".auditooor"
    pdir.mkdir(exist_ok=True)
    spec = pdir / "agent_pathspec.json"
    spec.write_text(json.dumps({"agents": agents}, indent=2))
    return spec


def _make_lane_report(
    repo: Path, lane_id: str, title: str, body_tokens: list[str],
    context_pack_id: str = "auditooor.vault_context_pack.v1:resume:abc123",
) -> Path:
    p = repo / "reports" / "v3_iter_2026-05-23_test" / f"lane_{lane_id}"
    p.mkdir(parents=True, exist_ok=True)
    rep = p / "results.md"
    body_lines = ["# " + title, ""]
    if context_pack_id:
        body_lines += [f"MCP context_pack_id: {context_pack_id}", ""]
    body_lines += body_tokens
    body = "\n".join(body_lines)
    rep.write_text(body)
    return rep


def _invoke(repo: Path, extra: list[str]) -> tuple[int, dict, str]:
    cmd = [
        "python3", str(ROOT / "tools" / "lane-integrator.py"),
        "--repo-root", str(repo),
        "--json",
    ] + extra
    out = _run(cmd, cwd=repo)
    try:
        payload = json.loads(out.stdout)
    except json.JSONDecodeError:
        payload = {"_raw": out.stdout, "_stderr": out.stderr}
    return out.returncode, payload, out.stderr


ROADMAP_MEMORY_FIXTURE = """# Roadmap result memory fixture

## PHASE 0 - Foundation

### 0.1 Integrator result memory
**Owner**: CODEX
"""


class LaneIntegratorTests(unittest.TestCase):
    # ------------------------------------------------------------------
    # Pure-function unit tests (no git).
    # ------------------------------------------------------------------
    def test_01_parse_lane_report_extracts_title_and_headings(self):
        text = (
            "# My Lane Title\n\n"
            "MCP context_pack_id: auditooor.vault_context_pack.v1:resume:abc123\n\n"
            "## Status: LANDED\n\nbody text foo\n"
        )
        rep = mod.parse_lane_report(text)
        self.assertEqual(rep["title"], "My Lane Title")
        self.assertIn("my lane title", rep["headings"])
        self.assertIn("status: landed", rep["headings"])
        self.assertEqual(
            rep["context_pack_id"],
            "auditooor.vault_context_pack.v1:resume:abc123",
        )

    def test_02_claim_overclaim_passes_when_tokens_in_report(self):
        report = mod.parse_lane_report(
            "# Lane\n\nThis lane added a foobar widget under tools/.\n"
        )
        commit = "Phase X: lane adds foobar widget\n"
        over, lines = mod.claim_overclaim_check(commit, report)
        self.assertFalse(over, msg=f"unexpected overclaim lines: {lines}")

    def test_03_claim_overclaim_catches_iter17_ttttt_style(self):
        # Report only mentions foo; commit claims it added quuxwidget.
        # "added" is a claim keyword (per _CLAIM_KEYWORD_RE) and triggers
        # claim-vs-report token matching.
        report = mod.parse_lane_report(
            "# Lane\n\nWe added the foo widget. Done.\n"
        )
        commit = "Phase X: added quuxwidget and zorktool blast\n"
        over, lines = mod.claim_overclaim_check(commit, report)
        self.assertTrue(over, msg=f"expected overclaim catch; lines={lines}")
        self.assertEqual(len(lines), 1)

    def test_04_split_lane_vs_sibling_basic(self):
        agents = [
            {"agent_id": "lane-A", "files": ["a.py", "b.py"],
             "expires_at": _future_iso()},
            {"agent_id": "lane-B", "files": ["c.py", "d.py"],
             "expires_at": _future_iso()},
        ]
        lane_a, sib = mod.split_lane_vs_sibling(agents, "lane-A")
        self.assertEqual(lane_a, {"a.py", "b.py"})
        self.assertEqual(sib, {"c.py", "d.py"})

    def test_05_split_lane_vs_sibling_drops_expired_siblings(self):
        agents = [
            {"agent_id": "lane-A", "files": ["a.py"],
             "expires_at": _future_iso()},
            {"agent_id": "lane-B-expired", "files": ["z.py"],
             "expires_at": _past_iso()},
        ]
        lane_a, sib = mod.split_lane_vs_sibling(agents, "lane-A")
        self.assertEqual(lane_a, {"a.py"})
        self.assertEqual(sib, set(),
                         msg="expired sibling must be dropped")

    def test_06_load_pathspec_missing_returns_empty_with_warning(self):
        repo = Path(tempfile.mkdtemp(prefix="lt_missing_"))
        agents, warns = mod.load_pathspec(
            repo / ".auditooor" / "agent_pathspec.json"
        )
        self.assertEqual(agents, [])
        self.assertTrue(warns)

    def test_07_compose_commit_message_shape(self):
        msg = mod.compose_commit_message(
            headline="Phase X: do the thing",
            report_path=Path("reports/test/lane_X/results.md"),
            lane_id="lane-X",
            declared_files=["tools/foo.py", "tools/tests/test_foo.py"],
            claim_evidence="ok all tests pass",
        )
        self.assertIn("Phase X: do the thing", msg)
        self.assertIn("Lane: lane-X", msg)
        self.assertIn("tools/foo.py", msg)
        self.assertIn("Claim evidence: ok all tests pass", msg)
        self.assertIn("WF-7 #3", msg)

    def test_07a_extracts_invariant_candidate_anchor_shape(self):
        report = Path("reports/v3_iter_2026-05-25/lane_HYPERBRIDGE_DRILL_7/results.md")
        text = (
            "# Lane HYPERBRIDGE-DRILL-7 Results\n\n"
            "- Lane: HYPERBRIDGE-DRILL-7-HANDLERV2-DOUBLE-REFUND\n"
            "context_pack_id: auditooor.vault_active_roadmap.v1:abc123\n\n"
            "## Key invariant identified\n\n"
            "INV-HYPERBRIDGE-001: For any request R, receipt existence implies timestamp < T.\n\n"
            "Enforcing code path: `modules/ismp/core/src/handlers/request.rs:62-65`:\n"
            "Composed with the receipt write at request.rs:104.\n"
        )
        rows = mod.extract_invariant_candidates_from_report(report, text)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["schema_version"], "auditooor.invariant_candidate.v1")
        self.assertEqual(row["invariant_id"], "INV-HYPERBRIDGE-001")
        self.assertEqual(row["target"], "HYPERBRIDGE")
        self.assertEqual(
            row["verification_tier"],
            "tier-2-verified-public-archive",
        )
        self.assertEqual(
            row["source_lane"],
            "HYPERBRIDGE-DRILL-7-HANDLERV2-DOUBLE-REFUND",
        )
        self.assertEqual(
            row["audit_pin"],
            "auditooor.vault_active_roadmap.v1:abc123",
        )
        self.assertEqual(
            row["enforcing_code_path"],
            ["modules/ismp/core/src/handlers/request.rs:62-65", "request.rs:104"],
        )

    def test_07aaa_inline_invariant_references_are_not_candidates(self):
        report = Path("reports/v3_iter_2026-05-25/lane_X/results.md")
        text = (
            "# Lane X\n\n"
            "- Lane: X\n"
            "context_pack_id: pin:1\n\n"
            "Prior P1 invariants INV-BND-004 + INV-AUTH-001 are relevant; "
            "HandlerV2.sol:270 was reviewed.\n"
        )
        self.assertEqual(mod.extract_invariant_candidates_from_report(report, text), [])

    def test_07aa_emit_invariant_candidates_is_idempotent(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out_path = Path(tmp.name) / "audit" / "corpus_tags" / "ws" / "invariants_extracted.jsonl"
        rows = [
            {
                "schema_version": "auditooor.invariant_candidate.v1",
                "invariant_id": "INV-FOO-001",
                "target": "FOO",
                "statement": "Foo MUST hold.",
                "enforcing_code_path": ["src/foo.rs:12"],
                "verification_tier": "tier-2-verified-public-archive",
                "source_lane": "LANE-FOO",
                "audit_pin": "pin:1",
            }
        ]
        first = mod.emit_invariant_candidates(out_path, rows)
        second = mod.emit_invariant_candidates(out_path, rows)
        self.assertEqual(first["rows_appended"], 1)
        self.assertEqual(second["rows_appended"], 0)
        lines = out_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["invariant_id"], "INV-FOO-001")

    def test_07ab_dry_run_emits_fuzz_target_plan_from_sibling_results(self):
        repo = _init_repo()
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "foo.py").write_text("# foo widget code\n", encoding="utf-8")
        rep = _make_lane_report(
            repo,
            "lane-FUZZ-A",
            "Lane FUZZ A",
            ["body: ship foo widget"],
        )
        payload = {
            "schema": "auditooor.fuzz_campaign_results.v1",
            "lane": "lane-FUZZ-A",
            "workspace": "hyperbridge",
            "fuzz_targets": [
                {
                    "id": "T3",
                    "name": "VWAPOracle.recordSpread / spread()",
                    "tool": "Foundry forge fuzz",
                    "verdict": "VIOLATED",
                    "invariant": "spread() always in [-10000,+10000]",
                    "fileable_finding": True,
                    "title_candidate": "VWAPOracle.spread() returns unbounded values",
                    "forge_path": "/tmp/does-not-exist/FuzzVWAPOracle.t.sol",
                }
            ],
        }
        rep.with_name("fuzz_results.json").write_text(
            json.dumps(payload),
            encoding="utf-8",
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-FUZZ-A",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, parsed, _ = _invoke(repo, [
            "--lane-id", "lane-FUZZ-A",
            "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship foo widget",
            "--gate", "skip", "--dry-run",
            "--fuzz-workspace", "hyperbridge",
        ])
        self.assertEqual(rc, 0, msg=parsed)
        self.assertEqual(parsed["verdict"], "pass-dry-run")
        self.assertEqual(parsed["fuzz_target_emit"]["targets_found"], 1)
        self.assertTrue(
            parsed["fuzz_target_emit"]["path"].endswith(
                "audit/corpus_tags/hyperbridge/fuzz_targets.jsonl"
            )
        )

    def test_07b_record_roadmap_result_invokes_vault_remember(self):
        os.environ.setdefault("AUDITOOOR_MCP_SECRET", "lane-integrator-memory-test")
        repo = _init_repo()
        (repo / "obsidian-vault").mkdir(exist_ok=True)
        roadmap = repo / "roadmap.md"
        state = repo / "state.json"
        roadmap.write_text(ROADMAP_MEMORY_FIXTURE, encoding="utf-8")

        vault_spec = importlib.util.spec_from_file_location(
            "vault_mcp_server_for_lane_integrator_test",
            ROOT / "tools" / "vault-mcp-server.py",
        )
        vault_mod = importlib.util.module_from_spec(vault_spec)
        assert vault_spec.loader is not None
        sys.modules[vault_spec.name] = vault_mod
        vault_spec.loader.exec_module(vault_mod)
        vault = vault_mod.VaultQuery(repo / "obsidian-vault", repo)
        claimed = vault.vault_active_roadmap(
            side="codex",
            claim=True,
            item_id="PHASE-0.1",
            roadmap_path=str(roadmap),
            state_path=str(state),
        )

        receipt = mod._record_roadmap_result(
            repo_root=repo,
            item_id="PHASE-0.1",
            claim_token=claimed["claim_token"],
            result_status="LANDED",
            result_summary="Integrator helper recorded result-time memory.",
            remember_signed_token="",
            roadmap_path=roadmap,
            state_path=state,
        )

        self.assertTrue(receipt["attempted"], msg=receipt)
        self.assertTrue(receipt["accepted"], msg=receipt)
        remember = receipt["result_remember"]
        self.assertTrue(remember["accepted"], msg=remember)
        self.assertTrue(Path(remember["memory_path"]).exists())
        state_payload = json.loads(state.read_text(encoding="utf-8"))
        self.assertTrue(
            state_payload["items"]["PHASE-0.1"]["result_remember"]["accepted"]
        )
        shutil.rmtree(Path(remember["memory_path"]).parent, ignore_errors=True)

    # ------------------------------------------------------------------
    # End-to-end CLI tests (real git repo, real subprocess).
    # ------------------------------------------------------------------
    def test_08_e2e_fail_no_pathspec_registered(self):
        repo = _init_repo()
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-nothing", "--auto-discover", "--gate", "skip",
        ])
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-pathspec-registered")

    def test_09_e2e_fail_no_lane_report(self):
        repo = _init_repo()
        _write_pathspec(repo, [
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-A", "--auto-discover", "--gate", "skip",
        ])
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-lane-report")

    def test_10_e2e_fail_no_pack_id_in_lane_results(self):
        repo = _init_repo()
        (repo / "tools").mkdir(exist_ok=True)
        target = repo / "tools" / "foo.py"
        target.write_text("# foo widget added\n")
        rep = _make_lane_report(
            repo, "lane-A", "Lane A added foo widget",
            ["body: foo widget under tools/foo.py shipped"],
            context_pack_id="",
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-A",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-A", "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship the foo widget",
            "--gate", "skip",
        ])
        self.assertEqual(rc, 1, msg=payload)
        self.assertEqual(payload["verdict"], "fail-no-pack-id-in-lane-results")

    def test_11_e2e_pass_dry_run(self):
        repo = _init_repo()
        (repo / "tools").mkdir(exist_ok=True)
        target = repo / "tools" / "foo.py"
        target.write_text("# foo widget added\n")
        rep = _make_lane_report(
            repo, "lane-A", "Lane A added foo widget",
            [
                "MCP context_pack_id: auditooor.vault_context_pack.v1:"
                "resume:abc123",
                "body: foo widget under tools/foo.py shipped",
            ],
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-A",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-A", "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship the foo widget",
            "--gate", "skip", "--dry-run",
        ])
        self.assertEqual(rc, 0, msg=payload)
        self.assertEqual(payload["verdict"], "pass-dry-run")
        self.assertIn("tools/foo.py", payload["would_stage"])

    def test_12_e2e_pass_clean_commit(self):
        repo = _init_repo()
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "foo.py").write_text("# foo widget code\n")
        rep = _make_lane_report(
            repo, "lane-A", "Lane A added foo widget",
            [
                "MCP context_pack_id: auditooor.vault_context_pack.v1:"
                "resume:abc123",
                "body: foo widget under tools/foo.py shipped",
            ],
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-A",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-A", "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship the foo widget",
            "--gate", "skip",
        ])
        self.assertEqual(rc, 0, msg=payload)
        self.assertEqual(payload["verdict"], "pass-clean-commit")
        self.assertTrue(payload["commit_sha"])
        # Verify commit landed via git log.
        log = _git(["log", "--oneline", "-1"], cwd=repo).stdout
        self.assertIn("Phase X", log)

    def test_13_e2e_fail_sibling_file_staged(self):
        # Sibling owns sib.py.  Working tree contains sib.py edits that
        # are NOT in lane-A's pathspec.  Lane-A's own file is also edited
        # (so we get past the empty-stage check).  After lane-A's
        # explicit-pathspec stage, only its own file should be staged.
        # We verify by introducing the sibling file into the lane's
        # declared list AFTER pathspec load to simulate overflow.  Easier
        # path: install our own pre-commit hook that stages sib.py, then
        # confirm the post-stage check refuses.
        repo = _init_repo()
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "foo.py").write_text("# foo widget code\n")
        (repo / "tools" / "sib.py").write_text("# sibling work\n")
        rep = _make_lane_report(
            repo, "lane-A", "Lane A added foo widget",
            ["body: foo widget under tools/foo.py shipped"],
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-A",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
            {"agent_id": "lane-B-sibling",
             "files": ["tools/sib.py"],
             "expires_at": _future_iso()},
        ])
        # Pre-stage the sibling file so it lands in the staged diff.
        _git(["add", "tools/sib.py"], cwd=repo)
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-A", "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship the foo widget",
            "--gate", "skip",
        ])
        self.assertEqual(rc, 1, msg=payload)
        self.assertEqual(payload["verdict"], "fail-sibling-file-staged")
        self.assertIn("tools/sib.py", payload["sibling_overflow"])

    def test_14_e2e_fail_claim_overclaim(self):
        repo = _init_repo()
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "foo.py").write_text("# foo widget code\n")
        rep = _make_lane_report(
            repo, "lane-A", "Lane A only mentions the foo widget",
            ["body: foo widget under tools/foo.py only"],
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-A",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        # Commit message claims foo AND quuxwidget shipped; report only
        # documents foo.  This is the iter17 TTTTT overclaim shape.
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-A", "--report", str(rep.relative_to(repo)),
            "--message",
            "Phase X: added quuxwidget and zorktool plus blastbear",
            "--gate", "skip",
        ])
        self.assertEqual(rc, 1, msg=payload)
        self.assertEqual(payload["verdict"], "fail-claim-overclaim")
        self.assertTrue(payload["overclaim_lines"])

    def test_15_e2e_fail_gate_broken(self):
        repo = _init_repo()
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "foo.py").write_text("# foo widget code\n")
        rep = _make_lane_report(
            repo, "lane-A", "Lane A added foo widget",
            ["body: foo widget under tools/foo.py shipped"],
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-A",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-A", "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship the foo widget",
            "--gate", "false",
        ])
        self.assertEqual(rc, 1, msg=payload)
        self.assertEqual(payload["verdict"], "fail-gate-broken")
        self.assertEqual(payload["gate_command"], "false")

    def test_16_e2e_fail_empty_stage(self):
        repo = _init_repo()
        # Create + COMMIT a report so it does not show up in the staged diff.
        rep = _make_lane_report(
            repo, "lane-A", "Lane A added foo widget",
            ["body: foo widget under tools/foo.py shipped"],
        )
        _git(["add", str(rep.relative_to(repo))], cwd=repo)
        _git(["commit", "-q", "-m", "pre-commit lane report"], cwd=repo)
        # Declare ONLY a file that does NOT exist in the working tree.
        _write_pathspec(repo, [
            {"agent_id": "lane-A",
             "files": ["tools/nonexistent.py"],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-A", "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship the foo widget",
            "--gate", "skip",
        ])
        self.assertEqual(rc, 1, msg=payload)
        self.assertEqual(payload["verdict"], "fail-empty-stage")

    def test_17_e2e_auto_discover_finds_lane_report(self):
        repo = _init_repo()
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "foo.py").write_text("# foo widget code\n")
        rep = _make_lane_report(
            repo, "auto-discover-A", "Lane added foo widget",
            [
                "MCP context_pack_id: auditooor.vault_context_pack.v1:"
                "resume:abc123",
                "body: foo widget under tools/foo.py shipped",
            ],
        )
        _write_pathspec(repo, [
            {"agent_id": "auto-discover-A",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "auto-discover-A", "--auto-discover",
            "--message", "Phase X: ship the foo widget",
            "--gate", "skip", "--dry-run",
        ])
        self.assertEqual(rc, 0, msg=payload)
        self.assertEqual(payload["verdict"], "pass-dry-run")
        self.assertIn("auto-discover-A", payload["lane_report"])

    def test_18b_e2e_fail_undeclared_overflow(self):
        # Undeclared (unowned by any sibling) file pre-staged by another
        # process must be refused with fail-sibling-file-staged and
        # unstaged in the process.
        repo = _init_repo()
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "foo.py").write_text("# foo widget code\n")
        (repo / "stray.md").write_text("# stray file from elsewhere\n")
        rep = _make_lane_report(
            repo, "lane-A", "Lane A added foo widget",
            ["body: foo widget under tools/foo.py shipped"],
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-A",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        _git(["add", "stray.md"], cwd=repo)
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-A", "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship the foo widget",
            "--gate", "skip",
        ])
        self.assertEqual(rc, 1, msg=payload)
        self.assertEqual(payload["verdict"], "fail-sibling-file-staged")
        self.assertIn("stray.md", payload["undeclared_overflow"])
        # After refusal, stray.md should be unstaged.
        leftover = _git(["diff", "--cached", "--name-only"],
                        cwd=repo).stdout.strip()
        self.assertNotIn("stray.md", leftover.splitlines())

    # ------------------------------------------------------------------
    # LANE-INTEGRATOR-AUTODISCOVER-FIX regression tests (2026-05-23).
    # STATUS-SNAPSHOT surfaced: matcher rejected valid lane reports whose
    # directory casing / separator style / token count didn't exactly
    # match the registered lane ID. Fix: tokenize + token-prefix match.
    # ------------------------------------------------------------------
    def test_19_token_match_upper_case_matches_underscore_dir(self):
        """Upper-case lane ID matches `lane_STATUS_SNAPSHOT/` directory."""
        # Direct unit test of the canonical matcher.
        self.assertTrue(mod._lane_token_match("STATUS-SNAPSHOT",
                                              "lane_STATUS_SNAPSHOT"))
        self.assertTrue(mod._lane_token_match("lane_STATUS_SNAPSHOT",
                                              "STATUS-SNAPSHOT"))

    def test_20_token_match_hyphen_vs_underscore(self):
        """`lane-WIRE-1` matches `lane_WIRE_1` (separator-only difference)."""
        self.assertTrue(mod._lane_token_match("lane-WIRE-1", "lane_WIRE_1"))
        self.assertTrue(mod._lane_token_match("WIRE-1", "lane_WIRE_1"))
        self.assertTrue(mod._lane_token_match("lane-WIRE-1-hunt-tools-wiring",
                                              "lane_WIRE_1"))

    def test_21_token_match_mixed_case_multi_part_prefix(self):
        """`lane-FIX-A-pathspec` matches `lane_FIX_A_pathspec_race`
        (token-prefix match - the registered id has extra trailing tokens).
        """
        self.assertTrue(mod._lane_token_match(
            "lane-FIX-A-pathspec", "lane_FIX_A_pathspec_race"
        ))
        # Symmetric: longer registered id matches shorter dir name.
        self.assertTrue(mod._lane_token_match(
            "lane-STATUS-SNAPSHOT-iter18", "lane_STATUS_SNAPSHOT"
        ))
        # Operator-typed short form matches registered long form.
        self.assertTrue(mod._lane_token_match(
            "STATUS-SNAPSHOT", "lane-STATUS-SNAPSHOT-iter18"
        ))

    def test_22_token_match_genuine_non_match_still_fails(self):
        """`lane-X` vs `lane_Y` must still NOT match (no false positives)."""
        self.assertFalse(mod._lane_token_match("lane-X", "lane_Y"))
        self.assertFalse(mod._lane_token_match("FIX-A", "FIX-B"))
        # Token mismatch at the prefix boundary is NOT a token-prefix.
        self.assertFalse(mod._lane_token_match(
            "lane-FIX-A-pathspec", "lane_FIX_B_pathspec_race"
        ))
        # Empty / blank ids never match.
        self.assertFalse(mod._lane_token_match("", "lane_X"))
        self.assertFalse(mod._lane_token_match("lane_X", ""))
        # `lane` prefix alone (nothing else) does not match anything.
        self.assertFalse(mod._lane_token_match("lane", "lane_X"))

    def test_21b_token_match_doubled_lane_prefix(self):
        """`lane-LANE-X` and `lane_LANE_X` both reduce to `[x]` so a lane id
        like `LANE-INTEGRATOR-AUTODISCOVER-FIX` whose directory ends up as
        `lane_LANE_INTEGRATOR_AUTODISCOVER_FIX` still matches.

        The fix is to strip ALL leading `lane` tokens, not just the first
        one. Dogfood anchor: this LANE-INTEGRATOR-AUTODISCOVER-FIX lane
        itself triggered the doubled-prefix case when self-integrating.
        """
        self.assertTrue(mod._lane_token_match(
            "LANE-INTEGRATOR-AUTODISCOVER-FIX",
            "lane_LANE_INTEGRATOR_AUTODISCOVER_FIX",
        ))
        self.assertTrue(mod._lane_token_match(
            "lane-LANE-INTEGRATOR-AUTODISCOVER-FIX",
            "LANE-INTEGRATOR-AUTODISCOVER-FIX",
        ))
        self.assertEqual(
            mod._lane_tokens("lane_LANE_INTEGRATOR_AUTODISCOVER_FIX"),
            ["integrator", "autodiscover", "fix"],
        )

    def test_22_e2e_status_snapshot_short_form_auto_discover(self):
        """End-to-end regression for the STATUS-SNAPSHOT bug shape.

        The lane is registered with agent_id=`lane-STATUS-SNAPSHOT-iter18`
        and the report sits at `lane_STATUS_SNAPSHOT/results.md`. Operator
        invokes with the short `--lane-id STATUS-SNAPSHOT`. Pre-fix this
        produced `fail-no-pathspec-registered` (matcher missed the longer
        registered id) and even if pathspec matched, the directory name
        `lane_STATUS_SNAPSHOT` was found only by accident. Post-fix both
        sides resolve and the dry-run passes cleanly.
        """
        repo = _init_repo()
        (repo / "tools").mkdir(exist_ok=True)
        target = repo / "tools" / "foo.py"
        target.write_text("# foo widget code\n")
        # Report dir uses UPPER_SNAKE; lane id registered with iter18 suffix.
        rep_dir = (
            repo / "reports" / "v3_iter_2026-05-23_iter18"
            / "lane_STATUS_SNAPSHOT"
        )
        rep_dir.mkdir(parents=True, exist_ok=True)
        rep = rep_dir / "results.md"
        rep.write_text(
            "# STATUS-SNAPSHOT iter18\n\n"
            "MCP context_pack_id: auditooor.vault_context_pack.v1:resume:abc123\n\n"
            "body: foo widget under tools/foo.py shipped\n"
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-STATUS-SNAPSHOT-iter18",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "STATUS-SNAPSHOT",
            "--auto-discover",
            "--message", "Phase X: ship the foo widget",
            "--gate", "skip", "--dry-run",
        ])
        self.assertEqual(rc, 0, msg=payload)
        self.assertEqual(payload["verdict"], "pass-dry-run")
        self.assertIn("lane_STATUS_SNAPSHOT", payload["lane_report"])
        self.assertIn("tools/foo.py", payload["would_stage"])

    def test_23_e2e_token_prefix_lane_id_matches_longer_dir(self):
        """`lane-FIX-A-pathspec` (operator-typed) discovers
        `lane_FIX_A_pathspec_race/results.md` (registered long form).
        """
        repo = _init_repo()
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "foo.py").write_text("# fix-a pathspec code\n")
        rep_dir = (
            repo / "reports" / "v3_iter_2026-05-23_iter18"
            / "lane_FIX_A_pathspec_race"
        )
        rep_dir.mkdir(parents=True, exist_ok=True)
        rep = rep_dir / "results.md"
        rep.write_text(
            "# FIX-A pathspec race lane report\n\n"
            "MCP context_pack_id: auditooor.vault_context_pack.v1:resume:abc123\n\n"
            "body: FIX-A-pathspec change under tools/foo.py shipped\n"
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-FIX-A-pathspec-race",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "FIX-A-pathspec",
            "--auto-discover",
            "--message", "Phase X: ship fix-a pathspec",
            "--gate", "skip", "--dry-run",
        ])
        self.assertEqual(rc, 0, msg=payload)
        self.assertEqual(payload["verdict"], "pass-dry-run")
        self.assertIn("lane_FIX_A_pathspec_race", payload["lane_report"])

    def test_24_e2e_genuine_non_match_still_fails(self):
        """Make sure the looser matcher doesn't paper over real misses.

        `--lane-id FIX-Z` (typo / nonexistent lane) must still fail with
        `fail-no-pathspec-registered`; we must NOT silently bind to a
        nearby `lane-FIX-A-pathspec-race` entry.
        """
        repo = _init_repo()
        _write_pathspec(repo, [
            {"agent_id": "lane-FIX-A-pathspec-race",
             "files": ["tools/foo.py"],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "FIX-Z",
            "--auto-discover",
            "--gate", "skip",
        ])
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-pathspec-registered")

    def test_17_e2e_push_flag_opt_in(self):
        # Set up a bare upstream so push has somewhere to go.
        upstream = Path(tempfile.mkdtemp(prefix="lt_upstream_"))
        _git(["init", "-q", "--bare"], cwd=upstream)
        repo = _init_repo()
        _git(["remote", "add", "origin", str(upstream)], cwd=repo)
        _git(["push", "-u", "origin", "main"], cwd=repo)
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "foo.py").write_text("# foo widget code\n")
        rep = _make_lane_report(
            repo, "lane-A", "Lane A added foo widget",
            ["body: foo widget under tools/foo.py shipped"],
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-A",
             "files": ["tools/foo.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-A", "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship the foo widget",
            "--gate", "skip", "--push",
        ])
        self.assertEqual(rc, 0, msg=payload)
        self.assertEqual(payload["verdict"], "pass-clean-commit-and-push")
        self.assertTrue(payload["pushed"])


# ============================================================================
# v1.2 auto-merge tests (LANE-INTEGRATOR-AUTOMERGE-PATCH, 2026-05-23)
#
# Patches structural merge-gap: spawn-lane-worktree creates
# lane/<id>-<sha> branch; lane-integrator --push lands on that branch;
# cleanup never merges to main. v1.2 adds FF-only auto-merge after push.
# R55-safe: FF-only, no --force / --force-with-lease.
# ============================================================================


def _setup_upstream_repo() -> tuple[Path, Path]:
    """Create a bare upstream + clone on main. Return (upstream, repo)."""
    upstream = Path(tempfile.mkdtemp(prefix="lt_am_upstream_"))
    _git(["init", "-q", "--bare", "-b", "main"], cwd=upstream)
    repo = _init_repo()
    _git(["remote", "add", "origin", str(upstream)], cwd=repo)
    _git(["push", "-u", "origin", "main"], cwd=repo)
    return upstream, repo


def _checkout_lane_feature_branch(repo: Path, lane_id: str,
                                  short_sha: str = "abc1234") -> str:
    """Check out a `lane/<id>-<sha>` feature branch matching the spawn
    convention so the integrator's auto-merge path fires."""
    branch = f"lane/{lane_id}-{short_sha}"
    _git(["checkout", "-b", branch], cwd=repo)
    return branch


class LaneIntegratorAutoMergeTests(unittest.TestCase):
    # ---- helper-function unit tests ----

    def test_am_01_lane_feature_branch_re_matches_canonical(self):
        # spawn-lane-worktree.sh:148 BRANCH_NAME=lane/${LANE_ID}-${SHORT_SHA}
        self.assertTrue(mod.LANE_FEATURE_BRANCH_RE.match(
            "refs/heads/lane/FIX-AUTOMERGE-abc1234"))
        self.assertTrue(mod.LANE_FEATURE_BRANCH_RE.match(
            "refs/heads/lane/R57-FIXTURE-EXPANSION-v2-74500f90d0"))
        self.assertTrue(mod.LANE_FEATURE_BRANCH_RE.match(
            "refs/heads/lane/X-1234567"))

    def test_am_02_lane_feature_branch_re_rejects_main_and_others(self):
        self.assertIsNone(mod.LANE_FEATURE_BRANCH_RE.match(
            "refs/heads/main"))
        self.assertIsNone(mod.LANE_FEATURE_BRANCH_RE.match(
            "refs/heads/feature/some-branch"))
        # Missing hex tail
        self.assertIsNone(mod.LANE_FEATURE_BRANCH_RE.match(
            "refs/heads/lane/FIX-AUTOMERGE"))
        # Non-hex tail
        self.assertIsNone(mod.LANE_FEATURE_BRANCH_RE.match(
            "refs/heads/lane/X-zzzzzzz"))

    def test_am_03_is_on_lane_feature_branch_on_main(self):
        repo = _init_repo()
        self.assertFalse(mod._is_on_lane_feature_branch(repo))

    def test_am_04_is_on_lane_feature_branch_on_feature(self):
        repo = _init_repo()
        _checkout_lane_feature_branch(repo, "AUTOMERGE-UNIT-TEST", "abc1234")
        self.assertTrue(mod._is_on_lane_feature_branch(repo))

    # ---- end-to-end auto-merge tests ----

    def test_am_05_main_branch_context_no_automerge_attempt(self):
        """On the canonical main branch, no auto-merge is attempted -
        backward compatibility with the existing pass-clean-commit-and-push
        verdict (P-1-D / iter18 / 14 lanes that already work this way)."""
        _, repo = _setup_upstream_repo()
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "foo_am.py").write_text("# foo am widget\n")
        rep = _make_lane_report(
            repo, "lane-AM-MAIN", "Lane AM MAIN adds foo am",
            ["body: foo_am widget under tools/foo_am.py shipped",
             "Lane: lane-AM-MAIN",
             "Lane report: reports body content",
             "results.md results.md results.md"],
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-AM-MAIN",
             "files": ["tools/foo_am.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-AM-MAIN",
            "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship foo am widget",
            "--gate", "skip", "--push",
        ])
        self.assertEqual(rc, 0, msg=payload)
        self.assertEqual(payload["verdict"], "pass-clean-commit-and-push")
        self.assertFalse(payload.get("automerge_attempted", False))

    def test_am_06_feature_branch_ff_merge_success(self):
        """On a lane/<id>-<sha> feature branch FF-able to origin/main,
        the integrator auto-merges and emits the new verdict."""
        _, repo = _setup_upstream_repo()
        _checkout_lane_feature_branch(repo, "AUTOMERGE-FF-CASE", "abc1234")
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "ff_widget.py").write_text("# ff widget\n")
        rep = _make_lane_report(
            repo, "lane-AUTOMERGE-FF-CASE", "Lane FIX AM FF adds ff_widget",
            ["body: ff_widget under tools/ff_widget.py shipped",
             "Lane: lane-AUTOMERGE-FF-CASE",
             "Lane report: reports body content",
             "results.md results.md results.md"],
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-AUTOMERGE-FF-CASE",
             "files": ["tools/ff_widget.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-AUTOMERGE-FF-CASE",
            "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship ff_widget",
            "--gate", "skip", "--push",
        ])
        self.assertEqual(rc, 0, msg=payload)
        self.assertEqual(payload["verdict"],
                         "pass-clean-commit-and-push-and-automerged")
        self.assertTrue(payload.get("automerge_attempted"))
        self.assertEqual(payload.get("automerge_suffix"), "automerged")
        # Verify origin/main actually advanced to the new commit.
        head_sha = _git(["rev-parse", "HEAD"], cwd=repo).stdout.strip()
        upstream_main = _git(
            ["rev-parse", "origin/main"], cwd=repo,
        ).stdout.strip()
        self.assertEqual(head_sha, upstream_main,
                         msg="origin/main must point at HEAD after FF merge")

    def test_am_07_feature_branch_divergence_escalates(self):
        """When main has commits NOT in the feature branch, FF is unsafe;
        the integrator must refuse with fail-feature-branch-diverged-
        from-main (R55: no --force)."""
        upstream, repo = _setup_upstream_repo()
        # Branch off main BEFORE main advances.
        _checkout_lane_feature_branch(repo, "AUTOMERGE-DIV-CASE", "abc1234")
        # Now simulate another lane advancing main upstream: clone, commit,
        # push to main from a sibling clone so origin/main moves ahead.
        sib = Path(tempfile.mkdtemp(prefix="lt_am_sib_"))
        _git(["clone", "-q", str(upstream), str(sib)], cwd=sib.parent)
        (sib / "OTHER.md").write_text("# sibling lane commit\n")
        _git(["add", "OTHER.md"], cwd=sib)
        _git(["commit", "-q", "-m", "sib: advance main"], cwd=sib)
        _git(["push", "origin", "main"], cwd=sib)
        # Now in our feature branch make a commit that diverges from main.
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "div_widget.py").write_text("# div widget\n")
        rep = _make_lane_report(
            repo, "lane-AUTOMERGE-DIV-CASE", "Lane FIX AM DIV adds div_widget",
            ["body: div_widget under tools/div_widget.py shipped",
             "Lane: lane-AUTOMERGE-DIV-CASE",
             "lane_lane-AUTOMERGE-DIV-CASE path content",
             "Lane report: reports body content",
             "results.md results.md results.md"],
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-AUTOMERGE-DIV-CASE",
             "files": ["tools/div_widget.py", str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-AUTOMERGE-DIV-CASE",
            "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship div_widget",
            "--gate", "skip", "--push",
        ])
        self.assertEqual(rc, 1, msg=payload)
        self.assertEqual(payload["verdict"],
                         "fail-feature-branch-diverged-from-main")
        # The feature-branch push itself succeeded; only the auto-merge
        # was refused. So the lane's commit is NOT lost.
        self.assertTrue(payload.get("pushed"))
        self.assertEqual(payload.get("automerge_suffix"),
                         "feature-branch-diverged")

    def test_am_08_new_verdict_vocabulary_present(self):
        """Doc-test: schema bump + all 3 new verdicts referenced in the
        module-level docstring / SCHEMA_VERSION constant.
        """
        self.assertEqual(mod.SCHEMA_VERSION, "auditooor.lane_integrator.v1.2")
        doc = (mod.__doc__ or "")
        for v in ("pass-clean-commit-and-push-and-automerged",
                  "pass-clean-commit-and-push-with-unmerged-feature-branch",
                  "fail-feature-branch-diverged-from-main"):
            self.assertIn(v, doc, msg=f"verdict {v} missing from docstring")

    def test_am_09_feature_branch_with_no_origin_main_marks_unmerged(self):
        """When origin/main is unfetchable (no remote main configured), the
        auto-merge degrades gracefully to the unmerged-feature-branch
        verdict rather than crashing or losing the push."""
        # Build a bare upstream that does NOT have main yet (push from
        # feature branch only).
        upstream = Path(tempfile.mkdtemp(prefix="lt_am_nomain_up_"))
        _git(["init", "-q", "--bare"], cwd=upstream)
        repo = _init_repo()
        _git(["remote", "add", "origin", str(upstream)], cwd=repo)
        _checkout_lane_feature_branch(repo, "AUTOMERGE-NOMAIN-CASE", "abc1234")
        (repo / "tools").mkdir(exist_ok=True)
        (repo / "tools" / "nomain_widget.py").write_text("# nomain widget\n")
        rep = _make_lane_report(
            repo, "lane-AUTOMERGE-NOMAIN-CASE", "Lane FIX AM NOMAIN adds widget",
            ["body: nomain_widget under tools/nomain_widget.py shipped",
             "Lane: lane-AUTOMERGE-NOMAIN-CASE",
             "lane_lane-AUTOMERGE-NOMAIN-CASE path content",
             "Lane report: reports body content",
             "results.md results.md results.md"],
        )
        _write_pathspec(repo, [
            {"agent_id": "lane-AUTOMERGE-NOMAIN-CASE",
             "files": ["tools/nomain_widget.py",
                       str(rep.relative_to(repo))],
             "expires_at": _future_iso()},
        ])
        rc, payload, _ = _invoke(repo, [
            "--lane-id", "lane-AUTOMERGE-NOMAIN-CASE",
            "--report", str(rep.relative_to(repo)),
            "--message", "Phase X: ship nomain_widget",
            "--gate", "skip", "--push",
        ])
        # Push to the feature branch succeeds; auto-merge degrades to
        # unmerged-feature-branch verdict because origin/main does not
        # resolve. The commit is NOT lost.
        self.assertEqual(rc, 0, msg=payload)
        self.assertEqual(
            payload["verdict"],
            "pass-clean-commit-and-push-with-unmerged-feature-branch")
        self.assertTrue(payload.get("pushed"))
        self.assertIn(payload.get("automerge_suffix"),
                      ("fetch-failed", "push-failed"))


if __name__ == "__main__":
    unittest.main()
