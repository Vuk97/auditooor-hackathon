#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "v3-source-first-prereq-gate.py"
PIN_A = "0123456789abcdef0123456789abcdef01234567"
PIN_B = "abcdef0123456789abcdef0123456789abcdef01"


def _write_required_files(ws: Path, *, scope: dict[str, object] | None = None, targets: str | None = None) -> None:
    ws.mkdir(parents=True, exist_ok=True)
    contents = {
        "SCOPE.md": "# Scope\n\nIn scope: https://github.com/acme/protocol at pinned commit.\n",
        "OOS_PASTED.md": "# OOS\n\nFront-running-only and imported dependency vulnerabilities are out of scope.\n",
        "SEVERITY.md": "# Severity\n\nCritical: stealing or loss of user funds. High: unauthorized transaction.\n",
        "SEVERITY_CAPS.md": "# Severity caps\n\nSEV-CAP: front-running-only: out-of-scope\n",
        "RUBRIC_COVERAGE.md": "# Rubric coverage\n\n| rubric-tag | covered? | evidence |\n|---|---|---|\n| smart-contract-critical | yes | SCOPE.md |\n",
    }
    for name, text in contents.items():
        (ws / name).write_text(text, encoding="utf-8")
    (ws / "scope.json").write_text(
        json.dumps(scope if scope is not None else {"target_repos": [], "audit_pin_sha": PIN_A}) + "\n",
        encoding="utf-8",
    )
    (ws / "targets.tsv").write_text(targets if targets is not None else "", encoding="utf-8")


def _write_report(
    ws: Path,
    *,
    repo_slug: str,
    pin: str,
    commits_scanned: int = 8,
    upstream_repo: str = "acme/protocol",
) -> str:
    rel = f"mining_rounds/round/{repo_slug}_git_commits_mining.json"
    path = ws / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": "auditooor.git_commits_mining.v1",
                "upstream_repo": upstream_repo,
                "audit_pin_sha": pin,
                "commits_scanned": commits_scanned,
                "generated_at": "2026-05-21T00:00:00Z",
                "shaped_commits_index": [
                    {
                        "sha": pin,
                        "url": f"https://github.com/{upstream_repo}/commit/{pin}",
                        "subject": "fix: bounded source-first mining fixture",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return rel


def _run(ws: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), "--workspace", str(ws), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class V3SourceFirstPrereqGateTest(unittest.TestCase):
    def test_pre_passes_with_operator_truth_and_pinned_github_targets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-pre-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": ["acme/protocol"], "audit_pin_sha": PIN_A},
                targets=f"https://github.com/acme/protocol\t{PIN_A}\tprotocol\n",
            )

            proc = _run(ws, "--phase", "pre", "--strict")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            out_json = ws / ".auditooor" / "v3_source_first_prereq_gate.json"
            out_md = ws / ".auditooor" / "v3_source_first_prereq_gate.md"
            self.assertTrue(out_json.is_file())
            self.assertTrue(out_md.is_file())
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "pass")
            self.assertEqual(payload["blockers"], [])
            self.assertEqual(
                {(row["repo"], row["pin"]) for row in payload["github_targets"]},
                {("acme/protocol", PIN_A)},
            )

    def test_pre_blocks_unpinned_github_target_only_in_strict_exit_code(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-unpinned-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": []},
                targets="https://github.com/acme/protocol\tmain\tprotocol\n",
            )

            soft = _run(ws, "--phase", "pre")
            strict = _run(ws, "--phase", "pre", "--strict")

            self.assertEqual(soft.returncode, 0, soft.stderr)
            self.assertNotEqual(strict.returncode, 0)
            payload = json.loads(
                (ws / ".auditooor" / "v3_source_first_prereq_gate.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(payload["status"], "fail")
            self.assertIn(
                "GitHub target pin is not a 40-hex commit: acme/protocol@main (targets.tsv:1)",
                payload["blockers"],
            )

    def test_pre_blocks_scope_string_target_with_non_40_global_ref(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-non40-global-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": ["acme/protocol"], "audit_pin_sha": "main"},
                targets="",
            )

            proc = _run(ws, "--phase", "pre", "--strict")

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(
                (ws / ".auditooor" / "v3_source_first_prereq_gate.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(payload["github_targets"][0]["repo"], "acme/protocol")
            self.assertEqual(payload["github_targets"][0]["pin"], "main")
            self.assertIn(
                "GitHub target pin is not a 40-hex commit: acme/protocol@main (scope.json:target_repos[0])",
                payload["blockers"],
            )

    def test_pre_blocks_bare_owner_repo_targets_tsv_non_40_ref(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-non40-tsv-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": []},
                targets="acme/protocol\tmain\tprotocol\n",
            )

            proc = _run(ws, "--phase", "pre", "--strict")

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(
                (ws / ".auditooor" / "v3_source_first_prereq_gate.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(payload["github_targets"][0]["repo"], "acme/protocol")
            self.assertEqual(payload["github_targets"][0]["pin"], "main")
            self.assertIn(
                "GitHub target pin is not a 40-hex commit: acme/protocol@main (targets.tsv:1)",
                payload["blockers"],
            )

    def test_typed_waiver_covers_unpinned_github_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-waiver-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": []},
                targets="https://github.com/acme/protocol\tmain\tprotocol\n",
            )
            waiver_dir = ws / ".auditooor"
            waiver_dir.mkdir(parents=True)
            (waiver_dir / "source_first_waivers.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.source_first_waivers.v1",
                        "waivers": [
                            {
                                "id": "operator-main-ref",
                                "type": "github_pin_waiver",
                                "repo": "acme/protocol",
                                "reason": "temporary private program pin pending",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = _run(ws, "--phase", "pre", "--strict")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(
                (ws / ".auditooor" / "v3_source_first_prereq_gate.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(payload["status"], "pass")
            self.assertTrue(payload["github_targets"][0]["waived"])
            self.assertEqual(payload["github_targets"][0]["waiver_id"], "operator-main-ref")

    def test_placeholder_operator_truth_blocks_pre_phase(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-placeholder-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": ["acme/protocol"], "audit_pin_sha": PIN_A},
                targets="",
            )
            (ws / "OOS_PASTED.md").write_text("TODO: paste the bounty OOS text\n", encoding="utf-8")

            proc = _run(ws, "--phase", "pre", "--strict")

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(
                (ws / ".auditooor" / "v3_source_first_prereq_gate.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertIn(
                "operator truth file is empty or placeholder: OOS_PASTED.md",
                payload["blockers"],
            )

    def test_invalid_scope_json_blocks_even_when_targets_tsv_exists(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-bad-scope-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": ["acme/protocol"], "audit_pin_sha": PIN_A},
                targets=f"https://github.com/acme/protocol\t{PIN_A}\tprotocol\n",
            )
            (ws / "scope.json").write_text("{bad json", encoding="utf-8")

            proc = _run(ws, "--phase", "pre", "--strict")

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(
                (ws / ".auditooor" / "v3_source_first_prereq_gate.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(any(item.startswith("scope.json invalid json") for item in payload["blockers"]))

    def test_no_source_targets_blocks_pre_phase(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-no-targets-") as tmp:
            ws = Path(tmp)
            _write_required_files(ws, scope={"target_repos": [], "audit_pin_sha": PIN_A}, targets="")

            proc = _run(ws, "--phase", "pre", "--strict")

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(
                (ws / ".auditooor" / "v3_source_first_prereq_gate.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertIn("no source targets parsed from scope.json or targets.tsv", payload["blockers"])

    def test_local_targets_tsv_path_is_not_treated_as_github(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-local-target-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": []},
                targets="src/contracts\tmain\tcontracts\n",
            )

            proc = _run(ws, "--phase", "pre", "--strict")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(
                (ws / ".auditooor" / "v3_source_first_prereq_gate.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(payload["status"], "pass")
            self.assertEqual(payload["github_targets"], [])

    def test_post_requires_matching_ledger_target_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-post-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={
                    "target_repos": [
                        {"repo": "acme/protocol", "audit_pin_sha": PIN_A},
                        {"repo": "acme/bridge", "audit_pin_sha": PIN_B},
                    ]
                },
                targets="",
            )
            auditooor = ws / ".auditooor"
            auditooor.mkdir(parents=True)
            (auditooor / "commit_lifecycle_ledger.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.commit_lifecycle_ledger.v1",
                        "target_rows": [
                            {
                                "repo": "acme/protocol",
                                "pin": PIN_A,
                                "status": "ok",
                                "commits_scanned": 8,
                                "output_path": _write_report(ws, repo_slug="acme_protocol", pin=PIN_A),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = _run(ws, "--phase", "post", "--strict")

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(
                (auditooor / "v3_source_first_prereq_gate.json").read_text(encoding="utf-8")
            )
            self.assertTrue(
                any(
                    f"missing target_rows match for acme/bridge@{PIN_B}" in item
                    for item in payload["blockers"]
                )
            )

    def test_post_blocks_failed_or_dry_run_ledger_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-post-dry-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": ["acme/protocol"], "audit_pin_sha": PIN_A},
                targets="",
            )
            auditooor = ws / ".auditooor"
            auditooor.mkdir(parents=True)
            (auditooor / "commit_lifecycle_ledger.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.commit_lifecycle_ledger.v1",
                        "target_rows": [
                            {
                                "repo": "acme/protocol",
                                "pin": PIN_A,
                                "status": "dry-run",
                                "dry_run": True,
                                "commits_scanned": 8,
                                "output_path": _write_report(ws, repo_slug="acme_protocol", pin=PIN_A),
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = _run(ws, "--phase", "post", "--strict")

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(
                (auditooor / "v3_source_first_prereq_gate.json").read_text(encoding="utf-8")
            )
            self.assertIn(
                ".auditooor/commit_lifecycle_ledger.json contains failed or dry-run rows",
                payload["blockers"],
            )
            self.assertEqual(payload["post_ledger"]["bad_rows"][0]["dry_run"], True)

    def test_post_rejects_minimal_fabricated_ledger_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-post-fake-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": ["acme/protocol"], "audit_pin_sha": PIN_A},
                targets="",
            )
            auditooor = ws / ".auditooor"
            auditooor.mkdir(parents=True)
            (auditooor / "commit_lifecycle_ledger.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.commit_lifecycle_ledger.v1",
                        "target_rows": [
                            {"repo": "acme/protocol", "pin": PIN_A, "status": "ok"}
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = _run(ws, "--phase", "post", "--strict")

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(
                (auditooor / "v3_source_first_prereq_gate.json").read_text(encoding="utf-8")
            )
            self.assertTrue(
                any("report missing for acme/protocol" in item for item in payload["blockers"])
            )

    def test_post_rejects_fabricated_commit_report_with_only_claimed_counts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-post-fake-report-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": ["acme/protocol"], "audit_pin_sha": PIN_A},
                targets="",
            )
            auditooor = ws / ".auditooor"
            auditooor.mkdir(parents=True)
            report_rel = "mining_rounds/round/fake_git_commits_mining.json"
            report_path = ws / report_rel
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.git_commits_mining.v1",
                        "upstream_repo": "acme/protocol",
                        "audit_pin_sha": PIN_A,
                        "commits_scanned": 8,
                        "generated_at": "2026-05-21T00:00:00Z",
                        "head_sha": "x",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (auditooor / "commit_lifecycle_ledger.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.commit_lifecycle_ledger.v1",
                        "target_rows": [
                            {
                                "repo": "acme/protocol",
                                "pin": PIN_A,
                                "status": "ok",
                                "commits_scanned": 8,
                                "output_path": report_rel,
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = _run(ws, "--phase", "post", "--strict")

            self.assertNotEqual(proc.returncode, 0)
            payload = json.loads(
                (auditooor / "v3_source_first_prereq_gate.json").read_text(encoding="utf-8")
            )
            self.assertTrue(
                any("report lacks commit/window evidence for acme/protocol" in item for item in payload["blockers"])
            )

    def test_post_accepts_canonical_empty_window_commit_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-post-empty-window-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": ["acme/protocol"], "audit_pin_sha": PIN_A},
                targets="",
            )
            auditooor = ws / ".auditooor"
            auditooor.mkdir(parents=True)
            report_rel = "mining_rounds/round/empty_git_commits_mining.json"
            report_path = ws / report_rel
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.git_commits_mining.v1",
                        "schema_version": "1.1",
                        "workspace": str(ws),
                        "upstream_repo": "acme/protocol",
                        "audit_pin_sha": PIN_A,
                        "since_date": "2026-05-21",
                        "generated_at": "2026-05-21T00:00:00Z",
                        "commits_scanned": 0,
                        "security_fix_count": 0,
                        "filter_regex": "fix|security",
                        "fallback_used": False,
                        "commits": [],
                        "shaped_commits_index": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (auditooor / "commit_lifecycle_ledger.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.commit_lifecycle_ledger.v1",
                        "target_rows": [
                            {
                                "repo": "acme/protocol",
                                "pin": PIN_A,
                                "status": "ok",
                                "commits_scanned": 0,
                                "output_path": report_rel,
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = _run(ws, "--phase", "post", "--strict")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(
                (auditooor / "v3_source_first_prereq_gate.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload["status"], "pass")

    def test_print_json_matches_written_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v3-src-print-json-") as tmp:
            ws = Path(tmp)
            _write_required_files(
                ws,
                scope={"target_repos": ["acme/protocol"], "audit_pin_sha": PIN_A},
                targets="",
            )

            proc = _run(ws, "--phase", "pre", "--strict", "--print-json")

            self.assertEqual(proc.returncode, 0, proc.stderr)
            stdout_payload = json.loads(proc.stdout)
            sidecar_payload = json.loads(
                (ws / ".auditooor" / "v3_source_first_prereq_gate.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(stdout_payload, sidecar_payload)


if __name__ == "__main__":
    unittest.main()
