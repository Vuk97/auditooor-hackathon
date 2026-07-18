#!/usr/bin/env python3
"""Pre-submit integration coverage for R75-WAVE2-W21-POST-MIGRATION (Check #75).

Every synthetic record YAML written here carries ``synthetic_fixture: true``
per real-source-only discipline so the records are unambiguously NOT corpus
material. The check block is exercised via a real subprocess invocation of
``tools/pre-submit-check.sh``; assertions are made against the verdict
keywords (``pass-out-of-scope``, ``pass-validator-clean``,
``fail-v1-residual``, ``fail-quarantine-leak``, ``ok-rebuttal``) emitted in
the script's stdout, mirroring the R21/R23/R27 wiring tests.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"
VALIDATOR = ROOT / "tools" / "wave2-w21-post-migration-validator.py"


# --------------------------------------------------------------------------- #
# Fixture helpers (all synthetic, marked synthetic_fixture: true)
# --------------------------------------------------------------------------- #


def _v11_record_yaml(
    record_id: str,
    *,
    verification_tier: str = "tier-2-verified-public-archive",
    include_top_level_tier: bool = True,
) -> str:
    body = [
        "schema_version: auditooor.hackerman_record.v1.1",
        f"record_id: {record_id}",
    ]
    if include_top_level_tier:
        body.append(f"verification_tier: {verification_tier}")
    body.extend(
        [
            "attack_class: reentrancy-attack",
            "target_repo: synthetic/repo",
            "synthetic_fixture: true",
            "function_shape:",
            '  raw_signature: "function f()"',
            "  shape_tags:",
            "    - reentrancy",
            f"    - verification_tier:{verification_tier}",
            "",
        ]
    )
    return "\n".join(body)


def _v1_record_yaml(record_id: str) -> str:
    return "\n".join(
        [
            "schema_version: auditooor.hackerman_record.v1",
            f"record_id: {record_id}",
            "attack_class: reentrancy-attack",
            "target_repo: synthetic/repo",
            "synthetic_fixture: true",
            "function_shape:",
            '  raw_signature: "function f()"',
            "  shape_tags:",
            "    - reentrancy",
            "    - verification_tier:tier-2-verified-public-archive",
            "",
        ]
    )


def _write_clean_workspace(root: Path) -> None:
    tags = root / "audit" / "corpus_tags" / "tags"
    idx = root / "audit" / "corpus_tags" / "index"
    tags.mkdir(parents=True, exist_ok=True)
    idx.mkdir(parents=True, exist_ok=True)
    (tags / "rec_a.yaml").write_text(
        _v11_record_yaml("synthetic:rec_a"), encoding="utf-8"
    )
    (tags / "rec_b.yaml").write_text(
        _v11_record_yaml(
            "synthetic:rec_b",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
        ),
        encoding="utf-8",
    )
    # Minimal index files — one row each so they are non-empty + parse cleanly.
    (idx / "by_cve_id.jsonl").write_text(
        '{"record_id":"synthetic:rec_a","key":"CVE-2099-0001","tag_file":"rec_a.yaml"}\n',
        encoding="utf-8",
    )
    (idx / "by_ghsa_id.jsonl").write_text(
        '{"record_id":"synthetic:rec_b","key":"GHSA-xxxx-yyyy-zzzz","tag_file":"rec_b.yaml"}\n',
        encoding="utf-8",
    )
    (idx / "by_firm.jsonl").write_text(
        '{"record_id":"synthetic:rec_a","key":"synthetic-firm","tag_file":"rec_a.yaml"}\n',
        encoding="utf-8",
    )
    (idx / "by_verification_tier.jsonl").write_text(
        '{"record_id":"synthetic:rec_a","key":"tier-2-verified-public-archive","tag_file":"rec_a.yaml"}\n'
        '{"record_id":"synthetic:rec_b","key":"tier-3-synthetic-taxonomy-anchored","tag_file":"rec_b.yaml"}\n',
        encoding="utf-8",
    )
    (idx / "by_incident_date.jsonl").write_text(
        '{"record_id":"synthetic:rec_a","key":"2024-01-01","tag_file":"rec_a.yaml"}\n',
        encoding="utf-8",
    )


def _add_v1_residual(root: Path) -> None:
    tags = root / "audit" / "corpus_tags" / "tags"
    (tags / "rec_stale_v1.yaml").write_text(
        _v1_record_yaml("synthetic:rec_stale_v1"), encoding="utf-8"
    )


def _add_quarantine_leak(root: Path) -> None:
    tags = root / "audit" / "corpus_tags" / "tags"
    qdir = tags / "_QUARANTINE_FABRICATED_CVE"
    qdir.mkdir(parents=True, exist_ok=True)
    (qdir / "fake_rec.yaml").write_text(
        "\n".join(
            [
                "schema_version: auditooor.hackerman_record.v1.1",
                "record_id: synthetic:fake_quarantine",
                "verification_tier: tier-5-quarantine",
                "attack_class: fabricated",
                "target_repo: synthetic/repo",
                "synthetic_fixture: true",
                "function_shape:",
                '  raw_signature: "function f()"',
                "  shape_tags:",
                "    - verification_tier:tier-5-quarantine",
                "",
            ]
        ),
        encoding="utf-8",
    )
    # Leak the quarantine record into by_cve_id.jsonl
    idx = root / "audit" / "corpus_tags" / "index" / "by_cve_id.jsonl"
    with idx.open("a", encoding="utf-8") as fh:
        fh.write(
            '{"record_id":"synthetic:fake_quarantine","key":"CVE-9999-9999",'
            '"tag_file":"_QUARANTINE_FABRICATED_CVE/fake_rec.yaml"}\n'
        )


def _draft_in_scope(extra: str = "") -> str:
    extra = textwrap.dedent(extra).strip()
    return (
        textwrap.dedent(
            f"""
            # Synthetic corpus-touching finding

            **Severity:** Medium

            This synthetic test touches `audit/corpus_tags/tags/` and
            references the `auditooor.hackerman_record.v1.1` schema as part
            of Wave-2 corpus migration validation. synthetic_fixture: true.

            {extra}
            """
        ).strip()
        + "\n"
    )


def _draft_out_of_scope() -> str:
    return (
        textwrap.dedent(
            """
            # Unrelated reentrancy finding

            **Severity:** Medium

            This synthetic draft does not touch any corpus path.
            synthetic_fixture: true.
            """
        ).strip()
        + "\n"
    )


def _run(
    draft: Path,
    *,
    workspace: Path | None = None,
    severity: str = "Medium",
    scope_env: str | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if workspace is not None:
        env["AUDITOOOR_R75_WORKSPACE"] = str(workspace)
    if scope_env is not None:
        env["AUDITOOOR_R75_SCOPE"] = scope_env
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", severity],
        capture_output=True,
        text=True,
        env=env,
    )


def _grep_r75(stdout: str) -> str:
    for line in stdout.splitlines():
        if "75. R75-WAVE2-W21-POST-MIGRATION" in line:
            return line
    return ""


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


class CheckSeventyFiveR75Wave2W21Tests(unittest.TestCase):
    def setUp(self) -> None:
        if not PRE_SUBMIT.exists():
            self.skipTest(f"pre-submit-check.sh missing at {PRE_SUBMIT}")
        if not VALIDATOR.exists():
            self.skipTest(f"validator missing at {VALIDATOR}")

    def test_pass_out_of_scope_unrelated_draft(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            draft = tmp_p / "unrelated.md"
            draft.write_text(_draft_out_of_scope(), encoding="utf-8")
            proc = _run(draft)
            line = _grep_r75(proc.stdout)
            self.assertIn("pass-out-of-scope", line, proc.stdout)
            self.assertIn("✅", line)

    def test_pass_validator_clean_on_synthetic_clean_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            ws = tmp_p / "ws"
            _write_clean_workspace(ws)
            draft = tmp_p / "corpus_finding.md"
            draft.write_text(_draft_in_scope(), encoding="utf-8")
            proc = _run(draft, workspace=ws)
            line = _grep_r75(proc.stdout)
            self.assertIn("pass-validator-clean", line, proc.stdout)
            self.assertIn("v1=0", line)
            self.assertIn("v1.1=2", line)
            self.assertIn("✅", line)

    def test_fail_v1_residual_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            ws = tmp_p / "ws"
            _write_clean_workspace(ws)
            _add_v1_residual(ws)
            draft = tmp_p / "corpus_finding.md"
            draft.write_text(_draft_in_scope(), encoding="utf-8")
            proc = _run(draft, workspace=ws)
            line = _grep_r75(proc.stdout)
            self.assertIn("fail-v1-residual", line, proc.stdout)
            self.assertIn("blocked", line)
            self.assertIn("❌", line)

    def test_fail_quarantine_leak_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            ws = tmp_p / "ws"
            _write_clean_workspace(ws)
            _add_quarantine_leak(ws)
            draft = tmp_p / "corpus_finding.md"
            draft.write_text(_draft_in_scope(), encoding="utf-8")
            proc = _run(draft, workspace=ws)
            line = _grep_r75(proc.stdout)
            self.assertIn("fail-quarantine-leak", line, proc.stdout)
            self.assertIn("blocked", line)
            self.assertIn("❌", line)

    def test_ok_rebuttal_silences_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            ws = tmp_p / "ws"
            _write_clean_workspace(ws)
            _add_v1_residual(ws)  # force fail-v1-residual underlying
            draft = tmp_p / "corpus_finding.md"
            rebuttal = (
                "<!-- r75-rebuttal: synthetic test override; v1 residual "
                "expected during migration dry-run -->"
            )
            self.assertLess(
                len(re.sub(r"^<!--\s*r75-rebuttal:\s*", "",
                           re.sub(r"\s*-->$", "", rebuttal))),
                201,
            )
            draft.write_text(_draft_in_scope(rebuttal), encoding="utf-8")
            proc = _run(draft, workspace=ws)
            line = _grep_r75(proc.stdout)
            self.assertIn("ok-rebuttal", line, proc.stdout)
            self.assertIn("underlying=verdict=fail-v1-residual", line)
            self.assertIn("✅", line)

    def test_oversize_rebuttal_does_not_silence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            ws = tmp_p / "ws"
            _write_clean_workspace(ws)
            _add_v1_residual(ws)
            draft = tmp_p / "corpus_finding.md"
            # 201+ character reason → must NOT silence the fail.
            long_reason = "x" * 220
            rebuttal = f"<!-- r75-rebuttal: {long_reason} -->"
            draft.write_text(_draft_in_scope(rebuttal), encoding="utf-8")
            proc = _run(draft, workspace=ws)
            line = _grep_r75(proc.stdout)
            self.assertIn("fail-v1-residual", line, proc.stdout)
            self.assertIn("blocked", line)
            self.assertNotIn("ok-rebuttal", line)
            self.assertIn("❌", line)

    def test_scope_env_override_forces_in_scope(self) -> None:
        # Out-of-scope draft + clean synthetic corpus + AUDITOOOR_R75_SCOPE=corpus
        # → validator runs and emits pass-validator-clean.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            ws = tmp_p / "ws"
            _write_clean_workspace(ws)
            draft = tmp_p / "unrelated.md"
            draft.write_text(_draft_out_of_scope(), encoding="utf-8")
            proc = _run(draft, workspace=ws, scope_env="corpus")
            line = _grep_r75(proc.stdout)
            self.assertIn("pass-validator-clean", line, proc.stdout)
            self.assertIn("✅", line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
