#!/usr/bin/env python3
"""Tests for tools/oos-sidecar-manual-approve.py."""
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
APPROVER = ROOT / "tools" / "oos-sidecar-manual-approve.py"


def _seed_sidecar(workspace: Path, finding: Path, clause_ids: list[str]) -> Path:
    sha = hashlib.sha256(finding.read_bytes()).hexdigest()
    sidecar = workspace / ".auditooor" / f"oos_check_{sha}.json"
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(
        json.dumps(
            {
                "schema": "auditooor.oos_check.v1",
                "finding_sha256": sha,
                "mode": "heuristic",
                "verdict": "matches-oos",
                "clauses_checked": [
                    {
                        "id": cid,
                        "text": f"{cid} test out-of-scope clause",
                        "verdict": "MATCH",
                    }
                    for cid in clause_ids
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return sidecar


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(APPROVER), *args],
        text=True,
        capture_output=True,
    )


class OosSidecarManualApproveTests(unittest.TestCase):
    def test_all_clauses_ok_requires_each_clause_specific_rebuttal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            finding = ws / "draft.md"
            finding.write_text(
                "## Out-of-scope clause rebuttal\n\n"
                "- **C1 — admin action**: Rebuttal: not a match because the "
                "attack path is permissionless and uses a public production "
                "entrypoint.\n"
                "- **C2 — oracle assumptions**: Rebuttal: does not apply "
                "because the root cause is local accounting, not oracle input.\n"
                "- **C3 — best practice**: Rebuttal: not OOS because this "
                "causes direct loss through a public path.\n",
                encoding="utf-8",
            )
            sidecar = _seed_sidecar(ws, finding, ["C1", "C2", "C3", "C4"])

            r = _run_cli(
                [
                    "--workspace",
                    str(ws),
                    "--finding",
                    str(finding),
                    "--all-clauses-ok",
                    "--rationale",
                    "operator reviewed",
                ]
            )

            self.assertEqual(r.returncode, 1)
            self.assertIn("missing meaningful clause-specific rebuttals for C4", r.stderr)
            payload = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(payload["verdict"], "matches-oos")
            self.assertNotIn("manual_approved_clauses", payload)

    def test_all_clauses_ok_accepts_meaningful_rebuttals_for_all_ids(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            finding = ws / "draft.md"
            finding.write_text(
                "## Out-of-scope clause rebuttal\n\n"
                "- **C1 — admin action**: Rebuttal: not a match because the "
                "attack path is permissionless and uses a public production "
                "entrypoint.\n"
                "- **C2 — oracle assumptions**: Rebuttal: does not apply "
                "because the root cause is local accounting, not oracle input.\n",
                encoding="utf-8",
            )
            sidecar = _seed_sidecar(ws, finding, ["C1", "C2"])

            r = _run_cli(
                [
                    "--workspace",
                    str(ws),
                    "--finding",
                    str(finding),
                    "--all-clauses-ok",
                ]
            )

            self.assertEqual(r.returncode, 0, r.stderr)
            payload = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(payload["verdict"], "in-scope")
            self.assertEqual(payload["mode"], "heuristic+manual-rebuttal")
            self.assertEqual(payload["manual_approved_clauses"], ["C1", "C2"])
            self.assertEqual(set(payload["manual_approval_rebuttals"]), {"C1", "C2"})

    def test_clause_ids_only_require_selected_clause_rebuttals(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            finding = ws / "draft.md"
            finding.write_text(
                "## Out-of-scope clause rebuttal\n\n"
                "- **C2**: NOT a match because the exploit path is public, "
                "production reachable, and independent of privileged action.\n",
                encoding="utf-8",
            )
            sidecar = _seed_sidecar(ws, finding, ["C1", "C2"])

            r = _run_cli(
                [
                    "--workspace",
                    str(ws),
                    "--finding",
                    str(finding),
                    "--clause-ids",
                    "c2",
                ]
            )

            self.assertEqual(r.returncode, 0, r.stderr)
            payload = json.loads(sidecar.read_text(encoding="utf-8"))
            self.assertEqual(payload["manual_approved_clauses"], ["C2"])


if __name__ == "__main__":
    unittest.main()
