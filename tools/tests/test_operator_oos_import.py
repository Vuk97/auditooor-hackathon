#!/usr/bin/env python3
"""Tests for tools/operator-oos-import.py and the pre-submit Check 29 gate.

Hermetic: each test builds a throwaway workspace under ``tempfile`` and
runs the script as a subprocess so we exercise the same exit-code /
artifact contract that pre-submit-check and downstream agents rely on.

Coverage map (Wave-2 / I24):

  paste + persist
    test_import_persists_with_flag           --workspace flag form
    test_import_persists_with_positional     legacy positional form
    test_import_records_json_manifest        JSON manifest fence emitted

  idempotency
    test_idempotent_same_content_noop        identical clauses → no rotate
    test_paste_update_rotates                new clauses rotate prior file

  workspace handling
    test_missing_workspace_fails             --workspace nonexistent → rc=1
    test_empty_paste_fails                   blank stdin → rc=3

  pre-submit gate (Check 29)
    test_pre_submit_fails_when_pasted_oos_has_no_per_finding_artifact
    test_pre_submit_passes_with_in_scope_json_artifact
    test_pre_submit_fails_when_json_verdict_matches_oos
    test_per_finding_oos_check_marks_possible_match
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
IMPORTER = ROOT / "tools" / "operator-oos-import.py"
CHECKER = ROOT / "tools" / "per-finding-oos-check.py"
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


def _read_manifest(oos_pasted_path: Path) -> dict:
    text = oos_pasted_path.read_text(encoding="utf-8")
    open_tag = "<!-- OOS_PASTED_MANIFEST_BEGIN"
    close_tag = "OOS_PASTED_MANIFEST_END -->"
    block = text.split(open_tag, 1)[1].split(close_tag, 1)[0].strip()
    return json.loads(block)


class OperatorOosImportTests(unittest.TestCase):
    def test_import_persists_with_flag(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            proc = subprocess.run(
                [
                    "python3",
                    str(IMPORTER),
                    "--workspace",
                    str(ws),
                    "--project",
                    "Polymarket",
                    "--source-url",
                    "https://example.test/oos",
                ],
                input="- Impacts requiring privileged addresses are out of scope.\n",
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = ws / "OOS_PASTED.md"
            self.assertTrue(out.is_file())
            body = out.read_text()
            self.assertIn("Polymarket", body)
            self.assertIn("https://example.test/oos", body)

    def test_import_persists_with_positional(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            proc = subprocess.run(
                ["python3", str(IMPORTER), str(ws), "--project", "Foo"],
                input="- Best practice recommendations are out of scope.\n",
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = ws / "OOS_PASTED.md"
            self.assertIn("Best practice", out.read_text())

    def test_import_records_json_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            paste = (
                "Out of scope:\n"
                "- Impacts requiring privileged addresses are out of scope.\n"
                "- Best practice recommendations.\n"
                "1. Cross-chain bridge issues are excluded.\n"
            )
            proc = subprocess.run(
                ["python3", str(IMPORTER), "--workspace", str(ws)],
                input=paste,
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = _read_manifest(ws / "OOS_PASTED.md")
            ids = [c["id"] for c in manifest["clauses"]]
            self.assertEqual(ids, ["C1", "C2", "C3"])
            self.assertIn("privileged", manifest["clauses"][0]["text"].lower())
            self.assertIn("Best practice", manifest["clauses"][1]["text"])
            self.assertIn("Cross-chain", manifest["clauses"][2]["text"])
            self.assertEqual(manifest["schema"], "auditooor.oos_pasted.v1")
            self.assertTrue(manifest["clauses_hash"])

    def test_idempotent_same_content_noop(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            paste = "- Admin compromise is out of scope.\n"
            first = subprocess.run(
                ["python3", str(IMPORTER), "--workspace", str(ws)],
                input=paste,
                text=True,
                capture_output=True,
            )
            self.assertEqual(first.returncode, 0)
            mtime_before = (ws / "OOS_PASTED.md").stat().st_mtime
            second = subprocess.run(
                ["python3", str(IMPORTER), "--workspace", str(ws)],
                input=paste,
                text=True,
                capture_output=True,
            )
            self.assertEqual(second.returncode, 0)
            self.assertIn("no-op", second.stdout)
            mtime_after = (ws / "OOS_PASTED.md").stat().st_mtime
            self.assertEqual(mtime_before, mtime_after)
            # No rotation file written.
            rotated = list(ws.glob("OOS_PASTED.*.md"))
            self.assertEqual(rotated, [])

    def test_paste_update_rotates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            first_paste = "- Impacts requiring guardian action are out of scope.\n"
            second_paste = "- Best practice recommendations are out of scope.\n"
            r1 = subprocess.run(
                ["python3", str(IMPORTER), str(ws), "--project", "Polymarket"],
                input=first_paste,
                text=True,
                capture_output=True,
            )
            self.assertEqual(r1.returncode, 0, r1.stderr)
            r2 = subprocess.run(
                ["python3", str(IMPORTER), str(ws)],
                input=second_paste,
                text=True,
                capture_output=True,
            )
            self.assertEqual(r2.returncode, 0, r2.stderr)
            current = (ws / "OOS_PASTED.md").read_text()
            self.assertIn("Best practice", current)
            self.assertNotIn("Polymarket", current)
            # Prior file rotated.
            rotated = list(ws.glob("OOS_PASTED.*.md"))
            self.assertEqual(len(rotated), 1)
            self.assertIn("guardian action", rotated[0].read_text())

    def test_missing_workspace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ghost = Path(td) / "does-not-exist"
            proc = subprocess.run(
                ["python3", str(IMPORTER), "--workspace", str(ghost)],
                input="- something\n",
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("workspace not found", proc.stderr)

    def test_empty_paste_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            proc = subprocess.run(
                ["python3", str(IMPORTER), "--workspace", str(ws)],
                input="",
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 3)

    # ----- pre-submit Check 29 wiring ------------------------------------

    def _build_minimal_draft(self, ws: Path, draft_text: str) -> Path:
        (ws / "SCOPE.md").write_text("scope")
        (ws / "scope_review").mkdir(exist_ok=True)
        draft = ws / "draft.md"
        draft.write_text(draft_text)
        (ws / "scope_review" / "draft.heuristic-review.md").write_text(
            "VERDICT: NOVEL\n"
        )
        return draft

    def _draft_text(self) -> str:
        return "\n".join(
            [
                "**Severity:** Low",
                "Rubric: Medium impact cited.",
                "$ impact: $1 - $2.",
                "OOS: N/A: in-scope class.",
                "Originality: run today.",
                "Dupe risk: LOW.",
                "scope review: NOVEL.",
                "No event-only issue; concrete trigger.",
            ]
        )

    def test_pre_submit_fails_when_pasted_oos_has_no_per_finding_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            subprocess.run(
                ["python3", str(IMPORTER), "--workspace", str(ws)],
                input="- Best practice recommendations are out of scope.\n",
                text=True,
                check=True,
                capture_output=True,
            )
            draft = self._build_minimal_draft(ws, self._draft_text())
            proc = subprocess.run(
                ["bash", str(PRE_SUBMIT), str(draft), "--severity", "Low"],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("29. missing per-finding OOS check", proc.stdout)

    def test_pre_submit_passes_with_in_scope_json_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            subprocess.run(
                ["python3", str(IMPORTER), "--workspace", str(ws)],
                input="- Cross-chain bridge issues are out of scope.\n",
                text=True,
                check=True,
                capture_output=True,
            )
            draft = self._build_minimal_draft(ws, self._draft_text())
            proc = subprocess.run(
                [
                    "python3",
                    str(CHECKER),
                    "--workspace",
                    str(ws),
                    "--finding",
                    str(draft),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            # Verdict should be in-scope (heuristic finds no overlap).
            self.assertIn("verdict=in-scope", proc.stdout)
            gate = subprocess.run(
                ["bash", str(PRE_SUBMIT), str(draft), "--severity", "Low"],
                text=True,
                capture_output=True,
            )
            self.assertIn(
                "29. per-finding OOS check (JSON, verdict=in-scope)",
                gate.stdout,
                msg=gate.stdout + gate.stderr,
            )

    def test_pre_submit_fails_when_json_verdict_matches_oos(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            subprocess.run(
                ["python3", str(IMPORTER), "--workspace", str(ws)],
                input="- Impacts requiring guardian/admin action are out of scope.\n",
                text=True,
                check=True,
                capture_output=True,
            )
            # Draft mentions guardian → heuristic flags MATCH.
            text = self._draft_text() + (
                "\nThe guardian role can call blacklistDisputeGame and cause loss."
            )
            draft = self._build_minimal_draft(ws, text)
            proc = subprocess.run(
                [
                    "python3",
                    str(CHECKER),
                    "--workspace",
                    str(ws),
                    "--finding",
                    str(draft),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("verdict=matches-oos", proc.stdout)
            gate = subprocess.run(
                ["bash", str(PRE_SUBMIT), str(draft), "--severity", "Low"],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(gate.returncode, 0)
            self.assertIn(
                "29. per-finding OOS check matched a clause", gate.stdout
            )

    def test_per_finding_oos_check_marks_possible_match(self) -> None:
        # Legacy ergonomic test: heuristic catches admin-class overlap and
        # the Markdown sidecar carries NEEDS_REVIEW for the legacy verdict
        # column — preserved so older agents reading the sidecar still see
        # the warning.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            subprocess.run(
                ["python3", str(IMPORTER), str(ws)],
                input="- Impacts requiring guardian/admin action are out of scope.\n",
                text=True,
                check=True,
                capture_output=True,
            )
            finding = ws / "submissions" / "draft.md"
            finding.parent.mkdir()
            finding.write_text(
                "The guardian can call blacklistDisputeGame and cause loss."
            )
            proc = subprocess.run(
                ["python3", str(CHECKER), str(ws), str(finding)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            review = finding.with_name("OOS_CHECK.md").read_text()
            self.assertIn("NEEDS_REVIEW", review)
            # JSON canonical artifact written under .auditooor/
            json_files = list((ws / ".auditooor").glob("oos_check_*.json"))
            self.assertEqual(len(json_files), 1)
            payload = json.loads(json_files[0].read_text())
            self.assertEqual(payload["verdict"], "matches-oos")


if __name__ == "__main__":
    unittest.main()
