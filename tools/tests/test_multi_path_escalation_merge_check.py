"""Unit tests for Rule 28 Multi-path escalation merge check (Check #100)."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "multi_path_escalation_merge_check",
    ROOT / "tools" / "multi-path-escalation-merge-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r28_test_"))
    for rel in [
        "submissions/staging",
        "submissions/paste_ready",
        "submissions/held",
        "submissions/superseded",
    ]:
        (root / rel).mkdir(parents=True)
    return root


def _draft_text(
    *,
    severity: str = "High",
    body: str = "",
    cantina_id: str | None = None,
    rebuttal: str | None = None,
    merged_signal: bool = False,
) -> str:
    parts = [f"Severity: {severity}\n"]
    if cantina_id:
        parts.append(f"References Cantina submission #{cantina_id}\n")
    if merged_signal:
        parts.append("This is a merged unified response combining all paths.\n")
    if rebuttal:
        parts.append(f"<!-- r28-rebuttal: {rebuttal} -->\n")
    parts.append(body + "\n")
    return "".join(parts)


def _write_draft(ws: Path, rel: str, text: str) -> Path:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _run(draft: Path, ws: Path | None = None, **kw):
    return mod.run(draft, workspace=ws, **kw)


class R28OutOfScopeTests(unittest.TestCase):
    """Below HIGH should always pass out-of-scope."""

    def test_low_severity_out_of_scope(self) -> None:
        ws = _workspace()
        draft = _write_draft(ws, "submissions/staging/find.md",
                             _draft_text(severity="Low", cantina_id="192"))
        rc, payload = _run(draft, ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_medium_severity_out_of_scope(self) -> None:
        ws = _workspace()
        draft = _write_draft(ws, "submissions/staging/find.md",
                             _draft_text(severity="Medium", cantina_id="192"))
        rc, payload = _run(draft, ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_cli_severity_override_raises_into_scope(self) -> None:
        ws = _workspace()
        draft = _write_draft(ws, "submissions/staging/find.md",
                             _draft_text(severity="Medium", cantina_id="213"))
        # Even with no siblings this should become pass-only-one-path-in-flight
        rc, payload = _run(draft, ws, severity_override="High")
        self.assertEqual(rc, 0)
        self.assertIn(payload["verdict"], {
            "pass-only-one-path-in-flight", "pass-no-cantina-id-cited",
        })
        self.assertEqual(payload.get("severity_source"), "cli")


class R28NoCantinaCitationTests(unittest.TestCase):
    """Drafts without any Cantina ID should pass."""

    def test_no_cantina_id_passes(self) -> None:
        ws = _workspace()
        draft = _write_draft(ws, "submissions/staging/find.md",
                             _draft_text(severity="High", body="Some finding with no id."))
        rc, payload = _run(draft, ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-cantina-id-cited")


class R28SinglePathTests(unittest.TestCase):
    """Only one in-flight draft for a Cantina ID should pass."""

    def test_single_path_passes(self) -> None:
        ws = _workspace()
        draft = _write_draft(ws, "submissions/paste_ready/find-v2.md",
                             _draft_text(severity="High", cantina_id="192"))
        rc, payload = _run(draft, ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-only-one-path-in-flight")
        self.assertIn("192", payload["cantina_ids"])


class R28MultiplePathsTests(unittest.TestCase):
    """Two or more unmerged paths for same Cantina ID should fail."""

    def test_two_unmerged_paths_fail(self) -> None:
        ws = _workspace()
        draft_a = _write_draft(
            ws, "submissions/paste_ready/find-v3.md",
            _draft_text(severity="High", cantina_id="213",
                        body="This is path v3 for Cantina #213.")
        )
        _write_draft(
            ws, "submissions/staging/find-v4.md",
            _draft_text(severity="High", cantina_id="213",
                        body="This is path v4 for Cantina #213.")
        )
        rc, payload = _run(draft_a, ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-multiple-paths-in-flight-unmerged")
        self.assertIn("213", payload["triggering_id"])
        self.assertEqual(len(payload["sibling_paths"]), 1)

    def test_three_unmerged_paths_fail(self) -> None:
        ws = _workspace()
        draft_a = _write_draft(
            ws, "submissions/paste_ready/find-v3.md",
            _draft_text(severity="Critical", cantina_id="213")
        )
        _write_draft(
            ws, "submissions/staging/find-v4.md",
            _draft_text(severity="High", cantina_id="213")
        )
        _write_draft(
            ws, "submissions/held/find-asa.md",
            _draft_text(severity="High", cantina_id="213")
        )
        rc, payload = _run(draft_a, ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-multiple-paths-in-flight-unmerged")
        self.assertEqual(len(payload["sibling_paths"]), 2)


class R28MergedResponseTests(unittest.TestCase):
    """A draft with merged-signal present should pass."""

    def test_merged_unified_response_passes(self) -> None:
        ws = _workspace()
        draft_a = _write_draft(
            ws, "submissions/paste_ready/find-merged.md",
            _draft_text(severity="High", cantina_id="213", merged_signal=True)
        )
        _write_draft(
            ws, "submissions/staging/find-v4.md",
            _draft_text(severity="High", cantina_id="213")
        )
        rc, payload = _run(draft_a, ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-merged-into-unified-response")


class R28RebuttalTests(unittest.TestCase):
    """Rebuttal override should pass with ok-rebuttal verdict."""

    def test_html_comment_rebuttal_passes(self) -> None:
        ws = _workspace()
        _write_draft(ws, "submissions/staging/find-v4.md",
                     _draft_text(severity="High", cantina_id="192"))
        draft = _write_draft(
            ws, "submissions/paste_ready/find-v3.md",
            _draft_text(severity="High", cantina_id="192",
                        rebuttal="Operator approved single-path paste; v4 lane cancelled")
        )
        rc, payload = _run(draft, ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_empty_rebuttal_is_ignored(self) -> None:
        ws = _workspace()
        _write_draft(ws, "submissions/staging/find-v4.md",
                     _draft_text(severity="High", cantina_id="192"))
        # Manually write a draft with an empty rebuttal.
        p = ws / "submissions/paste_ready/find-v3.md"
        p.write_text(
            "Severity: High\nReferences Cantina submission #192\n"
            "<!-- r28-rebuttal:  -->\n",
            encoding="utf-8",
        )
        rc, payload = _run(p, ws)
        # Empty rebuttal should NOT satisfy the gate.
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-multiple-paths-in-flight-unmerged")


class R28CantinaCitationVariantsTests(unittest.TestCase):
    """Various ways to cite Cantina IDs should be detected."""

    def _one_path_check(self, body: str, expected_id: str) -> None:
        ws = _workspace()
        draft = _write_draft(
            ws, "submissions/paste_ready/find.md",
            f"Severity: High\n{body}\n"
        )
        rc, payload = _run(draft, ws)
        self.assertEqual(rc, 0)
        self.assertIn(payload["verdict"], {
            "pass-only-one-path-in-flight", "pass-no-cantina-id-cited"
        })
        if payload["verdict"] == "pass-only-one-path-in-flight":
            self.assertIn(expected_id, payload.get("cantina_ids", []))

    def test_cantina_dash_id(self) -> None:
        self._one_path_check("Re: cantina-192 triager response", "192")

    def test_cantina_slash_id(self) -> None:
        self._one_path_check("Filed at cantina/192", "192")

    def test_submission_hash_id(self) -> None:
        self._one_path_check("Triager response for submission #48", "48")

    def test_bare_hash_id(self) -> None:
        self._one_path_check("This addresses #213 escalation", "213")


if __name__ == "__main__":
    unittest.main()
