"""V5 Gap-23 (PR-E): HYPOTHESES.md silent failure — stage 16 must fix
the asymmetric-artefact bug (HYPOTHESIS_PROMPT.md emitted but
HYPOTHESES.md never produced).

Background — quoted from V5 Capability Gaps doc (Gap 23):
    Monetrix audit. Stage 16 (engage.py hypothesis generation) emitted
    282 KB raw HYPOTHESIS_PROMPT.md but no HYPOTHESES.md final-form.
    Silent failure. Downstream stages that consume HYPOTHESES.md
    (mining briefs, attack-tree) get nothing.

Fix design:
  - stage_economic_hypotheses calls _ensure_hypotheses_md after its
    own subprocess. _ensure_hypotheses_md inspects (HYPOTHESIS_PROMPT.md,
    HYPOTHESES.md) and:
      (a) does nothing if HYPOTHESES.md already exists (operator did it);
      (b) does nothing if HYPOTHESIS_PROMPT.md is missing (stage 7 didn't
          run — not our concern);
      (c) attempts LLM dispatch via tools/llm-dispatch.py if network
          consent is granted (AUDITOOOR_LLM_NETWORK_CONSENT=1 or
          ADVERSARIAL_LIVE_CONSENT=1) AND the dispatch tool exists;
      (d) on any failure (offline, no consent, dispatch crash) writes a
          loud TBD placeholder pointing back at the prompt.

Tests pinned by this file:
  1. Pre-existing HYPOTHESES.md is left alone (idempotency).
  2. No HYPOTHESIS_PROMPT.md → no placeholder written (stage 7 gate).
  3. Prompt present, no consent → placeholder written + content asserts.
  4. Prompt present, consent granted, LLM succeeds → real content used.
  5. Prompt present, consent granted, LLM rc=2 (cannot-run) → placeholder.
  6. Prompt present, consent granted, LLM crash → placeholder + warn log.
  7. closeout `hypotheses` check passes after _ensure_hypotheses_md
     writes the placeholder (integration with audit-closeout-check).
  8. Placeholder text intentionally NOT a valid hypothesis table (so a
     downstream consumer cannot mistake it for real output — Codex
     directive: "the placeholder must NOT mask the real bug").
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[2]
ENGAGE = REPO / "tools" / "engage.py"
CLOSEOUT = REPO / "tools" / "audit-closeout-check.py"


def _load_engage_module() -> types.ModuleType:
    tools_dir = str(REPO / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("engage", ENGAGE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_closeout_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        "audit_closeout_check", CLOSEOUT,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["audit_closeout_check"] = mod
    spec.loader.exec_module(mod)
    return mod


ENGAGE_MOD = _load_engage_module()


class EnsureHypothesesIdempotencyTest(unittest.TestCase):
    """`_ensure_hypotheses_md` must be a no-op when the goal artefact
    already exists or the upstream prompt does not exist.
    """

    def _make_args(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(quiet=True)

    def test_existing_hypotheses_left_alone(self) -> None:
        """If HYPOTHESES.md already exists (operator wrote it manually
        or earlier run produced it), do not overwrite it.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "HYPOTHESIS_PROMPT.md").write_text("# prompt\n")
            existing = "# my hand-written hypotheses\n"
            (ws / "HYPOTHESES.md").write_text(existing)
            with patch.dict(os.environ, {}, clear=False):
                # Strip consent so the "no LLM" path would otherwise fire.
                for k in (
                    "AUDITOOOR_LLM_NETWORK_CONSENT",
                    "ADVERSARIAL_LIVE_CONSENT",
                ):
                    os.environ.pop(k, None)
                ENGAGE_MOD._ensure_hypotheses_md(ws, self._make_args())
            self.assertEqual(
                (ws / "HYPOTHESES.md").read_text(),
                existing,
                "pre-existing HYPOTHESES.md must be preserved (idempotency)",
            )

    def test_no_prompt_means_no_placeholder(self) -> None:
        """If HYPOTHESIS_PROMPT.md is missing, stage 7 didn't run.
        We must NOT fabricate a placeholder — that would be a false
        positive on the closeout gate.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            ENGAGE_MOD._ensure_hypotheses_md(ws, self._make_args())
            self.assertFalse(
                (ws / "HYPOTHESES.md").exists(),
                "no prompt = no placeholder; closeout gate handles the "
                "neither-present WARN case separately",
            )


class PlaceholderModeTest(unittest.TestCase):
    """When LLM dispatch is unavailable (offline / no consent / no
    dispatch tool), stage 16 must write the loud TBD placeholder so the
    file exists for downstream consumers.
    """

    def _args(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(quiet=True)

    def test_no_consent_writes_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "HYPOTHESIS_PROMPT.md").write_text("# prompt body\n")
            with patch.dict(os.environ, {}, clear=False):
                for k in (
                    "AUDITOOOR_LLM_NETWORK_CONSENT",
                    "ADVERSARIAL_LIVE_CONSENT",
                ):
                    os.environ.pop(k, None)
                ENGAGE_MOD._ensure_hypotheses_md(ws, self._args())
            final = ws / "HYPOTHESES.md"
            self.assertTrue(
                final.exists(),
                "placeholder must be written so downstream stages don't "
                "trip on a missing file",
            )
            text = final.read_text()
            # Required content markers — each anchors a Codex directive.
            self.assertIn("TBD", text, "loud TBD banner required")
            self.assertIn("placeholder", text.lower())
            self.assertIn("Operator action required", text)
            self.assertIn("HYPOTHESIS_PROMPT.md", text,
                          "must point back at the prompt file")
            self.assertIn("AUDITOOOR_LLM_NETWORK_CONSENT", text,
                          "must show how to re-run with dispatch")
            # NEGATIVE assertion (Codex Gap-23 directive: placeholder
            # must NOT mask the real bug). It must NOT look like a valid
            # hypothesis table.
            self.assertNotIn(
                "| # | Target | Class (P?) |",
                text,
                "placeholder must not impersonate a real hypothesis table",
            )

    def test_llm_rc2_cannot_run_writes_placeholder(self) -> None:
        """Even with consent set, if the dispatch tool returns rc=2
        (cannot-run, e.g. no API key), we fall back to the placeholder.

        Note: tools/llm-dispatch.py exists in the repo, so we rely on
        that real path-existence check and only mock the subprocess
        ``run`` call. Patching ``Path.exists`` globally would interfere
        with the placeholder writer's own ``prompt_path.exists()`` call.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "HYPOTHESIS_PROMPT.md").write_text("# prompt\n")
            with patch.dict(
                os.environ,
                {"AUDITOOOR_LLM_NETWORK_CONSENT": "1"},
                clear=False,
            ), patch.object(
                ENGAGE_MOD, "run",
                return_value=(2, "", '{"error":"cannot-run: no-api-key"}'),
            ):
                ENGAGE_MOD._ensure_hypotheses_md(ws, self._args())
            final = ws / "HYPOTHESES.md"
            self.assertTrue(
                final.exists(),
                "rc=2 cannot-run must trigger placeholder fallback",
            )
            text = final.read_text()
            self.assertIn("TBD", text)
            self.assertIn("placeholder", text.lower())
            self.assertIn(
                "offline / no API key / no consent",
                text,
                "rc=2 reason text must indicate the offline class",
            )

    def test_llm_success_writes_real_content(self) -> None:
        """When dispatch returns rc=0 with real content, that becomes
        HYPOTHESES.md (no placeholder).
        """
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "HYPOTHESIS_PROMPT.md").write_text("# prompt\n")
            real_payload = (
                "# Hypotheses for ws\n\n"
                "| # | Target | Class (P?) | Trigger | Impact | Fast-check |\n"
                "|---|---|---|---|---|---|\n"
                "| 1 | Foo.bar() | P5 guard-drift | bad sig | drain | grep |\n"
            )
            with patch.dict(
                os.environ,
                {"AUDITOOOR_LLM_NETWORK_CONSENT": "1"},
                clear=False,
            ), patch.object(
                ENGAGE_MOD, "run",
                return_value=(0, real_payload, ""),
            ):
                ENGAGE_MOD._ensure_hypotheses_md(ws, self._args())
            final = ws / "HYPOTHESES.md"
            self.assertEqual(final.read_text(), real_payload)
            self.assertNotIn("placeholder", final.read_text().lower())
            self.assertNotIn("TBD", final.read_text())

    def test_llm_rc1_failure_writes_placeholder(self) -> None:
        """A non-cannot-run rc != 0 (e.g. dispatch tool crashed
        unexpectedly) still fails over to the placeholder so downstream
        stages don't break — but the WARN reason in the placeholder
        body distinguishes "failed" from "offline".
        """
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "HYPOTHESIS_PROMPT.md").write_text("# prompt\n")
            with patch.dict(
                os.environ,
                {"AUDITOOOR_LLM_NETWORK_CONSENT": "1"},
                clear=False,
            ), patch.object(
                ENGAGE_MOD, "run",
                return_value=(1, "", "unexpected crash inside dispatch"),
            ):
                ENGAGE_MOD._ensure_hypotheses_md(ws, self._args())
            final = ws / "HYPOTHESES.md"
            self.assertTrue(final.exists())
            text = final.read_text()
            self.assertIn("TBD", text)
            self.assertIn("LLM dispatch failed rc=1", text)


class CloseoutIntegrationTest(unittest.TestCase):
    """After _ensure_hypotheses_md writes a placeholder, the closeout
    `hypotheses` check must report PASS (file exists) — that is exactly
    the silent-failure mode Gap-23 detects, and the fix removes it.

    Note: PASS here is appropriate because the file *exists* and is
    plainly marked TBD. Operators see the placeholder text in the file
    and the warning in the engage summary; the closeout gate's job is to
    block on *missing* files, which the fix prevents.
    """

    def test_closeout_hypotheses_passes_after_placeholder(self) -> None:
        closeout = _load_closeout_module()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "HYPOTHESIS_PROMPT.md").write_text("# prompt\n")
            with patch.dict(os.environ, {}, clear=False):
                for k in (
                    "AUDITOOOR_LLM_NETWORK_CONSENT",
                    "ADVERSARIAL_LIVE_CONSENT",
                ):
                    os.environ.pop(k, None)
                ENGAGE_MOD._ensure_hypotheses_md(
                    ws, types.SimpleNamespace(quiet=True),
                )
            result = closeout.check_hypotheses(ws)
            self.assertEqual(
                result.status,
                closeout.PASS,
                f"closeout must PASS after Gap-23 fix; got: "
                f"status={result.status} reason={result.reason!r}",
            )

    def test_closeout_hypotheses_fail_without_fix(self) -> None:
        """Regression-anchor: with the prompt present and HYPOTHESES.md
        missing (the historical Gap-23 silent-failure shape), the
        closeout still FAILs. This ensures we haven't accidentally
        relaxed the gate while writing the fix.
        """
        closeout = _load_closeout_module()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "HYPOTHESIS_PROMPT.md").write_text("# prompt\n")
            # Deliberately do NOT call _ensure_hypotheses_md.
            result = closeout.check_hypotheses(ws)
            self.assertEqual(
                result.status,
                closeout.FAIL,
                "without the fix the closeout must still FAIL — "
                "Gap-23 detector unchanged",
            )


class PlaceholderContentSafetyTest(unittest.TestCase):
    """Codex Gap-23 directive: the placeholder must surface, not mask,
    the real generation bug. Pinned content invariants.
    """

    def test_placeholder_marks_status_clearly(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            prompt = ws / "HYPOTHESIS_PROMPT.md"
            prompt.write_text("# big prompt\n" + ("x" * 1000))
            ENGAGE_MOD._write_hypotheses_placeholder(
                ws, prompt, "test-reason", quiet=True,
            )
            text = (ws / "HYPOTHESES.md").read_text()
            self.assertIn("**Status:** placeholder", text)
            self.assertIn("test-reason", text)
            # Prompt size must be reported so operators can sanity-check
            # the upstream artefact.
            self.assertRegex(text, r"\d+ bytes")

    def test_placeholder_header_is_distinct_from_real_output(self) -> None:
        """Minimax pre-review caught a header-collision risk: the real
        ``HYPOTHESES.md`` produced by Claude starts with ``# Hypotheses
        for <project>``. If the placeholder used the same header, a
        downstream ``grep '^# Hypotheses for'`` would match both — false
        positive on "real output present". The placeholder must use a
        header that cannot be confused with real output. Pin it.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            prompt = ws / "HYPOTHESIS_PROMPT.md"
            prompt.write_text("# prompt\n")
            ENGAGE_MOD._write_hypotheses_placeholder(
                ws, prompt, "for-header-collision-test", quiet=True,
            )
            text = (ws / "HYPOTHESES.md").read_text()
            first_line = text.splitlines()[0]
            self.assertIn(
                "[PLACEHOLDER]",
                first_line,
                "header must include [PLACEHOLDER] so downstream tools "
                "cannot mistake it for real output",
            )
            # Machine-readable marker for any downstream gate that needs
            # to distinguish placeholder vs real without parsing markdown.
            self.assertIn(
                "<!-- AUDIT_STATUS: PLACEHOLDER_PENDING_LLM_DISPATCH -->",
                text,
                "machine-readable AUDIT_STATUS marker required",
            )

    def test_empty_hypotheses_md_treated_as_absent(self) -> None:
        """Kimi pre-review caught: a 0-byte HYPOTHESES.md (e.g. left by
        a crashed write) would otherwise short-circuit the placeholder
        writer and perpetuate the silent-failure mode. It must be
        treated as "absent" and overwritten.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            prompt = ws / "HYPOTHESIS_PROMPT.md"
            prompt.write_text("# prompt\n")
            empty = ws / "HYPOTHESES.md"
            empty.write_text("")  # 0 bytes
            self.assertEqual(empty.stat().st_size, 0)
            with patch.dict(os.environ, {}, clear=False):
                for k in (
                    "AUDITOOOR_LLM_NETWORK_CONSENT",
                    "ADVERSARIAL_LIVE_CONSENT",
                ):
                    os.environ.pop(k, None)
                ENGAGE_MOD._ensure_hypotheses_md(
                    ws, types.SimpleNamespace(quiet=True),
                )
            new_text = empty.read_text()
            self.assertGreater(len(new_text), 0)
            self.assertIn("[PLACEHOLDER]", new_text)


if __name__ == "__main__":
    unittest.main()
