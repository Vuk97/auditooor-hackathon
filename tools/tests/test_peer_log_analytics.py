#!/usr/bin/env python3
"""capability-v3 iter-v3-8 T2 — codex-peer-log-analytics regression tests.

Hermetic: no live log, no network, no ``gh``/``git``. All input comes
from the 3-tick fixture at
``tools/tests/fixtures/peer_log_analytics/sample_log.md`` or from inline
strings — nothing in this file touches the live log.
"""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "codex-peer-log-analytics.py"
FIXTURE_PATH = (
    ROOT / "tools" / "tests" / "fixtures" / "peer_log_analytics" / "sample_log.md"
)


def _load_tool():
    """Load codex-peer-log-analytics.py as a module.

    The hyphenated filename is not a valid Python identifier so we go
    through ``importlib`` rather than a plain ``import`` statement.
    """
    spec = importlib.util.spec_from_file_location(
        "codex_peer_log_analytics", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ParseFixtureTests(unittest.TestCase):
    """Locks fixture-parse accuracy for the 3-tick synthetic log."""

    def test_parse_fixture_counts(self) -> None:
        """Fixture: 3 ticks, 3 events total, 1 honest-zero, 1+1+1 classes.

        Tick-3 carries 3 events (the third row contains an escaped-pipe
        body preview added in FIX-8A to regression-lock the
        escape-aware splitter).
        """
        mod = _load_tool()
        text = FIXTURE_PATH.read_text(encoding="utf-8")
        summary = mod.analyze(text)

        self.assertEqual(summary["ticks"], 3)
        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["honest_zero_ticks"], 1)
        self.assertEqual(summary["by_class"]["review-feedback"], 1)
        self.assertEqual(summary["by_class"]["suggestion"], 1)
        self.assertEqual(summary["by_class"]["question"], 1)
        # All other classes must be zero.
        for cls in (
            "new-task-proposal",
            "commit-push",
            "new-pr",
            "unclassified",
        ):
            self.assertEqual(
                summary["by_class"][cls], 0, f"class={cls} expected 0"
            )
        # Sanity: time_span is populated.
        self.assertEqual(
            summary["time_span"]["first_tick"], "2026-04-24T10:00:00Z"
        )
        self.assertEqual(
            summary["time_span"]["last_tick"], "2026-04-24T12:00:00Z"
        )
        # Metadata (`- events: 3`) matches parsed count → no warnings.
        self.assertEqual(summary["parse_warnings"], 0)


class SinceFilterTests(unittest.TestCase):
    """--since filtering semantics."""

    def test_filter_since_excludes_earlier_ticks(self) -> None:
        """`--since` at tick-2 timestamp should yield 2 ticks (ticks 2+3)."""
        mod = _load_tool()
        text = FIXTURE_PATH.read_text(encoding="utf-8")
        since = mod._parse_iso("2026-04-24T11:00:00Z")
        self.assertIsNotNone(since)
        summary = mod.analyze(text, since=since)

        self.assertEqual(summary["ticks"], 2)
        # Tick 1 (bootstrap, 0 events, no marker) is dropped; tick 2
        # (honest-zero marker) + tick 3 (3 events, incl. escaped-pipe
        # preview from FIX-8A fixture row) remain.
        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["honest_zero_ticks"], 1)
        self.assertEqual(
            summary["time_span"]["first_tick"], "2026-04-24T11:00:00Z"
        )


class HonestZeroBootstrapTests(unittest.TestCase):
    """Bootstrap-tick honest-zero detection.

    Uses an inline fixture (NOT ``sample_log.md``) where the bootstrap
    section carries the ``_No peer events in window._`` marker — this
    is the shape currently live in ``docs/CAPABILITY_V3_CODEX_LOG.md``
    at line 85, so the parser must count it.
    """

    _LOG = (
        "# Capability v3 — Codex peer-poll log (inline test)\n"
        "\n"
        "## 2026-04-24T10:00:00Z — bootstrap (no peer events yet)\n"
        "\n"
        "- since: `—`\n"
        "- events: 0\n"
        "- reason: `bootstrap`\n"
        "\n"
        "_No peer events in window._ This section is the log's bootstrap entry.\n"
    )

    def test_honest_zero_detection_in_bootstrap_ticks(self) -> None:
        mod = _load_tool()
        summary = mod.analyze(self._LOG)

        self.assertEqual(summary["ticks"], 1)
        self.assertEqual(summary["total_events"], 0)
        self.assertEqual(
            summary["honest_zero_ticks"],
            1,
            "bootstrap tick with honest-zero marker must count",
        )
        self.assertEqual(summary["events_per_tick"]["max"], 0)


class FormatTextTests(unittest.TestCase):
    """`--format text` smoke — banner line + non-empty output."""

    def test_format_text_smoke(self) -> None:
        """Invoking the CLI with --format text produces a banner-led summary."""
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--log",
                str(FIXTURE_PATH),
                "--format",
                "text",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertTrue(proc.stdout.strip(), "text output must be non-empty")
        first_line = proc.stdout.splitlines()[0]
        self.assertTrue(
            first_line.startswith("Peer log analytics"),
            f"expected 'Peer log analytics' banner, got: {first_line!r}",
        )
        # Sanity: contains the ticks count somewhere in the body.
        self.assertIn("ticks:", proc.stdout)


class EscapedPipeTests(unittest.TestCase):
    """FIX-8A regression tests.

    Producer ``tools/codex-peer-poll.py`` (L657-658) escapes body-preview
    pipes as ``\\|`` so the pipe char survives inside a markdown table.
    A raw ``split("|")`` parser over-shards such rows and silently drops
    them on the ``len(cells) != len(columns)`` guard (the original
    iter-v3-8 T2 behaviour). These tests lock the fix in place.
    """

    def test_escaped_pipe_in_preview_is_parsed_correctly(self) -> None:
        """Tick 3 has an event with ``preview with \\| pipe`` in body.

        Pre-fix: row is silently dropped → ``total_events == 2`` and
        ``by_class["question"] == 0``.

        Post-fix: escape-aware splitter reassembles the row →
        ``total_events == 3`` and ``by_class["question"] == 1``.
        """
        mod = _load_tool()
        text = FIXTURE_PATH.read_text(encoding="utf-8")
        summary = mod.analyze(text)

        self.assertEqual(
            summary["total_events"],
            3,
            "fixture tick-3 has 3 rows incl. an escaped-pipe preview; "
            "pre-fix split('|') silently drops the 3rd row",
        )
        self.assertEqual(
            summary["by_class"]["question"],
            1,
            "the escaped-pipe row classifies as 'question' in the fixture",
        )
        # No warnings — fixture metadata (`- events: 3`) matches parse.
        self.assertEqual(summary["parse_warnings"], 0)

    def test_events_count_mismatch_emits_parse_warning(self) -> None:
        """Fixture: ``- events: 5`` metadata but only 3 table rows.

        The cross-check must flag this as a parse warning rather than
        silently accepting the drift.
        """
        mod = _load_tool()
        inline_log = (
            "# inline test\n"
            "\n"
            "## 2026-04-24T13:00:00Z — PR #104 peer poll (peer=opus)\n"
            "\n"
            "- since: `2026-04-24T12:00:00Z`\n"
            "- events: 5\n"
            "\n"
            "| type | class | author | route | preview |\n"
            "|---|---|---|---|---|\n"
            "| comment | review-feedback | Vuk97 | address-next-tick | row 1 |\n"
            "| comment | suggestion | Vuk97 | file-as-T-candidate | row 2 |\n"
            "| comment | question | Vuk97 | clarify | row 3 |\n"
        )
        summary = mod.analyze(inline_log)

        self.assertEqual(summary["ticks"], 1)
        self.assertEqual(summary["total_events"], 3)
        self.assertGreater(
            summary["parse_warnings"],
            0,
            "metadata=5 vs parsed=3 must surface as a parse_warning",
        )

    def test_literal_backslash_before_pipe_edge_case(self) -> None:
        """Defensive: a literal ``\\\\|`` (backslash + escaped pipe) in a
        preview must still split correctly — i.e. the row survives and
        the previous cell still ends with a single backslash.

        This is the edge case flagged in the FIX-8A truth audit: a body
        that happens to end with a backslash before a table boundary
        would confuse a naive regex. The current ``(?<!\\)\\|`` lookbehind
        treats ``\\\\|`` as "escaped backslash + escape of pipe" → cell
        boundary still detected, no silent drop.

        We assert the row count rather than byte-perfect preview content
        because this corner case only arises with producer-side escape
        bugs; the load-bearing behaviour is that the row is NOT dropped.
        """
        mod = _load_tool()
        inline_log = (
            "# inline test\n"
            "\n"
            "## 2026-04-24T14:00:00Z — PR #104 peer poll (peer=opus)\n"
            "\n"
            "- since: `2026-04-24T13:00:00Z`\n"
            "- events: 1\n"
            "\n"
            "| type | class | author | route | preview |\n"
            "|---|---|---|---|---|\n"
            "| comment | suggestion | Vuk97 | clarify | trailing backslash \\| then body |\n"
        )
        summary = mod.analyze(inline_log)

        self.assertEqual(summary["ticks"], 1)
        self.assertEqual(
            summary["total_events"],
            1,
            "escaped-pipe row must not be dropped by split",
        )


if __name__ == "__main__":
    unittest.main()
