#!/usr/bin/env python3
"""FIX-7C truth-sweep regression tests (capv3 iter-007 re-review blockers #5 + #6).

Locks two fixes from Codex FIX-7C:

  Part 1 — Artifact-path sanitization (bug #5).
    `agent_outputs/capv3_iter5_T1_live_*.json` (18 files) +
    `agent_outputs/capv3_iter5_T1_run_summary.json` had leaked
    operator-home paths (`/Users/wolf/audits/...`, `/Users/wolf/claude/...`)
    that iter-v3-4 FIX-5 did NOT catch because these artifacts shipped
    post-FIX-5. FIX-7C substitutes them with the FIX-5 conventions
    (`<workspace>`, `<repo>`) and asserts the resulting files remain
    valid JSON. Tests 1 + 2 lock both properties.

  Part 2 — Docs truth-sweep (bug #6).
    `docs/CAPABILITY_V3_ITER_{006,007}_RESULTS.md` said "6/6 SHIPPED"
    for the Codex roadmap, but key lanes (Check #22 draft_claims,
    provider abstraction, consent, failure propagation) are still open
    tooling/advisory/operator-gated paths — not reportable-signal-ready.
    FIX-7C reworded the overclaim to "6/6 addressed" and added a
    disclosure pointing out that capability-v3 still has zero new
    reportable bugs. Tests 3 + 4 lock both the reword and the
    disclosure.

Offline, stdlib-only, hermetic. No subprocess, no network.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AGENT_OUTPUTS = ROOT / "docs" / "archive" / "capability-loop-evidence-2026-05-02" / "agent_outputs"
DOCS = ROOT / "docs"

ITER5_T1_LIVE_GLOB = "capv3_iter5_T1_live_*.json"
ITER5_T1_RUN_SUMMARY = "capv3_iter5_T1_run_summary.json"

RESULTS_006 = DOCS / "CAPABILITY_V3_ITER_006_RESULTS.md"
RESULTS_007 = DOCS / "CAPABILITY_V3_ITER_007_RESULTS.md"

# The disclosure phrase that must appear verbatim in both results docs.
# Matches the FIX-7C spec: "Capability-v3 still has zero new reportable
# bugs; outputs are tooling, advisory harnesses, fixtures, cannot-run
# records, and operator handoff paths unless explicitly marked as a real
# finding."
DISCLOSURE_PHRASE = (
    "Capability-v3 still has zero new reportable bugs; "
    "outputs are tooling, advisory harnesses, fixtures, "
    "cannot-run records, and operator handoff paths "
    "unless explicitly marked as a real finding."
)

# Intentional string-split so this literal doesn't itself trip the
# grep the test enforces. The regex still matches the full pattern
# `6/6 [Ss]hipped`.
_OVERCLAIM_RE = re.compile(r"6/6\s+" + "[Ss]" + "hipped")


def _iter5_t1_files() -> list[Path]:
    """Return all iter5 T1 artifact paths the fix was responsible for.

    18 `capv3_iter5_T1_live_*.json` + 1 `capv3_iter5_T1_run_summary.json`
    = 19 files. Sorted for deterministic test output.
    """
    live = sorted(AGENT_OUTPUTS.glob(ITER5_T1_LIVE_GLOB))
    summary = AGENT_OUTPUTS / ITER5_T1_RUN_SUMMARY
    files = list(live) + [summary]
    # Sanity-check: we really do have the expected 19 files. If the
    # manifest changes in the future (more artifacts, renamed files),
    # this gate flips and forces a deliberate review — we don't want
    # the test to silently pass on a smaller set.
    assert len(live) == 18, (
        f"Expected 18 iter5 T1 live JSONs; found {len(live)}. "
        f"Glob was: {ITER5_T1_LIVE_GLOB}"
    )
    assert summary.exists(), (
        f"Expected iter5 T1 run summary at {summary}"
    )
    return files


class TestFix7cTruthSweep(unittest.TestCase):
    """The 4 FIX-7C regression gates, mirroring the Codex fix spec."""

    # ------------------------------------------------------------------
    # Part 1 — iter5 T1 artifact sanitization
    # ------------------------------------------------------------------

    def test_agent_outputs_iter5_no_home_paths(self) -> None:
        """Every iter5 T1 artifact must be free of `/Users/wolf` substrings.

        Equivalent to `grep -l '/Users/wolf' agent_outputs/capv3_iter5_T1_*.json`
        returning zero hits. Matches both the `/Users/wolf/audits/...` and
        `/Users/wolf/claude/...` leak classes documented in FIX-5 and extended
        to iter5 T1 in FIX-7C.
        """
        offenders: list[tuple[str, int]] = []
        for p in _iter5_t1_files():
            text = p.read_text(encoding="utf-8")
            if "/Users/wolf" in text:
                offenders.append((str(p.relative_to(ROOT)), text.count("/Users/wolf")))
        self.assertEqual(
            offenders, [],
            msg=(
                "Found `/Users/wolf` paths in iter5 T1 artifacts after "
                f"FIX-7C sanitization. Hits (path, count): {offenders}"
            ),
        )

    def test_agent_outputs_iter5_still_valid_json(self) -> None:
        """Every patched iter5 T1 artifact must still parse as JSON.

        Equivalent to
        `python3 -m json.tool agent_outputs/capv3_iter5_T1_*.json` succeeding
        on every file. Guards against a future sanitization pass that
        accidentally mangles JSON (e.g. substitutes inside a key-string
        that happens to contain a backslash or a quote).
        """
        broken: list[tuple[str, str]] = []
        for p in _iter5_t1_files():
            try:
                with p.open("r", encoding="utf-8") as fh:
                    json.load(fh)
            except (json.JSONDecodeError, OSError) as exc:
                broken.append((str(p.relative_to(ROOT)), str(exc)))
        self.assertEqual(
            broken, [],
            msg=(
                "Found iter5 T1 artifacts that are no longer valid JSON "
                f"after FIX-7C path substitution. Offenders: {broken}"
            ),
        )

    # ------------------------------------------------------------------
    # Part 2 — docs truth-sweep
    # ------------------------------------------------------------------

    def test_results_docs_no_6_of_6_shipped_overclaim(self) -> None:
        """Neither 006 nor 007 RESULTS may carry `6/6 [Ss]hipped` wording.

        FIX-7C reworded every such instance to "6/6 addressed (tooling/
        advisory/operator-gated paths exist; not all lanes are
        reportable-signal-ready)".
        """
        offenders: list[tuple[str, list[str]]] = []
        for doc in (RESULTS_006, RESULTS_007):
            hits = _OVERCLAIM_RE.findall(doc.read_text(encoding="utf-8"))
            if hits:
                offenders.append((str(doc.relative_to(ROOT)), hits))
        self.assertEqual(
            offenders, [],
            msg=(
                "Results docs still contain `6/6 [Ss]hipped` overclaim. "
                f"Offenders: {offenders}"
            ),
        )

    def test_results_docs_have_zero_reportable_bugs_disclosure(self) -> None:
        """Both 006 and 007 RESULTS must carry the FIX-7C disclosure phrase."""
        missing: list[str] = []
        for doc in (RESULTS_006, RESULTS_007):
            text = doc.read_text(encoding="utf-8")
            if DISCLOSURE_PHRASE not in text:
                missing.append(str(doc.relative_to(ROOT)))
        self.assertEqual(
            missing, [],
            msg=(
                "Results docs missing FIX-7C zero-reportable-bugs disclosure. "
                f"Missing from: {missing}"
            ),
        )


if __name__ == "__main__":
    unittest.main()
