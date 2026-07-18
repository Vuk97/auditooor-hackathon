#!/usr/bin/env python3
"""Offline tests for tools/track-submissions.py — Manual Submission Ledger.

No network. No subprocess to external tools. Everything runs in a tmp
workspace under unittest.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))


def _load_track_submissions():
    """Load tools/track-submissions.py despite the hyphen in the filename."""
    path = TOOLS / "track-submissions.py"
    spec = importlib.util.spec_from_file_location("track_submissions", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


track_submissions = _load_track_submissions()

# outcome_reweight is needed for the cross-tool regression test.
from outcome_reweight import (  # noqa: E402
    classify_title,
    load_outcome_history,
)


def _read_outcomes(ws: Path) -> list[dict]:
    path = ws / "reference" / "outcomes.jsonl"
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def _read_submissions(ws: Path) -> str:
    path = ws / "submissions" / "SUBMISSIONS.md"
    return path.read_text() if path.exists() else ""


def _read_pending_without_platform_id(ws: Path) -> list[dict]:
    path = ws / "reference" / "pending_filed_without_platform_id.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _call(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            rc = track_submissions.main(argv)
    except SystemExit as exc:  # argparse uses SystemExit on parse errors
        rc = int(exc.code or 0)
    return rc, buf.getvalue()


class TestRecord(unittest.TestCase):
    # ---------- case 1 ----------
    def test_record_creates_pending_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rc, out = _call([
                "record", str(ws),
                "--platform", "hackenproof",
                "--report-url", "https://hackenproof.com/reports/42",
                "--report-id", "HP-42",
                "--title", "reentrancy in vault withdraw",
                "--severity", "High",
            ])
            self.assertEqual(rc, 0, msg=out)

            # outcomes.jsonl
            rows = _read_outcomes(ws)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["outcome"], "pending")
            self.assertEqual(row["status"], "Pending")
            self.assertEqual(row["report_id"], "HP-42")
            self.assertEqual(row["platform"], "hackenproof")
            self.assertEqual(row["url"], "https://hackenproof.com/reports/42")
            self.assertEqual(row["title"], "reentrancy in vault withdraw")
            self.assertEqual(row["severity"], "High")
            self.assertIn("recorded_at", row)
            self.assertNotIn("resolved_at", row)
            self.assertIs(row["new_rule_codified"], False)

            # SUBMISSIONS.md
            md = _read_submissions(ws)
            self.assertIn("Manual Submission Ledger", md)
            self.assertIn("HP-42", md)
            self.assertIn("hackenproof", md)
            self.assertIn("https://hackenproof.com/reports/42", md)
            self.assertIn("Pending", md)
            self.assertIn("reentrancy in vault withdraw", md)
            # Canonical header is present.
            self.assertIn("| Date | Report-ID | Platform | URL | Severity | Title | Status |", md)

    def test_record_pending_filed_without_platform_id_uses_separate_non_evidence_tracker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rc, out = _call([
                "record-pending-filed-without-platform-id",
                str(ws),
                "--local-id",
                "HB-LOCAL-7",
                "--platform",
                "cantina",
                "--title",
                "operator says filed but platform id missing",
                "--severity",
                "High",
                "--source-path",
                "submissions/SUBMISSIONS.md",
                "--operator-note",
                "SUBMISSIONS.md row has Filed but no report URL",
            ])
            self.assertEqual(rc, 0, msg=out)

            self.assertEqual(_read_outcomes(ws), [])
            self.assertEqual(_read_submissions(ws), "")
            rows = _read_pending_without_platform_id(ws)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["schema"], "auditooor.pending_filed_without_platform_id.v1")
            self.assertEqual(row["local_id"], "HB-LOCAL-7")
            self.assertEqual(row["platform"], "cantina")
            self.assertEqual(row["outcome"], "pending_without_platform_id")
            self.assertEqual(row["status"], "artifact_present_pending")
            self.assertFalse(row["counts_as_outcome_evidence"])
            self.assertFalse(row["counts_as_submission_evidence"])
            self.assertTrue(row["requires_platform_id_backfill"])

            rc2, _ = _call([
                "record-pending-filed-without-platform-id",
                str(ws),
                "--local-id",
                "HB-LOCAL-7",
            ])
            self.assertEqual(rc2, 2)
            self.assertEqual(len(_read_pending_without_platform_id(ws)), 1)

    def test_record_can_store_scoreboard_linkage_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rc, out = _call([
                "record", str(ws),
                "--platform", "cantina",
                "--report-url", "https://cantina.xyz/reports/77",
                "--report-id", "CT-77",
                "--title", "scoreboard linked finding",
                "--severity", "High",
                "--lane", "source-mine",
                "--model-route", "kimi->minimax->codex",
                "--proof-artifact", "submissions/packaged/ct-77",
                "--production-path-status", "poc_ready",
            ])
            self.assertEqual(rc, 0, msg=out)

            rows = _read_outcomes(ws)
            self.assertEqual(rows[0]["lane"], "source-mine")
            self.assertEqual(rows[0]["model_route"], "kimi->minimax->codex")
            self.assertEqual(rows[0]["proof_artifact"], "submissions/packaged/ct-77")
            self.assertEqual(rows[0]["production_path_status"], "poc_ready")

            rc, _ = _call([
                "record-outcome", str(ws),
                "--report-id", "CT-77",
                "--state", "accepted",
            ])
            self.assertEqual(rc, 0)
            latest = _read_outcomes(ws)[-1]
            self.assertEqual(latest["outcome"], "accepted")
            self.assertEqual(latest["lane"], "source-mine")
            self.assertEqual(latest["model_route"], "kimi->minimax->codex")
            self.assertEqual(latest["proof_artifact"], "submissions/packaged/ct-77")
            self.assertEqual(latest["production_path_status"], "poc_ready")

    # ---------- case 2 ----------
    def test_record_rejects_duplicate_report_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rc1, _ = _call([
                "record", str(ws),
                "--platform", "cantina",
                "--report-url", "https://cantina.xyz/reports/9",
                "--report-id", "CT-9",
                "--title", "oracle drift",
            ])
            self.assertEqual(rc1, 0)

            # Second record with the SAME report_id — should exit 2.
            buf = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = buf
            try:
                rc2, _ = _call([
                    "record", str(ws),
                    "--platform", "cantina",
                    "--report-url", "https://cantina.xyz/reports/9",
                    "--report-id", "CT-9",
                    "--title", "oracle drift (dupe attempt)",
                ])
            finally:
                sys.stderr = old_stderr
            self.assertEqual(rc2, 2)
            self.assertIn("already tracked", buf.getvalue())

            # Only one outcome row persisted.
            rows = _read_outcomes(ws)
            self.assertEqual(len(rows), 1)

    # ---------- case 3 ----------
    def test_record_outcome_updates_pending_to_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rc, _ = _call([
                "record", str(ws),
                "--platform", "sherlock",
                "--report-url", "https://audits.sherlock.xyz/contests/xyz/judging/1",
                "--report-id", "SH-1",
                "--title", "access-control missing on setter",
            ])
            self.assertEqual(rc, 0)

            rc, _ = _call([
                "record-outcome", str(ws),
                "--report-id", "SH-1",
                "--state", "accepted",
            ])
            self.assertEqual(rc, 0)

            rows = _read_outcomes(ws)
            self.assertEqual(len(rows), 2)
            latest = rows[-1]
            self.assertEqual(latest["outcome"], "accepted")
            self.assertEqual(latest["status"], "Accepted")
            self.assertIn("resolved_at", latest)
            self.assertIs(latest["new_rule_codified"], False)
            # Metadata from the pending row is preserved so later readers
            # don't have to re-scan to reconstruct the report URL.
            self.assertEqual(latest["platform"], "sherlock")
            self.assertEqual(latest["url"], "https://audits.sherlock.xyz/contests/xyz/judging/1")
            self.assertEqual(latest["title"], "access-control missing on setter")

            md = _read_submissions(ws)
            self.assertIn("Accepted", md)
            # The Pending label for SH-1 should have been replaced.
            # (We still expect one row for SH-1 in the table.)
            self.assertEqual(md.count("SH-1"), 1)

    def test_record_outcome_can_mark_new_rule_codified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rc, _ = _call([
                "record", str(ws),
                "--platform", "cantina",
                "--report-url", "https://cantina.xyz/reports/238",
                "--report-id", "238",
                "--title", "rejection later codified as a rule",
            ])
            self.assertEqual(rc, 0)

            rc, _ = _call([
                "record-outcome", str(ws),
                "--report-id", "238",
                "--state", "rejected",
                "--new-rule-codified",
            ])
            self.assertEqual(rc, 0)

            rows = _read_outcomes(ws)
            self.assertEqual(rows[0]["new_rule_codified"], False)
            self.assertEqual(rows[-1]["outcome"], "rejected")
            self.assertEqual(rows[-1]["final_triager_outcome"], "rejected")
            self.assertIs(rows[-1]["new_rule_codified"], True)

    # ---------- case 4 ----------
    def test_list_filters_by_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            records = [
                ("HP-1", "hackenproof", "reentrancy one", "accepted"),
                ("HP-2", "hackenproof", "oracle two", None),  # stays pending
                ("HP-3", "hackenproof", "delegatecall three", "rejected"),
            ]
            for rid, platform, title, final in records:
                _call([
                    "record", str(ws),
                    "--platform", platform,
                    "--report-url", f"https://example.com/{rid}",
                    "--report-id", rid,
                    "--title", title,
                ])
                if final is not None:
                    _call([
                        "record-outcome", str(ws),
                        "--report-id", rid,
                        "--state", final,
                    ])

            # default = pending only
            _, out = _call(["list", "--workspace", str(ws)])
            self.assertIn("HP-2", out)
            self.assertNotIn("HP-1", out)
            self.assertNotIn("HP-3", out)

            _, out = _call(["list", "--workspace", str(ws), "--outcome", "accepted"])
            self.assertIn("HP-1", out)
            self.assertNotIn("HP-2", out)
            self.assertNotIn("HP-3", out)

            _, out = _call(["list", "--workspace", str(ws), "--outcome", "rejected"])
            self.assertIn("HP-3", out)
            self.assertNotIn("HP-1", out)
            self.assertNotIn("HP-2", out)

            _, out = _call(["list", "--workspace", str(ws), "--outcome", "all"])
            for rid in ("HP-1", "HP-2", "HP-3"):
                self.assertIn(rid, out)

    # ---------- case 5 ----------
    def test_append_only_preserves_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _call([
                "record", str(ws),
                "--platform", "immunefi",
                "--report-url", "https://bugs.immunefi.com/reports/77",
                "--report-id", "IM-77",
                "--title", "oracle stale price",
            ])
            _call([
                "record-outcome", str(ws),
                "--report-id", "IM-77",
                "--state", "paid",
            ])

            rows = _read_outcomes(ws)
            self.assertEqual(len(rows), 2)

            # First row is the original pending note — not rewritten.
            self.assertEqual(rows[0]["outcome"], "pending")
            self.assertEqual(rows[0]["status"], "Pending")
            self.assertNotIn("resolved_at", rows[0])

            # Second row is the transition.
            self.assertEqual(rows[1]["outcome"], "paid")
            self.assertEqual(rows[1]["status"], "Paid")
            self.assertIn("resolved_at", rows[1])

            # Readers must take the LAST record per report_id as authoritative.
            latest_map = track_submissions._latest_rows_by_report_id(rows)
            self.assertEqual(latest_map["IM-77"]["outcome"], "paid")

    # ---------- case 6 ----------
    def test_outcome_reweight_reads_new_rows(self) -> None:
        """Regression: PR 112's reweighting MUST see 'paid' rows we append.

        If this fails, the outcome-telemetry loop is silently undercounting
        wins — every class that ever got paid falls off the accepted bucket.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)

            # Seed 4 reentrancy reports: 1 pending, 2 paid, 1 accepted.
            # (classify_title() keys on the word 'reentrancy'.)
            bundles = [
                ("R-1", "reentrancy in vault withdraw", "paid"),
                ("R-2", "reentrancy flash swap", "paid"),
                ("R-3", "reentrancy on deposit", "accepted"),
                ("R-4", "reentrancy in staking", None),  # still pending
            ]
            for rid, title, final in bundles:
                _call([
                    "record", str(ws),
                    "--platform", "hackenproof",
                    "--report-url", f"https://example.com/{rid}",
                    "--report-id", rid,
                    "--title", title,
                ])
                if final is not None:
                    _call([
                        "record-outcome", str(ws),
                        "--report-id", rid,
                        "--state", final,
                    ])

            # Sanity: classify_title picks reentrancy slug.
            self.assertEqual(classify_title("reentrancy in vault withdraw"), "reentrancy")

            outcomes_path = ws / "reference" / "outcomes.jsonl"
            history = load_outcome_history(outcomes_path)
            self.assertIn("reentrancy", history)
            stats = history["reentrancy"]

            # All four reports land in total (load_outcome_history counts
            # every matching line — pending lines still classify, they just
            # don't land in the accepted bucket).
            self.assertGreaterEqual(stats["total"], 4)

            # accepted bucket must fold in BOTH 'accepted' and 'paid' per
            # Codex PR-102 non-blocker 1.
            # Three resolved rows in the accepted bucket: R-1 paid, R-2 paid,
            # R-3 accepted. (The append-only stream also contains the earlier
            # pending lines for those same reports, which add to total but
            # not to accepted.)
            self.assertGreaterEqual(stats["accepted"], 3,
                f"Expected >=3 accepted-bucket rows, got {stats['accepted']}. "
                "This means load_outcome_history is dropping paid rows.")

    # ---------- case 7: cannot-judge behaviour ----------
    def test_list_on_empty_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rc, out = _call(["list", "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            self.assertIn("no submissions recorded", out)

    # ---------- case 8: record-outcome rejects unknown report_id ----------
    def test_record_outcome_rejects_unknown_report_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            buf = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = buf
            try:
                rc, _ = _call([
                    "record-outcome", str(ws),
                    "--report-id", "DOES-NOT-EXIST",
                    "--state", "accepted",
                ])
            finally:
                sys.stderr = old_stderr
            self.assertEqual(rc, 2)
            self.assertIn("not found", buf.getvalue())

    # ---------- case 10: code4rena platform is accepted ----------
    def test_record_accepts_code4rena_platform(self) -> None:
        """iter7-T4: code4rena is now in VALID_PLATFORMS.

        Records a pending row with `--platform code4rena` and asserts the
        row persists with the platform field set to the exact string
        `code4rena` (no alias expansion, no case munging).
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rc, out = _call([
                "record", str(ws),
                "--platform", "code4rena",
                "--report-url", "https://code4rena.com/audits/2026-04-k2/submit",
                "--report-id", "C4-K2-1",
                "--title", "health-factor underflow on liquidation",
                "--severity", "High",
            ])
            self.assertEqual(rc, 0, msg=out)

            rows = _read_outcomes(ws)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["outcome"], "pending")
            self.assertEqual(row["status"], "Pending")
            self.assertEqual(row["report_id"], "C4-K2-1")
            self.assertEqual(row["platform"], "code4rena")
            self.assertEqual(row["severity"], "High")

            md = _read_submissions(ws)
            self.assertIn("code4rena", md)
            self.assertIn("C4-K2-1", md)

    # ---------- case 11: c4 shorthand is HARD-REJECTED ----------
    def test_record_rejects_c4_shorthand(self) -> None:
        """iter7-T4 hard-negative lock: `c4` MUST be rejected.

        The allowlist deliberately does NOT include `c4` — adding a
        shorthand would create typo-based ambiguity with the exact token
        `code4rena`. This test locks that decision so no future
        'helpful' alias expansion slips through silently.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            buf = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = buf
            try:
                rc, _ = _call([
                    "record", str(ws),
                    "--platform", "c4",
                    "--report-url", "https://code4rena.com/audits/2026-04-k2/submit",
                    "--report-id", "C4-K2-SHORTHAND",
                    "--title", "should be rejected",
                ])
            finally:
                sys.stderr = old_stderr
            self.assertNotEqual(rc, 0)
            stderr = buf.getvalue()
            self.assertIn("invalid --platform", stderr)
            # The error lists the valid platforms so the operator sees
            # the canonical token `code4rena` (not `c4`).
            self.assertIn("code4rena", stderr)
            # No row must have landed.
            self.assertEqual(_read_outcomes(ws), [])

    # ---------- case 9: invalid platform + invalid state ----------
    def test_validation_rejects_bad_platform_and_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)

            buf = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = buf
            try:
                rc, _ = _call([
                    "record", str(ws),
                    "--platform", "bogus-platform",
                    "--report-url", "https://x/y",
                    "--report-id", "X-1",
                ])
            finally:
                sys.stderr = old_stderr
            self.assertEqual(rc, 2)
            self.assertIn("invalid --platform", buf.getvalue())

            # record a valid row first
            _call([
                "record", str(ws),
                "--platform", "other",
                "--report-url", "https://x/y",
                "--report-id", "X-1",
            ])

            buf = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = buf
            try:
                rc, _ = _call([
                    "record-outcome", str(ws),
                    "--report-id", "X-1",
                    "--state", "maybe",
                ])
            finally:
                sys.stderr = old_stderr
            self.assertEqual(rc, 2)
            self.assertIn("invalid --state", buf.getvalue())


class TestStrictLinkage(unittest.TestCase):
    """P0-4 burn-down: required-field gate behaviour on `record`.

    Covers:
      - missing required field + strict flag -> exit 2 + nothing persisted
      - missing required field + env var     -> exit 2 + nothing persisted
      - missing required field, advisory     -> exit 0 + warn on stderr
      - complete required-field record       -> exit 0 silently
      - final_triager_outcome FIELD always present (default "unknown")
    """

    def _full_args(self, ws: Path, rid: str, *extra: str) -> list[str]:
        return [
            "record", str(ws),
            "--platform", "hackenproof",
            "--report-url", f"https://example.com/{rid}",
            "--report-id", rid,
            "--title", "complete-required-field row",
            "--lane", "source-mine",
            "--model-route", "kimi->minimax->codex",
            "--proof-artifact", "submissions/packaged/example",
            "--production-path-blockers-cleared", "yes",
            *extra,
        ]

    def test_strict_flag_blocks_record_when_required_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            buf = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = buf
            try:
                rc, _ = _call([
                    "record", str(ws),
                    "--platform", "hackenproof",
                    "--report-url", "https://example.com/SR-1",
                    "--report-id", "SR-1",
                    "--title", "missing required fields",
                    "--strict-linkage",
                ])
            finally:
                sys.stderr = old_stderr
            self.assertEqual(rc, 2)
            self.assertIn("strict-linkage", buf.getvalue())
            self.assertIn("missing required fields", buf.getvalue())
            # Nothing must have landed on disk.
            self.assertEqual(_read_outcomes(ws), [])
            self.assertFalse((ws / "submissions" / "SUBMISSIONS.md").exists())

    def test_env_var_promotes_advisory_to_strict(self) -> None:
        """AUDITOOOR_OUTCOME_REQUIRE_LINKAGE=1 fails closed without --strict-linkage."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            buf = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = buf
            saved = os.environ.get("AUDITOOOR_OUTCOME_REQUIRE_LINKAGE")
            os.environ["AUDITOOOR_OUTCOME_REQUIRE_LINKAGE"] = "1"
            try:
                rc, _ = _call([
                    "record", str(ws),
                    "--platform", "cantina",
                    "--report-url", "https://example.com/EV-1",
                    "--report-id", "EV-1",
                    "--title", "env-var strict gate",
                ])
            finally:
                sys.stderr = old_stderr
                if saved is None:
                    del os.environ["AUDITOOOR_OUTCOME_REQUIRE_LINKAGE"]
                else:
                    os.environ["AUDITOOOR_OUTCOME_REQUIRE_LINKAGE"] = saved
            self.assertEqual(rc, 2)
            self.assertIn("strict-linkage", buf.getvalue())
            self.assertEqual(_read_outcomes(ws), [])

    def test_advisory_warn_records_row_when_required_missing(self) -> None:
        """Default behaviour: warn loudly but still write the row (back-compat)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            buf = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = buf
            saved = os.environ.pop("AUDITOOOR_OUTCOME_REQUIRE_LINKAGE", None)
            try:
                rc, _ = _call([
                    "record", str(ws),
                    "--platform", "sherlock",
                    "--report-url", "https://example.com/AD-1",
                    "--report-id", "AD-1",
                    "--title", "advisory mode",
                ])
            finally:
                sys.stderr = old_stderr
                if saved is not None:
                    os.environ["AUDITOOOR_OUTCOME_REQUIRE_LINKAGE"] = saved
            self.assertEqual(rc, 0)
            self.assertIn("WARN", buf.getvalue())
            self.assertIn("missing P0-4 linkage fields", buf.getvalue())
            rows = _read_outcomes(ws)
            self.assertEqual(len(rows), 1)
            # The FIELD must always exist on the persisted row, even when
            # advisory mode allowed the row through.
            self.assertIn("final_triager_outcome", rows[0])
            self.assertEqual(rows[0]["final_triager_outcome"], "unknown")

    def test_complete_record_passes_strict_silently(self) -> None:
        """All four required fields supplied -> strict mode is a no-op pass."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            buf = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = buf
            try:
                rc, _ = _call(self._full_args(ws, "OK-1", "--strict-linkage"))
            finally:
                sys.stderr = old_stderr
            self.assertEqual(rc, 0)
            stderr = buf.getvalue()
            self.assertNotIn("WARN", stderr)
            self.assertNotIn("strict-linkage:", stderr)
            rows = _read_outcomes(ws)
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["lane"], "source-mine")
            self.assertEqual(row["model_route"], "kimi->minimax->codex")
            self.assertEqual(row["proof_artifact"], "submissions/packaged/example")
            self.assertEqual(row["production_path_blockers_cleared"], "yes")
            # final_triager_outcome FIELD must exist with the unknown default.
            self.assertEqual(row["final_triager_outcome"], "unknown")

    def test_explicit_final_triager_overrides_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rc, _ = _call(self._full_args(
                ws, "FT-1",
                "--final-triager-outcome", "in-review",
            ))
            self.assertEqual(rc, 0)
            row = _read_outcomes(ws)[0]
            self.assertEqual(row["final_triager_outcome"], "in-review")


class TestValidateLedger(unittest.TestCase):
    """P0-4: `validate-ledger` summarizes incomplete ledger rows."""

    def _seed_row(self, ws: Path, payload: dict) -> None:
        outcomes_path = ws / "reference" / "outcomes.jsonl"
        outcomes_path.parent.mkdir(parents=True, exist_ok=True)
        with outcomes_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")

    def test_validate_empty_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rc, out = _call(["validate-ledger", str(ws), "--json"])
            self.assertEqual(rc, 0)
            payload = json.loads(out)
            self.assertEqual(payload["summary"]["total_rows"], 0)
            self.assertEqual(payload["summary"]["complete_rows"], 0)
            self.assertEqual(payload["summary"]["incomplete_rows"], 0)
            self.assertEqual(payload["incomplete"], [])

    def test_validate_only_complete_rows_passes_strict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._seed_row(ws, {
                "report_id": "GOOD-1",
                "outcome": "pending",
                "lane": "audit-deep",
                "model_route": "kimi",
                "proof_artifact": "x/y",
                "production_path_blockers_cleared": "yes",
                "final_triager_outcome": "unknown",
            })
            rc, out = _call([
                "validate-ledger", str(ws), "--json", "--strict-linkage",
            ])
            self.assertEqual(rc, 0)
            payload = json.loads(out)
            self.assertEqual(payload["summary"]["total_rows"], 1)
            self.assertEqual(payload["summary"]["complete_rows"], 1)
            self.assertEqual(payload["summary"]["incomplete_rows"], 0)
            for missing_count in payload["summary"]["missing_per_field"].values():
                self.assertEqual(missing_count, 0)

    def test_validate_mixed_ledger_lists_incomplete_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Complete row.
            self._seed_row(ws, {
                "report_id": "OK-1",
                "outcome": "accepted",
                "lane": "source-mine",
                "model_route": "kimi",
                "proof_artifact": "x/y",
                "production_path_blockers_cleared": "yes",
                "final_triager_outcome": "accepted",
            })
            # Missing model_route + final_triager_outcome FIELD.
            self._seed_row(ws, {
                "report_id": "INC-1",
                "outcome": "pending",
                "lane": "source-mine",
                "proof_artifact": "x/y",
                "production_path_blockers_cleared": "no",
            })
            # Missing lane + proof_artifact + production_path_blockers_cleared.
            self._seed_row(ws, {
                "report_id": "INC-2",
                "outcome": "pending",
                "model_route": "minimax",
                "final_triager_outcome": "unknown",
            })

            rc, out = _call(["validate-ledger", str(ws), "--json"])
            self.assertEqual(rc, 0)
            payload = json.loads(out)
            summary = payload["summary"]
            self.assertEqual(summary["total_rows"], 3)
            self.assertEqual(summary["complete_rows"], 1)
            self.assertEqual(summary["incomplete_rows"], 2)
            self.assertEqual(summary["missing_final_triager_field"], 1)
            self.assertEqual(summary["missing_per_field"]["lane"], 1)
            self.assertEqual(summary["missing_per_field"]["model_route"], 1)
            self.assertEqual(summary["missing_per_field"]["proof_artifact"], 1)
            self.assertEqual(summary["missing_per_field"]["production_path_blockers_cleared"], 1)
            incomplete_ids = sorted(a["report_id"] for a in payload["incomplete"])
            self.assertEqual(incomplete_ids, ["INC-1", "INC-2"])

            # Strict mode flips the same data into a non-zero exit.
            buf = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = buf
            try:
                rc_strict, _ = _call([
                    "validate-ledger", str(ws), "--json", "--strict-linkage",
                ])
            finally:
                sys.stderr = old_stderr
            self.assertEqual(rc_strict, 1)
            self.assertIn("incomplete row", buf.getvalue())

    def test_validate_markdown_output_lists_required_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._seed_row(ws, {
                "report_id": "MD-1",
                "outcome": "pending",
            })
            rc, out = _call(["validate-ledger", str(ws)])
            self.assertEqual(rc, 0)
            self.assertIn("Outcome Ledger Linkage Audit", out)
            self.assertIn("| lane | 1 |", out)
            self.assertIn("| model_route | 1 |", out)
            self.assertIn("| proof_artifact | 1 |", out)
            self.assertIn("| production_path_blockers_cleared | 1 |", out)
            self.assertIn("| final_triager_outcome (field absent) | 1 |", out)
            self.assertIn("MD-1", out)

    def test_validate_writes_to_out_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._seed_row(ws, {
                "report_id": "OUT-1",
                "outcome": "pending",
                "lane": "x",
                "model_route": "y",
                "proof_artifact": "z",
                "production_path_blockers_cleared": "yes",
                "final_triager_outcome": "unknown",
            })
            out_path = Path(tmp) / "audit.md"
            rc, stdout = _call(["validate-ledger", str(ws), "--out", str(out_path)])
            self.assertEqual(rc, 0)
            self.assertEqual(stdout, "")
            self.assertTrue(out_path.exists())
            text = out_path.read_text()
            self.assertIn("Outcome Ledger Linkage Audit", text)


if __name__ == "__main__":
    unittest.main()
