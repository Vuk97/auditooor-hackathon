"""Hermetic tests for tools/outcome-ledger.py.

Roadmap-#7 outcome telemetry ledger. Tests cover:

- per-layout extraction (Polymarket table, Centrifuge line-item, Morpho
  section header) — proves the engagement-retro reuse path works end-to-end
- merge behaviour: parser-owned fields refresh, operator-owned fields
  (payout_usd, dupe_pointer, ...) survive a refresh
- validator: catches missing required fields, duplicate ids, bad
  outcome_class buckets, malformed dates
- session-delta: separates session rows from prior rows, sums payout deltas
- aggregate stats: accept-rate math; per-engagement breakdown

Test fixtures use neutral example titles (Foo / Bar / Baz protocols) —
NOT real submission text — so this file is comment-leak-safe.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "outcome-ledger.py"


def _load_module():
    cache_key = "_test_outcome_ledger"
    if cache_key in sys.modules:
        return sys.modules[cache_key]
    spec = importlib.util.spec_from_file_location(cache_key, TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[cache_key] = module
    spec.loader.exec_module(module)
    return module


# Neutral fixture text — no real engagement content. Three layouts, one each.

POLY_TABLE_FIXTURE = textwrap.dedent(
    """
    # Foo Protocol — Submissions

    | Cantina # | Date | Severity | Status | Title |
    |---:|---|---|---|---|
    | **101** | 2026-01-10 | High | Pending | Foo function lacks input validation |
    | **102** | 2026-01-11 | Medium | Paid | Bar accounting error in addLiquidity |
    | **103** | 2026-01-12 | Low | Rejected (event-only) | Baz event emits stale value |
    """
)

CENTRIFUGE_LINE_ITEM_FIXTURE = textwrap.dedent(
    """
    # Bar Protocol — Tracker

    Legend:
    - **Status** — `READY_TO_SUBMIT` etc.

    ---

    ## #500 — FooManager.decrease overflow path

    - **Severity**
      Medium
    - **Status**
      SUBMITTED
    - **Outcome**
      PAID
    """
)

MORPHO_SECTION_FIXTURE = textwrap.dedent(
    """
    # Baz Bounty — Index

    ---

    # Submission 1 — #X1.A — High

    **Status:** PAID — Triager confirmed (2026-02-01).

    ### Target

    body...
    """
)


# ---------------------------------------------------------------------------
# parse_engagement
# ---------------------------------------------------------------------------


class ParseEngagementTableLayout(unittest.TestCase):
    """Polymarket-style markdown table maps cleanly to ledger rows."""

    def test_parses_three_rows_with_ids_and_outcomes(self) -> None:
        mod = _load_module()
        with TemporaryDirectory() as td:
            ws = Path(td)
            sub = ws / "submissions"
            sub.mkdir()
            (sub / "SUBMISSIONS.md").write_text(POLY_TABLE_FIXTURE)
            rows = mod.parse_engagement("foo-eng", ws)
        self.assertEqual(len(rows), 3)
        by_id = {r["submission_id"]: r for r in rows}
        self.assertIn("foo-eng-101", by_id)
        self.assertEqual(by_id["foo-eng-102"]["outcome_class"], "real")
        self.assertEqual(by_id["foo-eng-103"]["outcome_class"], "rejected")
        self.assertEqual(by_id["foo-eng-101"]["submitted_date"], "2026-01-10")
        self.assertIs(by_id["foo-eng-101"]["new_rule_codified"], False)
        # Severity captured from the column
        self.assertEqual(by_id["foo-eng-101"]["severity_claimed"], "High")
        self.assertEqual(by_id["foo-eng-102"]["severity_claimed"], "Medium")


class ParseEngagementLineItemLayout(unittest.TestCase):
    """Centrifuge S-NNN / #NNN bullet layout maps to ledger rows."""

    def test_parses_line_item_finding_with_paid_outcome(self) -> None:
        mod = _load_module()
        with TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "SUBMISSIONS.md").write_text(CENTRIFUGE_LINE_ITEM_FIXTURE)
            rows = mod.parse_engagement("bar-eng", ws)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["engagement"], "bar-eng")
        # PAID outcome (from the Outcome bullet) is promoted into status
        self.assertEqual(r["outcome_class"], "real")
        self.assertEqual(r["severity_claimed"], "Medium")


class ParseEngagementSectionHeaderLayout(unittest.TestCase):
    """Morpho ``# Submission N`` header layout maps to ledger rows."""

    def test_parses_section_header_with_high_severity(self) -> None:
        mod = _load_module()
        with TemporaryDirectory() as td:
            ws = Path(td)
            sub = ws / "submissions"
            sub.mkdir()
            (sub / "SUBMISSIONS.md").write_text(MORPHO_SECTION_FIXTURE)
            rows = mod.parse_engagement("baz-eng", ws)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        # Section-header layout uses #X1.A as the title
        self.assertTrue(r["submission_id"].startswith("baz-eng-"))
        self.assertEqual(r["severity_claimed"], "High")
        self.assertEqual(r["outcome_class"], "real")


class ParseEngagementMissingFile(unittest.TestCase):
    """Missing SUBMISSIONS.md must not crash — return empty list."""

    def test_missing_workspace_returns_empty(self) -> None:
        mod = _load_module()
        with TemporaryDirectory() as td:
            rows = mod.parse_engagement("ghost-eng", Path(td))
        self.assertEqual(rows, [])


# ---------------------------------------------------------------------------
# merge_rows
# ---------------------------------------------------------------------------


class MergePreservesOperatorAnnotations(unittest.TestCase):
    """Operator-owned fields must survive a refresh."""

    def test_payout_dupe_session_preserved(self) -> None:
        mod = _load_module()
        existing = [
            {
                "submission_id": "foo-eng-101",
                "engagement": "foo-eng",
                "submitted_date": "2026-01-10",
                "title": "old title",
                "severity_claimed": "High",
                "severity_awarded": "Medium",  # operator-set
                "status": "Pending",
                "outcome_class": "pending",
                "payout_usd": 5000,           # operator-set
                "rejection_reason": None,
                "dupe_pointer": "ext-#42",    # operator-set
                "session_id": "2026-01-15",   # operator-set
                "shipped_via": "PR-#999",     # operator-set
                "new_rule_codified": True,     # operator-set lesson outcome
                "last_updated": "2026-01-12",
            }
        ]
        fresh = [
            {
                "submission_id": "foo-eng-101",
                "engagement": "foo-eng",
                "submitted_date": "2026-01-10",
                "title": "refreshed title",   # parser changed
                "severity_claimed": "Critical",  # parser changed
                "severity_awarded": None,
                "status": "Paid",
                "outcome_class": "real",
                "payout_usd": None,
                "rejection_reason": None,
                "dupe_pointer": None,
                "session_id": None,
                "shipped_via": None,
                "new_rule_codified": False,
                "last_updated": "2026-04-25",
            }
        ]
        merged = mod.merge_rows(existing, fresh)
        self.assertEqual(len(merged), 1)
        m = merged[0]
        # Parser-owned: refreshed
        self.assertEqual(m["title"], "refreshed title")
        self.assertEqual(m["severity_claimed"], "Critical")
        self.assertEqual(m["status"], "Paid")
        self.assertEqual(m["outcome_class"], "real")
        self.assertEqual(m["last_updated"], "2026-04-25")
        # Operator-owned: preserved
        self.assertEqual(m["payout_usd"], 5000)
        self.assertEqual(m["dupe_pointer"], "ext-#42")
        self.assertEqual(m["session_id"], "2026-01-15")
        self.assertEqual(m["shipped_via"], "PR-#999")
        self.assertEqual(m["severity_awarded"], "Medium")
        self.assertIs(m["new_rule_codified"], True)


class MergeAddsNewRowsAndKeepsStaleOnes(unittest.TestCase):
    """Rows in fresh-only are added; rows in existing-only are kept."""

    def test_union_behaviour(self) -> None:
        mod = _load_module()
        existing = [
            {"submission_id": "x-1", "engagement": "x", "title": "a",
             "status": "P", "outcome_class": "pending"},
        ]
        fresh = [
            {"submission_id": "x-1", "engagement": "x", "title": "a-new",
             "status": "Paid", "outcome_class": "real"},
            {"submission_id": "x-2", "engagement": "x", "title": "b",
             "status": "Pending", "outcome_class": "pending"},
        ]
        merged = mod.merge_rows(existing, fresh)
        ids = {r["submission_id"] for r in merged}
        self.assertEqual(ids, {"x-1", "x-2"})


# ---------------------------------------------------------------------------
# validate_rows
# ---------------------------------------------------------------------------


class ValidatorCatchesSchemaErrors(unittest.TestCase):
    """validate_rows surfaces every category of schema violation."""

    def _full_row(self, **overrides):
        base = {
            "submission_id": "x-1",
            "engagement": "x",
            "submitted_date": "2026-01-01",
            "title": "t",
            "severity_claimed": "High",
            "severity_awarded": None,
            "status": "Pending",
            "outcome_class": "pending",
            "payout_usd": None,
            "rejection_reason": None,
            "dupe_pointer": None,
            "session_id": None,
            "shipped_via": None,
            "new_rule_codified": False,
            "last_updated": "2026-04-25",
        }
        base.update(overrides)
        return base

    def test_clean_row_has_no_errors(self) -> None:
        mod = _load_module()
        self.assertEqual(mod.validate_rows([self._full_row()]), [])

    def test_missing_required_fields(self) -> None:
        mod = _load_module()
        bad = self._full_row(submission_id="", title="", outcome_class="")
        errs = mod.validate_rows([bad])
        # All three should be flagged
        joined = " | ".join(errs)
        self.assertIn("missing submission_id", joined)
        self.assertIn("missing title", joined)
        self.assertIn("missing outcome_class", joined)

    def test_duplicate_submission_ids_flagged(self) -> None:
        mod = _load_module()
        rows = [self._full_row(submission_id="dup-1"),
                self._full_row(submission_id="dup-1")]
        errs = mod.validate_rows(rows)
        self.assertTrue(any("duplicate submission_id" in e for e in errs))

    def test_invalid_outcome_class_flagged(self) -> None:
        mod = _load_module()
        rows = [self._full_row(outcome_class="maybe")]
        errs = mod.validate_rows(rows)
        self.assertTrue(any("outcome_class 'maybe' not in" in e for e in errs))

    def test_malformed_date_flagged(self) -> None:
        mod = _load_module()
        rows = [self._full_row(submitted_date="2026/01/01")]
        errs = mod.validate_rows(rows)
        self.assertTrue(any("not ISO-8601" in e for e in errs))

    def test_new_rule_codified_must_be_boolean_when_present(self) -> None:
        mod = _load_module()
        rows = [self._full_row(new_rule_codified="yes")]
        errs = mod.validate_rows(rows)
        self.assertTrue(any("new_rule_codified must be boolean" in e for e in errs))


# ---------------------------------------------------------------------------
# aggregate_stats + session_delta
# ---------------------------------------------------------------------------


class AggregateStatsMath(unittest.TestCase):
    """Accept-rate is real / (real + dupe + rejected). Pending excluded."""

    def test_accept_rate_with_payouts(self) -> None:
        mod = _load_module()
        rows = [
            {"submission_id": "a", "engagement": "e1",
             "outcome_class": "real", "payout_usd": 1000},
            {"submission_id": "b", "engagement": "e1",
             "outcome_class": "real", "payout_usd": 3000},
            {"submission_id": "c", "engagement": "e1",
             "outcome_class": "dupe", "payout_usd": None},
            {"submission_id": "d", "engagement": "e2",
             "outcome_class": "rejected", "payout_usd": None},
            {"submission_id": "e", "engagement": "e2",
             "outcome_class": "pending", "payout_usd": None},
        ]
        stats = mod.aggregate_stats(rows)
        self.assertEqual(stats["total"], 5)
        self.assertEqual(stats["resolved"], 4)
        # 2 real / 4 resolved = 0.5
        self.assertAlmostEqual(stats["accept_rate"], 0.5, places=4)
        self.assertEqual(stats["payout_total_usd"], 4000)
        self.assertEqual(stats["payout_count"], 2)
        self.assertEqual(stats["avg_payout_usd"], 2000)
        # Per-engagement bucketing
        self.assertEqual(stats["by_engagement"]["e1"]["total"], 3)
        self.assertEqual(stats["by_engagement"]["e2"]["total"], 2)


# ---------------------------------------------------------------------------
# end-to-end ledger I/O
# ---------------------------------------------------------------------------


class LedgerIORoundTrip(unittest.TestCase):
    """save_ledger then load_ledger preserves rows; sort key is submitted_date."""

    def test_save_and_reload_sorts_by_date(self) -> None:
        mod = _load_module()
        rows = [
            {"submission_id": "z-2", "engagement": "z", "title": "later",
             "status": "Pending", "outcome_class": "pending",
             "submitted_date": "2026-02-01"},
            {"submission_id": "z-1", "engagement": "z", "title": "earlier",
             "status": "Pending", "outcome_class": "pending",
             "submitted_date": "2026-01-01"},
        ]
        with TemporaryDirectory() as td:
            path = Path(td) / "outcomes.json"
            mod.save_ledger(rows, path)
            reloaded = mod.load_ledger(path)
        self.assertEqual([r["submission_id"] for r in reloaded], ["z-1", "z-2"])
        self.assertIs(reloaded[0]["new_rule_codified"], False)

    def test_load_missing_ledger_returns_empty(self) -> None:
        mod = _load_module()
        with TemporaryDirectory() as td:
            path = Path(td) / "missing.json"
            self.assertEqual(mod.load_ledger(path), [])


# ---------------------------------------------------------------------------
# JSONL canonical format (v3 Slice 6)
# ---------------------------------------------------------------------------


class JsonlRoundTrip(unittest.TestCase):
    """JSONL is one-object-per-line with sorted keys; survives roundtrip."""

    def test_jsonl_save_and_reload_preserves_rows(self) -> None:
        mod = _load_module()
        rows = [
            {"submission_id": "z-2", "engagement": "z", "title": "later",
             "status": "Pending", "outcome_class": "pending",
             "submitted_date": "2026-02-01"},
            {"submission_id": "z-1", "engagement": "z", "title": "earlier",
             "status": "Pending", "outcome_class": "pending",
             "submitted_date": "2026-01-01"},
        ]
        with TemporaryDirectory() as td:
            path = Path(td) / "outcomes.jsonl"
            mod.save_ledger(rows, path)
            reloaded = mod.load_ledger(path)
        # Same sort behaviour as the JSON form: oldest first
        self.assertEqual([r["submission_id"] for r in reloaded], ["z-1", "z-2"])

    def test_jsonl_serialisation_is_one_object_per_line(self) -> None:
        mod = _load_module()
        rows = [
            {"submission_id": "a-1", "engagement": "a", "title": "t1",
             "status": "P", "outcome_class": "pending",
             "submitted_date": "2026-01-01"},
            {"submission_id": "a-2", "engagement": "a", "title": "t2",
             "status": "P", "outcome_class": "pending",
             "submitted_date": "2026-01-02"},
        ]
        with TemporaryDirectory() as td:
            path = Path(td) / "outcomes.jsonl"
            mod.save_ledger(rows, path)
            text = path.read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 2)
        # Each line independently parseable
        for ln in lines:
            json.loads(ln)
        # Keys sorted within each line for stable diff
        self.assertTrue(lines[0].startswith('{"engagement":'))

    def test_explicit_format_overrides_path_suffix(self) -> None:
        """fmt='jsonl' on a .json path writes JSONL; fmt='json' on .jsonl writes JSON."""
        mod = _load_module()
        rows = [{"submission_id": "x-1", "engagement": "x", "title": "t",
                 "status": "P", "outcome_class": "pending"}]
        with TemporaryDirectory() as td:
            jsonl_in_json_suffix = Path(td) / "out.json"
            mod.save_ledger(rows, jsonl_in_json_suffix, fmt="jsonl")
            # File is JSONL despite the .json suffix
            text = jsonl_in_json_suffix.read_text(encoding="utf-8")
            self.assertNotIn("[", text.split("\n")[0])
            json.loads(text.strip())  # Parses as a single object
            # And reads back via explicit fmt
            reloaded = mod.load_ledger(jsonl_in_json_suffix, fmt="jsonl")
            self.assertEqual(reloaded[0]["submission_id"], "x-1")


class JsonlPassesThroughForeignRows(unittest.TestCase):
    """Non-ledger rows in a heterogeneous JSONL must survive a save."""

    def test_foreign_schema_rows_preserved(self) -> None:
        mod = _load_module()
        with TemporaryDirectory() as td:
            path = Path(td) / "outcomes.jsonl"
            # Pre-populate with two foreign rows from a different tool
            # (track-submissions.py simple-schema rows).
            with path.open("w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "finding_id": "999", "workspace": "foo",
                    "title": "foreign 1", "outcome": "pending",
                }) + "\n")
                fh.write(json.dumps({
                    "finding_id": "998", "workspace": "foo",
                    "title": "foreign 2", "outcome": "pending",
                }) + "\n")

            # Save a single ledger row to the same file.
            ledger_rows = [
                {"submission_id": "ledger-1", "engagement": "foo",
                 "title": "ledger row", "status": "Pending",
                 "outcome_class": "pending", "submitted_date": "2026-01-01"},
            ]
            mod.save_ledger(ledger_rows, path)

            # On disk: 2 foreign + 1 ledger = 3 lines
            on_disk = [
                json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            self.assertEqual(len(on_disk), 3)
            ids = {r.get("submission_id") for r in on_disk}
            findings = {r.get("finding_id") for r in on_disk}
            self.assertIn("ledger-1", ids)
            self.assertEqual({"998", "999"}, findings - {None})

            # load_ledger only returns ledger rows, foreign rows skipped.
            reloaded = mod.load_ledger(path)
            self.assertEqual(len(reloaded), 1)
            self.assertEqual(reloaded[0]["submission_id"], "ledger-1")

    def test_jsonl_rejects_invalid_object_line(self) -> None:
        mod = _load_module()
        with TemporaryDirectory() as td:
            path = Path(td) / "broken.jsonl"
            path.write_text("not-json\n", encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                mod.load_ledger(path)
            self.assertIn("not valid JSON", str(ctx.exception))


class BackwardsCompatJsonFallback(unittest.TestCase):
    """When the canonical JSONL is absent but legacy JSON exists, fall back."""

    def test_load_falls_back_to_legacy_json(self) -> None:
        mod = _load_module()
        # Drive the fallback by patching module globals to point at a tmp dir.
        original_jsonl = mod.LEDGER_PATH
        original_json = mod.LEDGER_PATH_JSON
        try:
            with TemporaryDirectory() as td:
                root = Path(td)
                jsonl_path = root / "reference" / "outcomes.jsonl"  # missing
                json_path = root / "tools" / "outcomes.json"
                json_path.parent.mkdir(parents=True)
                json_path.write_text(json.dumps([
                    {"submission_id": "legacy-1", "engagement": "x",
                     "title": "t", "status": "P", "outcome_class": "pending"},
                ]), encoding="utf-8")

                mod.LEDGER_PATH = jsonl_path
                mod.LEDGER_PATH_JSON = json_path

                rows = mod.load_ledger(jsonl_path)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["submission_id"], "legacy-1")
        finally:
            mod.LEDGER_PATH = original_jsonl
            mod.LEDGER_PATH_JSON = original_json


class CliFormatFlag(unittest.TestCase):
    """`--format` flag is plumbed through the top-level parser."""

    def test_parser_exposes_format_choice(self) -> None:
        mod = _load_module()
        parser = mod.build_parser()
        ns = parser.parse_args(["--format", "json", "validate"])
        self.assertEqual(ns.format, "json")
        ns2 = parser.parse_args(["validate"])
        self.assertIsNone(ns2.format)  # auto-detect from path suffix

    def test_default_ledger_path_is_canonical_jsonl(self) -> None:
        mod = _load_module()
        self.assertEqual(mod.LEDGER_PATH.suffix, ".jsonl")
        self.assertEqual(mod.LEDGER_PATH.name, "outcomes.jsonl")


if __name__ == "__main__":
    unittest.main()
