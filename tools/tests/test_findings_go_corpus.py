"""Regression tests for reference/findings_go.jsonl + tools/findings-go-corpus.py.

Stdlib-only. Asserts:
  1. The corpus file is parseable JSONL.
  2. Every row has the required fields.
  3. No row has language != "go".
  4. The two Spark back-feed rows reference github.com/buildonspark/spark@e8311d2.

Per Worker-DD Phase A spec in
docs/spark-engagement/CODEX_SPARK_HANDOFF_PLAN_2026-05-06.md.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import unittest


REPO = pathlib.Path(__file__).resolve().parents[2]
CORPUS = REPO / "reference" / "findings_go.jsonl"
TOOL = REPO / "tools" / "findings-go-corpus.py"

REQUIRED_FIELDS = (
    "finding_id",
    "protocol",
    "language",
    "impact_tier",
    "bug_class",
    "github_ref",
    "summary",
    "provenance",
)

SPARK_REF = "github.com/buildonspark/spark@e8311d2"
SPARK_BACKFEED_IDS = {
    "spark-lead1-2026-05-06",
    "spark-leadH-D-2026-05-06",
}


def _load_tool():
    name = "_test_findings_go_corpus_tool"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _read_rows() -> list[dict]:
    rows: list[dict] = []
    with CORPUS.open("r", encoding="utf-8") as fh:
        for raw in fh:
            stripped = raw.strip()
            if not stripped:
                continue
            rows.append(json.loads(stripped))
    return rows


class FindingsGoCorpusTests(unittest.TestCase):
    """Worker-DD Phase A regression suite."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.assertTrue_file = CORPUS.exists()
        if not CORPUS.exists():
            raise unittest.SkipTest(f"corpus not present: {CORPUS}")

    def test_1_corpus_is_parseable_jsonl(self) -> None:
        """Test 1: every non-empty line of the corpus parses as JSON."""
        # Reading by line and parsing is the strict JSONL definition.
        with CORPUS.open("r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    json.loads(stripped)
                except json.JSONDecodeError as exc:
                    self.fail(
                        f"line {lineno} of {CORPUS} is not valid JSON: {exc}"
                    )
        # Bonus: tool agrees with us via its own validate_file path.
        tool = _load_tool()
        rows, errors = tool.validate_file(CORPUS)
        self.assertGreater(rows, 0, "corpus must contain at least one row")
        # We only assert JSON-parse here; field-level checks in test 2.

    def test_2_each_row_has_required_fields(self) -> None:
        """Test 2: each row has all REQUIRED_FIELDS."""
        rows = _read_rows()
        self.assertGreater(len(rows), 0, "corpus is empty")
        for idx, row in enumerate(rows, start=1):
            for f in REQUIRED_FIELDS:
                self.assertIn(
                    f, row,
                    f"row {idx} ({row.get('finding_id', '?')}) missing '{f}'",
                )
                v = row[f]
                self.assertTrue(
                    v not in (None, "", []),
                    f"row {idx} ({row.get('finding_id','?')}) field '{f}' is empty",
                )

    def test_3_no_row_has_non_go_language(self) -> None:
        """Test 3: language must be exactly 'go' on every row."""
        rows = _read_rows()
        offenders = [
            (idx, row.get("finding_id"), row.get("language"))
            for idx, row in enumerate(rows, start=1)
            if row.get("language") != "go"
        ]
        self.assertEqual(
            offenders, [],
            f"non-go rows present in Go-scoped corpus: {offenders}",
        )

    def test_4_spark_backfeed_rows_have_correct_github_ref(self) -> None:
        """Test 4: Spark back-feed rows reference buildonspark/spark@e8311d2."""
        rows = _read_rows()
        spark_rows = [
            r for r in rows if r.get("finding_id") in SPARK_BACKFEED_IDS
        ]
        self.assertEqual(
            len(spark_rows), len(SPARK_BACKFEED_IDS),
            f"expected both Spark back-feed rows {SPARK_BACKFEED_IDS}, "
            f"found {[r.get('finding_id') for r in spark_rows]}",
        )
        for r in spark_rows:
            self.assertEqual(
                r["github_ref"], SPARK_REF,
                f"spark back-feed row {r.get('finding_id')!r} has "
                f"github_ref={r.get('github_ref')!r}, expected {SPARK_REF!r}",
            )
            self.assertEqual(
                r["language"], "go",
                f"spark back-feed row {r.get('finding_id')!r} must be language=go",
            )


if __name__ == "__main__":
    unittest.main()
