"""Regression tests for reference/findings_solidity.jsonl + tools/findings-solidity-corpus.py.

Stdlib-only. Asserts:
  1. The corpus file is parseable JSONL.
  2. Every row has the required fields.
  3. No row has language != "solidity".
  4. The three Centrifuge mining rows reference centrifuge/protocol@68ac68ba.

Per Worker-RR Loop 9 bootstrap spec in
docs/next-loop/findings_solidity_corpus_bootstrap_2026-05-07.md.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import unittest


REPO = pathlib.Path(__file__).resolve().parents[2]
CORPUS = REPO / "reference" / "findings_solidity.jsonl"
TOOL = REPO / "tools" / "findings-solidity-corpus.py"

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

CENTRIFUGE_REF = "centrifuge/protocol@68ac68ba"
CENTRIFUGE_MINING_IDS = {
    "centrifuge-v3-sol-eip150-64-63-2026-05-07",
    "centrifuge-v3-sol-dispatcher-unreachable-2026-05-07",
    "centrifuge-v3-sol-gas-limit-cap-2026-05-07",
}


def _load_tool():
    name = "_test_findings_solidity_corpus_tool"
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


class FindingsSolidityCorpusTests(unittest.TestCase):
    """Worker-RR Loop 9 bootstrap regression suite."""

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

    def test_3_no_row_has_non_solidity_language(self) -> None:
        """Test 3: language must be exactly 'solidity' on every row."""
        rows = _read_rows()
        offenders = [
            (idx, row.get("finding_id"), row.get("language"))
            for idx, row in enumerate(rows, start=1)
            if row.get("language") != "solidity"
        ]
        self.assertEqual(
            offenders, [],
            f"non-solidity rows present in Solidity-scoped corpus: {offenders}",
        )

    def test_4_centrifuge_mining_rows_have_correct_github_ref(self) -> None:
        """Test 4: Centrifuge mining rows reference centrifuge/protocol@68ac68ba."""
        rows = _read_rows()
        centrifuge_rows = [
            r for r in rows if r.get("finding_id") in CENTRIFUGE_MINING_IDS
        ]
        self.assertEqual(
            len(centrifuge_rows), len(CENTRIFUGE_MINING_IDS),
            f"expected all Centrifuge mining rows {CENTRIFUGE_MINING_IDS}, "
            f"found {[r.get('finding_id') for r in centrifuge_rows]}",
        )
        for r in centrifuge_rows:
            self.assertEqual(
                r["github_ref"], CENTRIFUGE_REF,
                f"centrifuge mining row {r.get('finding_id')!r} has "
                f"github_ref={r.get('github_ref')!r}, expected {CENTRIFUGE_REF!r}",
            )
            self.assertEqual(
                r["language"], "solidity",
                f"centrifuge mining row {r.get('finding_id')!r} must be language=solidity",
            )


if __name__ == "__main__":
    unittest.main()
