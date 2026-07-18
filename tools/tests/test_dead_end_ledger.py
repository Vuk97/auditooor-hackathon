"""Guard: dead-end-ledger - shared drop-class classifier + per-unit queryable ledger.

THE FIX UNDER TEST: there was no shared classifier turning a free-text drop reason
into a canonical drop_class, and no unified queryable ledger of ruled-out units, so
the learning loop could not answer "how many privileged-only drops this engagement?"
without re-reading every sidecar by hand.

Covers:
  1. classify() keyword rules (the two named in the lane spec + the catch-all).
  2. parse_rule_codes() pulls cited R-codes.
  3. dead-end-ledger.py over a tmp ws with 3 jsonl drop rows -> 3 ledger rows,
     idempotent on re-run, and --report renders a drop_class histogram table.
"""
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_PATH = REPO_ROOT / "tools" / "lib" / "dead_end_classify.py"
LEDGER_PATH = REPO_ROOT / "tools" / "dead-end-ledger.py"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


classify_mod = _load_module("dead_end_classify_test", LIB_PATH)
ledger_mod = _load_module("dead_end_ledger_test", LEDGER_PATH)


class TestClassify(unittest.TestCase):
    def test_upstream_unmodified(self):
        self.assertEqual(
            classify_mod.classify("unmodified upstream go-ethereum", ""),
            "oos-unmodified-upstream",
        )

    def test_privileged_only(self):
        self.assertEqual(
            classify_mod.classify("onlyOwner gate; unprivileged cannot reach", ""),
            "privileged-only-R24",
        )

    def test_generic_dos(self):
        self.assertEqual(
            classify_mod.classify("generic DoS, rate limit exhaustion", ""),
            "generic-dos-R35",
        )

    def test_designed_as_intended(self):
        self.assertEqual(
            classify_mod.classify("acknowledged by team, by design", ""),
            "designed-as-intended-R47",
        )

    def test_view_only(self):
        self.assertEqual(
            classify_mod.classify("pure function, no state change", ""),
            "view-only",
        )

    def test_evm_cannot_spoof(self):
        self.assertEqual(
            classify_mod.classify("attacker cannot spoof msg.sender (EVM-enforced)", ""),
            "evm-cannot-spoof-msgsender",
        )

    def test_catch_all(self):
        self.assertEqual(
            classify_mod.classify("some bespoke reason with no keyword", ""),
            "ruled-out-other",
        )

    def test_empty_is_catch_all_not_crash(self):
        self.assertEqual(classify_mod.classify("", ""), "ruled-out-other")
        self.assertEqual(classify_mod.classify(None, None), "ruled-out-other")

    def test_excerpt_contributes(self):
        # reason has no keyword but code excerpt reveals onlyOwner
        self.assertEqual(
            classify_mod.classify("ruled out", "function f() onlyOwner {"),
            "privileged-only-R24",
        )

    def test_parse_rule_codes(self):
        codes = classify_mod.parse_rule_codes("see R24 and R-35 acknowledged", "")
        self.assertIn("R24", codes)
        self.assertIn("R35", codes)
        # alias: "acknowledged" -> R47
        self.assertIn("R47", codes)

    def test_parse_rule_codes_empty(self):
        self.assertEqual(classify_mod.parse_rule_codes("no codes here", ""), [])


class TestLedger(unittest.TestCase):
    def _make_ws(self, tmp: Path) -> Path:
        ws = tmp / "ws"
        aud = ws / ".auditooor"
        sidecar_dir = aud / "hunt_findings_sidecars"
        probe_dir = aud / "depth_probes"
        sidecar_dir.mkdir(parents=True)
        probe_dir.mkdir(parents=True)

        # Row 1: hunt sidecar REJECTED (privileged-only).
        (sidecar_dir / "batch_0000_verdicts.jsonl").write_text(
            json.dumps({
                "unit_id": "Foo.setAdmin",
                "file_line": "src/Foo.sol:10",
                "verdict": "REJECTED",
                "rebuttal_or_guard": "onlyOwner gate; unprivileged cannot reach",
                "code_excerpt": "function setAdmin() onlyOwner {",
            }) + "\n",
            encoding="utf-8",
        )
        # Row 2: depth-probe negative-space drop (upstream unmodified).
        (probe_dir / "batch_000.jsonl").write_text(
            json.dumps({
                "guard_id": "NS-abc123",
                "file_line": "src/Bar.sol:42",
                "gap_found": False,
                "why_no_gap_or_exploit": "unmodified upstream go-ethereum library, R24 noted",
                "probe_source": "depth-probe-runner",
            }) + "\n",
            encoding="utf-8",
        )
        # Row 3: negative_space_gaps.jsonl explicit drop (generic dos).
        (aud / "negative_space_gaps.jsonl").write_text(
            json.dumps({
                "guard_id": "NS-def456",
                "file_line": "src/Baz.sol:88",
                "gap_found": False,
                "disposition": "drop",
                "ruled_out_reason": "generic DoS / rate-limit exhaustion, R35",
                "probed": True,
            }) + "\n",
            encoding="utf-8",
        )
        return ws

    def test_three_drop_rows_three_ledger_rows(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._make_ws(Path(td))
            rc = ledger_mod.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0)
            out = ws / ".auditooor" / "dead_end_ledger.jsonl"
            self.assertTrue(out.exists())
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows), 3)

            by_class = {r["drop_class"] for r in rows}
            self.assertIn("privileged-only-R24", by_class)
            self.assertIn("oos-unmodified-upstream", by_class)
            self.assertIn("generic-dos-R35", by_class)

            # schema + required fields present on every row
            for r in rows:
                self.assertEqual(r["schema"], "auditooor.known_dead_end.v1")
                for key in ("dead_end_id", "file_line", "unit_id", "verdict",
                            "drop_class", "rule_cited", "reason", "decided_by"):
                    self.assertIn(key, r)

            # R-codes parsed
            codes = sorted({c for r in rows for c in r["rule_cited"]})
            self.assertIn("R24", codes)
            self.assertIn("R35", codes)

    def test_idempotent_on_rerun(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._make_ws(Path(td))
            ledger_mod.main(["--workspace", str(ws)])
            ledger_mod.main(["--workspace", str(ws)])  # second run
            out = ws / ".auditooor" / "dead_end_ledger.jsonl"
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows), 3)  # no duplicate rows
            ids = [r["dead_end_id"] for r in rows]
            self.assertEqual(len(ids), len(set(ids)))

    def test_report_renders_histogram(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._make_ws(Path(td))
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = ledger_mod.main(["--workspace", str(ws), "--report"])
            self.assertEqual(rc, 0)
            report = buf.getvalue()
            self.assertIn("drop_class", report)
            self.assertIn("count", report)
            self.assertIn("privileged-only-R24", report)
            self.assertIn("oos-unmodified-upstream", report)
            self.assertIn("generic-dos-R35", report)
            self.assertIn("Total ruled-out units: 3", report)

    def test_plausible_verdict_not_a_dead_end(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            sidecar = ws / ".auditooor" / "hunt_findings_sidecars"
            sidecar.mkdir(parents=True)
            (sidecar / "v.jsonl").write_text(
                json.dumps({
                    "unit_id": "Foo.bar",
                    "file_line": "src/Foo.sol:1",
                    "verdict": "PLAUSIBLE",
                    "attacker_trace": "live lead",
                }) + "\n",
                encoding="utf-8",
            )
            ledger_mod.main(["--workspace", str(ws)])
            out = ws / ".auditooor" / "dead_end_ledger.jsonl"
            rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows), 0)


if __name__ == "__main__":
    unittest.main()
