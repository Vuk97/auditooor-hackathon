"""hunt-followup-lead-scanner.py + followup-lead-completeness-check.py
(SEI 2026-07-05). Generic, language-agnostic closer for the "agent flagged a
maybe/follow-up lead but nothing dispatched against it" gap.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


scanner = _load("hflscanner", _ROOT / "hunt-followup-lead-scanner.py")
gate = _load("hflgate", _ROOT / "followup-lead-completeness-check.py")


def _ws(sidecars):
    d = Path(tempfile.mkdtemp())
    sc_dir = d / ".auditooor" / "hunt_findings_sidecars"
    sc_dir.mkdir(parents=True)
    for name, outer in sidecars.items():
        (sc_dir / name).write_text(json.dumps(outer), encoding="utf-8")
    return d


def _sidecar(applies="no", notes="", task_id="t1"):
    return {
        "task_id": task_id,
        "result": json.dumps({
            "applies_to_target": applies,
            "file_line": "core/foo.go:10",
            "notes": notes,
        }),
    }


class ScannerTest(unittest.TestCase):
    def test_no_sidecar_dir_is_advisory_empty(self):
        d = Path(tempfile.mkdtemp())
        res = scanner.scan(d)
        self.assertEqual(res["total_flagged"], 0)
        self.assertIn("note", res)

    def test_clean_negative_verdict_not_flagged(self):
        ws = _ws({
            "hunt__foo.go__Bar__abc123__L10__I-x.json": _sidecar(applies="no", notes="clean rule-out"),
        })
        res = scanner.scan(ws)
        self.assertEqual(res["total_flagged"], 0)

    def test_maybe_verdict_flagged_open(self):
        ws = _ws({
            "hunt__foo.go__Bar__abc123__L10__I-x.json": _sidecar(applies="maybe", notes="not fully exhausted"),
        })
        res = scanner.scan(ws)
        self.assertEqual(res["total_flagged"], 1)
        self.assertEqual(res["open"], 1)
        self.assertEqual(res["leads"][0]["reason"], "maybe-verdict")

    def test_fallback_key_does_not_collapse_distinct_leads_same_file(self):
        # Non-conforming filenames (real SEI corpus has these) must not fall
        # back to (file, file) - that would silently merge two distinct
        # maybe-verdicts in the same file into one lead.
        ws = _ws({
            "perfn_mimo_sei_00001.json": {
                "task_id": "t1",
                "result": json.dumps({"applies_to_target": "maybe", "file_line": "core/foo.go:10", "notes": "a"}),
            },
            "perfn_mimo_sei_00002.json": {
                "task_id": "t2",
                "result": json.dumps({"applies_to_target": "maybe", "file_line": "core/foo.go:99", "notes": "b"}),
            },
        })
        res = scanner.scan(ws)
        self.assertEqual(res["total_flagged"], 2)

    def test_notes_followup_language_flagged_open(self):
        ws = _ws({
            "hunt__foo.go__Bar__abc123__L10__I-x.json": _sidecar(
                applies="no", notes="worth a dedicated hunt pass on the import side"),
        })
        res = scanner.scan(ws)
        self.assertEqual(res["total_flagged"], 1)
        self.assertEqual(res["leads"][0]["reason"], "notes-flagged-followup")

    def test_flat_schema_followup_sidecar_resolves_lead(self):
        # Real-world bug (SEI 2026-07-05): follow-up agents wrote a flat
        # unit/file/verdict/reasoning schema with NO "result" wrapper at all,
        # instead of the standard hunt sidecar shape - the resolution check
        # must not silently skip these via the early `if not result: continue`.
        ws = _ws({
            "hunt__foo.go__Bar__abc111__L10__I-x.json": _sidecar(applies="maybe", notes="a"),
        })
        flat = ws / ".auditooor" / "hunt_findings_sidecars" / "followup_lead_0001_Bar.json"
        flat.write_text(json.dumps({
            "unit": "followup_lead_0001_Bar",
            "file": "foo.go", "lines": "10-20", "verdict": "NEGATIVE",
            "reasoning": "Re-resolved: Bar is a pure accessor, no gap.",
        }), encoding="utf-8")
        res = scanner.scan(ws)
        self.assertEqual(res["total_flagged"], 1)
        self.assertEqual(res["open"], 0)
        self.assertEqual(res["resolved"], 1)

    def test_multi_lead_combined_followup_sidecar_resolves_multiple(self):
        ws = _ws({
            "hunt__foo.go__Bar__abc111__L10__I-x.json": _sidecar(applies="maybe", notes="a"),
            "hunt__baz.go__Qux__abc222__L20__I-y.json": _sidecar(applies="maybe", notes="b"),
        })
        combined = ws / ".auditooor" / "hunt_findings_sidecars" / "followup_group_resolutions.json"
        combined.write_text(json.dumps({
            "resolutions": [
                {"unit": "foo.go::Bar", "verdict": "NEGATIVE"},
                {"unit": "baz.go::Qux", "verdict": "NEGATIVE"},
            ]
        }), encoding="utf-8")
        res = scanner.scan(ws)
        self.assertEqual(res["total_flagged"], 2)
        self.assertEqual(res["open"], 0)
        self.assertEqual(res["resolved"], 2)

    def test_dedup_same_file_function_across_batches(self):
        ws = _ws({
            "hunt__foo.go__Bar__abc111__L10__I-x.json": _sidecar(applies="maybe", notes="a"),
            "hunt__foo.go__Bar__abc222__L10__I-y.json": _sidecar(applies="maybe", notes="b"),
        })
        res = scanner.scan(ws)
        self.assertEqual(res["total_flagged"], 1)

    def test_followup_dispatch_sidecar_resolves_lead(self):
        ws = _ws({
            "hunt__foo.go__Bar__abc111__L10__I-x.json": _sidecar(applies="maybe", notes="a"),
            "hunt__foo.go__Bar__followup__L10__I-x.json": _sidecar(applies="no", notes="resolved clean"),
        })
        res = scanner.scan(ws)
        self.assertEqual(res["total_flagged"], 1)
        self.assertEqual(res["open"], 0)
        self.assertEqual(res["resolved"], 1)

    def test_emit_writes_leads_and_tasks(self):
        ws = _ws({
            "hunt__foo.go__Bar__abc123__L10__I-x.json": _sidecar(applies="maybe", notes="not fully exhausted"),
        })
        rc = scanner.main(["--workspace", str(ws), "--emit"])
        self.assertEqual(rc, 0)
        leads_path = ws / ".auditooor" / "followup_leads.json"
        tasks_path = ws / ".auditooor" / "followup_lead_hunt_tasks.jsonl"
        self.assertTrue(leads_path.is_file())
        self.assertTrue(tasks_path.is_file())
        tasks = [json.loads(l) for l in tasks_path.read_text().splitlines() if l.strip()]
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["schema"], "auditooor.followup_lead_hunt_task.v1")


class GateTest(unittest.TestCase):
    def test_no_scan_yet_is_warn_not_fail(self):
        d = Path(tempfile.mkdtemp())
        res = gate.evaluate(d)
        self.assertEqual(res["verdict"], "warn-followup-leads-not-scanned")

    def test_zero_open_leads_passes(self):
        ws = _ws({})
        scanner.main(["--workspace", str(ws), "--emit"])
        res = gate.evaluate(ws)
        self.assertEqual(res["verdict"], "pass-followup-leads-resolved")

    def test_open_leads_fail_under_strict(self):
        ws = _ws({
            "hunt__foo.go__Bar__abc123__L10__I-x.json": _sidecar(applies="maybe", notes="x"),
        })
        scanner.main(["--workspace", str(ws), "--emit"])
        res = gate.evaluate(ws)
        self.assertEqual(res["verdict"], "fail-followup-leads-undispatched")
        rc = gate.main(["--workspace", str(ws), "--strict"])
        self.assertEqual(rc, 1)

    def test_open_leads_warn_only_without_strict(self):
        ws = _ws({
            "hunt__foo.go__Bar__abc123__L10__I-x.json": _sidecar(applies="maybe", notes="x"),
        })
        scanner.main(["--workspace", str(ws), "--emit"])
        rc = gate.main(["--workspace", str(ws)])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
