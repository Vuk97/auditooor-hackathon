"""Regression for tools/workspace-originality-scan.py - the generic L37
originality producer. Verifies: (a) a workspace with prior_audits + candidate
terms yields a NON-VACUOUS report that satisfies check_originality; (b) a
workspace with no prior-disclosure corpus and no candidate terms yields an
HONEST hollow report (no fake comparison surface). Generic fix anchor:
audit-deep produced no originality artifact, so the L37 gate hard-failed on
every workspace (monero-oxide fail-no-originality).
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "workspace-originality-scan.py"


def _load():
    spec = importlib.util.spec_from_file_location("wos", _TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


WOS = _load()


class TestWorkspaceOriginalityScan(unittest.TestCase):
    def _ws(self, td):
        ws = Path(td)
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        return ws

    def test_nonvacuous_with_prior_audits_and_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._ws(td)
            (ws / ".auditooor" / "exploit_queue.json").write_text(json.dumps({
                "queue": [
                    {"slug": "bulletproofs_generator_recompute_soundness"},
                    {"slug": "clsag_challenge_binding_omission"},
                ]
            }), encoding="utf-8")
            pa = ws / "prior_audits"
            pa.mkdir()
            (pa / "Audit.txt").write_text(
                "The bulletproofs generator recomputation was reviewed. "
                "CLSAG challenge binding is correct.", encoding="utf-8")
            payload = WOS.scan(ws, None, 25)
            self.assertEqual(payload["status"], "ok")
            self.assertGreater(payload["counts"]["keyword_count"], 0)
            self.assertGreater(payload["counts"]["local_files_scanned"], 0)
            self.assertGreaterEqual(payload["candidates"], 2)
            # non-vacuous: keyword_count>0 AND corpus_compared>0
            self.assertTrue(
                payload["counts"]["keyword_count"] > 0
                and payload["corpus_compared"] > 0
            )

    def test_hollow_when_nothing_to_compare(self):
        # no prior_audits, no exploit_queue, no SCOPE -> honest hollow report
        with tempfile.TemporaryDirectory() as td:
            ws = self._ws(td)
            payload = WOS.scan(ws, None, 25)
            self.assertEqual(payload["counts"]["local_files_scanned"], 0)
            # keyword_count may be 0 (no candidate terms) -> hollow, NOT a fake pass
            non_vacuous = (
                payload["counts"]["keyword_count"] > 0
                and (payload["corpus_compared"] > 0 or payload["evidence"])
            )
            self.assertFalse(non_vacuous)

    def test_cli_writes_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._ws(td)
            (ws / ".auditooor" / "exploit_queue.json").write_text(json.dumps({
                "queue": [{"slug": "scalar_reduction_nonconstant_time"}]}), encoding="utf-8")
            pa = ws / "prior_audits"; pa.mkdir()
            (pa / "x.txt").write_text("scalar reduction in constant time verified", encoding="utf-8")
            r = subprocess.run([sys.executable, str(_TOOL), str(ws)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            art = ws / ".auditooor" / "originality_report.json"
            self.assertTrue(art.is_file())
            obj = json.loads(art.read_text())
            self.assertEqual(obj["schema"], "auditooor.workspace_originality_scan.v1")


if __name__ == "__main__":
    unittest.main()
