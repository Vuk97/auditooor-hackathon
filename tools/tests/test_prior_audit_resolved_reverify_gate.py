"""Regression: the prior-audit-resolved-reverify gate must, for a re-audit, enumerate every
prior Resolved/Fixed finding on an IN-SCOPE file as a re-verification obligation, credit only
a real {file,verdict in still-fixed|incomplete-fix|...} artifact, and FAIL under --strict when
any is unmet. Guards the Strata 2026 gap: the M-4/M-09 proxy-reuse fix was 'Resolved' but
missing in sUSDe/sNUSD - an incomplete fix that must not be assumed-fixed."""
import importlib.util, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

_TOOL = os.path.join(os.path.dirname(__file__), "..", "prior-audit-resolved-reverify-gate.py")


def _run(ws, strict=False):
    cmd = [sys.executable, _TOOL, str(ws), "--json"] + (["--strict"] if strict else [])
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, json.loads(p.stdout)


class TestReverifyGate(unittest.TestCase):
    def _ws(self, d):
        ws = Path(d); (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (ws / "prior_audits").mkdir(exist_ok=True)
        (ws / "SCOPE.md").write_text("in scope: UnstakeCooldown.sol AprPairFeed.sol\n## OUT-OF-SCOPE\n")
        (ws / "prior_audits" / "INGESTED_FINDINGS.md").write_text(
            "| M-4 | Medium | Proxy reuse | UnstakeCooldown.sol:46-105 | Resolved |\n"
            "| M-6 | Medium | Old data overwrites new | AprPairFeed.sol:91-95 | Resolved |\n"
            "| X-9 | Low | Something in an OOS file | OtherThing.sol | Resolved |\n")
        return ws

    def test_no_prior_audit_passes(self):
        with tempfile.TemporaryDirectory() as d:
            rc, r = _run(d)  # no prior_audits/ dir
            self.assertEqual(rc, 0); self.assertEqual(r["verdict"], "pass-no-prior-audit")

    def test_unverified_in_scope_resolved_fails_strict(self):
        with tempfile.TemporaryDirectory() as d:
            ws = self._ws(d)
            rc, r = _run(ws, strict=True)
            self.assertEqual(rc, 1)
            self.assertEqual(r["verdict"], "fail-prior-resolved-not-reverified")
            files = {o["file"] for o in r["unmet"]}
            self.assertIn("UnstakeCooldown.sol", files)
            self.assertIn("AprPairFeed.sol", files)
            self.assertNotIn("OtherThing.sol", files)  # OOS file excluded

    def test_reverification_artifact_credits(self):
        with tempfile.TemporaryDirectory() as d:
            ws = self._ws(d)
            rv = ws / ".auditooor" / "prior_resolved_reverify"; rv.mkdir(parents=True)
            (rv / "a.json").write_text(json.dumps({"file": "UnstakeCooldown.sol", "verdict": "incomplete-fix", "cite": "x"}))
            (rv / "b.json").write_text(json.dumps({"file": "AprPairFeed.sol", "verdict": "still-fixed", "cite": "y"}))
            rc, r = _run(ws, strict=True)
            self.assertEqual(rc, 0)
            self.assertEqual(r["verdict"], "pass-all-reverified")


if __name__ == "__main__":
    unittest.main()
