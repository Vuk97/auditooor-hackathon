"""Tests for claim-citation-check.py (R-CODE-CITED)."""
import importlib.util, json, os, sys, tempfile, unittest
from pathlib import Path
TOOL = Path(__file__).resolve().parents[1] / "claim-citation-check.py"
_spec = importlib.util.spec_from_file_location("ccc", TOOL)
ccc = importlib.util.module_from_spec(_spec); sys.modules["ccc"] = ccc
_spec.loader.exec_module(ccc)

def _ws(tmp, rows):
    a = Path(tmp) / ".auditooor" / "hacker_question_verdicts"; a.mkdir(parents=True, exist_ok=True)
    for i, r in enumerate(rows):
        (a / f"hq_{i:03d}.json").write_text(json.dumps(r))
    return Path(tmp)

class TestClaimCitation(unittest.TestCase):
    def setUp(self):
        os.environ.pop("AUDITOOOR_CLAIM_CITATION_STRICT", None)

    def test_flags_claims_without_citation(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _ws(tmp, [{"question_id": "q", "verdict": "KILL",
                            "reason": "the input is validated upstream and the call is "
                                      "guarded by an onlyOwner check, so it is unreachable "
                                      "and out of scope - the loss is capped."}])
            self.assertEqual(len(ccc.scan(ws)["flagged"]), 1, "claims + 0 citations must flag")

    def test_exempts_cited_claims(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _ws(tmp, [{"question_id": "q", "verdict": "KILL", "file_line": "x.go:88",
                            "reason": "the input is validated at vault.go:412 and the call is "
                                      "guarded by ValidateAdmin (msg_server.go:582), so it is "
                                      "unreachable by an unprivileged caller."}])
            self.assertEqual(len(ccc.scan(ws)["flagged"]), 0, "claims WITH file:line must pass")

    def test_no_claims_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _ws(tmp, [{"question_id": "q", "verdict": "KILL",
                            "reason": "this function does nothing interesting."}])
            self.assertEqual(len(ccc.scan(ws)["flagged"]), 0, "no claims -> nothing to cite")

    def test_strict_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _ws(tmp, [{"question_id": "q", "verdict": "NOT-FILEABLE",
                            "reason": "it is guarded and validated and privileged and capped."}])
            os.environ["AUDITOOOR_CLAIM_CITATION_STRICT"] = "1"
            try:
                self.assertEqual(ccc.main(["--workspace", str(ws)]), 1)
            finally:
                os.environ.pop("AUDITOOOR_CLAIM_CITATION_STRICT", None)

if __name__ == "__main__":
    unittest.main()
