import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "prior-audit-resolved-reverify-gate.py"


def _load():
    spec = importlib.util.spec_from_file_location("prior_gate", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PriorAuditDigestAliasTest(unittest.TestCase):
    def test_digest_does_not_duplicate_reviewed_raw_report(self):
        gate = _load()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            prior = ws / "prior_audits"
            prior.mkdir()
            raw = prior / "Example-audit.txt"
            raw.write_text("Issue M1 RESOLVED\n", encoding="utf-8")
            (prior / "DIGEST_Example-audit.md").write_text(
                "# Digest\n- Source: `prior_audits/Example-audit.txt`\n",
                encoding="utf-8",
            )
            raw_id = hashlib.sha256(raw.read_bytes()).hexdigest()[:16]
            analysis = ws / ".auditooor"
            analysis.mkdir()
            (analysis / "prior_audit_context_analysis.json").write_text(
                json.dumps({"documents": [{"document_id": raw_id, "status": "complete"}]}),
                encoding="utf-8",
            )
            rc, result = gate.context_review_gate(ws)
            self.assertEqual(rc, 0)
            self.assertEqual(result["documents"], 1)
            self.assertEqual(result["pending"], 0)


if __name__ == "__main__":
    unittest.main()
