#!/usr/bin/env python3
"""Regression: a persisted mvc_sidecar's evidence must be DURABLE + re-verifiable.

The /tmp-evaporation gap: ssv_cluster_solvency.json pointed evidence_logs at
/tmp/*.log paths that were wiped on restart - the credited kill became
unre-verifiable. _persist_durable_sidecar now copies out-of-workspace evidence
into <ws>/.auditooor/mvc_evidence/<slug>/, rewrites the paths, and stamps
`evidence_durable`.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "mutation-verify-coverage.py"
_s = importlib.util.spec_from_file_location("mvc", _T)
mvc = importlib.util.module_from_spec(_s)
sys.modules["mvc"] = mvc
_s.loader.exec_module(mvc)


class EvidenceDurableTest(unittest.TestCase):
    def test_external_log_copied_into_workspace(self):
        ws = Path(tempfile.mkdtemp())
        ext = Path(tempfile.mkdtemp()) / "run.log"   # simulates a /tmp evidence log
        ext.write_text("echidna: 1,000,000 calls; mutant killed\n", encoding="utf-8")
        rec = {"function": "withdraw", "source_file": "src/Vault.sol",
               "evidence_logs": [str(ext)], "mutants_killed": 1}
        out = mvc._durabilize_evidence(ws, rec, "vault-withdraw")
        self.assertTrue(out["evidence_durable"])
        # path rewritten under the workspace, and the file actually exists there
        self.assertEqual(len(out["evidence_logs"]), 1)
        dst = Path(out["evidence_logs"][0])
        self.assertTrue(str(dst).startswith(str(ws)))
        self.assertTrue(dst.is_file())
        self.assertIn("mutant killed", dst.read_text())

    def test_dangling_tmp_log_dropped_but_insidecar_keeps_durable(self):
        ws = Path(tempfile.mkdtemp())
        rec = {"function": "liquidate", "source_file": "src/C.sol",
               "evidence_logs": ["/tmp/gone-zzz/does-not-exist.log"],
               # in-sidecar proof: per-mutant call counts present
               "total_calls_mutant_a": 60073, "mutants_killed": 2}
        out = mvc._durabilize_evidence(ws, rec, "c-liquidate")
        # dangling path dropped, but in-sidecar proof keeps it durable/re-verifiable
        self.assertTrue(out["evidence_durable"])
        self.assertNotIn("/tmp/gone-zzz/does-not-exist.log",
                         out.get("evidence_logs", []))

    def test_no_evidence_no_insidecar_is_not_durable(self):
        ws = Path(tempfile.mkdtemp())
        rec = {"function": "foo", "source_file": "src/C.sol"}  # claim-only, nothing
        out = mvc._durabilize_evidence(ws, rec, "c-foo")
        self.assertFalse(out["evidence_durable"])

    def test_opt_out_env(self):
        import os
        ws = Path(tempfile.mkdtemp())
        rec = {"evidence_logs": ["/tmp/x.log"]}
        os.environ["AUDITOOOR_MVC_NO_EVIDENCE_COPY"] = "1"
        try:
            out = mvc._durabilize_evidence(ws, rec, "s")
            self.assertNotIn("evidence_durable", out)  # untouched
        finally:
            os.environ.pop("AUDITOOOR_MVC_NO_EVIDENCE_COPY", None)


if __name__ == "__main__":
    unittest.main()
