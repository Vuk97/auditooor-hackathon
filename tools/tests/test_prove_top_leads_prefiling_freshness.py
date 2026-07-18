#!/usr/bin/env python3
"""test_prove_top_leads_prefiling_freshness.py

Freshness guard for the prove-top-leads prefiling-stress corroboration (surfaced on
axelar 2026-07-12): _prefiling_confirms_all_terminal read
.auditooor/prove_top_leads_prefiling_stress_test.json and trusted its "0 non-terminal
top leads" verdict WITHOUT checking it was computed against the LIVE exploit_queue.
Observed: prefiling-stress artifact dated 02:24 while exploit_queue.json +
corpus_driven_hunt regenerated 13:38 (11h later, +7116 obligations) - the stale
artifact could corroborate a no-leads manifest against a queue it never actually
assessed (false honest-0). Fix: require the prefiling-stress artifact's mtime to be
>= every live queue file's mtime; a stale artifact can never corroborate.
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "audit-completeness-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("audit_completeness_check", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["audit_completeness_check"] = m
    try:
        spec.loader.exec_module(m)
    except Exception:
        pass
    return m


_ALL_TERMINAL_PREFILING = {"top_n": 10, "rows_assessed": 0, "terminal_rows_skipped": 134}


def _ws(queue_rows, prefiling, queue_mtime, prefiling_mtime):
    d = Path(tempfile.mkdtemp())
    a = d / ".auditooor"
    a.mkdir()
    q = {"queue": [{"i": i} for i in range(queue_rows)]}
    for rel in ("exploit_queue.json", "exploit_queue.source_mined.json"):
        p = a / rel
        p.write_text(json.dumps(q))
        os.utime(p, (queue_mtime, queue_mtime))
    p = a / "prove_top_leads_prefiling_stress_test.json"
    p.write_text(json.dumps(prefiling))
    os.utime(p, (prefiling_mtime, prefiling_mtime))
    return d


class TestPrefilingFreshness(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_stale_prefiling_vs_fresh_queue_not_corroborated(self):
        # prefiling-stress written 11h BEFORE the queue was regenerated (axelar
        # scenario: 02:24 prefiling vs 13:38 queue, +7116 obligations) -> stale,
        # must NOT corroborate.
        now = time.time()
        ws = _ws(7814, _ALL_TERMINAL_PREFILING,
                 queue_mtime=now, prefiling_mtime=now - 11 * 3600)
        self.assertFalse(self.m._prefiling_confirms_all_terminal(ws))

    def test_fresh_prefiling_vs_older_queue_corroborated(self):
        # prefiling-stress written AFTER (or at) the queue's last regeneration ->
        # it actually assessed the live queue, corroboration holds.
        now = time.time()
        ws = _ws(7814, _ALL_TERMINAL_PREFILING,
                 queue_mtime=now - 3600, prefiling_mtime=now)
        self.assertTrue(self.m._prefiling_confirms_all_terminal(ws))

    def test_equal_mtime_corroborated(self):
        # boundary: prefiling mtime == queue mtime is accepted (>=), not rejected.
        now = time.time()
        ws = _ws(7814, _ALL_TERMINAL_PREFILING,
                 queue_mtime=now, prefiling_mtime=now)
        self.assertTrue(self.m._prefiling_confirms_all_terminal(ws))

    def test_stale_prefiling_flows_through_no_leads_manifest_validator(self):
        # end-to-end: even with a well-formed manifest declaring all_top_leads_terminal
        # and matching current_queue_rows, a stale prefiling artifact must still
        # reject the manifest as a whole (no false honest-0 corroboration).
        now = time.time()
        ws = _ws(7814, _ALL_TERMINAL_PREFILING,
                 queue_mtime=now, prefiling_mtime=now - 11 * 3600)
        manifest = {
            "schema": "auditooor.prove_top_leads_no_leads.v1",
            "no_leads": True,
            "lead_count": 0,
            "all_top_leads_terminal": True,
            "current_queue_rows": {
                ".auditooor/exploit_queue.json": 7814,
                ".auditooor/exploit_queue.source_mined.json": 7814,
            },
        }
        manifest_path = ws / ".auditooor" / "prove_top_leads_no_leads.json"
        manifest_path.write_text(json.dumps(manifest))
        self.assertFalse(
            self.m._valid_prove_top_leads_no_leads_manifest(ws, manifest_path)
        )


if __name__ == "__main__":
    unittest.main()
