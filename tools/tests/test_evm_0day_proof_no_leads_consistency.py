#!/usr/bin/env python3
"""test_evm_0day_proof_no_leads_consistency.py

Generic gate-consistency fix (2026-07-03, NUVA): evm-0day-proof required an
evm_0day_proof artifact whenever a Medium+ EVM candidate sat in the exploit queue -
but the queue rows carry NO terminal-verdict field, so a genuine honest-0 (every top
lead already adjudicated terminal) still tripped it, contradicting prove-top-leads
which already greened the same all-terminal state via its no-leads manifest. The gate
now accepts a VALID prove-top-leads no-leads manifest as proof there is no OPEN EVM
0-day obligation. It reuses the un-fakeable prefiling corroboration, so it cannot be
gamed here independently.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "audit-completeness-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("audit_completeness_check_evm", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["audit_completeness_check_evm"] = m
    try:
        spec.loader.exec_module(m)
    except Exception:
        pass
    return m


_SCHEMA = "auditooor.prove_top_leads_no_leads.v1"


def _ws(*, with_manifest, sol=True):
    d = Path(tempfile.mkdtemp())
    a = d / ".auditooor"
    a.mkdir()
    if sol:
        (d / "src").mkdir()
        (d / "src" / "X.sol").write_text("contract X {}")
    q = {"queue": [{"likely_severity": "High"}] * 7814}
    (a / "exploit_queue.json").write_text(json.dumps(q))
    (a / "exploit_queue.source_mined.json").write_text(json.dumps(q))
    if with_manifest:
        (a / "prove_top_leads_no_leads.json").write_text(json.dumps({
            "schema": _SCHEMA, "no_leads": True, "lead_count": 0,
            "all_top_leads_terminal": True,
            "current_queue_rows": {".auditooor/exploit_queue.json": 7814,
                                   ".auditooor/exploit_queue.source_mined.json": 7814}}))
        (a / "prove_top_leads_prefiling_stress_test.json").write_text(json.dumps(
            {"top_n": 0, "rows_assessed": 0, "terminal_rows_skipped": 134}))
    return d


def _ws_corpus_fuel(*, base_source_empty=False):
    """A queue whose ONLY Medium+ rows are corpus-driven-hunt fuel.

    When ``base_source_empty`` is True, the base ``exploit_queue.json`` copies have
    LOST their ``source`` tag and the ``corpus-hunt-fuel:`` title prefix (the NUVA
    2026-07-04 base-queue re-population bug), while the authoritative source-mined
    queue still labels them corpus-fuel by ``source`` + ``lead_id``. Either way,
    these are cross-workspace invariant seeds, not genuine EVM 0-day candidates, so
    evm-0day-proof must NOT fire on them."""
    d = Path(tempfile.mkdtemp())
    a = d / ".auditooor"
    a.mkdir()
    (d / "src").mkdir()
    (d / "src" / "X.sol").write_text("contract X {}")
    sm_rows = [
        {"lead_id": f"EQ-{i:03d}", "source": "corpus-hunt-fuel",
         "likely_severity": "high",
         "title": f"corpus-hunt-fuel: INV-ORD-EX-{i:04d} (bridge_replay) @ helper"}
        for i in range(50)
    ]
    if base_source_empty:
        base_rows = [
            {"lead_id": r["lead_id"], "source": "", "likely_severity": "high",
             "title": "role-grant-divergence: SomeContract.f()"}
            for r in sm_rows
        ]
    else:
        base_rows = [dict(r) for r in sm_rows]
    (a / "exploit_queue.json").write_text(json.dumps({"queue": base_rows}))
    (a / "exploit_queue.source_mined.json").write_text(json.dumps({"queue": sm_rows}))
    return d


def _ws_genuine_evm(*, medium_plus=True):
    """A queue carrying a GENUINE (non-corpus-fuel) Medium+ EVM candidate that the
    gate must STILL treat as a real candidate (fail-closed)."""
    d = Path(tempfile.mkdtemp())
    a = d / ".auditooor"
    a.mkdir()
    (d / "src").mkdir()
    (d / "src" / "X.sol").write_text("contract X {}")
    row = {"lead_id": "EQ-900", "source": "glider-dsl",
           "likely_severity": "high" if medium_plus else "low",
           "contract": "src/nuva-evm-contracts/contracts/CustomToken.sol",
           "function": "mint",
           "title": "role-grant-divergence: CustomToken.mint(address,uint256)"}
    q = {"queue": [row]}
    (a / "exploit_queue.json").write_text(json.dumps(q))
    (a / "exploit_queue.source_mined.json").write_text(json.dumps(q))
    return d


class TestEvm0dayNoLeadsConsistency(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_passes_with_valid_no_leads_manifest(self):
        import os
        ws = _ws(with_manifest=True)
        os.environ["ENFORCE_AUTONOMOUS_PROOF_CONVERSION"] = "1"
        try:
            r = self.m.check_evm_0day_proof(ws)
        finally:
            os.environ.pop("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", None)
        self.assertTrue(r.ok, r.reason)

    def test_still_fails_without_manifest_or_proof_under_enforce(self):
        import os
        ws = _ws(with_manifest=False)
        os.environ["ENFORCE_AUTONOMOUS_PROOF_CONVERSION"] = "1"
        try:
            r = self.m.check_evm_0day_proof(ws)
        finally:
            os.environ.pop("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", None)
        self.assertFalse(r.ok, r.reason)


class TestEvm0dayCorpusFuelFalseRed(unittest.TestCase):
    """Regression (NUVA 2026-07-04): a corpus-fuel-ONLY queue is NOT a genuine
    Medium+ EVM candidate and must NOT trip evm-0day-proof, even without a no-leads
    manifest. A genuine .sol Medium+ candidate still must trip it (fail-closed)."""

    def setUp(self):
        self.m = _load()

    def test_corpus_fuel_not_a_medium_plus_evm_candidate(self):
        ws = _ws_corpus_fuel(base_source_empty=False)
        self.assertFalse(self.m._has_medium_plus_evm_candidate(ws))

    def test_corpus_fuel_base_lost_source_tag_still_excluded(self):
        # Base queue lost the source tag + title prefix; source-mined labelling wins.
        ws = _ws_corpus_fuel(base_source_empty=True)
        self.assertFalse(self.m._has_medium_plus_evm_candidate(ws))

    def test_corpus_fuel_only_queue_passes_gate_under_enforce(self):
        import os
        ws = _ws_corpus_fuel(base_source_empty=True)
        os.environ["ENFORCE_AUTONOMOUS_PROOF_CONVERSION"] = "1"
        try:
            r = self.m.check_evm_0day_proof(ws)
        finally:
            os.environ.pop("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", None)
        # No proof artifact, no no-leads manifest, yet the gate PASSES because the
        # only Medium+ rows are corpus-fuel (not real EVM 0-day candidates).
        self.assertTrue(r.ok, r.reason)
        self.assertFalse(r.detail.get("medium_plus_candidate"))

    def test_genuine_evm_candidate_still_qualifies(self):
        ws = _ws_genuine_evm(medium_plus=True)
        self.assertTrue(self.m._has_medium_plus_evm_candidate(ws))

    def test_genuine_evm_candidate_still_fails_without_proof_under_enforce(self):
        import os
        ws = _ws_genuine_evm(medium_plus=True)
        os.environ["ENFORCE_AUTONOMOUS_PROOF_CONVERSION"] = "1"
        try:
            r = self.m.check_evm_0day_proof(ws)
        finally:
            os.environ.pop("ENFORCE_AUTONOMOUS_PROOF_CONVERSION", None)
        # A REAL .sol Medium+ candidate with no proof artifact must still fail-closed.
        self.assertFalse(r.ok, r.reason)


if __name__ == "__main__":
    unittest.main()
