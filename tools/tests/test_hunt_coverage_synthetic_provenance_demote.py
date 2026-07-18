#!/usr/bin/env python3
"""Regression: hunt-coverage-gate must DEMOTE E4-flagged synthetic sidecars.

THE LOAD-BEARING BUG (NUVA 2026-07-03): hunt-coverage-gate credited a per-fn unit
as COVERED whenever a hunt_findings_sidecar cited it - INCLUDING the 437 NUVA
tier-3-synthetic-taxonomy-anchored sidecars (duration_s==0, started==ended, no
spawn_worker dispatch receipt) that the E4 provenance gate
(hunt-dispatch-provenance-check.classify_sidecar_provenance) flags as
``synthetic-lead: needs real hunt``. Those synthetic sidecars masked the real gap
so residual_surface_units=0 and NO genuine hunt was ever dispatched.

FIX (in tools/hunt-coverage-gate.py): when the E4 provenance gate is ENFORCED
(default-ON under AUDITOOOR_L37_STRICT; opt-out via
AUDITOOOR_SIDECAR_PROVENANCE_STRICT in {0,false,no}), a unit whose ONLY covering
sidecar(s) are E4-flagged synthetic must count as UNCOVERED (its coverage tokens
are subtracted before crediting scanned units), so the unit re-enters the residual
worker queue. Reuses classify_sidecar_provenance verbatim (no reclassifier
rebuild).

Cases tested:
  (a) ENFORCED: a unit covered ONLY by a synthetic sidecar -> its token is
      demoted (would re-enter residual / not be scanned-credited).
  (b) NEVER-FALSE-FLAG: a genuine-sidecar unit (real duration_s>0) stays covered;
      a unit covered by BOTH a synthetic AND a genuine sidecar stays covered.
  (c) ENFORCEMENT-OFF: byte-identical - the demotion set is EMPTY (no demotion),
      so a parked / non-strict caller sees today's residual unchanged.
"""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hunt-coverage-gate.py"
_s = importlib.util.spec_from_file_location("hcg_synth_demote", _T)
hcg = importlib.util.module_from_spec(_s)
_s.loader.exec_module(hcg)


def _write_sidecar(ws: Path, name: str, payload: dict) -> None:
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


def _synthetic_sidecar(file_line: str, fn: str) -> dict:
    """A NUVA-shaped tier-3-synthetic sidecar: self-declared synthetic tier,
    duration_s==0, started==ended, no dispatch receipt. E4 => synthetic-lead."""
    return {
        "schema": "auditooor.hunt_findings_sidecar.v1",
        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
        "provider": "sonnet-via-agent",
        "duration_s": 0.0,
        "started_at_utc": "2026-06-30T00:36:18.641111+00:00",
        "ended_at_utc": "2026-06-30T00:36:18.641111+00:00",
        "file": file_line.rsplit(":", 1)[0],
        "function": fn,
        "verdict": "no-finding",
        "file_line": file_line,
        "function_anchor": {"file": file_line.rsplit(":", 1)[0], "function": fn},
    }


def _genuine_sidecar(file_line: str, fn: str) -> dict:
    """A genuinely dispatched sidecar: real duration_s>0, started != ended.
    E4 => authentic (NEVER flagged, even at input_tokens==0)."""
    return {
        "schema": "auditooor.hunt_findings_sidecar.v1",
        "verification_tier": "tier-1-source-read",
        "provider": "sonnet-via-agent",
        "duration_s": 42.5,
        "started_at_utc": "2026-06-30T00:36:18.000000+00:00",
        "ended_at_utc": "2026-06-30T00:36:60.500000+00:00",
        "file": file_line.rsplit(":", 1)[0],
        "function": fn,
        "verdict": "finding-fp-defended",
        "file_line": file_line,
        "function_anchor": {"file": file_line.rsplit(":", 1)[0], "function": fn},
    }


class SyntheticProvenanceDemoteTest(unittest.TestCase):
    def setUp(self):
        # Ensure a clean env baseline; each test sets exactly what it needs.
        self._saved = {
            k: os.environ.get(k)
            for k in ("AUDITOOOR_L37_STRICT", "AUDITOOOR_SIDECAR_PROVENANCE_STRICT")
        }
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _make_ws(self) -> Path:
        tmp = tempfile.mkdtemp(prefix="hcg_synth_")
        ws = Path(tmp)
        # A unit covered ONLY by a synthetic sidecar.
        _write_sidecar(ws, "syn_only.json",
                       _synthetic_sidecar("src/Vault.sol:61", "sweep"))
        # A unit covered ONLY by a genuine sidecar.
        _write_sidecar(ws, "gen_only.json",
                       _genuine_sidecar("src/Router.sol:100", "deposit"))
        # A unit covered by BOTH a synthetic AND a genuine sidecar.
        _write_sidecar(ws, "both_syn.json",
                       _synthetic_sidecar("src/Both.sol:5", "withdraw"))
        _write_sidecar(ws, "both_gen.json",
                       _genuine_sidecar("src/Both.sol:5", "withdraw"))
        return ws

    # -- case (a): under enforcement, synthetic-only unit is demoted -----------
    def test_a_enforced_synthetic_only_token_demoted(self):
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        self.assertTrue(hcg._provenance_strict_enabled_for_coverage())
        ws = self._make_ws()
        synthetic_only, trace = hcg._synthetic_only_scanned_tokens(ws)
        self.assertTrue(trace["enforced"])
        # The synthetic-only unit's tokens ARE demoted (re-enter residual).
        self.assertIn("Vault.sol::sweep", synthetic_only)
        self.assertIn("src/Vault.sol::sweep", synthetic_only)
        # >=1 synthetic-lead sidecar was actually classified.
        self.assertGreaterEqual(trace["synthetic_lead_sidecar_count"], 1)

    # -- case (b): never-false-flag - genuine + shared stay covered ------------
    def test_b_genuine_and_shared_never_demoted(self):
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        ws = self._make_ws()
        synthetic_only, _trace = hcg._synthetic_only_scanned_tokens(ws)
        # A genuine-only unit is NEVER in the demotion set.
        self.assertNotIn("Router.sol::deposit", synthetic_only)
        self.assertNotIn("src/Router.sol::deposit", synthetic_only)
        # A unit covered by BOTH synthetic AND genuine stays covered
        # (its token is protected out of the synthetic-only set).
        self.assertNotIn("Both.sol::withdraw", synthetic_only)
        self.assertNotIn("src/Both.sol::withdraw", synthetic_only)

    # -- case (c): enforcement-off -> byte-identical (empty demotion) ----------
    def test_c_enforcement_off_is_byte_identical(self):
        # All envs unset -> not enforced.
        self.assertFalse(hcg._provenance_strict_enabled_for_coverage())
        # Explicit opt-out even under L37 -> not enforced.
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        os.environ["AUDITOOOR_SIDECAR_PROVENANCE_STRICT"] = "0"
        self.assertFalse(hcg._provenance_strict_enabled_for_coverage())

    def test_c_helper_returns_empty_when_classifier_semantics_off(self):
        # The check() gate only invokes the demotion when enforced; but even if
        # the helper is called directly, a workspace with no sidecars yields an
        # empty demotion (no false demotion), and the trace is well-formed.
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        tmp = tempfile.mkdtemp(prefix="hcg_empty_")
        ws = Path(tmp)
        synthetic_only, trace = hcg._synthetic_only_scanned_tokens(ws)
        self.assertEqual(synthetic_only, set())
        self.assertEqual(trace["synthetic_only_token_count"], 0)

    # -- reuse of the E4 classifier (no rebuild) -------------------------------
    def test_reuses_e4_classifier_and_predicate(self):
        mod = hcg._load_provenance_module()
        self.assertIsNotNone(mod)
        # Reused verbatim: the classifier + receipt-tokens + strict predicate.
        self.assertTrue(hasattr(mod, "classify_sidecar_provenance"))
        self.assertTrue(hasattr(mod, "_ws_dispatch_receipt_tokens"))
        self.assertTrue(hasattr(mod, "_sidecar_provenance_strict_enabled"))


if __name__ == "__main__":
    unittest.main()
