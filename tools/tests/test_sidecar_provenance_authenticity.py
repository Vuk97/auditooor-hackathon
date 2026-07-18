#!/usr/bin/env python3
"""E4: per-sidecar provenance-authenticity guard tests
(tools/hunt-dispatch-provenance-check.py --sidecars mode).

A synthetic (never-really-hunted) per-fn hunt sidecar can GREEN the per-function
function-coverage gate. This guard reclassifies a claimed-hunt sidecar with no
dispatch provenance as ``synthetic-lead: needs real hunt``.

*** THE TOKEN==0 TRAP (verified): tools/haiku-fanout-dispatcher.py HARDCODES
input_tokens=0 / output_tokens=0 for ALL genuine via-agent sidecars. So the guard
MUST NOT key on tokens. It keys on the inline-authoring signature (duration_s<=0/None
with started==ended) + absence of a dispatch receipt instead.

Covers (HARD REQUIREMENTS 2 + 3):
  (a) TRAP CASE: tokens==0 BUT a real duration_s>0 (genuine haiku)      -> NOT flagged
  (a') TRAP CASE: tokens==0 BUT a spawn_worker dispatch receipt links it -> NOT flagged
  (b) SYNTHETIC: claims dispatch/source-read but duration==0 & started==ended
      & NO receipt                                                       -> flagged (strict)
  (c) GENUINE non-zero-token sidecar                                    -> passes
  NEVER-FALSE-FLAG: a sidecar that merely OMITS timing (ambiguous, real source-read
      tier) is NOT flagged.
  NEVER-RETRO-RED: env unset => WARN + rc 0 (byte-identical); STRICT env/flag => FAIL + rc 1.
  A sidecar that does not claim coverage credit is not subject to the guard.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
_TOOL = _REPO / "tools" / "hunt-dispatch-provenance-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("hdp_e4", str(_TOOL))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["hdp_e4"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


mod = _load()


def _sc(**overrides) -> dict:
    """A baseline claimed-hunt sidecar (mirrors the haiku-fanout template shape:
    provider via-agent, tokens hardcoded 0). Overridable per test."""
    base = {
        "task_id": "perfn_mimo_testws_00001",
        "workspace": "testws",
        "workspace_path": "/x/testws",
        "function_anchor": "sweep",
        "task_type": "workspace_hunt_harnessed",
        "provider": "sonnet-via-agent",
        "model_id": "claude-opus-4-8",
        "status": "ok",
        "started_at_utc": "2026-06-30T00:00:00Z",
        "ended_at_utc": "2026-06-30T00:00:00Z",
        "duration_s": 0.0,
        "cost_usd": 0.0,
        "input_tokens": 0,
        "output_tokens": 0,
        "verification_tier": "tier-1-source-read-verified",
        "file_line": "src/Foo.sol:42",
        "code_excerpt": "require(msg.sender == owner);",
        "result": "{\"applies_to_target\":\"no\",\"file_line\":\"src/Foo.sol:42\"}",
    }
    base.update(overrides)
    return base


class SidecarProvenanceTest(unittest.TestCase):
    def _ws(self, sidecars: dict[str, dict], receipts: list[dict] | None = None) -> Path:
        """Build a temp workspace with the given {filename: sidecar} map and an
        optional spawn_worker_log ledger; inject the ledger path into the module."""
        root = Path(tempfile.mkdtemp())
        scdir = root / ".auditooor" / "hunt_findings_sidecars"
        scdir.mkdir(parents=True)
        for name, data in sidecars.items():
            (scdir / name).write_text(json.dumps(data), encoding="utf-8")
        ledger = root / "spawn_worker_log.jsonl"
        lines = [json.dumps(r) for r in (receipts or [])]
        ledger.write_text("\n".join(lines), encoding="utf-8")
        mod.LEDGER = ledger
        return root

    # ---- (a) THE HAIKU TRAP: tokens==0 but real duration -> NOT flagged ---------
    def test_trap_zero_tokens_but_real_duration_not_flagged(self):
        ws = self._ws({
            "genuine_haiku.json": _sc(
                # tokens hardcoded 0 (the trap) BUT subagent filled a real duration:
                input_tokens=0, output_tokens=0,
                started_at_utc="2026-06-30T00:00:00Z",
                ended_at_utc="2026-06-30T00:05:00Z",
                duration_s=300.0,
            ),
        })
        res = mod.scan_workspace_sidecars(ws)
        self.assertEqual(res["synthetic_lead_count"], 0,
                         "genuine haiku sidecar (tokens==0, real duration) must NOT flag")
        self.assertEqual(res["verdict"], mod.SC_V_PASS)

    # ---- (a') THE HAIKU TRAP via receipt: tokens==0 & dur==0 but a receipt links it
    def test_trap_zero_tokens_but_dispatch_receipt_not_flagged(self):
        # Even with the degenerate inline signature, a spawn_worker receipt whose
        # plan/batch token matches the sidecar's run identity means it WAS dispatched.
        ws = self._ws(
            {"perfn_mimo_receipted_00007.json": _sc(
                task_id="perfn_mimo_receipted_00007",
                input_tokens=0, output_tokens=0, duration_s=0.0,
                started_at_utc="2026-06-30T00:00:00Z",
                ended_at_utc="2026-06-30T00:00:00Z",
            )},
        )
        # add a receipt for THIS workspace referencing the sidecar's run identity
        ledger = ws / "spawn_worker_log.jsonl"
        ledger.write_text(json.dumps({
            "workspace": str(ws), "lane_type": "hunt",
            "prompt_file": "/tmp/haiku/perfn_mimo_receipted_00007_batch.md",
        }), encoding="utf-8")
        mod.LEDGER = ledger
        res = mod.scan_workspace_sidecars(ws)
        self.assertEqual(res["synthetic_lead_count"], 0,
                         "receipt-linked sidecar must NOT flag even with zero tokens/duration")

    # ---- (b) SYNTHETIC: claims dispatch/R76 but dur==0 & started==ended, no receipt
    def test_synthetic_no_receipt_flagged_under_strict(self):
        ws = self._ws({
            "inline_synthetic.json": _sc(
                duration_s=0.0,
                started_at_utc="2026-06-30T00:00:00Z",
                ended_at_utc="2026-06-30T00:00:00Z",
            ),
        })
        # default (advisory): WARN + rc 0
        res = mod.scan_workspace_sidecars(ws, strict=False)
        self.assertEqual(res["synthetic_lead_count"], 1)
        self.assertEqual(res["verdict"], mod.SC_V_WARN)
        self.assertEqual(res["synthetic_leads"][0]["reclass"], mod.SC_RECLASS)
        # strict: FAIL + rc 1
        res_strict = mod.scan_workspace_sidecars(ws, strict=True)
        self.assertEqual(res_strict["verdict"], mod.SC_V_FAIL)
        self.assertEqual(mod.main([str(ws), "--sidecars", "--strict", "--json"]), 1)

    # ---- (b2) tier-3-synthetic self-declaration (NUVA 437) flagged ---------------
    def test_tier3_self_declared_synthetic_flagged(self):
        ws = self._ws({
            "tier3.json": _sc(
                verification_tier="tier-3-synthetic-taxonomy-anchored",
                duration_s=0.0,
                started_at_utc="2026-06-30T00:00:00Z",
                ended_at_utc="2026-06-30T00:00:00Z",
            ),
        })
        res = mod.scan_workspace_sidecars(ws, strict=False)
        self.assertEqual(res["synthetic_lead_count"], 1)
        self.assertIn("self-declared", " ".join(res["synthetic_leads"][0]["signals"]))

    # ---- (c) GENUINE non-zero-token sidecar -> passes ---------------------------
    def test_genuine_nonzero_token_passes(self):
        ws = self._ws({
            "genuine_api.json": _sc(
                provider="deepseek-pro",
                verification_tier="tier-1-verified-realtime-api",
                input_tokens=1234, output_tokens=567,
                duration_s=12.5,
                started_at_utc="2026-06-30T00:00:00Z",
                ended_at_utc="2026-06-30T00:00:12Z",
            ),
        })
        res = mod.scan_workspace_sidecars(ws)
        self.assertEqual(res["synthetic_lead_count"], 0)
        self.assertEqual(res["verdict"], mod.SC_V_PASS)

    # ---- NEVER-FALSE-FLAG: timing simply absent + real source-read tier ---------
    def test_ambiguous_absent_timing_not_flagged(self):
        sc = _sc(verification_tier="tier-2-source-verified")
        for k in ("started_at_utc", "ended_at_utc", "duration_s"):
            sc.pop(k, None)
        ws = self._ws({"no_timing.json": sc})
        res = mod.scan_workspace_sidecars(ws)
        self.assertEqual(res["synthetic_lead_count"], 0,
                         "absent-timing (ambiguous) must NOT be flagged on that signal alone")

    # ---- a non-coverage-claiming sidecar is out of scope of the guard -----------
    def test_non_coverage_claiming_ignored(self):
        sc = {
            "task_id": "queue_only", "workspace": "testws",
            "task_type": "queue_row", "status": "queued",
            "duration_s": 0.0,
            "started_at_utc": "2026-06-30T00:00:00Z",
            "ended_at_utc": "2026-06-30T00:00:00Z",
        }
        ws = self._ws({"queue.json": sc})
        res = mod.scan_workspace_sidecars(ws)
        self.assertEqual(res["coverage_claiming"], 0)
        self.assertEqual(res["synthetic_lead_count"], 0)
        self.assertEqual(res["verdict"], mod.SC_V_PASS)

    # ---- 4-case matrix: default-ON under L37 + escape hatch + advisory ----------
    # E4 STRICT graduated to default-ON under AUDITOOOR_L37_STRICT (2026-07-03):
    #   (1) default-under-L37 : X unset, L37 set   -> FAIL rc1
    #   (2) explicit opt-out  : X=0 (even under L37) -> WARN rc0
    #   (3) explicit opt-in   : X=1 (L37 irrelevant) -> FAIL rc1
    #   (4) non-strict-advisory: X unset, L37 unset  -> WARN rc0 (byte-identical)
    def test_advisory_envelope_four_case_matrix(self):
        ws = self._ws({
            "inline_synthetic.json": _sc(
                duration_s=0.0,
                started_at_utc="2026-06-30T00:00:00Z",
                ended_at_utc="2026-06-30T00:00:00Z",
            ),
        })
        base = dict(os.environ)
        base.pop(mod.SIDECAR_STRICT_ENV, None)
        base.pop("AUDITOOOR_L37_STRICT", None)

        def _run(env):
            r = subprocess.run(
                [sys.executable, str(_TOOL), str(ws), "--sidecars", "--json"],
                capture_output=True, text=True, env=env)
            return r.returncode, json.loads(r.stdout)["verdict"], r.stderr

        # (4) non-strict-advisory: both envs unset -> WARN rc0 (byte-identical)
        rc, verdict, err = _run(dict(base))
        self.assertEqual(rc, 0, err)
        self.assertEqual(verdict, mod.SC_V_WARN)

        # (1) default-under-L37: X unset, L37 set -> FAIL rc1
        env1 = dict(base); env1["AUDITOOOR_L37_STRICT"] = "1"
        rc, verdict, err = _run(env1)
        self.assertEqual(rc, 1, err)
        self.assertEqual(verdict, mod.SC_V_FAIL)

        # (2) explicit opt-out: X=0 even under L37 -> WARN rc0 (escape hatch)
        env2 = dict(base)
        env2["AUDITOOOR_L37_STRICT"] = "1"; env2[mod.SIDECAR_STRICT_ENV] = "0"
        rc, verdict, err = _run(env2)
        self.assertEqual(rc, 0, err)
        self.assertEqual(verdict, mod.SC_V_WARN)

        # (3) explicit opt-in: X=1 with L37 unset -> FAIL rc1
        env3 = dict(base); env3[mod.SIDECAR_STRICT_ENV] = "1"
        rc, verdict, err = _run(env3)
        self.assertEqual(rc, 1, err)
        self.assertEqual(verdict, mod.SC_V_FAIL)

    def test_strict_helper_predicate_matrix(self):
        # Direct unit-level check of the extracted predicate.
        saved = {k: os.environ.get(k) for k in (mod.SIDECAR_STRICT_ENV, "AUDITOOOR_L37_STRICT")}
        try:
            for k in saved:
                os.environ.pop(k, None)
            # (4) both unset -> advisory
            self.assertFalse(mod._sidecar_provenance_strict_enabled())
            # (1) unset X + L37 truthy -> strict
            for l37 in ("1", "true", "yes"):
                os.environ["AUDITOOOR_L37_STRICT"] = l37
                self.assertTrue(mod._sidecar_provenance_strict_enabled(), l37)
            # (2) explicit opt-out overrides L37
            for falsey in ("0", "false", "no"):
                os.environ["AUDITOOOR_L37_STRICT"] = "1"
                os.environ[mod.SIDECAR_STRICT_ENV] = falsey
                self.assertFalse(mod._sidecar_provenance_strict_enabled(), falsey)
            # (3) explicit opt-in with L37 unset
            os.environ.pop("AUDITOOOR_L37_STRICT", None)
            for truthy in ("1", "true", "yes", "on"):
                os.environ[mod.SIDECAR_STRICT_ENV] = truthy
                self.assertTrue(mod._sidecar_provenance_strict_enabled(), truthy)
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v
                else:
                    os.environ.pop(k, None)

    # ---- the plan-level default check is UNCHANGED (no regression) --------------
    def test_plan_level_check_unchanged_default_mode(self):
        # A workspace with no plan -> not-applicable, rc 0, exactly as before.
        ws = self._ws({"x.json": _sc()})
        # point DERIVED somewhere with no plan
        mod.DERIVED = ws / "no_such_derived"
        self.assertEqual(mod.check(ws)["verdict"], mod.V_NA)
        self.assertEqual(mod.main([str(ws), "--json"]), 0)


class DispatchWindowProvenanceJoinTest(unittest.TestCase):
    """The provenance JOIN completion (NUVA 2026-07-03): a GENUINELY-DISPATCHED
    hand-written sidecar (duration_s==0, tier-3-synthetic self-label, NO own
    dispatch_receipt) is authentic when it was written inside the bounded FORWARD
    mtime window of a spawn_worker hunt lane whose brief a SIBLING sidecar's
    ``dispatch_receipt`` confirms. An inline synthetic with no covering dispatch
    lane (the NUVA 437) stays flagged. This is the fix for E4's inability to tell a
    dispatched duration==0 sidecar apart from an inline synthetic duration==0 one.

    Requirements exercised:
      (a) sidecar + a matching real dispatch lane in the window            -> authentic
      (b) sidecar with NO dispatch lane for the ws                          -> synthetic
      (c) old-mtime synthetic authored BEFORE any lane (window opens later) -> synthetic
      NEVER-FALSE-PASS: a bare hunt lane whose brief is NOT receipt-confirmed
          does NOT open a window (would false-credit the 437). Only a lane a sibling
          sidecar's dispatch_receipt confirms anchors a window.
    """

    def _ws(self, sidecars, receipts=None):
        root = Path(tempfile.mkdtemp())
        scdir = root / ".auditooor" / "hunt_findings_sidecars"
        scdir.mkdir(parents=True)
        paths = {}
        for name, data in sidecars.items():
            p = scdir / name
            p.write_text(json.dumps(data), encoding="utf-8")
            paths[name] = p
        ledger = root / "spawn_worker_log.jsonl"
        ledger.write_text(
            "\n".join(json.dumps(r) for r in (receipts or [])), encoding="utf-8")
        mod.LEDGER = ledger
        return root, paths

    @staticmethod
    def _iso(epoch):
        from datetime import datetime, timezone
        return datetime.fromtimestamp(epoch, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f") + "Z"

    def _brief(self):
        return "spawn_worker_ws-rehunt-0000_12345_enriched.md"

    def _confirming_sibling(self, brief):
        """A sidecar that carries a dispatch_receipt pointing at ``brief`` - this is
        what CONFIRMS the lane so a window opens. Genuine tier-1 dispatched output."""
        return _sc(
            task_id="perfn_dispatched_00099",
            verification_tier="tier-1-source-read",
            dispatch_receipt={"dispatch_brief_file": brief, "lane": "hunt"},
        )

    # ---- (a) dispatched duration==0 sidecar inside a receipt-confirmed window ----
    def test_a_dispatch_window_credits_zero_duration_sibling(self):
        import time
        brief = self._brief()
        now = time.time()
        # a hand-written, self-labelled tier-3 synthetic with NO own receipt and
        # duration==0 - identical on those fields to an inline synthetic:
        dispatched = _sc(
            task_id="perfn_mimo_ws_plane_00000",
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            duration_s=0.0,
            started_at_utc="2026-07-03T00:00:00Z",
            ended_at_utc="2026-07-03T00:00:00Z",
        )
        dispatched.pop("dispatch_receipt", None)
        ws, paths = self._ws(
            {"dispatched_plane.json": dispatched,
             "confirming_sibling.json": self._confirming_sibling(brief)},
            receipts=[{
                "workspace": None,  # patched below to the temp ws path
                "lane_type": "hunt", "lane_id": "ws-rehunt-0000",
                "enriched_file": "/tmp/" + brief,
                # lane dispatched ~just before the sidecar was written:
                "ts": self._iso(now - 60),
            }],
        )
        # rewrite the ledger with the real ws path now that we have it
        ledger = ws / "spawn_worker_log.jsonl"
        ledger.write_text(json.dumps({
            "workspace": str(ws), "lane_type": "hunt", "lane_id": "ws-rehunt-0000",
            "enriched_file": "/tmp/" + brief, "ts": self._iso(now - 60),
        }), encoding="utf-8")
        mod.LEDGER = ledger

        windows = mod._ws_confirmed_dispatch_windows(ws)
        self.assertEqual(len(windows), 1, "receipt-confirmed hunt lane must open 1 window")
        rt = mod._ws_dispatch_receipt_tokens(ws)
        cls = mod.classify_sidecar_provenance(
            paths["dispatched_plane.json"],
            json.loads(paths["dispatched_plane.json"].read_text()), rt, windows)
        self.assertEqual(cls["status"], "authentic")
        self.assertEqual(cls["reason"], "dispatch-window-verified")
        # end-to-end scan: 0 synthetic-lead (both sidecars authentic)
        res = mod.scan_workspace_sidecars(ws, strict=True)
        self.assertEqual(res["synthetic_lead_count"], 0)
        self.assertEqual(res["verdict"], mod.SC_V_PASS)
        self.assertEqual(res["dispatch_windows_seen"], 1)

    # ---- (b) NO dispatch lane for the ws -> the zero-duration synthetic is flagged
    def test_b_no_dispatch_lane_stays_synthetic(self):
        # Same hand-written tier-3 duration==0 sidecar, but NO ledger entry at all
        # (no dispatched hunt for this ws) -> synthetic-lead.
        synthetic = _sc(
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            duration_s=0.0,
            started_at_utc="2026-07-03T00:00:00Z",
            ended_at_utc="2026-07-03T00:00:00Z",
        )
        synthetic.pop("dispatch_receipt", None)
        ws, paths = self._ws({"inline_synthetic.json": synthetic}, receipts=[])
        windows = mod._ws_confirmed_dispatch_windows(ws)
        self.assertEqual(windows, [], "no receipt-confirmed lane -> no window")
        res = mod.scan_workspace_sidecars(ws, strict=True)
        self.assertEqual(res["synthetic_lead_count"], 1)
        self.assertEqual(res["verdict"], mod.SC_V_FAIL)

    # ---- (b') NEVER-FALSE-PASS: a bare hunt lane NOT receipt-confirmed opens NO
    #      window (this is the 437 trap - hunt lanes ran the whole time). ----------
    def test_bprime_unconfirmed_hunt_lane_opens_no_window(self):
        import time
        now = time.time()
        synthetic = _sc(
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            duration_s=0.0,
            started_at_utc="2026-07-03T00:00:00Z",
            ended_at_utc="2026-07-03T00:00:00Z",
        )
        synthetic.pop("dispatch_receipt", None)
        # a real hunt lane exists AND its window would cover the sidecar mtime, BUT
        # NO sidecar carries a dispatch_receipt confirming it -> no window opens.
        ws, paths = self._ws({"inline_synthetic.json": synthetic}, receipts=[])
        ledger = ws / "spawn_worker_log.jsonl"
        ledger.write_text(json.dumps({
            "workspace": str(ws), "lane_type": "hunt", "lane_id": "ws-unconfirmed-0000",
            "enriched_file": "/tmp/spawn_worker_ws-unconfirmed-0000_777_enriched.md",
            "ts": self._iso(now - 60),
        }), encoding="utf-8")
        mod.LEDGER = ledger
        self.assertEqual(mod._ws_confirmed_dispatch_windows(ws), [],
                         "an unconfirmed hunt lane must NOT open a window (437 trap)")
        res = mod.scan_workspace_sidecars(ws, strict=True)
        self.assertEqual(res["synthetic_lead_count"], 1)
        self.assertEqual(res["verdict"], mod.SC_V_FAIL)

    # ---- (c) old-mtime synthetic authored BEFORE the window opens -> synthetic ----
    def test_c_old_mtime_before_window_stays_synthetic(self):
        import os as _os, time
        brief = self._brief()
        now = time.time()
        old_synthetic = _sc(
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            duration_s=0.0,
            started_at_utc="2026-07-03T00:00:00Z",
            ended_at_utc="2026-07-03T00:00:00Z",
        )
        old_synthetic.pop("dispatch_receipt", None)
        ws, paths = self._ws(
            {"old_synthetic.json": old_synthetic,
             "confirming_sibling.json": self._confirming_sibling(brief)},
            receipts=[])
        # the dispatch lane fires in the FUTURE relative to the old synthetic's mtime:
        # force the old synthetic's mtime to well BEFORE the lane ts.
        old_mtime = now - 6 * 3600  # 6h ago
        _os.utime(paths["old_synthetic.json"], (old_mtime, old_mtime))
        ledger = ws / "spawn_worker_log.jsonl"
        ledger.write_text(json.dumps({
            "workspace": str(ws), "lane_type": "hunt", "lane_id": "ws-rehunt-0000",
            "enriched_file": "/tmp/" + brief,
            "ts": self._iso(now - 60),  # lane dispatched 1 min ago, AFTER old mtime
        }), encoding="utf-8")
        mod.LEDGER = ledger
        windows = mod._ws_confirmed_dispatch_windows(ws)
        self.assertEqual(len(windows), 1)
        rt = mod._ws_dispatch_receipt_tokens(ws)
        cls = mod.classify_sidecar_provenance(
            paths["old_synthetic.json"],
            json.loads(paths["old_synthetic.json"].read_text()), rt, windows)
        self.assertEqual(cls["status"], "synthetic-lead",
                         "a synthetic authored BEFORE the dispatch window must stay flagged")

    # ---- byte-parity: classify with dispatch_windows=None == pre-window behavior --
    def test_none_windows_is_byte_identical_to_pre_window(self):
        synthetic = _sc(
            verification_tier="tier-3-synthetic-taxonomy-anchored",
            duration_s=0.0,
            started_at_utc="2026-07-03T00:00:00Z",
            ended_at_utc="2026-07-03T00:00:00Z",
        )
        synthetic.pop("dispatch_receipt", None)
        ws, paths = self._ws({"s.json": synthetic}, receipts=[])
        p = paths["s.json"]
        data = json.loads(p.read_text())
        # None (default) and [] windows both preserve the flagged verdict
        c_none = mod.classify_sidecar_provenance(p, data, set(), None)
        c_empty = mod.classify_sidecar_provenance(p, data, set(), [])
        self.assertEqual(c_none["status"], "synthetic-lead")
        self.assertEqual(c_empty["status"], "synthetic-lead")


if __name__ == "__main__":
    unittest.main()
