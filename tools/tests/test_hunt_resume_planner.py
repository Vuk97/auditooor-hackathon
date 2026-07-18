#!/usr/bin/env python3
"""Offline tests for tools/hunt-resume-planner.py.

NO network / NO live rate-limited calls. Everything is driven by a mocked
record-set + a simulated provider that rate-limits the primary then succeeds
on the alternate.

Covers the deliverable test matrix:
  (a) N successful + M rate-limited -> plan selects exactly the M (+ empty/
      unattempted), never the N successful.
  (b) simulated provider that rate-limits primary then succeeds on alternate
      -> the failover path is exercised and the task ends successful.
  (c) idempotence: re-running on a now-complete dir yields an empty plan.
  (d) generic: no workspace literal anywhere in the planner output logic.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load_planner():
    path = _TOOLS / "hunt-resume-planner.py"
    spec = importlib.util.spec_from_file_location("_hrp", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


HRP = _load_planner()
# Reuse the real classifier the planner uses (no re-derivation).
_CLASSIFY = HRP._import_health_check().classify_record


def _ok_record(task_id: str, provider: str = "mimo") -> dict:
    return {
        "task_id": task_id, "status": "ok", "provider": provider,
        "error": None,
        "result": '```json\n{"applies_to_target":"yes",'
                  '"file_path_hint":"src/Vault.sol"}\n```',
        "function_anchor": {"file": "src/Vault.sol", "fn": "deposit"},
    }


def _rate_limited_record(task_id: str, provider: str = "mimo") -> dict:
    return {
        "task_id": task_id, "status": "failed", "provider": provider,
        "error": "retry-max-exhausted: rate-limited",
        "result": None,
    }


def _empty_record(task_id: str, provider: str = "mimo") -> dict:
    return {
        "task_id": task_id, "status": "ok", "provider": provider,
        "error": None,
        "result": '```json\n{"applies_to_target":"no","file_path_hint":"?"}\n```',
        "function_anchor": {"file": "?", "fn": "?"},
    }


def _write_record_dir(d: Path, records: list[dict]) -> None:
    for rec in records:
        (d / f"{rec['task_id']}.json").write_text(
            json.dumps(rec), encoding="utf-8"
        )


def _write_batch(path: Path, task_ids: list[str], provider: str = "mimo") -> None:
    with path.open("w", encoding="utf-8") as fh:
        for tid in task_ids:
            fh.write(json.dumps({
                "task_id": tid,
                "prompt": f"hunt prompt for {tid}",
                "provider": provider,
                "task_type": "per_fn_hunt",
                "max_output_tokens": 1500,
            }) + "\n")


# ---- simulated provider: rate-limits primary, succeeds on alternate ----
class SimProvider:
    """Mock LLM dispatch: the `primary` provider always 429s; any other
    provider succeeds. Used to exercise the failover path end-to-end."""

    def __init__(self, primary: str) -> None:
        self.primary = primary
        self.calls: list[tuple[str, str]] = []

    def call(self, task_id: str, provider: str) -> tuple[bool, str]:
        self.calls.append((task_id, provider))
        if provider == self.primary:
            return (False, "rate-limited")  # 429 -> retry-max-exhausted
        return (True, '{"applies_to_target":"yes","file_path_hint":"src/X.sol"}')


class TestSelection(unittest.TestCase):
    def test_a_selects_exactly_rate_limited_never_success(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "mega_perfn_GENERIC_KEY6"
            d.mkdir()
            N, M = 5, 3
            recs = [_ok_record(f"t_ok_{i:02d}") for i in range(N)]
            recs += [_rate_limited_record(f"t_rl_{i:02d}") for i in range(M)]
            _write_record_dir(d, recs)
            plan, _ = HRP.build_resume_plan(
                d, _CLASSIFY, ["mimo", "deepseek-flash", "kimi"],
                rehunt_empty=True,
            )
            self.assertEqual(plan["counts"]["success"], N)
            self.assertEqual(plan["counts"]["rate_limited"], M)
            # exactly the M rate-limited selected; zero success selected
            self.assertEqual(plan["resume_task_count"], M)
            sel_ids = {e["task_id"] for e in plan["resume_tasks"]}
            self.assertTrue(all(i.startswith("t_rl_") for i in sel_ids))
            self.assertFalse(any(i.startswith("t_ok_") for i in sel_ids))

    def test_a_empty_records_also_selected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "mega_perfn_GENERIC_KEY6"
            d.mkdir()
            recs = [_ok_record("t_ok_00")]
            recs += [_empty_record("t_empty_00"), _empty_record("t_empty_01")]
            _write_record_dir(d, recs)
            plan, _ = HRP.build_resume_plan(
                d, _CLASSIFY, ["mimo", "kimi"], rehunt_empty=True
            )
            self.assertEqual(plan["resume_task_count"], 2)
            # --no-rehunt-empty excludes them
            plan2, _ = HRP.build_resume_plan(
                d, _CLASSIFY, ["mimo", "kimi"], rehunt_empty=False
            )
            self.assertEqual(plan2["resume_task_count"], 0)

    def test_unattempted_detected_with_batch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "mega_perfn_GENERIC_KEY6"
            d.mkdir()
            _write_record_dir(d, [_ok_record("t_00"), _ok_record("t_01")])
            batch_path = Path(td) / "batch.jsonl"
            # batch has 4 tasks; only 2 have result files -> 2 unattempted
            _write_batch(batch_path, ["t_00", "t_01", "t_02", "t_03"])
            batch = HRP._read_jsonl(batch_path)
            plan, _ = HRP.build_resume_plan(
                d, _CLASSIFY, ["mimo", "kimi"], original_batch=batch
            )
            self.assertEqual(plan["unattempted_in_batch"], 2)
            sel = {e["task_id"] for e in plan["resume_tasks"]}
            self.assertEqual(sel, {"t_02", "t_03"})


class TestFailover(unittest.TestCase):
    def test_pick_failover_distinct(self) -> None:
        self.assertEqual(
            HRP.pick_failover_provider("mimo", ["mimo", "deepseek-flash"]),
            "deepseek-flash",
        )
        # single-provider deployment -> no failover possible
        self.assertIsNone(HRP.pick_failover_provider("mimo", ["mimo"]))

    def test_b_failover_path_ends_successful(self) -> None:
        """Simulated provider rate-limits primary; planner routes the task to
        an alternate; re-dispatch via the sim succeeds. End state: success."""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "mega_perfn_GENERIC_KEY6"
            d.mkdir()
            # one task rate-limited on the primary provider 'mimo'
            _write_record_dir(d, [_rate_limited_record("t_rl_00", provider="mimo")])
            batch_path = Path(td) / "batch.jsonl"
            _write_batch(batch_path, ["t_rl_00"], provider="mimo")
            batch = HRP._read_jsonl(batch_path)

            providers = ["mimo", "deepseek-flash"]
            plan, batch_by_id = HRP.build_resume_plan(
                d, _CLASSIFY, providers, original_batch=batch
            )
            # the rate-limited task got a failover provider != mimo
            entry = next(e for e in plan["resume_tasks"] if e["task_id"] == "t_rl_00")
            self.assertEqual(entry["reason"], "rate_limited")
            self.assertTrue(entry["failover_available"])
            self.assertEqual(entry["failover_provider"], "deepseek-flash")

            # write the resume batch -> the rehydrated task routes to the alt
            resume_out = Path(td) / "resume_batch.jsonl"
            written, missing = HRP.write_resume_batch(plan, batch_by_id, resume_out)
            self.assertEqual(written, 1)
            self.assertEqual(missing, 0)
            resume_tasks = HRP._read_jsonl(resume_out)
            self.assertEqual(resume_tasks[0]["provider"], "deepseek-flash")

            # now SIMULATE the re-dispatch: primary 429s, alternate succeeds
            sim = SimProvider(primary="mimo")
            t = resume_tasks[0]
            ok, _result = sim.call(t["task_id"], t["provider"])
            self.assertTrue(ok, "failover provider should succeed")
            # and assert: had we re-used the primary, it would have 429'd again
            ok_primary, _ = sim.call("t_rl_00", "mimo")
            self.assertFalse(ok_primary)

    def test_no_alternate_provider_is_honest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "mega_perfn_GENERIC_KEY6"
            d.mkdir()
            _write_record_dir(d, [_rate_limited_record("t_rl_00", provider="mimo")])
            plan, _ = HRP.build_resume_plan(d, _CLASSIFY, ["mimo"])  # only one
            entry = plan["resume_tasks"][0]
            self.assertFalse(entry["failover_available"])
            self.assertIsNone(entry["failover_provider"])


class TestIdempotence(unittest.TestCase):
    def test_c_complete_dir_yields_empty_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "mega_perfn_GENERIC_KEY6"
            d.mkdir()
            # all-success dir (e.g. after a successful resume re-dispatch)
            _write_record_dir(d, [_ok_record(f"t_{i:02d}") for i in range(6)])
            plan, _ = HRP.build_resume_plan(d, _CLASSIFY, ["mimo", "kimi"])
            self.assertEqual(plan["resume_task_count"], 0)
            self.assertTrue(plan["idempotent_empty"])

    def test_c_resume_then_recomplete_is_empty(self) -> None:
        """Full loop: rate-limited dir -> plan non-empty; flip the failed
        record to success (simulating a successful failover re-dispatch) ->
        re-plan is empty."""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "mega_perfn_GENERIC_KEY6"
            d.mkdir()
            _write_record_dir(d, [_ok_record("t_00"),
                                  _rate_limited_record("t_01")])
            plan1, _ = HRP.build_resume_plan(d, _CLASSIFY, ["mimo", "kimi"])
            self.assertEqual(plan1["resume_task_count"], 1)
            # simulate successful re-dispatch overwriting the failed record
            (d / "t_01.json").write_text(json.dumps(_ok_record("t_01")),
                                         encoding="utf-8")
            plan2, _ = HRP.build_resume_plan(d, _CLASSIFY, ["mimo", "kimi"])
            self.assertEqual(plan2["resume_task_count"], 0)
            self.assertTrue(plan2["idempotent_empty"])


class TestProviderRegistry(unittest.TestCase):
    def test_load_providers_from_budget_dict(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "budget.json"
            cfg.write_text(json.dumps({
                "providers": {"kimi": {}, "minimax": {}, "deepseek-flash": {}}
            }), encoding="utf-8")
            provs = HRP.load_providers(cfg)
            self.assertIn("kimi", provs)
            self.assertIn("deepseek-flash", provs)

    def test_load_providers_from_list_override(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            pj = Path(td) / "p.json"
            pj.write_text(json.dumps(["a", "b"]), encoding="utf-8")
            self.assertEqual(HRP.load_providers(Path("/nonexistent"), pj),
                             ["a", "b"])

    def test_d_generic_no_workspace_literal(self) -> None:
        """Planner output carries no hardcoded workspace name; the record_dir
        is the only ws-specific string and it is caller-supplied."""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "mega_perfn_ANYTHING_KEY6"
            d.mkdir()
            _write_record_dir(d, [_rate_limited_record("t_00")])
            plan, _ = HRP.build_resume_plan(d, _CLASSIFY, ["x", "y"])
            blob = json.dumps(plan)
            for lit in ("dydx", "morpho", "spark", "hyperbridge", "near"):
                self.assertNotIn(lit, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
