#!/usr/bin/env python3
"""Tests for ``tools/campaign-state.py``.

Hermetic: each test creates a throwaway workspace under ``tempfile`` and
invokes the script as a subprocess so we exercise the same exit-code /
stdout-JSON contract that downstream V5 wrappers (PRs 3-6) will rely on.

Coverage map:

  init / idempotent
    test_init_creates_workspace_layout    init lays out .auditooor/<id>/{config,artifacts,telemetry}
    test_init_idempotent_does_not_dup     init twice -> single state file, init-noop telemetry,
                                          created_at preserved (Codex acceptance #1)
    test_init_rejects_bad_lane            unknown --lane -> non-zero rc
    test_init_rejects_bad_id              non-regex --id -> rc=1, classification=bad-input
    test_init_default_models              omitted --models -> kimi,minimax,claude

  resume
    test_resume_partial_campaign          init -> resume -> status=running, telemetry preserved
                                          (Codex acceptance #2)
    test_resume_missing_campaign          unknown --id -> rc=1, classification=not-found
    test_resume_recreates_telemetry       deleted telemetry.jsonl is recreated on resume
                                          (resume must not silently lose telemetry)
    test_resume_rejects_completed         resume on completed campaign -> classification=already-completed

  complete / summary
    test_complete_writes_summary          completed campaign has summary.json with inputs,
                                          artifacts, survivors, rejections, tests, verdicts,
                                          next_action (Codex acceptance #3)
    test_complete_with_external_summary   --summary path is merged; campaign_id pinned
    test_complete_then_resume_blocked     completed campaign cannot be re-resumed

  validate / promotion gate
    test_validate_passes_on_fresh_init    just-init'd campaign passes validate
    test_validate_detects_corruption      hand-edited config.json with bad enum -> schema-violation
    test_running_requires_next_action     running with empty next_action -> rejected (orphan guard)
    test_promoted_finding_requires_proof  finding.v1 schema enforces reproduction_plan OR
                                          source_only_or_pre_deployment for status==promoted
                                          (Codex acceptance #4)

  list
    test_list_empty_workspace             list on empty workspace -> classification=ok, [] campaigns
    test_list_multiple_campaigns          list shows all campaigns with status

The promoted-without-proof guard (Codex acceptance #4) lives in
finding.v1.json. We exercise it here by re-implementing the same
conditional rule in pure Python and confirming the JSON matches what the
schema would assert (the helper in this PR is campaign-only; finding
state lives in PR 5).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "campaign-state.py"
SCHEMAS_DIR = ROOT / "docs" / "schemas"


def _run(*args: str) -> tuple[int, str, str]:
    """Invoke campaign-state.py and capture (rc, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _last_json_line(out: str) -> dict:
    """campaign-state.py prints one JSON object per invocation. Some
    subcommands print multiple lines (e.g. list --human); take the final
    JSON object on stdout."""
    lines = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise AssertionError(f"no JSON line in stdout: {out!r}")
    return json.loads(lines[-1])


class InitTests(unittest.TestCase):
    def test_init_creates_workspace_layout(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            rc, out, _ = _run("init", "--workspace", ws,
                              "--lane", "source_mine",
                              "--id", "test-001")
            self.assertEqual(rc, 0, msg=out)
            payload = _last_json_line(out)
            self.assertEqual(payload["classification"], "ok")
            self.assertEqual(payload["action"], "init")
            campaign_dir = Path(ws) / ".auditooor" / "campaigns" / "test-001"
            self.assertTrue((campaign_dir / "config.json").exists())
            self.assertTrue((campaign_dir / "telemetry.jsonl").exists())
            self.assertTrue((campaign_dir / "artifacts").is_dir())

    def test_init_idempotent_does_not_dup(self) -> None:
        """Codex acceptance test #1."""
        with tempfile.TemporaryDirectory() as ws:
            rc1, out1, _ = _run("init", "--workspace", ws,
                                "--lane", "source_mine", "--id", "idem-1")
            self.assertEqual(rc1, 0, msg=out1)
            cfg_path = Path(ws) / ".auditooor" / "campaigns" / "idem-1" / "config.json"
            first_state = json.loads(cfg_path.read_text())
            first_created = first_state["created_at"]

            rc2, out2, _ = _run("init", "--workspace", ws,
                                "--lane", "source_mine", "--id", "idem-1")
            self.assertEqual(rc2, 0, msg=out2)
            payload = _last_json_line(out2)
            self.assertEqual(payload["action"], "init-noop")

            second_state = json.loads(cfg_path.read_text())
            self.assertEqual(first_created, second_state["created_at"])
            # Confirm we have exactly one campaign dir, not duplicates.
            campaigns = list((Path(ws) / ".auditooor" / "campaigns").iterdir())
            self.assertEqual([c.name for c in campaigns], ["idem-1"])
            # Telemetry should record both events.
            tel = (Path(ws) / ".auditooor" / "campaigns" / "idem-1" / "telemetry.jsonl").read_text()
            events = [json.loads(ln)["event"] for ln in tel.splitlines() if ln.strip()]
            self.assertIn("init", events)
            self.assertIn("init-noop", events)

    def test_init_rejects_bad_lane(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            rc, out, err = _run("init", "--workspace", ws,
                                "--lane", "bogus", "--id", "x")
            # argparse rejects the unknown choice with rc=2 — that is fine
            # because it is still a hard rejection. We only care that the
            # process refuses the bad input.
            self.assertNotEqual(rc, 0)
            self.assertTrue(err or out)

    def test_init_rejects_bad_id(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            rc, out, _ = _run("init", "--workspace", ws,
                              "--lane", "source_mine",
                              "--id", "bad id with spaces")
            self.assertNotEqual(rc, 0, msg=out)
            payload = _last_json_line(out)
            self.assertEqual(payload["classification"], "bad-input")

    def test_init_default_models(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            rc, out, _ = _run("init", "--workspace", ws,
                              "--lane", "fuzz", "--id", "f-001")
            self.assertEqual(rc, 0, msg=out)
            cfg_path = Path(ws) / ".auditooor" / "campaigns" / "f-001" / "config.json"
            state = json.loads(cfg_path.read_text())
            self.assertEqual(state["models"], ["kimi", "minimax", "claude"])
            self.assertEqual(state["status"], "created")
            self.assertEqual(state["lane"], "fuzz")


class ResumeTests(unittest.TestCase):
    def test_resume_partial_campaign(self) -> None:
        """Codex acceptance test #2."""
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "source_mine", "--id", "r-001")
            tel_path = Path(ws) / ".auditooor" / "campaigns" / "r-001" / "telemetry.jsonl"
            tel_before = tel_path.read_text()

            rc, out, _ = _run("resume", "--workspace", ws, "--id", "r-001",
                              "--next-action", "scan packets/A")
            self.assertEqual(rc, 0, msg=out)
            payload = _last_json_line(out)
            self.assertEqual(payload["state"]["status"], "running")
            self.assertEqual(payload["state"]["next_action"], "scan packets/A")

            tel_after = tel_path.read_text()
            # Append-only: prior telemetry must still be present.
            self.assertTrue(tel_after.startswith(tel_before),
                            msg="telemetry.jsonl was truncated on resume")
            self.assertIn("\"event\": \"resume\"", tel_after)

    def test_resume_missing_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            rc, out, _ = _run("resume", "--workspace", ws, "--id", "ghost")
            self.assertEqual(rc, 1, msg=out)
            payload = _last_json_line(out)
            self.assertEqual(payload["classification"], "not-found")

    def test_resume_recreates_telemetry(self) -> None:
        """Foot-gun guard: resume must not silently lose telemetry even if
        an interrupted init left the file missing."""
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "fuzz", "--id", "tlm-001")
            tel = Path(ws) / ".auditooor" / "campaigns" / "tlm-001" / "telemetry.jsonl"
            tel.unlink()
            rc, out, _ = _run("resume", "--workspace", ws, "--id", "tlm-001",
                              "--next-action", "ok")
            self.assertEqual(rc, 0, msg=out)
            self.assertTrue(tel.exists())
            self.assertIn("resume", tel.read_text())

    def test_resume_rejects_completed(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "source_mine", "--id", "c-1")
            _run("complete", "--workspace", ws, "--id", "c-1")
            rc, out, _ = _run("resume", "--workspace", ws, "--id", "c-1",
                              "--next-action", "ignored")
            self.assertEqual(rc, 1, msg=out)
            payload = _last_json_line(out)
            self.assertEqual(payload["classification"], "already-completed")


class CompleteTests(unittest.TestCase):
    def test_complete_writes_summary(self) -> None:
        """Codex acceptance test #3."""
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "source_mine", "--id", "s-1")
            rc, out, _ = _run("complete", "--workspace", ws, "--id", "s-1")
            self.assertEqual(rc, 0, msg=out)
            summary = Path(ws) / ".auditooor" / "campaigns" / "s-1" / "summary.json"
            self.assertTrue(summary.exists())
            data = json.loads(summary.read_text())
            for field in ("inputs", "artifacts", "survivors", "rejections",
                          "tests", "verdicts", "next_action"):
                self.assertIn(field, data, msg=f"summary missing {field}")
            self.assertEqual(data["campaign_id"], "s-1")
            cfg = json.loads((Path(ws) / ".auditooor" / "campaigns" / "s-1" /
                              "config.json").read_text())
            self.assertEqual(cfg["status"], "completed")
            self.assertTrue(cfg.get("completed_at"))
            self.assertTrue(cfg.get("summary_path"))

    def test_complete_with_external_summary(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "fuzz", "--id", "ext-1")
            ext = Path(ws) / "out.json"
            ext.write_text(json.dumps({
                "operator_note": "manually approved",
                "verdicts": {"survivors": 2, "rejections": 1},
                "campaign_id": "WRONG-ID-SHOULD-BE-OVERRIDDEN",
            }))
            rc, out, _ = _run("complete", "--workspace", ws, "--id", "ext-1",
                              "--summary", str(ext))
            self.assertEqual(rc, 0, msg=out)
            summary = json.loads((Path(ws) / ".auditooor" / "campaigns" /
                                  "ext-1" / "summary.json").read_text())
            # Operator note preserved
            self.assertEqual(summary["operator_note"], "manually approved")
            # campaign_id pinned to the real campaign — never trust caller
            self.assertEqual(summary["campaign_id"], "ext-1")
            # Operator-supplied verdicts win on collision
            self.assertEqual(summary["verdicts"], {"survivors": 2, "rejections": 1})

    def test_complete_then_resume_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "deep", "--id", "blk-1")
            _run("complete", "--workspace", ws, "--id", "blk-1")
            rc, out, _ = _run("resume", "--workspace", ws, "--id", "blk-1")
            self.assertEqual(rc, 1, msg=out)
            self.assertEqual(_last_json_line(out)["classification"],
                             "already-completed")


class ValidateTests(unittest.TestCase):
    def test_validate_passes_on_fresh_init(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "math", "--id", "v-1")
            rc, out, _ = _run("validate", "--workspace", ws, "--id", "v-1")
            self.assertEqual(rc, 0, msg=out)
            self.assertEqual(_last_json_line(out)["classification"], "ok")

    def test_validate_detects_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "math", "--id", "v-2")
            cfg = Path(ws) / ".auditooor" / "campaigns" / "v-2" / "config.json"
            data = json.loads(cfg.read_text())
            data["lane"] = "totally_made_up_lane"  # invalid enum
            cfg.write_text(json.dumps(data))
            rc, out, _ = _run("validate", "--workspace", ws, "--id", "v-2")
            self.assertEqual(rc, 2, msg=out)
            payload = _last_json_line(out)
            self.assertEqual(payload["classification"], "schema-violation")
            self.assertTrue(any("lane" in e for e in payload["errors"]))

    def test_running_requires_next_action(self) -> None:
        """Orphan-campaign guard: a running campaign must always carry a
        next_action so an operator can pick it up."""
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "fuzz", "--id", "na-1")
            cfg = Path(ws) / ".auditooor" / "campaigns" / "na-1" / "config.json"
            data = json.loads(cfg.read_text())
            data["status"] = "running"
            data["next_action"] = ""
            cfg.write_text(json.dumps(data))
            rc, out, _ = _run("validate", "--workspace", ws, "--id", "na-1")
            self.assertEqual(rc, 2, msg=out)
            payload = _last_json_line(out)
            self.assertEqual(payload["classification"], "schema-violation")
            self.assertTrue(any("next_action" in e for e in payload["errors"]))

    def test_promoted_finding_requires_proof(self) -> None:
        """Codex acceptance test #4. The campaign-state helper does not
        own findings yet (PR 5), but the schema must already enforce the
        rule. We re-implement the conditional rule here to confirm the
        schema's intent matches the gate downstream code will rely on."""
        finding_schema = json.loads((SCHEMAS_DIR / "finding.v1.json").read_text())

        # Locate the conditional that fires on status==promoted.
        promoted_clause = None
        for clause in finding_schema.get("allOf", []):
            cond = clause.get("if", {}).get("properties", {}).get("status", {})
            if cond.get("const") == "promoted":
                promoted_clause = clause
                break
        self.assertIsNotNone(promoted_clause,
                             msg="finding.v1.json must conditionally constrain "
                                 "status==promoted")
        then = promoted_clause["then"]
        any_of = then.get("anyOf")
        self.assertIsNotNone(any_of,
                             msg="status==promoted must require reproduction_plan "
                                 "OR source_only_or_pre_deployment via anyOf")
        self.assertIn(
            "reproduction_plan",
            {req for clause in any_of for req in clause.get("required", [])},
        )
        # Either a required reproduction_plan branch OR a source_only branch.
        has_source_only_branch = False
        for clause in any_of:
            props = clause.get("properties", {})
            if props.get("source_only_or_pre_deployment", {}).get("const") is True:
                has_source_only_branch = True
                break
        self.assertTrue(has_source_only_branch,
                        msg="anyOf must include source_only_or_pre_deployment=true branch")
        self.assertIn("promoted_at", then.get("required", []))


class ListTests(unittest.TestCase):
    def test_list_empty_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            rc, out, _ = _run("list", "--workspace", ws, "--json")
            self.assertEqual(rc, 0, msg=out)
            payload = _last_json_line(out)
            self.assertEqual(payload["classification"], "ok")
            self.assertEqual(payload["campaigns"], [])

    def test_list_multiple_campaigns(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "source_mine", "--id", "L-001")
            _run("init", "--workspace", ws, "--lane", "fuzz", "--id", "L-002")
            _run("complete", "--workspace", ws, "--id", "L-001")
            rc, out, _ = _run("list", "--workspace", ws, "--json")
            self.assertEqual(rc, 0, msg=out)
            payload = _last_json_line(out)
            ids = {c["campaign_id"]: c["status"] for c in payload["campaigns"]}
            self.assertEqual(ids, {"L-001": "completed", "L-002": "created"})


class FindingValidationTests(unittest.TestCase):
    """Codex acceptance #4 + Minimax M-2: the campaign-state helper now
    owns the promotion gate so PR 5 can call it without re-inventing
    rules. We exercise the new ``validate-finding`` subcommand."""

    def _write(self, ws: Path, body: dict) -> Path:
        path = ws / "f.json"
        path.write_text(json.dumps(body))
        return path

    def _base(self) -> dict:
        return {
            "schema_version": "finding.v1",
            "finding_id": "F-001",
            "campaign_id": "C-001",
            "workspace": "/tmp/ws",
            "lane": "source_mine",
            "status": "candidate",
            "title": "test",
            "files": ["src/Foo.sol"],
            "claim": "thing",
            "created_at": "2026-04-27T00:00:00Z",
            "updated_at": "2026-04-27T00:00:00Z",
        }

    def test_validate_finding_candidate_passes(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            path = self._write(Path(ws), self._base())
            rc, out, _ = _run("validate-finding", "--path", str(path))
            self.assertEqual(rc, 0, msg=out)
            self.assertEqual(_last_json_line(out)["classification"], "ok")

    def test_validate_finding_promoted_without_proof_fails(self) -> None:
        """Codex acceptance #4 — direct subcommand-level enforcement."""
        with tempfile.TemporaryDirectory() as ws:
            body = self._base()
            body["status"] = "promoted"
            body["promoted_at"] = "2026-04-27T01:00:00Z"
            path = self._write(Path(ws), body)
            rc, out, _ = _run("validate-finding", "--path", str(path))
            self.assertEqual(rc, 2, msg=out)
            payload = _last_json_line(out)
            self.assertEqual(payload["classification"], "schema-violation")
            self.assertTrue(any("reproduction_plan" in e
                                for e in payload["errors"]))

    def test_validate_finding_promoted_with_repro_plan_passes(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            body = self._base()
            body["status"] = "promoted"
            body["promoted_at"] = "2026-04-27T01:00:00Z"
            body["reproduction_plan"] = "forge test --match-test test_X"
            path = self._write(Path(ws), body)
            rc, out, _ = _run("validate-finding", "--path", str(path))
            self.assertEqual(rc, 0, msg=out)

    def test_validate_finding_promoted_source_only_passes(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            body = self._base()
            body["status"] = "promoted"
            body["promoted_at"] = "2026-04-27T01:00:00Z"
            body["source_only_or_pre_deployment"] = True
            path = self._write(Path(ws), body)
            rc, out, _ = _run("validate-finding", "--path", str(path))
            self.assertEqual(rc, 0, msg=out)

    def test_validate_finding_rejected_requires_reason(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            body = self._base()
            body["status"] = "rejected"
            path = self._write(Path(ws), body)
            rc, out, _ = _run("validate-finding", "--path", str(path))
            self.assertEqual(rc, 2, msg=out)
            self.assertTrue(any("rejection_reason" in e
                                for e in _last_json_line(out)["errors"]))

    def test_validate_finding_rejects_unknown_field(self) -> None:
        """additionalProperties:false parity for findings."""
        with tempfile.TemporaryDirectory() as ws:
            body = self._base()
            body["mystery_field"] = "should-fail"
            path = self._write(Path(ws), body)
            rc, out, _ = _run("validate-finding", "--path", str(path))
            self.assertEqual(rc, 2, msg=out)
            self.assertTrue(any("mystery_field" in e
                                for e in _last_json_line(out)["errors"]))


class RejectCampaignTests(unittest.TestCase):
    """Minimax M-1: rejected campaigns must carry a rejection_reason or
    they orphan. The new ``reject`` subcommand enforces that gate."""

    def test_reject_requires_reason_via_argparse(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "source_mine", "--id", "rj-1")
            # Missing --reason -> argparse rejects with rc=2
            rc, _, _ = _run("reject", "--workspace", ws, "--id", "rj-1")
            self.assertNotEqual(rc, 0)

    def test_reject_writes_reason(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "source_mine", "--id", "rj-2")
            rc, out, _ = _run("reject", "--workspace", ws, "--id", "rj-2",
                              "--reason", "no in-scope verifier surface")
            self.assertEqual(rc, 0, msg=out)
            cfg = json.loads((Path(ws) / ".auditooor" / "campaigns" /
                              "rj-2" / "config.json").read_text())
            self.assertEqual(cfg["status"], "rejected")
            self.assertEqual(cfg["rejection_reason"],
                             "no in-scope verifier surface")
            # validate-roundtrip still passes after reject
            rc2, out2, _ = _run("validate", "--workspace", ws, "--id", "rj-2")
            self.assertEqual(rc2, 0, msg=out2)

    def test_reject_blocks_terminal_states(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "fuzz", "--id", "rj-3")
            _run("complete", "--workspace", ws, "--id", "rj-3")
            rc, out, _ = _run("reject", "--workspace", ws, "--id", "rj-3",
                              "--reason", "n/a")
            self.assertEqual(rc, 1, msg=out)


class AdditionalPropertiesTests(unittest.TestCase):
    """Minimax M-3 + Kimi K-1 disprove: the python validator must mirror
    schema's additionalProperties:false for campaigns AND must NOT reject
    legitimately declared extension fields like ``notes`` or
    ``lane_config``."""

    def test_unknown_field_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "source_mine", "--id", "x-1")
            cfg = Path(ws) / ".auditooor" / "campaigns" / "x-1" / "config.json"
            data = json.loads(cfg.read_text())
            data["secret_debug_token"] = "leaked"
            cfg.write_text(json.dumps(data))
            rc, out, _ = _run("validate", "--workspace", ws, "--id", "x-1")
            self.assertEqual(rc, 2, msg=out)
            self.assertTrue(any("secret_debug_token" in e
                                for e in _last_json_line(out)["errors"]))

    def test_declared_optional_fields_accepted(self) -> None:
        """Kimi K-1 hallucinated that notes would fail; this confirms the
        schema and python validator both accept declared optional fields."""
        with tempfile.TemporaryDirectory() as ws:
            _run("init", "--workspace", ws, "--lane", "fuzz", "--id", "x-2")
            cfg = Path(ws) / ".auditooor" / "campaigns" / "x-2" / "config.json"
            data = json.loads(cfg.read_text())
            data["notes"] = ["operator note"]
            data["lane_config"] = {"duration_seconds": 3600}
            cfg.write_text(json.dumps(data))
            rc, out, _ = _run("validate", "--workspace", ws, "--id", "x-2")
            self.assertEqual(rc, 0, msg=out)


class SchemaShapeTests(unittest.TestCase):
    """Ensure the three v1 schemas exist and are valid JSON. Loose: the
    rich behavioral checks live in the subprocess tests above."""

    def test_schemas_exist_and_are_valid_json(self) -> None:
        for name in ("campaign.v1.json", "finding.v1.json", "candidate.v1.json"):
            path = SCHEMAS_DIR / name
            self.assertTrue(path.exists(), msg=f"missing schema: {path}")
            data = json.loads(path.read_text())
            self.assertEqual(data.get("$schema"),
                             "http://json-schema.org/draft-07/schema#")
            self.assertIn("title", data)
            self.assertIn("required", data)


if __name__ == "__main__":
    unittest.main()
