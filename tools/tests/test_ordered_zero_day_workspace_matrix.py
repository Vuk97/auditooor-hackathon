import json
import hashlib
import importlib.util
import base64
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures" / "ordered_zero_day_workspace_matrix.json"


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


APPLICABILITY = load_module("ordered_zero_day_applicability", "pipeline-applicability.py")
LEDGER = load_module("ordered_zero_day_awareness_ledger", "awareness-ledger.py")
FREEZER = load_module("ordered_zero_day_freezer", "zero-day-freeze-compiler.py")
EXECUTOR = load_module("ordered_zero_day_executor", "pipeline-executor.py")
PIN = "commit:ordered-zero-day-matrix"
EXTENSIONS = {"go": ".go", "oscript": ".aa", "rust": ".rs", "solidity": ".sol"}
LOGICAL = {
    "target_unit": "fixture.CUT",
    "asset_invariant": "fixture asset remains conserved",
    "violation_relation": "fixture debit can diverge",
    "actor_model": "permissionless fixture caller",
    "impact_class": "fixture loss of funds",
}


def source_row(source_id, kind, state, **extra):
    content = f"reviewed awareness evidence {source_id}"
    return {
        "source_id": source_id,
        "source_kind": kind,
        "pin_binding": PIN,
        "content": content,
        "source_ref": f"fixture://{kind}/{source_id}",
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "awareness_state": state,
        **extra,
    }


def reviewed_candidate(name, source_ids):
    return {
        "candidate_id": name,
        "source_ids": source_ids,
        "pin_binding": PIN,
        "root_cause": "reviewed root cause",
        "affected_path": "reviewed/path",
        "required_fix": "reviewed required fix",
        "obligation_logical": LOGICAL,
        "reviewer_rationale": "A named reviewer bound all source evidence to this identity.",
        "semantic_review": {
            "reviewer_id": "fixture-reviewer",
            "reviewed_at": "2026-07-18T12:00:00Z",
            "method": "contextual semantic review",
            "rationale": "The reviewed source records the team disposition.",
            "source_ids": source_ids,
        },
    }


def executor_command(output: Path, content: str) -> list[str]:
    body = (
        "from pathlib import Path; "
        f"output=Path(r'{output}'); output.parent.mkdir(parents=True, exist_ok=True); "
        f"output.write_text({content!r}, encoding='utf-8')"
    )
    return encoded_python(body)


def encoded_python(body: str) -> list[str]:
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    return [sys.executable, "-c", f"import base64;exec(base64.b64decode('{encoded}'))"]


def executor_manifest(workspace: Path, version: Path) -> dict:
    producer = workspace / "source_snapshot.json"
    reasoner = workspace / "reasoner.json"
    depth = workspace / "depth.json"
    drive = workspace / "drive.json"
    producer_body = (
        "from pathlib import Path; "
        f"version=Path(r'{version}').read_text(encoding='utf-8'); "
        f"output=Path(r'{producer}'); output.write_text('{{\"version\":\"' + version.strip() + '\"}}', encoding='utf-8')"
    )
    steps = []
    for index, step_id, produces, consumes, target in (
        (0, "producer", "source_snapshot", [], encoded_python(producer_body)),
        (1, "reasoner", "reasoner_output", ["source_snapshot"], executor_command(reasoner, "{}")),
        (2, "depth", "depth_output", ["reasoner_output"], executor_command(depth, "{}")),
        (3, "drive", "drive_output", ["depth_output"], executor_command(drive, "{}")),
    ):
        steps.append({
            "step_id": step_id,
            "order_index": index,
            "run_sequence": index,
            "phase": "reasoning" if index == 1 else "drive",
            "execution_target": target,
            "applicability_probe": "always",
            "depends_on": [] if index == 0 else [steps[-1]["step_id"]],
            "consumes": consumes,
            "produces": [produces],
            "validators": ["json"],
            "invalidates": [],
            "terminal_output": True,
            "required": True,
        })
    return {
        "schema": "auditooor.pipeline_manifest.v2",
        "expected_step_count": len(steps),
        "steps": steps,
        "artifact_contracts": [
            {"id": "source_snapshot", "path": str(producer.relative_to(workspace)), "kind": "file", "validators": ["json"]},
            {"id": "reasoner_output", "path": str(reasoner.relative_to(workspace)), "kind": "file", "validators": ["json"]},
            {"id": "depth_output", "path": str(depth.relative_to(workspace)), "kind": "file", "validators": ["json"]},
            {"id": "drive_output", "path": str(drive.relative_to(workspace)), "kind": "file", "validators": ["json"]},
        ],
        "applicability_probes": [{"id": "always", "kind": "always"}],
        "validators": ["json"],
    }


class OrderedZeroDayWorkspaceMatrixTest(unittest.TestCase):
    def test_matrix_covers_requested_languages_and_dispositions(self):
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual("auditooor.ordered_zero_day_workspace_matrix.v1", payload["schema"])
        cases = payload["cases"]
        self.assertEqual({"obyte-oscript-applicable", "nuva-go-fixed-live", "sei-go-known-issue", "solidity-control-inapplicable", "rust-control-applicable"}, {case["name"] for case in cases})
        self.assertEqual({"oscript", "go", "rust", "solidity"}, {case["language"] for case in cases})
        self.assertTrue(all(case["queue_role"] == "candidate_leads" for case in cases))
        by_name = {case["name"]: case for case in cases}
        self.assertTrue(by_name["obyte-oscript-applicable"]["expected_novelty_blocked"])
        self.assertFalse(by_name["nuva-go-fixed-live"]["expected_novelty_blocked"])
        self.assertTrue(by_name["sei-go-known-issue"]["expected_novelty_blocked"])
        self.assertFalse(by_name["solidity-control-inapplicable"]["applicable"])

    def test_matrix_exercises_machine_applicability_and_semantic_awareness_routing(self):
        cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
        probe_manifest = {
            "applicability_probes": [
                {"id": "candidate-language", "kind": "language_any", "languages": ["go", "oscript", "rust"]}
            ]
        }
        for case in cases:
            with self.subTest(case=case["name"]), tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp)
                source = workspace / f"cut{EXTENSIONS[case['language']]}"
                source.write_text("fixture source\n", encoding="utf-8")
                auditooor = workspace / ".auditooor"
                auditooor.mkdir()
                (auditooor / "inscope_units.jsonl").write_text(
                    json.dumps({"file": source.name, "lang": case["language"]}) + "\n",
                    encoding="utf-8",
                )
                applicability = APPLICABILITY.evaluate_probe(probe_manifest, "candidate-language", workspace)
                self.assertEqual(case["applicable"], applicability["result"])
                if not case["applicable"]:
                    self.assertEqual("not_applicable", case["awareness_state"])
                    continue

                state = "marked_fixed" if case["awareness_state"] == "marked_fixed_live" else case["awareness_state"]
                rows = []
                for index, kind in enumerate(sorted(LEDGER.SOURCE_KINDS)):
                    extra = {"fix_verification": "bypassable"} if index == 0 and state == "marked_fixed" else {}
                    rows.append(source_row(f"{case['name']}-{index}", kind, state, **extra))
                source_ids = [row["source_id"] for row in rows]
                result = LEDGER.build_ledger(
                    {
                        "audit_pin": PIN,
                        "expected_sources": [{
                            "source_id": row["source_id"], "source_kind": row["source_kind"],
                            "source_ref": row["source_ref"], "pin_binding": row["pin_binding"],
                        } for row in rows],
                        "evidence_rows": rows,
                        "candidates": [reviewed_candidate(case["name"], source_ids)],
                    }
                )
                finding = result["candidates"][0]
                self.assertFalse(result["fail_closed"])
                self.assertTrue(finding["terminal"])
                self.assertEqual(case["awareness_state"], finding["state"])
                self.assertEqual(case["expected_novelty_blocked"], finding["novelty_blocked"])

                obligation_id = "zdo_" + FREEZER.digest(LOGICAL)
                excluded_ids, exclusion_rows = FREEZER.awareness_exclusions(
                    result,
                    [{"obligation_id": obligation_id, "revision_id": "fixture-revision"}],
                )
                if case["expected_novelty_blocked"]:
                    self.assertEqual({obligation_id}, excluded_ids)
                    self.assertEqual(case["name"], exclusion_rows[0]["candidate_id"])
                else:
                    self.assertEqual(set(), excluded_ids)
                    self.assertEqual([], exclusion_rows)

    def test_case_matrix_enforces_transitive_executor_invalidation(self):
        """A refreshed substrate invalidates every later phase before any rerun credit."""

        cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]
        file_validator = mock.patch.object(
            EXECUTOR._validator,
            "validate_manifest_file",
            return_value={"valid": True, "diagnostics": []},
        )
        memory_validator = mock.patch.object(
            EXECUTOR._machine._manifest_validator,
            "validate_manifest",
            return_value={"valid": True, "diagnostics": []},
        )
        with file_validator, memory_validator:
            for case in cases:
                with self.subTest(case=case["name"]), tempfile.TemporaryDirectory() as tmp:
                    workspace = Path(tmp)
                    (workspace / "src").mkdir()
                    (workspace / "src" / f"cut{EXTENSIONS[case['language']]}").write_text("fixture source\n", encoding="utf-8")
                    for name in ("SCOPE.md", "SEVERITY.md", "targets.tsv"):
                        (workspace / name).write_text(f"{case['name']}\n", encoding="utf-8")
                    (workspace / ".auditooor").mkdir()
                    (workspace / ".auditooor" / "program_rules.json").write_text("{}\n", encoding="utf-8")
                    version = workspace / "producer-version"
                    version.write_text("v1\n", encoding="utf-8")
                    manifest_path = workspace / "pipeline.json"
                    manifest_path.write_text(json.dumps(executor_manifest(workspace, version)), encoding="utf-8")

                    first = EXECUTOR.run_all(manifest_path=manifest_path, workspace=workspace)
                    self.assertTrue(first["ok"], first)
                    state_path = workspace / ".auditooor" / "pipeline" / "state.json"
                    before = json.loads(state_path.read_text(encoding="utf-8"))
                    old_receipts = {step_id: before["steps"][step_id]["current_receipt_id"] for step_id in before["steps"]}

                    version.write_text("v2\n", encoding="utf-8")
                    (workspace / "source_snapshot.json").write_text('{"version":"tampered"}', encoding="utf-8")
                    rerun = EXECUTOR.run_step(manifest_path=manifest_path, workspace=workspace, step_id="producer")
                    self.assertTrue(rerun["ok"], rerun)
                    self.assertEqual("producer", rerun["invalidated_producer"])
                    invalidated = json.loads(state_path.read_text(encoding="utf-8"))
                    self.assertEqual("succeeded", invalidated["steps"]["producer"]["state"])
                    for step_id in ("reasoner", "depth", "drive"):
                        entry = invalidated["steps"][step_id]
                        self.assertEqual("invalidated", entry["state"])
                        self.assertIsNone(entry["current_receipt_id"])
                        self.assertEqual([], entry["current_output_artifacts"])
                        self.assertEqual(old_receipts[step_id], entry["receipt_history"][-1]["receipt_id"])

                    resumed = EXECUTOR.run_all(manifest_path=manifest_path, workspace=workspace)
                    self.assertTrue(resumed["ok"], resumed)
                    current = json.loads(state_path.read_text(encoding="utf-8"))
                    for step_id, entry in current["steps"].items():
                        self.assertEqual("succeeded", entry["state"])
                        self.assertIsNotNone(entry["current_receipt_id"])
                        self.assertNotEqual(old_receipts[step_id], entry["current_receipt_id"])


if __name__ == "__main__":
    unittest.main()
