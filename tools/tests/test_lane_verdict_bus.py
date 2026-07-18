"""Tests for tools/lane-verdict-bus.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "lane-verdict-bus.py"
SCHEMA = ROOT / "tools" / "schemas" / "lane_verdict.v1.json"


def _load_tool():
    spec = importlib.util.spec_from_file_location("lane_verdict_bus_test_subject", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        check=False,
    )


class LaneVerdictBusTests(unittest.TestCase):
    def test_append_and_read_one_lane(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            proc = _run(
                "append",
                "--workspace", str(ws),
                "--lane-id", "M1-1",
                "--candidate-id", "cand-1",
                "--attack-class", "rounding",
                "--verdict", "dropped",
                "--summary", "not exploitable",
                "--evidence-ref", "reports/lane/results.md",
                "--metadata", "context_pack_id=pack-1",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            payload = json.loads(proc.stdout)
            record = payload["record"]
            self.assertEqual(payload["classification"], "appended")
            self.assertEqual(record["schema_version"], "auditooor.lane_verdict.v1")
            self.assertEqual(record["lane_id"], "M1-1")
            self.assertEqual(record["sequence"], 1)
            self.assertEqual(record["verdict"], "DROPPED")
            self.assertEqual(record["metadata"]["context_pack_id"], "pack-1")

            path = ws / ".auditooor" / "lane_verdict_bus" / "M1-1.jsonl"
            self.assertTrue(path.is_file())
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 1)

            read = _run("read", "--workspace", str(ws), "--lane-id", "M1-1")
            self.assertEqual(read.returncode, 0, msg=read.stderr or read.stdout)
            data = json.loads(read.stdout)
            self.assertFalse(data["bus_empty"])
            self.assertEqual(data["record_count"], 1)
            self.assertEqual(data["records"][0]["candidate_id"], "cand-1")

    def test_append_is_idempotent_by_lane_candidate_and_verdict_hash_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            args = (
                "append",
                "--workspace", str(ws),
                "--lane-id", "M1-1",
                "--candidate-id", "cand-1",
                "--attack-class", "rounding",
                "--verdict", "DROPPED",
                "--metadata", "verdict_hash=abc123",
                "--metadata", "source=posttooluse:Task",
                "--metadata", "reply_sha256=def456",
            )
            first = _run(*args)
            second = _run(*args)
            self.assertEqual(first.returncode, 0, msg=first.stderr or first.stdout)
            self.assertEqual(second.returncode, 0, msg=second.stderr or second.stdout)
            first_payload = json.loads(first.stdout)
            second_payload = json.loads(second.stdout)
            self.assertEqual(first_payload["classification"], "appended")
            self.assertEqual(second_payload["classification"], "duplicate")
            self.assertEqual(
                second_payload["record"]["record_id"],
                first_payload["record"]["record_id"],
            )

            path = ws / ".auditooor" / "lane_verdict_bus" / "M1-1.jsonl"
            rows = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(rows), 1)

    def test_concurrent_appends_to_same_lane_have_no_lost_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            procs: list[subprocess.Popen[str]] = []
            for idx in range(30):
                procs.append(subprocess.Popen(
                    [
                        sys.executable,
                        str(TOOL),
                        "append",
                        "--workspace", str(ws),
                        "--lane-id", "M1-1",
                        "--candidate-id", f"cand-{idx}",
                        "--attack-class", "access-control",
                        "--verdict", "LANDED",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ))
            failures = []
            for proc in procs:
                stdout, stderr = proc.communicate(timeout=20)
                if proc.returncode != 0:
                    failures.append((proc.returncode, stdout, stderr))
            self.assertEqual(failures, [])

            tool = _load_tool()
            records = tool.read_records(ws, lane_id="M1-1")
            self.assertEqual(len(records), 30)
            self.assertEqual(
                sorted(record["sequence"] for record in records),
                list(range(1, 31)),
            )
            self.assertEqual(
                {record["candidate_id"] for record in records},
                {f"cand-{idx}" for idx in range(30)},
            )

    def test_aggregate_is_deterministic_and_writes_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _run(
                "append", "--workspace", str(ws), "--lane-id", "lane-B",
                "--candidate-id", "cand-B", "--attack-class", "dos",
                "--verdict", "DROPPED",
            )
            _run(
                "append", "--workspace", str(ws), "--lane-id", "lane-A",
                "--candidate-id", "cand-A", "--attack-class", "theft",
                "--verdict", "LANDED",
            )
            proc1 = _run("aggregate", "--workspace", str(ws))
            proc2 = _run("aggregate", "--workspace", str(ws))
            self.assertEqual(proc1.returncode, 0, msg=proc1.stderr or proc1.stdout)
            self.assertEqual(proc2.returncode, 0, msg=proc2.stderr or proc2.stdout)
            self.assertEqual(json.loads(proc1.stdout), json.loads(proc2.stdout))
            data = json.loads(proc1.stdout)
            self.assertEqual(data["record_count"], 2)
            self.assertEqual([lane["lane_id"] for lane in data["lanes"]], ["lane-A", "lane-B"])
            self.assertEqual(data["by_verdict"], {"DROPPED": 1, "LANDED": 1})
            snapshot = ws / ".auditooor" / "lane_verdict_bus" / "aggregated.json"
            self.assertTrue(snapshot.is_file())
            self.assertEqual(json.loads(snapshot.read_text(encoding="utf-8"))["record_count"], 2)

    def test_consult_filters_candidate_attack_class_verdict_and_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rows = [
                ("lane-A", "cand-1", "rounding", "DROPPED"),
                ("lane-B", "cand-1", "rounding", "LANDED"),
                ("lane-C", "cand-2", "access-control", "DROPPED"),
            ]
            for lane_id, candidate_id, attack_class, verdict in rows:
                proc = _run(
                    "append",
                    "--workspace", str(ws),
                    "--lane-id", lane_id,
                    "--candidate-id", candidate_id,
                    "--attack-class", attack_class,
                    "--verdict", verdict,
                )
                self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)

            proc = _run(
                "consult",
                "--workspace", str(ws),
                "--candidate-id", "cand-1",
                "--attack-class", "rounding",
                "--filter", "verdict=DROPPED",
                "--limit", "1",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            data = json.loads(proc.stdout)
            self.assertEqual(data["classification"], "consulted")
            self.assertEqual(data["match_count"], 1)
            self.assertEqual(data["records"][0]["lane_id"], "lane-A")

            zero = _run("consult", "--workspace", str(ws), "--limit", "0")
            self.assertEqual(zero.returncode, 0, msg=zero.stderr or zero.stdout)
            zero_data = json.loads(zero.stdout)
            self.assertEqual(zero_data["match_count"], 0)
            self.assertEqual(zero_data["records"], [])

    def test_consult_empty_bus_is_successful_and_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = _run(
                "consult",
                "--workspace", tmp,
                "--candidate-id", "missing",
                "--filter", "verdict=DROPPED",
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)
            data = json.loads(proc.stdout)
            self.assertEqual(data["classification"], "empty-bus")
            self.assertTrue(data["bus_empty"])
            self.assertEqual(data["total_record_count"], 0)
            self.assertEqual(data["match_count"], 0)
            self.assertEqual(data["records"], [])

    def test_schema_file_matches_runtime_required_fields(self) -> None:
        tool = _load_tool()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(schema["$id"], "auditooor.lane_verdict.v1")
        self.assertIn("verdict", schema["required"])
        record = tool.build_record(
            lane_id="M1-1",
            sequence=1,
            candidate_id="cand-1",
            attack_class="rounding",
            verdict="DROPPED",
        )
        self.assertEqual(tool.validate_record(record), [])
        for field in schema["required"]:
            self.assertIn(field, record)

    def test_bad_lane_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = _run(
                "append",
                "--workspace", tmp,
                "--lane-id", "../bad",
                "--candidate-id", "cand-1",
                "--attack-class", "rounding",
                "--verdict", "DROPPED",
            )
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(json.loads(proc.stdout)["classification"], "error")


if __name__ == "__main__":
    unittest.main()
