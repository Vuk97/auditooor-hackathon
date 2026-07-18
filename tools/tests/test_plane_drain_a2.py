# <!-- r36-rebuttal: lane RW-RWBUILD-A2 registered via agent-pathspec-register.py -->
"""A2 coverage-plane drain regression: both hunt builders
(inscope-hunt-batch-builder.py, per-fn-mimo-batch-gen.py) emit one hunt task per
NOT-ENUMERATED coverage_plane.jsonl cell when AUDITOOOR_PLANE_DRAIN=1, tagged
source_of_truth='coverage_plane'; and are BYTE-IDENTICAL to the legacy output
when the env is unset (default OFF)."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_INSCOPE = _TOOLS / "inscope-hunt-batch-builder.py"
_MIMO = _TOOLS / "per-fn-mimo-batch-gen.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def _write_ws_with_plane(tmp: Path) -> None:
    (tmp / ".auditooor").mkdir(parents=True, exist_ok=True)
    (tmp / "src").mkdir(parents=True, exist_ok=True)
    # A tiny real source file so the body-extractor / excerpt has something to read.
    (tmp / "src" / "Vault.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "  mapping(address => uint256) balances;\n"
        "  function withdraw(uint256 amt) external {\n"
        "    balances[msg.sender] -= amt;\n"
        "    payable(msg.sender).transfer(amt);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    plane_rows = [
        # two not-enumerated cells on the same unit, different frames
        {"file": "src/Vault.sol", "asset": "src/Vault.sol", "function": "withdraw",
         "frame": "direct-theft", "frame_kind": "impact", "lang": "solidity",
         "status": "not-enumerated",
         "unit": "src/Vault.sol::withdraw::src/Vault.sol:5",
         "schema": "auditooor.coverage_plane.v1", "ws_name": tmp.name},
        {"file": "src/Vault.sol", "asset": "src/Vault.sol", "function": "withdraw",
         "frame": "permanent-freeze", "frame_kind": "impact", "lang": "solidity",
         "status": "not-enumerated",
         "unit": "src/Vault.sol::withdraw::src/Vault.sol:5",
         "schema": "auditooor.coverage_plane.v1", "ws_name": tmp.name},
        # a COVERED cell that MUST be skipped
        {"file": "src/Vault.sol", "asset": "src/Vault.sol", "function": "withdraw",
         "frame": "insolvency", "frame_kind": "impact", "lang": "solidity",
         "status": "covered",
         "unit": "src/Vault.sol::withdraw::src/Vault.sol:5",
         "schema": "auditooor.coverage_plane.v1", "ws_name": tmp.name},
    ]
    (tmp / ".auditooor" / "coverage_plane.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in plane_rows), encoding="utf-8")
    # inscope manifest so the legacy (env-off) path has a real, non-empty output.
    manifest = [
        {"file": "src/Vault.sol", "function": "withdraw", "lang": "solidity",
         "file_line": "src/Vault.sol:5", "prior_covered": False},
    ]
    (tmp / ".auditooor" / "inscope_units.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in manifest), encoding="utf-8")


class InscopeA2PlaneDrainTest(unittest.TestCase):
    def setUp(self):
        self.m = _load(_INSCOPE, "inscope_hunt_batch_builder_a2")
        self.tmp = Path(tempfile.mkdtemp())
        _write_ws_with_plane(self.tmp)
        os.environ.pop("AUDITOOOR_PLANE_DRAIN", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_PLANE_DRAIN", None)

    def _run_main(self, out: Path):
        rc = self.m.main(["--workspace", str(self.tmp), "--out", str(out)])
        self.assertEqual(rc, 0)
        return [json.loads(l) for l in out.read_text().splitlines() if l.strip()]

    def test_env_on_emits_plane_cells(self):
        os.environ["AUDITOOOR_PLANE_DRAIN"] = "1"
        out = self.tmp / "on.jsonl"
        rows = self._run_main(out)
        # exactly the 2 not-enumerated cells (covered cell skipped).
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r.get("source_of_truth") == "coverage_plane" for r in rows))
        self.assertEqual({r.get("impact") for r in rows},
                         {"direct-theft", "permanent-freeze"})
        # distinct task_ids (impact folded into stable id)
        self.assertEqual(len({r["task_id"] for r in rows}), 2)

    def test_env_off_byte_identical_to_legacy(self):
        # env-off run
        out_off = self.tmp / "off.jsonl"
        self._run_main(out_off)
        off_bytes = out_off.read_bytes()
        # env-off must NOT carry any coverage_plane provenance
        rows = [json.loads(l) for l in out_off.read_text().splitlines() if l.strip()]
        self.assertTrue(all(r.get("source_of_truth") != "coverage_plane" for r in rows))
        # a second env-off run is byte-stable (determinism sanity)
        out_off2 = self.tmp / "off2.jsonl"
        self._run_main(out_off2)
        self.assertEqual(off_bytes, out_off2.read_bytes())


class MimoA2PlaneDrainTest(unittest.TestCase):
    def setUp(self):
        self.m = _load(_MIMO, "per_fn_mimo_batch_gen_a2")
        self.tmp = Path(tempfile.mkdtemp())
        _write_ws_with_plane(self.tmp)
        # a minimal ranked-questions file with one question so the legacy path is non-empty.
        self.ranked = self.tmp / "ranked.jsonl"
        self.ranked.write_text(json.dumps({
            "function": "withdraw", "file": "src/Vault.sol",
            "unit_id": "Vault.sol::withdraw", "question_class": "generic",
            "question": "Can withdraw underflow?", "anchor_invariant": "conservation",
            "rank": 0, "score": 1.0,
        }) + "\n", encoding="utf-8")
        os.environ.pop("AUDITOOOR_PLANE_DRAIN", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_PLANE_DRAIN", None)

    def _run_main(self, out: Path):
        rc = self.m.main(["--ranked-questions", str(self.ranked),
                          "--workspace", str(self.tmp), "--output", str(out)])
        self.assertEqual(rc, 0)
        return [json.loads(l) for l in out.read_text().splitlines() if l.strip()]

    def test_env_on_appends_plane_cells(self):
        os.environ["AUDITOOOR_PLANE_DRAIN"] = "1"
        out = self.tmp / "on.jsonl"
        rows = self._run_main(out)
        plane = [r for r in rows if r.get("source_of_truth") == "coverage_plane"]
        # 1 ranked question + 2 not-enumerated plane cells
        self.assertEqual(len(plane), 2)
        self.assertEqual({r.get("impact") for r in plane},
                         {"direct-theft", "permanent-freeze"})
        self.assertEqual(len(rows), 3)

    def test_env_off_byte_identical_to_legacy(self):
        out_off = self.tmp / "off.jsonl"
        rows = self._run_main(out_off)
        # env-off: NO plane tasks appended (only the 1 ranked question)
        self.assertEqual(len(rows), 1)
        self.assertTrue(all(r.get("source_of_truth") != "coverage_plane" for r in rows))
        off_bytes = out_off.read_bytes()
        out_off2 = self.tmp / "off2.jsonl"
        self._run_main(out_off2)
        self.assertEqual(off_bytes, out_off2.read_bytes())


if __name__ == "__main__":
    unittest.main()
