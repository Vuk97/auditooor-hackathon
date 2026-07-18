#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-INVARIANT-FUZZ-GATE registered via agent-pathspec-register.py -->
"""Guard: invariant-fuzz-completeness enforces breadth + non-vacuity + ACTUALLY-FUZZED.
The load-bearing case: a harness that was AUTHORED but never fuzzed must FAIL.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ifc", str(_TOOLS / "invariant-fuzz-completeness.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["ifc"] = m
spec.loader.exec_module(m)


def _harness(ws: Path, *, invariants=2, mutation=True, evidence=True):
    hd = ws / "chimera_harnesses" / "H" / "test" / "recon"
    hd.mkdir(parents=True)
    props = "\n".join(f"    function property_inv{i}() public view returns (bool) {{ return true; }}"
                      for i in range(invariants))
    body = "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract Properties {\n" + props + "\n"
    if mutation:
        body += "    function test_mutation_breaks_inv0() public { assertFalse(false); }\n"
    body += "}\n"
    (hd / "Properties.sol").write_text(body)
    (hd / "CryticTester.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract CryticTester {\n"
        "    function echidna_inv0() public view returns (bool) { return true; }\n}\n")
    if evidence:
        deng = ws / ".auditooor" / "deep-engine-findings"
        deng.mkdir(parents=True)
        # a GENUINE artifact must prove the engine executed call sequences -
        # a forge-invariant PASS line with runs>0 / calls>0 (not just bytes).
        # P1-d: the executed call count must clear the >=1,000,000 floor.
        (deng / "H-SOLVENCY-fuzz.md").write_text(
            "# H invariant fuzz\n" + ("x" * 400) +
            "\n[PASS] invariant_solvency() (runs: 25000, calls: 1024000, reverts: 3)\n")
    return hd


class TestInvariantFuzzCompleteness(unittest.TestCase):
    def test_genuine_passes(self):
        ws = Path(tempfile.mkdtemp()); _harness(ws)
        self.assertEqual(m.evaluate(ws)["verdict"], "pass-invariant-fuzz-complete")

    def test_authored_but_never_fuzzed_FAILS(self):
        ws = Path(tempfile.mkdtemp()); _harness(ws, evidence=False)
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-invariant-fuzz-incomplete")
        self.assertIn("NEVER FUZZED", r["harnesses"][0]["fail"])

    def test_single_invariant_FAILS(self):
        ws = Path(tempfile.mkdtemp()); _harness(ws, invariants=1)
        # CryticTester adds 1 echidna_ too => total 2; force below min via min_invariants=3
        self.assertEqual(m.evaluate(ws, min_invariants=5)["verdict"], "fail-invariant-fuzz-incomplete")

    def test_no_mutation_verify_FAILS(self):
        ws = Path(tempfile.mkdtemp()); _harness(ws, mutation=False)
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-invariant-fuzz-incomplete")
        self.assertIn("mutation", r["harnesses"][0]["fail"])

    # r36-rebuttal: lane FIX-INVARIANT-FUZZ-DEPTH registered in .auditooor/agent_pathspec.json
    def test_shallow_seqlen_FAILS(self):
        ws = Path(tempfile.mkdtemp()); hd = _harness(ws)
        # add >=5 actions so the seqlen branch is reached, and a shallow medusa.json
        acts = "\n".join(f"    function midnight_a{i}(uint256 x) public {{}}" for i in range(6))
        (hd / "TargetFunctions.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract T {\n" + acts + "\n}\n")
        (hd / "medusa.json").write_text('{"fuzzing":{"callSequenceLength":10}}')
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-invariant-fuzz-incomplete")
        self.assertIn("too shallow", r["harnesses"][0]["fail"])

    def test_too_few_actions_FAILS(self):
        ws = Path(tempfile.mkdtemp()); hd = _harness(ws)
        (hd / "TargetFunctions.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract T {\n"
            "    function midnight_only(uint256 x) public {}\n}\n")
        (hd / "medusa.json").write_text('{"fuzzing":{"callSequenceLength":100}}')
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-invariant-fuzz-incomplete")
        self.assertIn("fuzz action", r["harnesses"][0]["fail"])

    # r36-rebuttal: lane FIX-FORK-DIVERGENCE-CONTENT registered in .auditooor/agent_pathspec.json
    # FALSE-GREEN GUARD: a fuzz artifact that exists + matches the keyword + is
    # >200 bytes but shows the engine NEVER EXECUTED (runs:0/calls:0 - a setUp
    # failure like an RPC 429 or pruned fork) must NOT credit the gate. This is
    # the bean fork-harness false-green we observed: forge-invariant 429'd with
    # runs:0, the .md still matched 'invariant' + >200 bytes, gate went green.
    def test_zero_call_setup_failure_artifact_does_NOT_credit(self):
        ws = Path(tempfile.mkdtemp()); _harness(ws, evidence=False)
        deng = ws / ".auditooor" / "deep-engine-findings"; deng.mkdir(parents=True)
        (deng / "H-invariant-fuzz.md").write_text(
            "# H invariant fuzz\n" + ("x" * 400) +
            "\n[FAIL: failed to set up invariant testing environment: HTTP error 429 "
            "Too Many Requests] invariant_solvency() (runs: 0, calls: 0, reverts: 0)\n")
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-invariant-fuzz-incomplete",
                         "a 0-call setup-failure artifact must NOT false-green the gate")
        self.assertIn("NEVER FUZZED", r["harnesses"][0]["fail"])

    def test_executed_artifact_credits(self):
        """The same harness WITH a real executed-run artifact (>=1M calls) passes."""
        ws = Path(tempfile.mkdtemp()); _harness(ws, evidence=False)
        deng = ws / ".auditooor" / "deep-engine-findings"; deng.mkdir(parents=True)
        (deng / "H-invariant-fuzz.md").write_text(
            "# H invariant fuzz\n" + ("x" * 400) +
            "\n[PASS] invariant_solvency() (runs: 25000, calls: 1024000, reverts: 1)\n")
        self.assertEqual(m.evaluate(ws)["verdict"], "pass-invariant-fuzz-complete")

    def test_artifact_shows_execution_unit(self):
        self.assertFalse(m._artifact_shows_execution("runs: 0, calls: 0"))
        self.assertFalse(m._artifact_shows_execution("HTTP error 429 Too Many Requests"))
        self.assertFalse(m._artifact_shows_execution(""))
        self.assertTrue(m._artifact_shows_execution("(runs: 256, calls: 12800, reverts: 3)"))
        self.assertTrue(m._artifact_shows_execution("[PASS] invariant_x() (runs: 1, calls: 1)"))
        self.assertTrue(m._artifact_shows_execution("call_sequences_tested: 50000\nelapsed time: 12m"))

    def test_no_harness_is_advisory_pass(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "Foo.sol").write_text("contract Foo {}")
        self.assertEqual(m.evaluate(ws)["verdict"], "pass-no-invariant-harness")

    # -- P1-d: 1M-floor + no-dry-run + selfdestruct-engine + check_ prefix ----
    def test_under_budgeted_500k_FAILS(self):
        """A 500K smoke campaign is under the >=1M floor -> under-budgeted."""
        ws = Path(tempfile.mkdtemp()); _harness(ws, evidence=False)
        deng = ws / ".auditooor" / "deep-engine-findings"; deng.mkdir(parents=True)
        (deng / "H-fuzz.md").write_text(
            "# H invariant fuzz\n" + ("x" * 400) +
            "\n[PASS] invariant_solvency() (runs: 9765, calls: 500000, reverts: 0)\n")
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-invariant-fuzz-incomplete")
        self.assertIn("under-budgeted", r["harnesses"][0]["fail"])

    def test_dry_run_status_skipped_FAILS(self):
        """A status=skipped dry-run manifest is NOT a campaign -> hard fail."""
        ws = Path(tempfile.mkdtemp()); _harness(ws)  # has a real 1.024M artifact too
        fr = ws / ".auditooor" / "fuzz_runs" / "20260622T000229Z"
        fr.mkdir(parents=True)
        (fr / "status.txt").write_text("status=skipped\ndry-run: engine NOT invoked\n")
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-invariant-fuzz-incomplete")
        self.assertIn("dry-run-not-a-campaign", r["harnesses"][0]["fail"])

    def test_selfdestruct_cut_needs_echidna_FAILS(self):
        """A medusa-only campaign over a selfdestruct CUT must require echidna."""
        ws = Path(tempfile.mkdtemp()); hd = _harness(ws)
        # add a CUT under the harness root that force-sends via selfdestruct.
        (hd / "Vault.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\n"
            "contract Vault { function kill() public { selfdestruct(payable(msg.sender)); } }\n")
        # medusa.json present (medusa engine), NO echidna config.
        (hd / "medusa.json").write_text('{"fuzzing":{"callSequenceLength":100}}')
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-invariant-fuzz-incomplete")
        self.assertIn("selfdestruct-needs-echidna", r["harnesses"][0]["fail"])

    def test_selfdestruct_cut_with_echidna_PASSES(self):
        """The same selfdestruct CUT WITH an echidna config/log passes the engine
        check (and otherwise meets the bar)."""
        ws = Path(tempfile.mkdtemp()); hd = _harness(ws)
        (hd / "Vault.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\n"
            "contract Vault { function kill() public { selfdestruct(payable(msg.sender)); } }\n")
        (hd / "echidna.yaml").write_text("testMode: assertion\nseqLen: 100\n")
        # need >=5 actions + seqLen>=50 to clear the depth branches.
        acts = "\n".join(f"    function midnight_a{i}(uint256 x) public {{}}" for i in range(6))
        (hd / "TargetFunctions.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract T {\n" + acts + "\n}\n")
        self.assertEqual(m.evaluate(ws)["verdict"], "pass-invariant-fuzz-complete")

    # -- G8 (2026-06-27): _cut_needs_echidna false-positive guards -----------
    def test_selfdestruct_in_comment_does_NOT_need_echidna(self):
        """The word 'selfdestruct' in a COMMENT (e.g. forge-std StdCheats.sol
        describes selfdestruct in prose) must NOT flag the CUT as needing
        echidna. Only an actual force-send CALL counts."""
        ws = Path(tempfile.mkdtemp()); hd = _harness(ws)
        (hd / "Vault.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\n"
            "// This is similar to selfdestruct but not identical: selfdestruct\n"
            "/* block: SafeSend mentioned only in a comment */\n"
            "contract Vault { function ok() public pure returns (uint) { return 1; } }\n")
        (hd / "medusa.json").write_text('{"fuzzing":{"callSequenceLength":100}}')
        self.assertFalse(m._cut_needs_echidna(hd, ws))

    def test_selfdestruct_in_vendored_lib_does_NOT_need_echidna(self):
        """A selfdestruct force-send inside a vendored lib/ test framework
        (forge-std) is NOT the CUT and must be skipped (matches _iter_sol's
        _SKIP_DIRS exclusion)."""
        ws = Path(tempfile.mkdtemp()); hd = _harness(ws)
        vend = hd / "lib" / "forge-std" / "src"; vend.mkdir(parents=True)
        (vend / "StdCheats.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\n"
            "contract StdCheats { function kill() public { selfdestruct(payable(msg.sender)); } }\n")
        self.assertFalse(m._cut_needs_echidna(hd, ws))

    def test_selfdestruct_above_workspace_does_NOT_leak(self):
        """A selfdestruct in a SIBLING workspace (above <ws>) must never be
        scanned: harness_dir.parent.parent can escape <ws> for a root-level
        harness; clamp to the workspace boundary."""
        parent = Path(tempfile.mkdtemp())
        ws = parent / "ws"; ws.mkdir()
        # sibling-workspace file above <ws> with a real force-send
        (parent / "OtherAudit.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\n"
            "contract Other { function kill() public { selfdestruct(payable(msg.sender)); } }\n")
        # a root-level harness whose parent.parent == parent (above ws)
        hd = ws / "test"; hd.mkdir()
        (hd / "Props.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract P {\n"
            "    function property_a() public view returns (bool) { return true; }\n}\n")
        self.assertFalse(m._cut_needs_echidna(hd, ws))

    def test_selfdestruct_in_real_cut_STILL_needs_echidna(self):
        """False-green-safe regression: a genuine force-send CALL in real
        in-scope CUT code (not a comment, not vendored, inside <ws>) is still
        detected after the G8 filters."""
        ws = Path(tempfile.mkdtemp()); hd = _harness(ws)
        (hd / "Vault.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\n"
            "contract Vault { function kill() public { selfdestruct(payable(msg.sender)); } }\n")
        self.assertTrue(m._cut_needs_echidna(hd, ws))

    def test_check_prefix_property_counts_toward_breadth(self):
        """P1-d (mode 8 residual): a `function check_` Halmos property is recognised
        by _PROP_RE so the breadth count includes it."""
        ws = Path(tempfile.mkdtemp())
        hd = ws / "chimera_harnesses" / "C" / "test"
        hd.mkdir(parents=True)
        (hd / "Props.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract C {\n"
            "    function check_cap() public {}\n"
            "    function check_solvency() public {}\n}\n")
        props = m._find_harness_dirs(ws)
        self.assertEqual(len(props), 1)
        txt = (hd / "Props.sol").read_text()
        names = [mm.group(0).split()[-1] for mm in m._PROP_RE.finditer(txt)]
        self.assertIn("check_cap", names)
        self.assertIn("check_solvency", names)

    def test_executed_call_count_unit(self):
        self.assertEqual(m._executed_call_count("calls: 1,024,000"), 1024000)
        self.assertEqual(m._executed_call_count("call_sequences_tested: 1500000"), 1500000)
        self.assertEqual(m._executed_call_count("total calls: 2000000"), 2000000)
        self.assertEqual(m._executed_call_count("no counter here"), 0)

    def test_dry_run_detection_unit(self):
        self.assertTrue(m._artifact_is_dry_run("status=skipped"))
        self.assertTrue(m._artifact_is_dry_run("dry-run: engine NOT invoked"))
        self.assertFalse(m._artifact_is_dry_run("status=complete, calls: 2000000"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
