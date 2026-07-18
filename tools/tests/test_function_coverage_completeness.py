#!/usr/bin/env python3
"""Unit tests for tools/function-coverage-completeness.py.

The tool is the REAL per-function attack coverage gate: it enumerates every
in-scope external/public/entry function and classifies each as real-attack /
hollow / untouched. These tests use SYNTHETIC workspaces for the logic cases
(zero target hardcoding in the tool body); the morpho-midnight workspace is
used ONLY as a final smoke anchor and is skipped when absent.

Cases:
 1. fully-covered: one entry fn with a CONFIRMED finding -> pass-fully-covered
 2. untouched: one entry fn with no reference -> fail (untouched)
 3. hollow via vacuous harness (assert(true)) -> fail (hollow), NOT real
 4. hollow via CCIA heuristic angle -> fail (hollow), NOT real
 5. hollow via DROP/FALSE-POSITIVE analysis-only sidecar -> fail (hollow)
 6. discarded sidecar with prose "confirmed but non-weaponizable" does NOT
    flip to real-attack (R76-style free-text false-signal guard)
 7. internal/private functions are NOT counted as in-scope surface
 8. test/lib/mock/interface/script files are excluded from the surface
 9. multi-line Solidity signature (`function f(...)\n external\n{`) is parsed
10. non-vacuous per-function harness (check_<name> with real assert) -> real
11. Go exported (capitalized) function is entry surface
12. Rust `pub fn` is entry surface; private `fn` is not
13. no in-scope source -> pass-no-source
14. --emit-worklist lists the hollow/untouched rows
15. span-precision: a finding citing line L credits ONLY the fn whose body
    span contains L, not an unrelated sibling fn far away
16. SMOKE: morpho-midnight shows MidnightBundles + TickLib + fee setters as
    untouched/hollow (the bug this gate was built to catch)
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parents[1] / "function-coverage-completeness.py"
_spec = importlib.util.spec_from_file_location("function_coverage_completeness", _MOD_PATH)
fcc = importlib.util.module_from_spec(_spec)
sys.modules["function_coverage_completeness"] = fcc
_spec.loader.exec_module(fcc)


def _mkws(files: dict) -> Path:
    """files: {relpath: content}. Returns the workspace root."""
    d = Path(tempfile.mkdtemp(prefix="fcc_test_"))
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


def _classes(result):
    return {f["name"]: f["classification"] for f in result["functions"]}


class TestFunctionCoverageCompleteness(unittest.TestCase):
    def test_01_fully_covered_confirmed_finding(self):
        ws = _mkws({
            "src/Vault.sol": (
                "contract Vault {\n"
                "  function deposit(uint256 a) external { x = a; }\n"
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/F1.json": json.dumps({
                "verdict": "CONFIRMED",
                "file_line": "src/Vault.sol:2",
                "poc_evidence_lines": "[PASS] testDepositDrain",
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(r["verdict"], "pass-fully-covered", r["reason"])
        self.assertEqual(_classes(r)["deposit"], "real-attack")

    def test_02_untouched(self):
        ws = _mkws({"src/Vault.sol":
                    "contract Vault {\n  function deposit() external {}\n}\n"})
        r = fcc.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-functions-untouched-or-hollow")
        self.assertEqual(_classes(r)["deposit"], "untouched")

    def test_03_hollow_vacuous_harness(self):
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            "poc-tests/per_function_invariants/Halmos_Vault_deposit.t.sol": (
                "// Function under test: Vault.deposit at src/Vault.sol:2\n"
                "contract H { function check_deposit() public { assert(true); } }\n"
            ),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(_classes(r)["deposit"], "hollow")
        self.assertEqual(r["verdict"], "fail-functions-untouched-or-hollow")

    def test_04_hollow_ccia_angle(self):
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            ".auditooor/ccia_attack_angles.json": json.dumps([
                {"id": "A-AUTH", "severity": "MEDIUM",
                 "title": "Unauthenticated state write: Vault.deposit",
                 "contracts": ["Vault"], "line": 2},
            ]),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(_classes(r)["deposit"], "hollow")

    def test_05_hollow_dropped_sidecar(self):
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            ".auditooor/hunt_findings_sidecars/F1.json": json.dumps({
                "verdict": "FALSE-POSITIVE",
                "disposition": "DROP - benign",
                "file_line": "src/Vault.sol:2",
                "poc_evidence_lines": "[PASS] testNoDrain",
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(_classes(r)["deposit"], "hollow")

    def test_06_dropped_with_confirmed_prose_stays_hollow(self):
        # R76-style guard: free-text "confirmed but non-weaponizable" in a
        # DROP sidecar must NOT flip the fn to real-attack.
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            ".auditooor/hunt_findings_sidecars/F1.json": json.dumps({
                "verdict": "FALSE-POSITIVE",
                "disposition": "DROP - benign",
                "file_line": "src/Vault.sol:2",
                "analysis": "the stale allowance is confirmed but non-weaponizable",
                "poc_evidence_lines": "[PASS] testNoDrain",
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(_classes(r)["deposit"], "hollow")

    def test_07_internal_private_not_surface(self):
        ws = _mkws({"src/Vault.sol": (
            "contract Vault {\n"
            "  function pub() external {}\n"
            "  function _helper() internal {}\n"
            "  function secret() private {}\n"
            "}\n"
        )})
        r = fcc.evaluate(ws)
        names = {f["name"] for f in r["functions"]}
        self.assertIn("pub", names)
        self.assertNotIn("_helper", names)
        self.assertNotIn("secret", names)

    def test_08_excludes_test_lib_mock_interface_script(self):
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            "src/test/VaultTest.sol":
                "contract VaultTest {\n  function tHelper() external {}\n}\n",
            "src/mocks/MockToken.sol":
                "contract MockToken {\n  function mockFn() external {}\n}\n",
            "src/interfaces/IVault.sol":
                "interface IVault {\n  function ideposit() external;\n}\n",
            "src/lib/Util.sol":
                "library Util {\n  function libFn() external {}\n}\n",
            "src/script/Deploy.s.sol":
                "contract Deploy {\n  function run() external {}\n}\n",
        })
        r = fcc.evaluate(ws)
        names = {f["name"] for f in r["functions"]}
        self.assertEqual(names, {"deposit"}, names)

    def test_09_multiline_solidity_signature(self):
        ws = _mkws({"src/Vault.sol": (
            "contract Vault {\n"
            "  function repay(\n"
            "    uint256 units,\n"
            "    address onBehalf\n"
            "  )\n"
            "    external\n"
            "  {\n"
            "    x = units;\n"
            "  }\n"
            "}\n"
        )})
        r = fcc.evaluate(ws)
        names = {f["name"] for f in r["functions"]}
        self.assertIn("repay", names)

    def test_10_real_nonvacuous_harness(self):
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            "poc-tests/per_function_invariants/Halmos_Vault_deposit.t.sol": (
                "// Function under test: Vault.deposit at src/Vault.sol:2\n"
                "contract H {\n"
                "  function check_deposit() public {\n"
                "    uint256 b = bal();\n"
                "    assertEq(b, expected);\n"
                "  }\n"
                "}\n"
            ),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(_classes(r)["deposit"], "real-attack")

    def test_11_go_exported_is_surface(self):
        ws = _mkws({"src/handler.go": (
            "package h\n"
            "func Exported() {}\n"
            "func unexported() {}\n"
        )})
        r = fcc.evaluate(ws)
        names = {f["name"] for f in r["functions"]}
        self.assertIn("Exported", names)
        self.assertNotIn("unexported", names)

    def test_12_rust_pub_fn_is_surface(self):
        ws = _mkws({"src/lib.rs": (
            "pub fn entry() {}\n"
            "fn private_fn() {}\n"
        )})
        r = fcc.evaluate(ws)
        names = {f["name"] for f in r["functions"]}
        self.assertIn("entry", names)
        self.assertNotIn("private_fn", names)

    def test_13_no_source(self):
        ws = _mkws({"README.md": "no code here\n"})
        r = fcc.evaluate(ws)
        self.assertEqual(r["verdict"], "pass-no-source")

    def test_14_emit_worklist(self):
        ws = _mkws({"src/Vault.sol": (
            "contract Vault {\n"
            "  function a() external {}\n"
            "  function b() external {}\n"
            "}\n"
        )})
        r = fcc.evaluate(ws)
        wl = fcc._emit_worklist(r)
        self.assertEqual(wl["worklist_size"], 2)
        self.assertEqual(wl["schema"], "auditooor.function_coverage_worklist.v1")
        funcs = {row["function"] for row in wl["worklist"]}
        self.assertEqual(funcs, {"a", "b"})

    def test_15_span_precision_no_cross_function_bleed(self):
        # A finding citing line 3 (inside f1's body) must NOT credit f2 which
        # starts at line 6.
        ws = _mkws({
            "src/Vault.sol": (
                "contract Vault {\n"          # 1
                "  function f1() external {\n"  # 2
                "    x = 1;\n"                  # 3
                "  }\n"                         # 4
                "\n"                            # 5
                "  function f2() external {\n"  # 6
                "    y = 2;\n"                   # 7
                "  }\n"                          # 8
                "}\n"                            # 9
            ),
            ".auditooor/hunt_findings_sidecars/F1.json": json.dumps({
                "verdict": "CONFIRMED",
                "file_line": "src/Vault.sol:3",
                "poc_evidence_lines": "[PASS] testF1",
            }),
        })
        r = fcc.evaluate(ws)
        cl = _classes(r)
        self.assertEqual(cl["f1"], "real-attack")
        self.assertNotEqual(cl["f2"], "real-attack", "finding bled into sibling fn")

    def test_16_schema_field_present(self):
        ws = _mkws({"src/Vault.sol":
                    "contract Vault {\n  function a() external {}\n}\n"})
        r = fcc.evaluate(ws)
        self.assertEqual(r["schema"], "auditooor.function_coverage_completeness.v1")
        self.assertIn("counts", r)
        self.assertIn("total", r["counts"])

    def test_17_per_function_clean_worklist_counts_as_real_attack(self):
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            ".auditooor/per_function_attack_worklist.jsonl": (
                json.dumps({"schema": "auditooor.per_function_attack_worklist.v1"}) + "\n" +
                json.dumps({
                    "file_line": "src/Vault.sol:2",
                    "function": "deposit",
                    "contract": "Vault",
                    "status": "CLEAN-NO-CONFIRMED-FINDING",
                    "source_refs": ["src/Vault.sol:2"],
                    "verdict_detail": "deposit source-traced with no exploitable path",
                }) + "\n"
            ),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(r["verdict"], "pass-fully-covered", r["reason"])
        rec = next(f for f in r["functions"] if f["name"] == "deposit")
        self.assertEqual(rec["classification"], "real-attack")
        self.assertTrue(any("terminal-clean" in e for e in rec["evidence"]), rec["evidence"])

    def test_18_weak_clean_worklist_does_not_count(self):
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            ".auditooor/per_function_attack_worklist.jsonl": (
                json.dumps({"schema": "auditooor.per_function_attack_worklist.v1"}) + "\n" +
                json.dumps({
                    "file_line": "src/Vault.sol:2",
                    "function": "deposit",
                    "contract": "Vault",
                    "status": "clean",
                    "verdict_detail": "done",
                }) + "\n"
            ),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(_classes(r)["deposit"], "untouched")

    def test_18b_per_function_attacks_jsonl_counts_as_terminal_record(self):
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            ".auditooor/per_function_attacks/manual-clean.jsonl": (
                json.dumps({
                    "file_line": "src/Vault.sol:2",
                    "function": "deposit",
                    "contract": "Vault",
                    "status": "no-exploit",
                    "source_refs": ["src/Vault.sol:2"],
                    "verdict_detail": (
                        "Source-verified clean terminal row for "
                        "src/Vault.sol:2 function deposit"
                    ),
                }) + "\n"
            ),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(r["verdict"], "pass-fully-covered", r["reason"])
        rec = next(f for f in r["functions"] if f["name"] == "deposit")
        self.assertEqual(rec["classification"], "real-attack")
        self.assertTrue(any("manual-clean.jsonl" in e for e in rec["evidence"]))

    def test_19_clean_reason_with_function_but_no_source_ref_does_not_count(self):
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            ".auditooor/per_function_attack_worklist.jsonl": (
                json.dumps({"schema": "auditooor.per_function_attack_worklist.v1"}) + "\n" +
                json.dumps({
                    "file_line": "src/Vault.sol:2",
                    "function": "deposit",
                    "contract": "Vault",
                    "status": "clean",
                    "verdict_detail": "deposit was reviewed and no exploitable path was found in this function",
                }) + "\n"
            ),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(_classes(r)["deposit"], "untouched")

    def test_20_cluster_clean_sidecar_does_not_match_confirmed_substring(self):
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            ".auditooor/hunt_findings_sidecars/cluster-clean.json": json.dumps({
                "verdict": "CLEAN-NO-CONFIRMED-FINDING",
                "file_line": "src/Vault.sol:2",
                "summary": "cluster-level clean sidecar, not per-function evidence",
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(_classes(r)["deposit"], "hollow")

    # --- Nested-result sidecar schema (per-fn MIMO/haiku hunt) ---
    # Bug: sidecars with result as nested JSON string were invisible to Pass 1.
    # applies_to_target=no with function_anchor must mark fn as "hollow" (not
    # "untouched"), since the function WAS examined and the hypothesis was ruled
    # out.  Before the fix, all 304 beanstalk sidecars read as 0 real verdicts.
    # r36-rebuttal: funnel-generic-fixes-wave3

    def test_21_nested_result_applies_no_marks_hollow(self):
        """applies_to_target=no sidecar with function_anchor -> hollow, not untouched.
        Regression for the nested-result schema bug: before the fix this
        function would remain 'untouched' (false gap) because Pass 1 only
        scanned top-level fields and file_line='NA' gave no file:line match."""
        ws = _mkws({
            "src/Vault.sol": (
                "contract Vault {\n"
                "  function deposit() external {\n"  # line 2
                "    x = 1;\n"
                "  }\n"
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/nested_no.json": json.dumps({
                "status": "ok",
                "task_type": "workspace_hunt_harnessed",
                "function_anchor": {
                    "file": "src/Vault.sol",
                    "fn": "deposit",
                    "start_line": 2,
                    "end_line": 4,
                },
                "result": json.dumps({
                    "applies_to_target": "no",
                    "confidence": "high",
                    "candidate_finding": "N/A",
                    "file_line": "NA",
                    "verdict": "NA",
                    "notes": "hypothesis does not apply to deposit",
                }),
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(
            _classes(r)["deposit"], "hollow",
            "applies_to_target=no sidecar must mark fn as hollow (examined+ruled-out), "
            "not untouched (zero engagement)",
        )

    def test_22_nested_result_applies_yes_confirmed_marks_real_attack(self):
        """applies_to_target=yes sidecar with CONFIRMED in inner result -> real-attack."""
        ws = _mkws({
            "src/Vault.sol": (
                "contract Vault {\n"
                "  function withdraw() external {\n"  # line 2
                "    send(owner, bal);\n"
                "  }\n"
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/nested_yes.json": json.dumps({
                "status": "ok",
                "task_type": "workspace_hunt_harnessed",
                "function_anchor": {
                    "file": "src/Vault.sol",
                    "fn": "withdraw",
                    "start_line": 2,
                    "end_line": 4,
                },
                "result": json.dumps({
                    "applies_to_target": "yes",
                    "confidence": "high",
                    "candidate_finding": "Missing zero-address check allows drain",
                    "file_line": "NA",
                    "verdict": "CONFIRMED",
                    "severity_estimate": "HIGH",
                    "notes": "owner can be address(0) bricking withdrawals",
                }),
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(
            _classes(r)["withdraw"], "real-attack",
            "applies_to_target=yes with CONFIRMED inner verdict must mark fn real-attack",
        )

    def test_23_nested_result_failed_sidecar_not_coverage(self):
        """A failed/errored sidecar (outer status!=ok) must NOT count as coverage."""
        ws = _mkws({
            "src/Vault.sol": (
                "contract Vault {\n"
                "  function deposit() external {}\n"
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/failed.json": json.dumps({
                "status": "failed",
                "error": "retry-max-exhausted: rate-limited",
                "function_anchor": {
                    "file": "src/Vault.sol",
                    "fn": "deposit",
                    "start_line": 2,
                    "end_line": 2,
                },
                "result": None,
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(
            _classes(r)["deposit"], "untouched",
            "Failed sidecar (rate-limited/errored) must not count as hollow or real-attack",
        )

    # r36-rebuttal: lane FCC-ANCHOR-FILELINE-FALLBACK registered in .auditooor/agent_pathspec.json
    def test_23b_empty_fn_anchor_with_fileline_cite_is_credited(self):
        """Body-pack / residual hunt sidecars emit function_anchor={file, fn:''}
        with NO line, but a real 'file:line' source cite in file_line. The fn
        record often has no end_line, so strict span containment misses a cite
        one line past the decl. The anchor must fall back to the file_line cite
        and credit the OWNING fn as a source-cited rule-out (real coverage).
        Regression: before the fix these fell through to hollow (false-red)."""
        ws = _mkws({
            "src/p2p/sync.go": (
                "package p2p\n"                       # line 1
                "func PayloadByNumberProtocolID(id uint64) string {\n"  # line 2
                "  return fmt.Sprintf(\"/op/%d\", id)\n"  # line 3 (cited)
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/bodypack.json": json.dumps({
                "status": "ok",
                "function_anchor": {"file": "src/p2p/sync.go", "fn": ""},
                "file_line": "src/p2p/sync.go:3",
                "result": {
                    "applies_to_target": "no",
                    "severity_estimate": "NA",
                    "candidate_finding": "Pure protocol-id formatter; no reachable vuln.",
                    "file_line": "src/p2p/sync.go:3",
                    "code_excerpt": "return fmt.Sprintf(\"/op/%d\", id)",
                },
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(
            _classes(r)["PayloadByNumberProtocolID"], "real-attack",
            "empty-fn anchor + real file_line cite must credit the owning fn as a "
            "source-cited rule-out (genuine coverage), not fall through to hollow",
        )

    def test_23c_empty_fn_anchor_without_cite_stays_hollow(self):
        """R80 preserved: an empty-fn anchor with file_line='NA' (no real source
        cite) is a bare-prose rule-out and must STAY hollow - the fallback must
        not manufacture a false-green from a citeless verdict."""
        ws = _mkws({
            "src/p2p/sync.go": (
                "package p2p\n"
                "func DoThing(id uint64) string {\n"
                "  if id > 0 { return \"x\" }\n"  # non-trivial body
                "  return \"\"\n"
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/nocite.json": json.dumps({
                "status": "ok",
                "function_anchor": {"file": "src/p2p/sync.go", "fn": ""},
                "file_line": "NA",
                "result": {
                    "applies_to_target": "no",
                    "severity_estimate": "NA",
                    "candidate_finding": "looks clean",
                    "file_line": "NA",
                },
            }),
        })
        r = fcc.evaluate(ws)
        self.assertNotEqual(
            _classes(r)["DoThing"], "real-attack",
            "empty-fn anchor with no source cite (file_line='NA') must NOT be credited "
            "as coverage (R80: bare prose is not coverage; the fallback must not "
            "manufacture a false-green from a citeless verdict)",
        )

    # r36-rebuttal: funnel-generic-fixes-wave3
    def test_24_nested_result_applies_yes_no_poc_stays_hollow(self):
        """applies_to_target=yes but no CONFIRMED verdict and no PoC -> hollow
        (live candidate, not confirmed exploit).
        The inner result has a verdict field (as real sidecars always do) but
        it is not CONFIRMED/EXPLOITABLE so there is no executed-PoC proof."""
        ws = _mkws({
            "src/Vault.sol": (
                "contract Vault {\n"
                "  function transfer() external {\n"  # line 2
                "    move(amt);\n"
                "  }\n"
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/nested_yes_candidate.json": json.dumps({
                "status": "ok",
                "task_type": "workspace_hunt_harnessed",
                "function_anchor": {
                    "file": "src/Vault.sol",
                    "fn": "transfer",
                    "start_line": 2,
                    "end_line": 4,
                },
                "result": json.dumps({
                    "applies_to_target": "yes",
                    "confidence": "medium",
                    "candidate_finding": "Possible re-entrancy",
                    "file_line": "NA",
                    "verdict": "needs-further-investigation",
                    "severity_estimate": "MEDIUM",
                    "notes": "needs further investigation",
                }),
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(
            _classes(r)["transfer"], "hollow",
            "applies_to_target=yes with no CONFIRMED verdict and no PoC is a "
            "live hypothesis, not a confirmed exploit - should be hollow",
        )

    def test_25_nested_result_string_anchor_parsed(self):
        """function_anchor as JSON-in-string (some generators serialise the
        anchor dict as a string) is parsed correctly."""
        anchor_str = json.dumps({
            "file": "src/Vault.sol",
            "fn": "repay",
            "start_line": 2,
            "end_line": 4,
        })
        ws = _mkws({
            "src/Vault.sol": (
                "contract Vault {\n"
                "  function repay() external {\n"
                "    x = 0;\n"
                "  }\n"
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/anchor_str.json": json.dumps({
                "status": "ok",
                "task_type": "workspace_hunt_harnessed",
                "function_anchor": anchor_str,
                "result": json.dumps({
                    "applies_to_target": "no",
                    "confidence": "high",
                    "file_line": "NA",
                    "notes": "repay is a simple setter",
                }),
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(
            _classes(r)["repay"], "hollow",
            "JSON-in-string function_anchor must be parsed and resolve to hollow",
        )


    # --- funccov-sourcecite guard tests (applies_to_target=no + defending_lines) ---
    # Bug: applies_to_target=no unconditionally marked the function hollow even
    # when the inner result.defending_lines contained a real file:line cite.
    # Per the gate's own docstring a "FP-DEFENDED / source-traced reason" must
    # count as real-attack. Fix: check defending_lines against _FILE_LINE_RE
    # before deciding hollow; bare prose (no file:line) preserves hollow (R80).

    def test_26_applies_no_with_file_line_in_defending_lines_is_real_attack(self):
        """applies_to_target=no + defending_lines='Foo.sol:42' -> real-attack.
        The agent source-cited the exact line that makes the attack inapplicable;
        that is a FP-DEFENDED / source-traced rule-out and counts as coverage."""
        ws = _mkws({
            "src/Foo.sol": (
                "contract Foo {\n"
                "  function bar() external {\n"  # line 2
                "    x = 1;\n"
                "  }\n"
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/fp_defended.json": json.dumps({
                "status": "ok",
                "task_type": "g15_coverage_hunt",
                "function_anchor": {
                    "file": "src/Foo.sol",
                    "function": "bar",
                    "line": 2,
                },
                "result": {
                    "applies_to_target": "no",
                    "confidence": "high",
                    "candidate_finding": "N/A",
                    "defending_lines": "src/Foo.sol:42 (internal pure)",
                    "attacker_path": "",
                },
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(
            _classes(r)["bar"], "real-attack",
            "applies_to_target=no with file:line in defending_lines must be "
            "credited as real-attack (FP-defended source-cited rule-out), "
            "not hollow",
        )
        ev = [f for f in r["functions"] if f["name"] == "bar"][0]["evidence"]
        self.assertTrue(
            any("finding-fp-defended-anchor" in e for e in ev),
            f"evidence must carry finding-fp-defended-anchor tag; got: {ev}",
        )

    def test_29_fp_defended_survives_mutation_verify_reconciliation(self):
        """A source-cited FP-defended rule-out must STAY real-attack under
        --mutation-verify (you cannot mutation-verify a ruled-out function;
        the gate docstring says Pass-1 is unaffected). Regression for the BEAN
        0-vs-418 drop: finding-fp-defended-anchor was absent from the
        mutation-verify genuine-evidence whitelist and got downgraded to hollow."""
        ws = _mkws({
            "src/Foo.sol": (
                "contract Foo {\n  function bar() external {\n    x = 1;\n  }\n}\n"
            ),
            ".auditooor/hunt_findings_sidecars/fp_defended.json": json.dumps({
                "status": "ok", "task_type": "g15_coverage_hunt",
                "function_anchor": {"file": "src/Foo.sol", "function": "bar", "line": 2},
                "result": {
                    "applies_to_target": "no", "confidence": "high",
                    "candidate_finding": "N/A",
                    "defending_lines": "src/Foo.sol:42 (internal pure)",
                    "attacker_path": "",
                },
            }),
        })
        r = fcc.evaluate(ws, mutation_verify=True)
        self.assertEqual(
            _classes(r)["bar"], "real-attack",
            "fp-defended source-cited rule-out must remain real-attack under "
            "mutation_verify (no attack/harness to inject a mutant into); it was "
            "being downgraded to hollow by the reconciliation whitelist gap",
        )

    def test_30_clean_trivial_survives_mutation_verify(self):
        """A source-verified TRIVIAL one-line accessor (finding-clean-trivial) must
        STAY real-attack under --mutation-verify: a field getter has nothing to
        mutation-verify (`fn k(&self)->u8 { self.k }`). Regression for near-intents
        2026-06-26: 22 trivial FROST/channel/getter accessors were downgraded to
        hollow because finding-clean-trivial was missing from the mutation-verify
        genuine-evidence whitelist."""
        ws = _mkws({
            "src/lib.rs": (
                "pub struct S { k: u8 }\n"
                "impl S {\n"
                "    pub fn k(&self) -> u8 { self.k }\n"
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/k_clean.json": json.dumps({
                "status": "ok", "task_type": "g15_coverage_hunt",
                "verdict": "NEGATIVE", "function": "k", "file_line": "src/lib.rs:3",
                "candidate_finding": "k is a trivial field accessor; no attack surface",
            }),
        })
        r = fcc.evaluate(ws, mutation_verify=True)
        self.assertEqual(
            _classes(r).get("k"), "real-attack",
            "trivial-clean accessor must remain real-attack under mutation_verify "
            "(nothing to mutate in a field getter); it was downgraded to hollow",
        )

    def test_27_applies_no_with_bare_prose_defending_lines_stays_hollow(self):
        """applies_to_target=no + bare prose defending_lines (no file:line) -> hollow.
        Bare prose without a source cite is not verifiable evidence (R80 preserved)."""
        ws = _mkws({
            "src/Foo.sol": (
                "contract Foo {\n"
                "  function baz() external {\n"  # line 2
                "    y = 2;\n"
                "  }\n"
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/bare_prose.json": json.dumps({
                "status": "ok",
                "task_type": "g15_coverage_hunt",
                "function_anchor": {
                    "file": "src/Foo.sol",
                    "function": "baz",
                    "line": 2,
                },
                "result": {
                    "applies_to_target": "no",
                    "confidence": "high",
                    "candidate_finding": "N/A",
                    "defending_lines": "the function is a pure view with no state writes",
                    "attacker_path": "",
                },
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(
            _classes(r)["baz"], "hollow",
            "applies_to_target=no with bare prose defending_lines (no file:line) "
            "must stay hollow - bare prose is not source-cited coverage (R80)",
        )

    def test_28_applies_no_empty_defending_lines_stays_hollow(self):
        """applies_to_target=no + empty defending_lines -> hollow (unchanged behavior)."""
        ws = _mkws({
            "src/Foo.sol": (
                "contract Foo {\n"
                "  function qux() external {\n"  # line 2
                "    z = 3;\n"
                "  }\n"
                "}\n"
            ),
            ".auditooor/hunt_findings_sidecars/no_defending.json": json.dumps({
                "status": "ok",
                "task_type": "g15_coverage_hunt",
                "function_anchor": {
                    "file": "src/Foo.sol",
                    "function": "qux",
                    "line": 2,
                },
                "result": {
                    "applies_to_target": "no",
                    "confidence": "high",
                    "candidate_finding": "N/A",
                    "defending_lines": "",
                    "attacker_path": "",
                },
            }),
        })
        r = fcc.evaluate(ws)
        self.assertEqual(
            _classes(r)["qux"], "hollow",
            "applies_to_target=no with empty defending_lines must stay hollow",
        )


class TestTrivialFnExclusion(unittest.TestCase):
    """trivial-fn-exclusion: Cosmos/CLI/codec/proto BOILERPLATE is NOT an
    attack-coverage unit. The gate must (a) skip machine-generated files
    (``// Code generated ... DO NOT EDIT.`` header + ``.pb.go``/``.abigen.go``
    suffixes) wholesale, and (b) drop hand-written codec/CLI/module boilerplate
    by NAME - while NEVER dropping a real security function (state mutation /
    Msg handler / fund movement / sig verification). These are the before/after
    guard tests for the injective 29,371 -> low-thousands worklist drop.
    Language-generic: synthetic Go/Solidity fixtures, zero target hardcoding."""

    def test_excludes_generated_pb_go_file_by_header(self):
        # A protoc-gen-gogo .pb.go file is full of Marshal/Unmarshal/String/
        # Reset boilerplate. It must be excluded WHOLESALE (header marker), so
        # NONE of its fns reach the worklist - even though the suffix-only check
        # would also catch it, the header is the load-bearing generic signal.
        ws = _mkws({
            "src/types/tx.pb.go": (
                "// Code generated by protoc-gen-gogo. DO NOT EDIT.\n"
                "// source: x/foo/tx.proto\n"
                "package types\n"
                "func (m *MsgFoo) Reset() {}\n"
                "func (m *MsgFoo) String() string { return \"\" }\n"
                "func (m *MsgFoo) Marshal() ([]byte, error) { return nil, nil }\n"
                "func (m *MsgFoo) Unmarshal(b []byte) error { return nil }\n"
                "func (m *MsgFoo) XXX_Unmarshal(b []byte) error { return nil }\n"
            ),
            # A hand-written keeper file (NO generated header) MUST survive.
            "src/keeper/msg_server.go": (
                "package keeper\n"
                "func (k Keeper) Withdraw(ctx Context, msg *MsgWithdraw) error {\n"
                "  k.bank.SendCoins(ctx, a, b, msg.Amount)\n"
                "  return nil\n"
                "}\n"
            ),
        })
        r = fcc.evaluate(ws)
        names = {f["name"] for f in r["functions"]}
        # the entire generated file is gone
        for boiler in ("Reset", "String", "Marshal", "Unmarshal", "XXX_Unmarshal"):
            self.assertNotIn(boiler, names,
                             f"generated-file boilerplate {boiler} must be excluded")
        # the real fund-moving Msg handler stays
        self.assertIn("Withdraw", names,
                      "hand-written keeper Withdraw (moves funds) MUST stay")

    def test_excludes_generated_abigen_go_file(self):
        ws = _mkws({
            "src/bindings/i_bank.abigen.go": (
                "// Code generated - DO NOT EDIT.\n"
                "// This file is a generated binding.\n"
                "package bindings\n"
                "func (b *Bank) Transfer(to Address, amt Int) (*Tx, error) { return nil, nil }\n"
                "func (b *Bank) BalanceOf(a Address) (Int, error) { return nil, nil }\n"
                "func (b *Bank) Call(opts *CallOpts) error { return nil }\n"
            ),
        })
        r = fcc.evaluate(ws)
        names = {f["name"] for f in r["functions"]}
        self.assertEqual(names, set(),
                         f"generated abigen binding fns must all be excluded: {names}")

    def test_excludes_handwritten_cosmos_boilerplate_by_name(self):
        # A hand-written module.go / codec.go file (NO generated header) still
        # carries Cosmos boilerplate that must be dropped BY NAME, while the
        # real handler in the same fixture survives.
        ws = _mkws({
            "src/module.go": (
                "package foo\n"
                "func (AppModule) Name() string { return \"foo\" }\n"
                "func (AppModule) DefaultGenesis(c Codec) RawMessage { return nil }\n"
                "func (AppModule) ValidateGenesis(c Codec) error { return nil }\n"
                "func (AppModule) ConsensusVersion() uint64 { return 1 }\n"
                "func (AppModule) RegisterServices(cfg Configurator) {}\n"
                "func (AppModule) RegisterInterfaces(r Registry) {}\n"
                "func (AppModule) GetTxCmd() *cobra.Command { return NewTxCmd() }\n"
                "func (AppModule) GetQueryCmd() *cobra.Command { return nil }\n"
                "func RegisterLegacyAminoCodec(c *Amino) {}\n"
                "func RegisterCodec(c *Amino) {}\n"
            ),
            "src/cli/tx.go": (
                "package cli\n"
                "func NewTxCmd() *cobra.Command { return &cobra.Command{} }\n"
                "func NewQueryCmd() *cobra.Command { return &cobra.Command{} }\n"
                "func CmdSendToEth() *cobra.Command { return &cobra.Command{} }\n"
                "func NewMsgLiquidatePositionTxCmd() *cobra.Command { return nil }\n"
                "func AddTxFlagsToCmd(cmd *cobra.Command) {}\n"
            ),
            "src/keeper/msg_server.go": (
                "package keeper\n"
                "func (k Keeper) SubmitBatch(ctx Context, msg *MsgSubmitBatch) error {\n"
                "  if !k.verifySig(msg) { return ErrBadSig }\n"
                "  k.bank.SendCoins(ctx, a, b, msg.Amount)\n"
                "  return nil\n"
                "}\n"
                "func (k Keeper) MatchOrders(ctx Context, m *Market) error {\n"
                "  for _, o := range m.Orders { k.fill(o) }\n"
                "  return nil\n"
                "}\n"
            ),
        })
        r = fcc.evaluate(ws)
        names = {f["name"] for f in r["functions"]}
        # --- boilerplate dropped ---
        dropped = {
            "Name", "DefaultGenesis", "ValidateGenesis", "ConsensusVersion",
            "RegisterServices", "RegisterInterfaces", "GetTxCmd", "GetQueryCmd",
            "RegisterLegacyAminoCodec", "RegisterCodec",
            "NewTxCmd", "NewQueryCmd", "CmdSendToEth",
            "NewMsgLiquidatePositionTxCmd", "AddTxFlagsToCmd",
        }
        leaked = dropped & names
        self.assertEqual(leaked, set(),
                         f"Cosmos/CLI/codec boilerplate must be excluded by name: {leaked}")
        # --- real security fns kept ---
        for keep in ("SubmitBatch", "MatchOrders"):
            self.assertIn(keep, names,
                          f"real Msg handler {keep} (sig verify / fund move / "
                          f"state mutation) MUST stay")

    def test_does_not_over_exclude_security_lookalikes(self):
        # DANGER guard: names that LOOK boilerplate-adjacent but ARE security
        # surface must be KEPT (when in doubt, KEEP). ValidateBasic is the first
        # input-validation defense; InitGenesis writes state; GetSigners returns
        # the auth signer set; Transfer/Deposit move funds.
        ws = _mkws({
            "src/keeper/msg_server.go": (
                "package keeper\n"
                "func (m MsgWithdraw) ValidateBasic() error { return nil }\n"
                "func (am AppModule) InitGenesis(ctx Context, c Codec, b Raw) {}\n"
                "func (m MsgFoo) GetSigners() []AccAddress { return nil }\n"
                "func (k Keeper) Transfer(ctx Context, from, to Addr, amt Int) error { return nil }\n"
                "func (k Keeper) Deposit(ctx Context, msg *MsgDeposit) error { return nil }\n"
            ),
        })
        r = fcc.evaluate(ws)
        names = {f["name"] for f in r["functions"]}
        for keep in ("ValidateBasic", "InitGenesis", "GetSigners", "Transfer", "Deposit"):
            self.assertIn(keep, names,
                          f"security-relevant {keep} must NOT be over-excluded")

    def test_injective_real_modules_survive_smoke(self):
        # SMOKE (skipped when absent): on the real injective workspace the
        # worklist must drop substantially below the 29,371 all-fns baseline AND
        # still retain real exchange/peggy keeper fns.
        ws = Path("/Users/wolf/audits/injective")
        if not ws.is_dir():
            self.skipTest("injective workspace absent")
        r = fcc.evaluate(ws)
        total = r["counts"]["total"]
        if total == 0:
            # dir exists but holds no in-scope source (cloned-out / cleaned between
            # engagements) - the smoke has nothing to assert; skip rather than fail.
            self.skipTest("injective workspace present but empty (no in-scope source)")
        self.assertLess(total, 12000,
                        f"boilerplate exclusion must drop the all-fns baseline "
                        f"(29371) substantially; got {total}")
        self.assertGreater(total, 1500,
                           f"must not over-exclude real surface; got {total}")
        by_file = {}
        for f in r["functions"]:
            by_file.setdefault(f["file"], []).append(f["name"])

        def _has(path_sub, fn):
            return any(path_sub in p and fn in v for p, v in by_file.items())

        # real peggy bridge attestation + exchange fund handlers survive
        self.assertTrue(_has("peggy/keeper", "Attest"),
                        "peggy keeper Attest must stay")
        self.assertTrue(_has("exchange/keeper/msg_server", "Deposit"),
                        "exchange msg_server Deposit must stay")
        self.assertTrue(_has("exchange/keeper/msg_server", "Withdraw"),
                        "exchange msg_server Withdraw must stay")
        # and proto/codec boilerplate is gone from the whole surface
        all_names = {n for v in by_file.values() for n in v}
        for boiler in ("XXX_Unmarshal", "MarshalToSizedBuffer", "ProtoMessage",
                       "RegisterInterfaces", "ConsensusVersion"):
            self.assertNotIn(boiler, all_names,
                             f"{boiler} boilerplate must be excluded on injective")


class TestMutationVerifyBar(unittest.TestCase):
    """--mutation-verify upgrades the harness-derived real-attack bar: a
    syntactically non-vacuous harness counts as real-attack ONLY if it is
    mutation-killed. These cases use a CACHED mutation artifact
    (.auditooor/mutation_verify_coverage.json) so they do NOT depend on the
    sibling tool being present, and an explicit fake-tool case to exercise
    the live-invocation path."""

    _HARNESS = (
        "// Function under test: Vault.deposit at src/Vault.sol:2\n"
        "contract H {\n"
        "  function check_deposit() public {\n"
        "    uint256 b = bal();\n"
        "    assertEq(b, expected);\n"
        "  }\n"
        "}\n"
    )

    def _base_files(self):
        return {
            "src/Vault.sol":
                "contract Vault {\n  function deposit() external {}\n}\n",
            "poc-tests/per_function_invariants/Halmos_Vault_deposit.t.sol":
                self._HARNESS,
        }

    def test_17_without_flag_harness_is_real_attack(self):
        # Control: default (no mutation-verify) keeps the existing behavior.
        ws = _mkws(self._base_files())
        r = fcc.evaluate(ws, mutation_verify=False)
        self.assertEqual(_classes(r)["deposit"], "real-attack")

    def test_18_mutation_killed_artifact_stays_real_attack(self):
        files = self._base_files()
        files[".auditooor/mutation_verify_coverage.json"] = json.dumps({
            "results": [{
                "function": "Vault.deposit",
                "file": "src/Vault.sol",
                "harness": "Halmos_Vault_deposit.t.sol",
                "mutation_verdict": "killed",
            }],
        })
        ws = _mkws(files)
        r = fcc.evaluate(ws, mutation_verify=True)
        self.assertEqual(_classes(r)["deposit"], "real-attack")
        self.assertEqual(r["mutation_verify"]["mutation_backend"], "available")

    def test_19_mutation_vacuous_artifact_downgrades_to_hollow(self):
        # The morpho-midnight bug class: harness body LOOKS real (assertEq) but
        # passes even with an injected bug => vacuous => HOLLOW under the bar.
        files = self._base_files()
        files[".auditooor/mutation_verify_coverage.json"] = json.dumps({
            "results": [{
                "function": "Vault.deposit",
                "file": "src/Vault.sol",
                "harness": "Halmos_Vault_deposit.t.sol",
                "mutation_verdict": "vacuous",
            }],
        })
        ws = _mkws(files)
        r = fcc.evaluate(ws, mutation_verify=True)
        self.assertEqual(_classes(r)["deposit"], "hollow")
        self.assertEqual(r["verdict"], "fail-functions-untouched-or-hollow")
        # evidence must name the precise reason
        ev = [f for f in r["functions"] if f["name"] == "deposit"][0]["evidence"]
        self.assertTrue(any("mutation-vacuous" in e for e in ev), ev)

    def test_20_no_baseline_artifact_downgrades_to_hollow(self):
        files = self._base_files()
        files[".auditooor/mutation_verify_coverage.json"] = json.dumps({
            "verdicts": [{
                "fn": "deposit", "file_line": "src/Vault.sol:2",
                "verdict": "no-baseline",
            }],
        })
        ws = _mkws(files)
        r = fcc.evaluate(ws, mutation_verify=True)
        self.assertEqual(_classes(r)["deposit"], "hollow")

    def test_20b_direct_non_vacuous_sidecar_is_killed(self):
        files = self._base_files()
        files[".auditooor/mutation_verify_coverage.json"] = json.dumps({"verdicts": []})
        files[".auditooor/cross-function-coverage/mutation_deposit.json"] = json.dumps({
            "function": "deposit",
            "source_file": "src/Vault.sol",
            "harness": "Halmos_Vault_deposit.t.sol",
            "verdict": "non-vacuous",
        })
        ws = _mkws(files)
        r = fcc.evaluate(ws, mutation_verify=True)
        self.assertEqual(_classes(r)["deposit"], "real-attack")

    def test_21_backend_unavailable_conservatively_downgrades(self):
        # No cached artifact AND the sibling tool path overridden to a
        # nonexistent file => backend unavailable => conservative hollow.
        ws = _mkws(self._base_files())
        old = os.environ.get("AUDITOOOR_FCC_MUTATION_TOOL")
        os.environ["AUDITOOOR_FCC_MUTATION_TOOL"] = str(ws / "does_not_exist.py")
        try:
            r = fcc.evaluate(ws, mutation_verify=True)
        finally:
            if old is None:
                os.environ.pop("AUDITOOOR_FCC_MUTATION_TOOL", None)
            else:
                os.environ["AUDITOOOR_FCC_MUTATION_TOOL"] = old
        self.assertEqual(_classes(r)["deposit"], "hollow")
        self.assertEqual(r["mutation_verify"]["mutation_backend"], "unavailable")

    def test_22_live_fake_tool_invocation_kills(self):
        # Exercise the live subprocess path with a fake sibling tool that
        # emits a kill verdict on stdout (with leading log noise to test the
        # tolerant JSON extraction).
        ws = _mkws(self._base_files())
        fake = ws / "fake_mut.py"
        fake.write_text(
            "import sys, json\n"
            "print('[log] running mutation pass...')\n"
            "print(json.dumps({'results': [\n"
            "  {'function': 'deposit', 'file': 'src/Vault.sol',\n"
            "   'harness': 'Halmos_Vault_deposit.t.sol', 'killed': True}]}))\n",
            encoding="utf-8",
        )
        old = os.environ.get("AUDITOOOR_FCC_MUTATION_TOOL")
        os.environ["AUDITOOOR_FCC_MUTATION_TOOL"] = str(fake)
        try:
            r = fcc.evaluate(ws, mutation_verify=True)
        finally:
            if old is None:
                os.environ.pop("AUDITOOOR_FCC_MUTATION_TOOL", None)
            else:
                os.environ["AUDITOOOR_FCC_MUTATION_TOOL"] = old
        self.assertEqual(_classes(r)["deposit"], "real-attack")

    def test_23_finding_real_attack_unaffected_by_mutation_bar(self):
        # Pass-1 finding-derived real-attack must NOT be gated by mutation
        # verification (only harness-derived Pass-2 coverage is).
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function deposit(uint256 a) external { x = a; }\n}\n",
            ".auditooor/hunt_findings_sidecars/F1.json": json.dumps({
                "verdict": "CONFIRMED",
                "file_line": "src/Vault.sol:2",
                "poc_evidence_lines": "[PASS] testDepositDrain",
            }),
        })
        r = fcc.evaluate(ws, mutation_verify=True)
        self.assertEqual(_classes(r)["deposit"], "real-attack")

    def test_24_env_default_enables_bar(self):
        files = self._base_files()
        files[".auditooor/mutation_verify_coverage.json"] = json.dumps({
            "results": [{"function": "Vault.deposit", "file": "src/Vault.sol",
                         "harness": "Halmos_Vault_deposit.t.sol",
                         "mutation_verdict": "vacuous"}],
        })
        ws = _mkws(files)
        # The env flag is read in main(); evaluate() takes the explicit param,
        # so we assert the param wiring directly (env parse covered in main).
        r_on = fcc.evaluate(ws, mutation_verify=True)
        r_off = fcc.evaluate(ws, mutation_verify=False)
        self.assertEqual(_classes(r_on)["deposit"], "hollow")
        self.assertEqual(_classes(r_off)["deposit"], "real-attack")

    def test_26_prose_confirmed_credit_downgraded_under_mutation_bar(self):
        # r36-rebuttal: funnel-generic-fixes-wave4
        # Wave-4 over-credit reconciliation: a real-attack credited ONLY by a prose
        # _CONFIRMED_RE claim (no executed-PoC transcript, no mutation-kill) must NOT
        # survive mutation_verify - that is the morpho-midnight false-green class
        # (prose "confirmed" on a vacuous/unverified function reads as covered). In
        # default mode it stays real-attack (lenient); under the mutation bar it is
        # downgraded to hollow. Contrast with test_23, where an executed PoC
        # ([PASS] ...) DOES survive.
        ws = _mkws({
            "src/Vault.sol":
                "contract Vault {\n  function f(uint256 a) external { x = a; }\n}\n",
            ".auditooor/hunt_findings_sidecars/prose.json": json.dumps({
                "verdict": "CONFIRMED",          # prose claim - NO poc/pass transcript
                "file_line": "src/Vault.sol:2",
            }),
        })
        self.assertEqual(_classes(fcc.evaluate(ws, mutation_verify=True))["f"],
                         "hollow", "prose-only credit must downgrade under mutation bar")
        self.assertEqual(_classes(fcc.evaluate(ws, mutation_verify=False))["f"],
                         "real-attack", "default mode stays lenient (unchanged)")


class TestMorphoSmokeAnchor(unittest.TestCase):
    WS = Path("/Users/wolf/audits/morpho-midnight")

    @unittest.skipUnless(
        Path("/Users/wolf/audits/morpho-midnight").is_dir(),
        "morpho-midnight workspace not present (smoke anchor)",
    )
    def test_morpho_terminal_clean_credit_vs_proven_vacuous(self):
        # r36-rebuttal: lane-funcov-clean-credit
        # Corrected semantics (supersedes the Wave-4 "all hollow" anchor, whose
        # premise - "harnesses are vacuous, 0/46 kills" - CONFLATED two distinct
        # mutation outcomes):
        #   * INCONCLUSIVE (mutant_count==0 / no-mutants): the generator produced
        #     no mutants because the body has no mutable operators (setters,
        #     access-control, view). A reasoned PoC-backed rule-out (real
        #     poc_path + [PASS] + a named attack invariant e.g.
        #     unauthorizedCannotDrainVictimCollateral) is GENUINE coverage - a
        #     harness is the PROVE step for a surviving bug, not a precondition
        #     for a clean verdict. -> real-attack.
        #   * PROVEN-VACUOUS / NO-BASELINE (mutants WERE generated and survived,
        #     or the harness never produced a passing baseline): the clean PoC is
        #     demonstrably non-protective or did not run. -> stays hollow.
        # morpho-midnight ships .auditooor/mutation_verify_coverage.json so the
        # gate runs with mutation_verify=True (as audit-complete invokes it).
        r = fcc.evaluate(self.WS, mutation_verify=True)
        by_name = {}
        for f in r["functions"]:
            by_name.setdefault(f["name"], []).append(f)

        def _has(name, cls):
            return any(f["classification"] == cls for f in by_name.get(name, []))

        # FIX direction: PoC-backed reasoned rule-outs on inconclusive bodies are
        # credited as covered (these were wrongly downgraded by Wave-4).
        credited = [
            "repayAndWithdrawCollateral",         # MidnightBundles, theft-of-funds invariant
            "buyWithUnitsTargetAndWithdrawCollateral",
            "supplyCollateralAndSellWithUnitsTarget",
            "setRoleSetter", "multicall",
        ]
        wrongly_hollow = [n for n in credited
                          if n in by_name and not _has(n, "real-attack")]
        self.assertEqual(
            wrongly_hollow, [],
            f"PoC-backed reasoned rule-outs (inconclusive mutation) MUST count as "
            f"covered, not hollow: {wrongly_hollow}")

        # FALSE-GREEN guard: any function whose mutation record is proven-vacuous
        # / no-baseline must NOT be credited from a terminal-clean record.
        leaked = []
        for f in r["functions"]:
            ev = f.get("evidence") or []
            disproven = any("over-credit-downgrade" in e for e in ev)
            if f["classification"] == "real-attack" and disproven:
                leaked.append(f"{f['name']} (proven-vacuous but credited)")
        self.assertEqual(leaked, [],
                         f"proven-vacuous clean PoCs MUST stay hollow: {leaked}")


class FcFalseRedKillVerdictTest(unittest.TestCase):
    """FC-FALSE-RED: the canonical per-fn hunt verdict KILL must normalize to a
    clean terminal status (ruled-out) so a source-cited rule-out credits coverage,
    instead of being dropped (unmapped 'kill') and false-downgraded to hollow."""

    def test_kill_normalizes_to_ruled_out(self):
        self.assertEqual(fcc._normalize_terminal_status("KILL"), "ruled-out")
        self.assertEqual(fcc._normalize_terminal_status("killed"), "ruled-out")
        self.assertIn("ruled-out", fcc._TERMINAL_CLEAN_STATUSES)

    def test_confirmed_still_maps_to_finding(self):
        self.assertEqual(fcc._normalize_terminal_status("CONFIRMED"), "finding")
        self.assertIn("finding", fcc._TERMINAL_ATTACK_STATUSES)

    def test_kill_verdict_yields_terminal_status_from_raw(self):
        raw = json.dumps({
            "status": "ok",
            "result": json.dumps({
                "applies_to_target": "yes", "verdict": "KILL",
                "file_line": "src/solidity/contracts/Mailbox.sol:225",
            }),
        })
        # KILL (even with applies_to_target=yes) is a terminal clean verdict.
        self.assertEqual(fcc._structured_status_from_raw(raw), "ruled-out")


class TestDerivedDirAnchorCredit(unittest.TestCase):
    """SSV loop fix 2026-06-23: Pass-1 anchor-crediting historically read only
    ws/.auditooor/, so a per-fn KILL emitted by the canonical hunt to the REPO
    derived dir (audit/corpus_tags/derived/mimo_harness_<ws>*) - carrying an
    authoritative top-level function_anchor - was never credited (the subject fn
    stayed hollow). _pass1_evidence_paths now also globs the derived dir. Gated by
    a real verdict + anchor downstream, so it cannot create a false-green.
    """
    def setUp(self):
        self._derived_dirs = []

    def tearDown(self):
        import shutil
        for d in self._derived_dirs:
            shutil.rmtree(d, ignore_errors=True)

    def test_anchored_kill_in_derived_dir_credits_subject_fn(self):
        ws = _mkws({"src/Ops.sol":
                    "contract Ops {\n  function registerOperator() external {}\n}\n"})
        derived = (Path(fcc.__file__).resolve().parent.parent
                   / "audit" / "corpus_tags" / "derived"
                   / f"mimo_harness_{ws.name}_workflow")
        derived.mkdir(parents=True, exist_ok=True)
        self._derived_dirs.append(derived)
        # workflow-drill per-fn KILL sidecar: TOP-LEVEL function_anchor + a same-file
        # source cite (agent cited a body line, not the decl line).
        (derived / "ssv-fc-registerOperator-2.json").write_text(json.dumps({
            "status": "ok", "task_id": "ssv-fc-registerOperator-2",
            "source": "workflow-drill-sidecar-emit",
            "function_anchor": {"file": "src/Ops.sol", "fn": "registerOperator",
                                "function": "registerOperator", "line": 2},
            "result": json.dumps({
                "verdict": "KILL", "applies_to_target": "no", "confidence": "high",
                "file_line": "src/Ops.sol:2",
                "reasoning": "owner-gated; no unprivileged path",
            }),
        }))
        r = fcc.evaluate(ws)
        self.assertEqual(_classes(r)["registerOperator"], "real-attack", r.get("reason"))
        self.assertEqual(r["verdict"], "pass-fully-covered")


if __name__ == "__main__":
    unittest.main(verbosity=2)
