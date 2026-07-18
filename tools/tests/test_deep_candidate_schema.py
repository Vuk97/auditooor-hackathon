#!/usr/bin/env python3
"""Tests for V5 PR-5: typed deep_candidate.v1 schema + lane emitters.

Covers Codex's four acceptance tests verbatim:

1. Malformed candidate JSON fails validation.
2. ``crypto-deep-runner --emit-candidate`` with no verifier surface exits
   cleanly as skipped, NOT green-with-empty-candidate.
3. Symbolic counterexamples must replay OR remain advisory: a
   counterexample without replay is emitted with confidence='low' and
   blocking_questions=['needs replay', ...].
4. Economic simulations must state assumptions: a candidate with empty
   ``reproduction`` is rejected by the validator.

Plus targeted coverage for:

* validator cross-field transitions (high requires poc_ready, etc.)
* claim plain-text guard (markdown / severity-smuggling rejection)
* reproduction placeholder guard (TBD/TODO/N/A rejection)
* the shared ``tools/lib/deep_candidate.py`` build_candidate API
* math-invariant-miner emission round-trip

Hermetic. No network. Stdlib only.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "docs" / "schemas" / "deep_candidate.v1.json"
VALIDATOR = ROOT / "tools" / "validate-deep-candidate.py"
LIB_PATH = ROOT / "tools" / "lib" / "deep_candidate.py"
MATH_TOOL = ROOT / "tools" / "math-invariant-miner.py"
CRYPTO_TOOL = ROOT / "tools" / "crypto-deep-runner.py"
ECON_TOOL = ROOT / "tools" / "econ-actor-modeler.py"
SOURCE_MINE_TOOL = ROOT / "tools" / "source-mining-campaign.py"
SYMBOLIC_TOOL = ROOT / "tools" / "symbolic-execution-validator.py"
EXAMPLE = ROOT / "docs" / "schemas" / "example_candidate.json"


def _load_lib():
    spec = importlib.util.spec_from_file_location("_deep_candidate_lib_test", LIB_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_deep_candidate_lib_test", module)
    spec.loader.exec_module(module)
    return module


def _load_validator():
    path = VALIDATOR
    spec = importlib.util.spec_from_file_location("_validator_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_validator_test", module)
    spec.loader.exec_module(module)
    return module


def _good_candidate(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "schema_version": "deep_candidate.v1",
        "lane": "math",
        "candidate_id": "math.test.001",
        "files": ["src/Vault.sol"],
        "claim": "Vault.deposit may round shares against the depositor on first deposit.",
        "trigger": "Empty vault, attacker pre-funds with 1 wei before first user.",
        "impact": "Late depositors may receive zero shares for non-trivial assets.",
        "reproduction": "forge test --match-test test_FirstDepositRounding -vv",
        "confidence": "low",
        "blocking_questions": ["Confirm rounding direction in deposit()."],
        "promotion_status": "investigate",
    }
    base.update(overrides)
    return base


class SchemaShapeTests(unittest.TestCase):
    """Schema file is well-formed and has the keys lane wirings depend on."""

    def test_schema_is_valid_json(self) -> None:
        doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(doc.get("title"), "Deep Candidate v1")
        self.assertIn("$id", doc)

    def test_schema_required_fields(self) -> None:
        doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        required = doc.get("required") or []
        for key in (
            "schema_version",
            "lane",
            "candidate_id",
            "files",
            "claim",
            "trigger",
            "impact",
            "reproduction",
            "confidence",
            "blocking_questions",
            "promotion_status",
        ):
            self.assertIn(key, required)

    def test_schema_lane_enum(self) -> None:
        doc = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        lanes = doc["properties"]["lane"]["enum"]
        self.assertEqual(
            sorted(lanes),
            ["crypto", "econ", "fuzz", "math", "source_mine", "symbolic"],
        )


class ValidatorAcceptanceTests(unittest.TestCase):
    """Codex's four acceptance tests + cross-field transitions."""

    def setUp(self) -> None:
        self.validator = _load_validator()

    # Acceptance test 1: malformed candidate JSON fails validation.
    def test_acceptance_1_malformed_fails(self) -> None:
        ok, errors = self.validator.validate({"lane": "math"})
        self.assertFalse(ok)
        self.assertTrue(any("missing required field" in e for e in errors))

    def test_acceptance_1_unknown_field_fails(self) -> None:
        bad = _good_candidate(**{"unexpected_extra": "boom"})
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("unexpected field" in e for e in errors))

    def test_acceptance_1_bad_lane_fails(self) -> None:
        bad = _good_candidate(lane="bogus")
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("lane must be one of" in e for e in errors))

    def test_acceptance_1_absolute_path_rejected(self) -> None:
        bad = _good_candidate(files=["/abs/path/to/file.sol"])
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("workspace-relative" in e for e in errors))

    def test_acceptance_1_parent_traversal_rejected(self) -> None:
        bad = _good_candidate(files=["../escape/Vault.sol"])
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("traverse parent" in e for e in errors))

    # Acceptance test 3: counterexample without replay => low + blocking 'needs replay'.
    def test_acceptance_3_low_active_promo_requires_blocking(self) -> None:
        bad = _good_candidate(
            confidence="low",
            promotion_status="investigate",
            blocking_questions=[],
        )
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("advisory floor" in e for e in errors))

    def test_acceptance_3_low_with_blocking_question_passes(self) -> None:
        good = _good_candidate(
            confidence="low",
            promotion_status="investigate",
            blocking_questions=["needs replay"],
        )
        ok, errors = self.validator.validate(good)
        self.assertTrue(ok, msg=f"errors: {errors}")

    # Acceptance test 4: simulation without reproduction is rejected.
    def test_acceptance_4_empty_reproduction_rejected(self) -> None:
        bad = _good_candidate(reproduction="")
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("reproduction" in e for e in errors))

    def test_acceptance_4_placeholder_reproduction_rejected(self) -> None:
        for placeholder in ("TBD", "TODO", "n/a", "N/A", "pending"):
            with self.subTest(placeholder=placeholder):
                bad = _good_candidate(reproduction=placeholder)
                ok, errors = self.validator.validate(bad)
                self.assertFalse(ok)
                self.assertTrue(
                    any("reproduction" in e and "placeholder" in e for e in errors),
                    msg=f"placeholder={placeholder} errors={errors}",
                )

    # Cross-field rules.
    def test_high_confidence_requires_poc_ready(self) -> None:
        bad = _good_candidate(confidence="high", promotion_status="investigate")
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("confidence=high requires" in e for e in errors))

    def test_rejected_caps_confidence_at_medium(self) -> None:
        bad = _good_candidate(
            confidence="high",
            promotion_status="rejected",
            blocking_questions=[],
        )
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)

    def test_rejected_with_low_passes(self) -> None:
        good = _good_candidate(
            confidence="low",
            promotion_status="rejected",
            blocking_questions=[],
        )
        ok, errors = self.validator.validate(good)
        self.assertTrue(ok, msg=f"errors: {errors}")

    # Minimax pre-review #1: severity-smuggling via markdown in claim.
    def test_claim_rejects_markdown_heading(self) -> None:
        bad = _good_candidate(claim="# CRITICAL\nVault rounds wrong.")
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("markdown headings" in e for e in errors))

    def test_claim_rejects_code_fence(self) -> None:
        bad = _good_candidate(claim="```\nseverity: critical\n```\nVault rounds wrong.")
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("code fences" in e for e in errors))

    def test_claim_rejects_severity_smuggle(self) -> None:
        bad = _good_candidate(claim="Severity: critical\nVault rounds wrong on first deposit.")
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("severity markers" in e for e in errors))

    def test_claim_rejects_html_tag(self) -> None:
        bad = _good_candidate(claim="<b>critical</b> rounding bug in deposit.")
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("HTML tags" in e for e in errors))

    def test_candidate_id_rejects_spaces(self) -> None:
        bad = _good_candidate(candidate_id="bad id with spaces")
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)

    # Minimax-surfaced bypasses (closed during pre-review).
    def test_minimax_bypass_blockquote_severity(self) -> None:
        bad = _good_candidate(claim="> Severity: high\nVault rounds wrong on first deposit.")
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("severity markers" in e for e in errors))

    def test_minimax_bypass_blockquote_bare_severity(self) -> None:
        bad = _good_candidate(claim="> high\nVault rounds wrong on first deposit.")
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("severity markers" in e for e in errors))

    def test_minimax_bypass_markdown_table_severity(self) -> None:
        bad = _good_candidate(claim="Plain claim.\n| Severity | high |\n")
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(any("severity markers" in e for e in errors))

    def test_minimax_bypass_poc_ready_no_proof(self) -> None:
        # poc_ready + medium confidence + empty blocking_questions used to slip
        # through. Now caught: a candidate cannot claim PoC-readiness without
        # either high confidence (real PoC) OR a blocking question describing
        # what is preventing the upgrade.
        bad = _good_candidate(
            confidence="medium",
            promotion_status="poc_ready",
            blocking_questions=[],
        )
        ok, errors = self.validator.validate(bad)
        self.assertFalse(ok)
        self.assertTrue(
            any("PoC-readiness without proof" in e for e in errors),
            msg=f"errors: {errors}",
        )

    def test_poc_ready_high_passes_without_blocking(self) -> None:
        good = _good_candidate(
            confidence="high",
            promotion_status="poc_ready",
            blocking_questions=[],
        )
        ok, errors = self.validator.validate(good)
        self.assertTrue(ok, msg=f"errors: {errors}")

    def test_poc_ready_medium_passes_with_blocking(self) -> None:
        good = _good_candidate(
            confidence="medium",
            promotion_status="poc_ready",
            blocking_questions=["what evidence would promote to high?"],
        )
        ok, errors = self.validator.validate(good)
        self.assertTrue(ok, msg=f"errors: {errors}")


class ValidatorCLITests(unittest.TestCase):
    """Smoke: CLI wrapper exits 0 on the example candidate."""

    def test_cli_accepts_example(self) -> None:
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(EXAMPLE)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_cli_rejects_malformed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "bad.json"
            bad_path.write_text(
                json.dumps({"lane": "math"}), encoding="utf-8"
            )
            result = subprocess.run(
                [sys.executable, str(VALIDATOR), str(bad_path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1, msg=result.stderr)
            self.assertIn("INVALID", result.stderr)

    def test_cli_rejects_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad_path = Path(tmp) / "bad.json"
            bad_path.write_text("{not json", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(VALIDATOR), str(bad_path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2, msg=result.stderr)


class BuildCandidateLibTests(unittest.TestCase):
    """tools/lib/deep_candidate.py build_candidate API."""

    def setUp(self) -> None:
        self.lib = _load_lib()
        self.validator = _load_validator()

    def test_build_defaults_advisory_floor(self) -> None:
        doc = self.lib.build_candidate(
            lane="math",
            candidate_id="math.x.001",
            files=["src/A.sol"],
            claim="Plain claim about A.",
            trigger="Caller invokes A.foo() under condition X.",
            impact="Possible drift between paired state vars.",
            reproduction="forge test --match-test test_A -vv",
            blocking_questions=["Confirm pairing assumption."],
        )
        self.assertEqual(doc["confidence"], "low")
        self.assertEqual(doc["promotion_status"], "investigate")
        ok, errors = self.validator.validate(doc)
        self.assertTrue(ok, msg=f"errors: {errors}")

    def test_unknown_lane_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.lib.build_candidate(
                lane="bogus",
                candidate_id="x.1",
                files=["src/A.sol"],
                claim="c",
                trigger="t",
                impact="i",
                reproduction="r",
            )

    def test_workspace_relative_normalisation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp).resolve()
            inside = ws / "src" / "X.sol"
            inside.parent.mkdir(parents=True)
            inside.write_text("// stub", encoding="utf-8")
            doc = self.lib.build_candidate(
                lane="math",
                candidate_id="math.norm.1",
                files=[str(inside)],
                claim="claim",
                trigger="trig",
                impact="imp",
                reproduction="forge test -vv",
                blocking_questions=["q"],
                workspace=ws,
            )
            self.assertEqual(doc["files"], ["src/X.sol"])

    def test_write_candidate_creates_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            doc = self.lib.build_candidate(
                lane="math",
                candidate_id="math.write.1",
                files=["src/X.sol"],
                claim="c",
                trigger="t",
                impact="i",
                reproduction="forge test -vv",
                blocking_questions=["q"],
            )
            out = self.lib.write_candidate(doc, workspace=ws)
            self.assertTrue(out.exists())
            self.assertEqual(out.parent.name, "deep_candidates")


class MathLaneEmissionTests(unittest.TestCase):
    """Round-trip: math-invariant-miner --emit-candidate produces valid JSON."""

    def setUp(self) -> None:
        self.validator = _load_validator()

    def _make_workspace(self, tmp: Path) -> Path:
        ws = tmp / "ws"
        (ws / "src").mkdir(parents=True)
        # A contract with a one-sided mutation: mint() increments
        # totalSupply but does NOT touch balanceOf — the miner's
        # _conservation_candidates emits a violation for this.
        (ws / "src" / "Token.sol").write_text(
            """
            pragma solidity ^0.8.0;
            contract Token {
                uint256 public totalSupply;
                mapping(address => uint256) public balanceOf;
                function mint(uint256 amount) external {
                    totalSupply = totalSupply + amount;
                }
                function burn(uint256 amount) external {
                    totalSupply = totalSupply - amount;
                }
            }
            """,
            encoding="utf-8",
        )
        return ws

    def test_math_emit_candidate_writes_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_workspace(Path(tmp))
            out_dir = ws / "math_invariants"
            result = subprocess.run(
                [
                    sys.executable,
                    str(MATH_TOOL),
                    "--workspace",
                    str(ws),
                    "--output-dir",
                    str(out_dir),
                    "--emit-candidate",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            emitted_dir = ws / "deep_candidates"
            self.assertTrue(emitted_dir.exists(), msg=result.stderr)
            files = sorted(emitted_dir.glob("math_*.json"))
            self.assertGreater(len(files), 0, msg="no candidate emitted")
            for f in files:
                doc = json.loads(f.read_text(encoding="utf-8"))
                ok, errors = self.validator.validate(doc)
                self.assertTrue(ok, msg=f"{f}: {errors}")

    def test_math_no_emit_flag_keeps_default_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_workspace(Path(tmp))
            out_dir = ws / "math_invariants"
            result = subprocess.run(
                [
                    sys.executable,
                    str(MATH_TOOL),
                    "--workspace",
                    str(ws),
                    "--output-dir",
                    str(out_dir),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue((out_dir / "math_spec.json").exists())
            self.assertFalse((ws / "deep_candidates").exists(),
                             msg="opt-in violated: emission ran without flag")


class CryptoLaneEmissionTests(unittest.TestCase):
    """Acceptance test 2: zero-surface workspace must NOT green-with-empty."""

    def test_acceptance_2_no_surface_skipped_no_empty_emission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / "src").mkdir(parents=True)
            # Plain ERC20-shaped contract: no verifier surface tokens.
            (ws / "src" / "Plain.sol").write_text(
                """
                pragma solidity ^0.8.0;
                contract Plain {
                    function transfer(address to, uint256 a) external {}
                }
                """,
                encoding="utf-8",
            )
            packet = ws / "packet.json"
            report = ws / "report.md"
            result = subprocess.run(
                [
                    sys.executable,
                    str(CRYPTO_TOOL),
                    "--phase",
                    "all",
                    "--root",
                    str(ws / "src"),
                    "--workspace",
                    str(ws),
                    "--template",
                    str(ROOT / "templates" / "crypto_verifier_review.md"),
                    "--packet-out",
                    str(packet),
                    "--report-out",
                    str(report),
                    "--emit-candidate",
                ],
                capture_output=True,
                text=True,
            )
            # Tool exits cleanly...
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            # ...skip path was taken (preflight prints SKIPPED)...
            self.assertIn("SKIPPED", result.stderr)
            # ...and CRUCIALLY no deep_candidates dir was populated.
            emitted_dir = ws / "deep_candidates"
            if emitted_dir.exists():
                self.assertEqual(
                    list(emitted_dir.iterdir()),
                    [],
                    msg="acceptance test 2 violated: empty emission written despite SKIPPED",
                )

    def test_force_with_surface_emits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Verifier.sol").write_text(
                """
                pragma solidity ^0.8.0;
                contract Groth16Verifier {
                    function verifyProof(uint256[8] calldata proof,
                                         uint256[2] calldata publicInputs)
                        external view returns (bool) { return true; }
                }
                """,
                encoding="utf-8",
            )
            packet = ws / "packet.json"
            report = ws / "report.md"
            result = subprocess.run(
                [
                    sys.executable,
                    str(CRYPTO_TOOL),
                    "--phase",
                    "all",
                    "--root",
                    str(ws / "src"),
                    "--workspace",
                    str(ws),
                    "--template",
                    str(ROOT / "templates" / "crypto_verifier_review.md"),
                    "--packet-out",
                    str(packet),
                    "--report-out",
                    str(report),
                    "--emit-candidate",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            # Surface present => at least one candidate emitted.
            emitted_dir = ws / "deep_candidates"
            self.assertTrue(emitted_dir.exists(), msg=result.stderr)
            files = list(emitted_dir.glob("crypto_*.json"))
            self.assertGreater(len(files), 0, msg=result.stderr)
            # And it validates.
            validator = _load_validator()
            for f in files:
                doc = json.loads(f.read_text(encoding="utf-8"))
                ok, errors = validator.validate(doc)
                self.assertTrue(ok, msg=f"{f}: {errors}")


class SourceMineStubEmissionTests(unittest.TestCase):
    """source-mining-campaign.py vendor stub round-trip."""

    def test_jsonl_to_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            jsonl = ws / "claims.jsonl"
            jsonl.write_text(
                json.dumps(
                    {
                        "bug_class": "rounding-against-user",
                        "files": ["src/Vault.sol"],
                        "description": "Vault.deposit rounds against user.",
                        "trigger": "First deposit on empty vault.",
                        "impact": "Late depositors get zero shares.",
                        "repro": "forge test --match-test test_Round -vv",
                        "exhibited_in_workspace": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SOURCE_MINE_TOOL),
                    "--workspace",
                    str(ws),
                    "--from-jsonl",
                    str(jsonl),
                    "--emit-candidate",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            emitted = list((ws / "deep_candidates").glob("source_mine_*.json"))
            self.assertEqual(len(emitted), 1)
            doc = json.loads(emitted[0].read_text(encoding="utf-8"))
            validator = _load_validator()
            ok, errors = validator.validate(doc)
            self.assertTrue(ok, msg=f"errors: {errors}")
            self.assertEqual(doc["lane"], "source_mine")
            self.assertEqual(doc["promotion_status"], "investigate")

    def test_requires_emit_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            jsonl = ws / "claims.jsonl"
            jsonl.write_text(json.dumps({"bug_class": "x"}) + "\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SOURCE_MINE_TOOL),
                    "--workspace",
                    str(ws),
                    "--from-jsonl",
                    str(jsonl),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2, msg=result.stderr)
            self.assertIn("--emit-candidate", result.stderr)


class FuzzCandidateEmitTests(unittest.TestCase):
    """fuzz-candidate-emit.py converts a fuzz manifest into typed candidates."""

    def test_emits_one_per_failure(self) -> None:
        from importlib import util as _util
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            manifest = ws / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "failures": [
                            {
                                "invariant": "test_VaultSolvent",
                                "contract": "Vault",
                                "path": "test/Vault.t.sol",
                                "seed": {"call_sequence": [{"fn": "deposit", "args": [1]}]},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            tool = ROOT / "tools" / "fuzz-candidate-emit.py"
            result = subprocess.run(
                [
                    sys.executable,
                    str(tool),
                    "--workspace",
                    str(ws),
                    "--manifest",
                    str(manifest),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            emitted = list((ws / "deep_candidates").glob("fuzz_*.json"))
            self.assertEqual(len(emitted), 1)
            doc = json.loads(emitted[0].read_text(encoding="utf-8"))
            validator = _load_validator()
            ok, errors = validator.validate(doc)
            self.assertTrue(ok, msg=f"errors: {errors}")
            self.assertEqual(doc["lane"], "fuzz")


class SymbolicCounterexampleTests(unittest.TestCase):
    """Acceptance test 3 fixture: CE without replay => low + 'needs replay'."""

    def test_ce_without_replay_emits_advisory(self) -> None:
        # We exercise the helper directly because the symbolic-runner.sh
        # binary is not always on PATH in CI.
        sym_module = importlib.util.spec_from_file_location(
            "_sym_validator_test", SYMBOLIC_TOOL
        )
        assert sym_module is not None and sym_module.loader is not None
        mod = importlib.util.module_from_spec(sym_module)
        sys.modules.setdefault("_sym_validator_test", mod)
        sym_module.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            draft = ws / "draft.md"
            draft.write_text("# draft\n", encoding="utf-8")
            manifest = {
                "schema_version": 1,
                "engagement": "demo",
                "draft": "draft.md",
                "angle": "A-AUTH",
                "verdict": "counterexample",
                "runtime_ms": 100,
                "counterexample": {"call_sequence": []},  # empty => no replay
                "backend": "halmos",
                "backend_version": "0.0.0",
                "runner_manifest": None,
                "skipped_reason": None,
            }
            out = mod._emit_symbolic_candidate(ws, manifest, draft)
            self.assertIsNotNone(out)
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(doc["confidence"], "low")
            self.assertIn("needs replay", doc["blocking_questions"])
            validator = _load_validator()
            ok, errors = validator.validate(doc)
            self.assertTrue(ok, msg=f"errors: {errors}")


if __name__ == "__main__":
    unittest.main()
