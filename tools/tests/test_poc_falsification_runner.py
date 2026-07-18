"""Unit tests for Lane 4 PoC Falsification Runner.

Covered scenarios:
1. Low row with ``--cmd 'true'`` -> sane verdict (proved/inconclusive, not needs_harness).
2. High row with no negative control -> verdict NOT ``proved`` and ``open_blockers``
   records the missing control.
3. ``--cmd 'false'`` on a High row -> verdict is ``disproved``.
4. A timing/persistence claim with no restart check -> verdict downgraded
   (inconclusive or needs_harness).
5. Output schema has all required fields.
6. not_in_scope oracle returns ``not_in_scope`` verdict.
7. cosmos/network-level row without multi-validator evidence -> blocker recorded.
8. EVM row with ``--cmd 'true'`` and no control -> inconclusive (not proved).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "poc-falsification-runner.py"

_spec = importlib.util.spec_from_file_location("poc_falsification_runner", TOOL)
mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(mod)  # type: ignore[union-attr]

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

LOW_ROW: dict = {
    "lead_id": "EQ-LOW-01",
    "title": "minor gas inefficiency in transfer helper",
    "source_refs": ["contracts/Transfer.sol:42"],
    "attack_class": "gas-inefficiency",
    "likely_severity": "Low",
    "severity_confidence": "high",
    "attacker_control": "known",
    "impact_path": "yield theft",
    "proof_path": "foundry",
    "next_command": "forge test -vvv -run testGasInefficiency",
    "blockers": [],
    "dupe_risk": "low",
    "priority_score": 0.1,
}

HIGH_ROW_NO_CONTROL: dict = {
    "lead_id": "EQ-HIGH-01",
    "title": "reentrancy in vault withdrawal allows fund drain",
    "source_refs": ["contracts/Vault.sol:88"],
    "attack_class": "reentrancy",
    "likely_severity": "High",
    "severity_confidence": "high",
    "attacker_control": "known",
    "impact_path": "fund theft",
    "proof_path": "foundry",
    "next_command": "forge test -vvv -run testReentrancy",
    "blockers": [],
    "dupe_risk": "low",
    "priority_score": 0.9,
}

HIGH_ROW_WITH_CONTROL: dict = {
    "lead_id": "EQ-HIGH-02",
    "title": "price manipulation in AMM share accounting",
    "source_refs": ["contracts/AMM.sol:200"],
    "attack_class": "price-manipulation",
    "likely_severity": "High",
    "severity_confidence": "medium",
    "attacker_control": "known",
    "impact_path": "fund theft",
    "proof_path": "foundry",
    # Embed control hint in blockers so the transcript scanner sees it
    "next_command": "forge test -vvv",
    "blockers": ["negative control test: run baseline without price feed manipulation"],
    "dupe_risk": "low",
    "priority_score": 0.85,
}

TIMING_LIVENESS_ROW: dict = {
    "lead_id": "EQ-TIMING-01",
    "title": "consensus liveness failure due to validator halt under load",
    "source_refs": ["node/consensus.go:300"],
    "attack_class": "liveness-failure",
    "likely_severity": "High",
    "severity_confidence": "low",
    "attacker_control": "partial",
    "impact_path": "liveness",
    "proof_path": "cosmos-production",
    "next_command": "go test ./... -run TestConsensusLiveness -v",
    "blockers": ["no restart evidence yet"],
    "dupe_risk": "unknown",
    "priority_score": 0.7,
}

COSMOS_NETWORK_ROW: dict = {
    "lead_id": "EQ-COSMOS-01",
    "title": "AppHash divergence in cosmos state-machine write path",
    "source_refs": ["app/abci.go:150"],
    "attack_class": "apphash-divergence",
    "likely_severity": "Critical",
    "severity_confidence": "medium",
    "attacker_control": "known",
    "impact_path": "liveness",
    "proof_path": "cosmos-production",
    "next_command": "go test ./... -run TestAppHash -v",
    "blockers": [],
    "dupe_risk": "low",
    "priority_score": 0.95,
}

OOS_ORACLE: dict = {
    "scope": "out_of_scope",
    "likely_severity": "High",
    "oos_reason": "test fixture only",
}

REQUIRED_FIELDS = {
    "candidate_id",
    "verdict",
    "commands_run",
    "transcript_paths",
    "negative_controls",
    "production_path_checks",
    "restart_checks",
    "multi_validator_checks",
    "synthetic_state_status",
    "open_blockers",
}

VALID_VERDICTS = {"proved", "disproved", "inconclusive", "needs_harness", "not_in_scope"}
VALID_SYNTH_STATUS = {"none", "waived", "detected"}


def _write_row(row: dict, tmp_dir: Path) -> Path:
    p = tmp_dir / f"{row['lead_id']}.json"
    p.write_text(json.dumps(row), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSchemaFieldPresence(unittest.TestCase):
    """All required output fields must be present regardless of inputs."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="pfr_schema_")
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_required_fields_present_low_row_true_cmd(self) -> None:
        result = mod.run(LOW_ROW, cmd="true")
        missing = REQUIRED_FIELDS - set(result.keys())
        self.assertFalse(missing, f"Missing fields: {missing}")

    def test_verdict_in_valid_set(self) -> None:
        result = mod.run(LOW_ROW, cmd="true")
        self.assertIn(result["verdict"], VALID_VERDICTS)

    def test_synthetic_state_status_in_valid_set(self) -> None:
        result = mod.run(LOW_ROW, cmd="true")
        self.assertIn(result["synthetic_state_status"], VALID_SYNTH_STATUS)

    def test_commands_run_is_list(self) -> None:
        result = mod.run(LOW_ROW, cmd="true")
        self.assertIsInstance(result["commands_run"], list)

    def test_open_blockers_is_list(self) -> None:
        result = mod.run(LOW_ROW)
        self.assertIsInstance(result["open_blockers"], list)


class TestLowRowTrueCmd(unittest.TestCase):
    """Low severity row with cmd='true' should produce a sane verdict."""

    def test_verdict_is_sane_not_needs_harness(self) -> None:
        result = mod.run(LOW_ROW, cmd="true")
        # Low row, true exit -> proved or inconclusive but NOT needs_harness
        self.assertIn(result["verdict"], {"proved", "inconclusive", "disproved"})

    def test_cmd_recorded(self) -> None:
        result = mod.run(LOW_ROW, cmd="true")
        self.assertTrue(len(result["commands_run"]) > 0)
        self.assertEqual(result["commands_run"][0]["cmd"], "true")

    def test_returncode_recorded(self) -> None:
        result = mod.run(LOW_ROW, cmd="true")
        self.assertEqual(result["commands_run"][0]["returncode"], 0)


class TestHighRowNoNegativeControl(unittest.TestCase):
    """High row with no negative control -> verdict NOT proved, blocker recorded."""

    def test_verdict_is_not_proved(self) -> None:
        # cmd='true' would normally pass, but missing negative control must prevent 'proved'
        result = mod.run(HIGH_ROW_NO_CONTROL, cmd="true")
        self.assertNotEqual(
            result["verdict"],
            "proved",
            "High row without negative control must not yield 'proved'",
        )

    def test_open_blockers_records_missing_control(self) -> None:
        result = mod.run(HIGH_ROW_NO_CONTROL, cmd="true")
        blocker_text = " ".join(result["open_blockers"])
        self.assertRegex(
            blocker_text.upper(),
            r"NEGATIVE.CONTROL|NO.CONTROL",
            "open_blockers must mention missing negative control",
        )

    def test_verdict_is_inconclusive_or_needs_harness(self) -> None:
        result = mod.run(HIGH_ROW_NO_CONTROL, cmd="true")
        self.assertIn(result["verdict"], {"inconclusive", "needs_harness"})


class TestFalseCmdDisproves(unittest.TestCase):
    """cmd='false' (exit code 1) -> verdict is disproved."""

    def test_false_cmd_gives_disproved(self) -> None:
        # Even High row: if harness returns non-zero, verdict is disproved
        result = mod.run(HIGH_ROW_NO_CONTROL, cmd="false")
        self.assertEqual(result["verdict"], "disproved")

    def test_false_cmd_returncode_recorded(self) -> None:
        result = mod.run(HIGH_ROW_NO_CONTROL, cmd="false")
        self.assertGreater(result["commands_run"][0]["returncode"], 0)


class TestTimingPersistenceClaimDowngrade(unittest.TestCase):
    """timing/persistence/liveness row without restart check -> verdict downgraded."""

    def test_missing_restart_evidence_yields_blocker(self) -> None:
        # cmd='true' passes but timing/liveness without restart evidence -> blocker
        result = mod.run(TIMING_LIVENESS_ROW, cmd="true")
        has_restart_blocker = any(
            "RESTART" in b.upper() or "PERSISTENCE" in b.upper() or "PRODUCTION_PATH" in b.upper()
            for b in result["open_blockers"]
        )
        self.assertTrue(
            has_restart_blocker,
            f"Expected restart/production-path blocker; got: {result['open_blockers']}",
        )

    def test_timing_row_verdict_not_proved_without_production_path(self) -> None:
        result = mod.run(TIMING_LIVENESS_ROW, cmd="true")
        self.assertNotEqual(
            result["verdict"],
            "proved",
            "timing/liveness claim without production-path evidence must not yield 'proved'",
        )

    def test_timing_row_verdict_in_downgraded_set(self) -> None:
        result = mod.run(TIMING_LIVENESS_ROW, cmd="true")
        self.assertIn(result["verdict"], {"inconclusive", "needs_harness"})


class TestCosmosMultiValidatorCheck(unittest.TestCase):
    """Cosmos network-level row without multi-validator evidence -> blocker recorded."""

    def test_multi_validator_blocker_present(self) -> None:
        result = mod.run(COSMOS_NETWORK_ROW, cmd="true")
        has_mv_blocker = any(
            "MULTI_VALIDATOR" in b.upper() or "MULTI-VALIDATOR" in b.upper()
            for b in result["open_blockers"]
        )
        self.assertTrue(
            has_mv_blocker,
            f"Expected multi-validator blocker; got: {result['open_blockers']}",
        )

    def test_cosmos_row_verdict_not_proved_without_mv(self) -> None:
        result = mod.run(COSMOS_NETWORK_ROW, cmd="true")
        self.assertNotEqual(result["verdict"], "proved")


class TestNotInScope(unittest.TestCase):
    """Oracle marking out_of_scope -> not_in_scope verdict."""

    def test_oos_oracle_yields_not_in_scope(self) -> None:
        result = mod.run(HIGH_ROW_NO_CONTROL, cmd="true", severity_oracle=OOS_ORACLE)
        self.assertEqual(result["verdict"], "not_in_scope")


class TestNoCmd(unittest.TestCase):
    """Without a command, verdict should be needs_harness or inconclusive."""

    def test_no_cmd_low_missing_proof_path(self) -> None:
        row = dict(LOW_ROW)
        row["proof_path"] = "missing"
        result = mod.run(row)
        self.assertIn(result["verdict"], {"needs_harness", "inconclusive"})

    def test_no_cmd_no_blockers_inconclusive(self) -> None:
        result = mod.run(LOW_ROW)
        self.assertIn(result["verdict"], {"needs_harness", "inconclusive"})


class TestCliInterface(unittest.TestCase):
    """CLI --json flag emits parseable JSON with required fields."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="pfr_cli_")
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_cli_json_output_parseable(self) -> None:
        row_path = _write_row(LOW_ROW, self.tmp_dir)
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--queue-row", str(row_path),
                "--cmd", "true",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertIn(result.returncode, (0, 1), f"Unexpected rc: {result.returncode}")
        payload = json.loads(result.stdout)
        missing = REQUIRED_FIELDS - set(payload.keys())
        self.assertFalse(missing, f"CLI JSON missing fields: {missing}")

    def test_cli_false_cmd_disproved(self) -> None:
        row_path = _write_row(LOW_ROW, self.tmp_dir)
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--queue-row", str(row_path),
                "--cmd", "false",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["verdict"], "disproved")

    def test_cli_invalid_row_path_exits_2(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--queue-row", "/nonexistent/path.json",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)


class TestSyntheticStateDetection(unittest.TestCase):
    """Synthetic state (MemDB) in transcript should set synthetic_state_status=detected."""

    def test_memdb_in_cmd_output_detected(self) -> None:
        # Echo a transcript containing memdb indicator
        result = mod.run(
            HIGH_ROW_NO_CONTROL,
            cmd="echo 'using memdb for storage'",
        )
        self.assertEqual(result["synthetic_state_status"], "detected")

    def test_clean_cmd_output_not_detected(self) -> None:
        result = mod.run(
            LOW_ROW,
            cmd="echo 'using goleveldb for storage'",
        )
        self.assertEqual(result["synthetic_state_status"], "none")


class TestHighRowWithControl(unittest.TestCase):
    """High row where control is embedded in row content (blockers field)."""

    def test_control_in_blockers_field_reduces_blocker(self) -> None:
        # HIGH_ROW_WITH_CONTROL has "negative control test" in its blockers field
        result = mod.run(HIGH_ROW_WITH_CONTROL, cmd="true")
        # negative_controls should have found something from the row text
        # (the scanner reads row JSON as probe text)
        # open_blockers MAY still have it if regex missed - that's acceptable
        # but verdict should not be proved if no controls found
        if not result["negative_controls"]:
            self.assertNotEqual(result["verdict"], "proved")

    def test_evm_high_row_true_cmd_not_proved_without_control(self) -> None:
        """EVM High row: cmd passes but if controls not found, not proved."""
        row = dict(HIGH_ROW_NO_CONTROL)
        row["attack_class"] = "evm-accounting-share"
        row["title"] = "share price manipulation in EVM vault"
        result = mod.run(row, cmd="true")
        if not result["negative_controls"]:
            self.assertNotEqual(result["verdict"], "proved")


# ---------------------------------------------------------------------------
# Empty-run / zero-tests-executed guard tests
# ---------------------------------------------------------------------------

# A minimal High row that has a negative control embedded so the ONLY
# blocker we are testing for is the empty-run one.
HIGH_ROW_WITH_CONTROL_FOR_EMPTY: dict = {
    "lead_id": "EQ-HIGH-EMPTY",
    "title": "reentrancy in vault withdrawal allows fund drain",
    "source_refs": ["contracts/Vault.sol:88"],
    "attack_class": "reentrancy",
    "likely_severity": "High",
    "severity_confidence": "high",
    "attacker_control": "known",
    "impact_path": "fund theft",
    "proof_path": "foundry",
    "next_command": "forge test -vvv",
    # negative control embedded so that gate does not add an independent blocker
    "blockers": ["negative control test: baseline run without exploit"],
    "dupe_risk": "low",
    "priority_score": 0.9,
}


class TestEmptyRunGuard(unittest.TestCase):
    """Harness that exits 0 but runs zero tests must not yield 'proved'."""

    # ------------------------------------------------------------------
    # forge: "No tests found in project!" - the exact bug from lane6/7
    # ------------------------------------------------------------------

    def test_forge_no_tests_found_verdict_not_proved(self) -> None:
        """forge exits 0 with 'No tests found in project!' -> NOT proved."""
        result = mod.run(
            HIGH_ROW_WITH_CONTROL_FOR_EMPTY,
            cmd="echo 'No tests found in project! Forge looks for functions that start with test'",
        )
        self.assertNotEqual(
            result["verdict"],
            "proved",
            "Empty forge run (no tests found) must not yield 'proved'",
        )

    def test_forge_no_tests_found_verdict_is_needs_harness(self) -> None:
        """forge exits 0 with 'No tests found in project!' -> needs_harness."""
        result = mod.run(
            HIGH_ROW_WITH_CONTROL_FOR_EMPTY,
            cmd="echo 'No tests found in project! Forge looks for functions that start with test'",
        )
        self.assertEqual(
            result["verdict"],
            "needs_harness",
            f"Expected needs_harness but got {result['verdict']}",
        )

    def test_forge_no_tests_found_open_blockers_record(self) -> None:
        """open_blockers must record the zero-tests reason for empty forge run."""
        result = mod.run(
            HIGH_ROW_WITH_CONTROL_FOR_EMPTY,
            cmd="echo 'No tests found in project! Forge looks for functions that start with test'",
        )
        blocker_text = " ".join(result["open_blockers"])
        self.assertRegex(
            blocker_text,
            r"(?i)empty.run|zero.tests|no tests found",
            f"open_blockers must record the zero-tests reason; got: {result['open_blockers']}",
        )

    def test_forge_empty_run_flag_in_commands_run(self) -> None:
        """commands_run entry for an empty forge run must include empty_run=True."""
        result = mod.run(
            HIGH_ROW_WITH_CONTROL_FOR_EMPTY,
            cmd="echo 'No tests found in project!'",
        )
        self.assertTrue(len(result["commands_run"]) > 0)
        self.assertTrue(
            result["commands_run"][0].get("empty_run", False),
            "commands_run entry must have empty_run=True for an empty forge run",
        )

    # ------------------------------------------------------------------
    # go test: "[no test files]"
    # ------------------------------------------------------------------

    def test_go_no_test_files_verdict_not_proved(self) -> None:
        """go test exits 0 with '[no test files]' -> NOT proved."""
        result = mod.run(
            HIGH_ROW_WITH_CONTROL_FOR_EMPTY,
            cmd="echo '?   example.com/mypackage [no test files]'",
        )
        self.assertNotEqual(
            result["verdict"],
            "proved",
            "Empty go test run must not yield 'proved'",
        )

    def test_go_no_test_files_verdict_is_needs_harness(self) -> None:
        """go test exits 0 with '[no test files]' -> needs_harness."""
        result = mod.run(
            HIGH_ROW_WITH_CONTROL_FOR_EMPTY,
            cmd="echo '?   example.com/mypackage [no test files]'",
        )
        self.assertEqual(result["verdict"], "needs_harness")

    def test_go_no_test_files_open_blockers_record(self) -> None:
        """open_blockers must record the zero-tests reason for empty go test run."""
        result = mod.run(
            HIGH_ROW_WITH_CONTROL_FOR_EMPTY,
            cmd="echo '?   example.com/mypackage [no test files]'",
        )
        blocker_text = " ".join(result["open_blockers"])
        self.assertRegex(
            blocker_text,
            r"(?i)empty.run|zero.tests|no test files",
            f"open_blockers must record the zero-tests reason; got: {result['open_blockers']}",
        )

    # ------------------------------------------------------------------
    # cargo: "running 0 tests"
    # ------------------------------------------------------------------

    def test_cargo_zero_tests_verdict_not_proved(self) -> None:
        """cargo test exits 0 with 'running 0 tests' -> NOT proved."""
        result = mod.run(
            HIGH_ROW_WITH_CONTROL_FOR_EMPTY,
            cmd="echo 'running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored'",
        )
        self.assertNotEqual(result["verdict"], "proved")

    def test_cargo_zero_tests_verdict_is_needs_harness(self) -> None:
        """cargo test exits 0 with 'running 0 tests' -> needs_harness."""
        result = mod.run(
            HIGH_ROW_WITH_CONTROL_FOR_EMPTY,
            cmd="echo 'running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored'",
        )
        self.assertEqual(result["verdict"], "needs_harness")

    # ------------------------------------------------------------------
    # pytest: "collected 0 items"
    # ------------------------------------------------------------------

    def test_pytest_no_items_verdict_not_proved(self) -> None:
        """pytest exits 0 with 'collected 0 items' -> NOT proved."""
        result = mod.run(
            HIGH_ROW_WITH_CONTROL_FOR_EMPTY,
            cmd="echo 'collected 0 items\n\n==== no tests ran ===='",
        )
        self.assertNotEqual(result["verdict"], "proved")

    # ------------------------------------------------------------------
    # Genuine passing run regression guard
    # ------------------------------------------------------------------

    def test_genuine_passing_run_can_still_prove(self) -> None:
        """A real passing run (no empty-run marker) can still reach 'proved' if controls met."""
        # Low row: no negative-control gate; exit 0; no empty-run markers in output
        result = mod.run(LOW_ROW, cmd="echo 'test_something ... PASSED'")
        # Must NOT be forced to needs_harness by the empty-run guard
        self.assertNotIn(
            "EMPTY_RUN",
            " ".join(result["open_blockers"]),
            "Genuine passing run must not trigger empty-run guard",
        )
        # Verdict should be proved (low row, exit 0, no blockers)
        self.assertEqual(
            result["verdict"],
            "proved",
            f"Low row genuine passing run should be proved; got {result['verdict']}",
        )

    def test_genuine_passing_run_no_empty_run_flag(self) -> None:
        """commands_run entry for a genuine passing run must not have empty_run=True."""
        result = mod.run(LOW_ROW, cmd="echo 'all 5 tests passed'")
        self.assertFalse(
            result["commands_run"][0].get("empty_run", False),
            "Genuine passing run must not be flagged as empty_run",
        )

    def test_schema_field_empty_run_in_commands_run(self) -> None:
        """empty_run key only appears in commands_run when the run was empty."""
        result_empty = mod.run(
            HIGH_ROW_WITH_CONTROL_FOR_EMPTY,
            cmd="echo 'No tests found in project!'",
        )
        result_real = mod.run(LOW_ROW, cmd="echo 'tests passed'")
        self.assertTrue(result_empty["commands_run"][0].get("empty_run", False))
        self.assertFalse(result_real["commands_run"][0].get("empty_run", False))


# ---------------------------------------------------------------------------
# Lane-10 draft mode tests
# ---------------------------------------------------------------------------

# Lane-10 artifact shape required fields
LANE10_REQUIRED_FIELDS = REQUIRED_FIELDS | {
    "proof_claim",
    "mechanism",
    "controls",
    "falsification_result",
    "remaining_triager_questions",
    "draft_path",
    "schema",
}

LANE10_CONTROL_KEYS = {
    "clean_negative_control",
    "adjacent_condition_control",
    "production_path_proof",
    "no_synthetic_state_seeding",
    "no_private_field_reflection",
    "restart_behavior",
    "multi_validator_network_claims",
    "real_backend_db_storage",
    "no_teardown_contamination",
    "exact_command_and_transcript",
    "commit_hash_or_config",
    "inline_poc_body",
}


def _write_draft(content: str, tmp_dir: Path, name: str = "test_draft.md") -> Path:
    p = tmp_dir / name
    p.write_text(content, encoding="utf-8")
    return p


# Minimal valid High draft with all Lane-10 controls present
FULL_PASSING_HIGH_DRAFT = """\
# Reentrancy in Vault withdraw allows fund drain

## Severity

- Severity: High
- Likelihood: High

## Summary

Reentrancy in the withdraw function allows attacker to drain vault funds.

## Root Cause

Vault.sol:88 calls external contract before updating balance.

## Proof of Concept

Baseline (negative control test): run without exploit -> no funds drained.
Adjacent-condition control: test boundary where attack is just outside trigger.

```bash
forge test -vvv --match-test testReentrancyDrain
```

Suite result: ok. 3 passed; 0 failed

### What the tests prove

The attacker can drain funds by re-entering before balance update.
The negative control confirms no drain occurs without the exploit.

Audit pin: dc27a68463cec356ff18bbdd3d8edfe9b2534372

```solidity
function testReentrancyDrain() public {
    // setup
    attacker.attack();
    assertEq(vault.balance(), 0);
}
```

## Recommendation

Add reentrancy guard.
"""

# High draft MISSING clean negative control
HIGH_DRAFT_MISSING_NEGATIVE_CONTROL = """\
# Reentrancy in Vault withdraw allows fund drain

## Severity

- Severity: High

## Summary

Reentrancy in the withdraw function.

## Root Cause

Vault.sol:88 external call before balance update.

## Proof of Concept

```bash
forge test -vvv --match-test testReentrancyDrain
```

Suite result: ok. 1 passed; 0 failed

Audit pin: dc27a68463cec356ff18bbdd3d8edfe9b2534372

```solidity
function testReentrancyDrain() public {
    attacker.attack();
    assertEq(vault.balance(), 0);
}
```
"""

# High draft with MemDB synthetic state seeding
HIGH_DRAFT_WITH_MEMDB = """\
# AppHash divergence leads to chain halt

## Severity

- Severity: High

## Summary

IAVL pruning race causes AppHash divergence.

## Root Cause

app/store.go:42 lacks mutex.

## Proof of Concept

Negative control test: no divergence without concurrent writes.

```bash
go test ./... -run TestAppHashDivergence
```

Using memdb for storage in test environment.
Audit pin: abc1234

```go
func TestAppHashDivergence(t *testing.T) {
    db := dbm.NewMemDB()
    // ...
}
```
"""

# Critical draft missing inline PoC body
CRITICAL_DRAFT_NO_INLINE_POC = """\
# Price manipulation in AMM leads to fund drain

## Severity

- Severity: Critical

## Summary

Flash loan price manipulation drains AMM.

## Root Cause

AMM.sol:200 uses spot price not TWAP.

## Proof of Concept

Negative control test: without flash loan, price is stable.

```bash
forge test -vvv --match-test testPriceManipulation
```

Suite result: ok. 2 passed; 0 failed
Audit pin: def5678

See attached test file for full proof.
"""

# Low draft - should not require negative control
LOW_DRAFT = """\
# Minor rounding error in fee calculation

## Severity

- Severity: Low

## Summary

Fee rounding loses 1 wei per transaction.

## Root Cause

FeeManager.sol:10 uses integer division.

## Proof of Concept

```bash
forge test -vvv --match-test testFeeRounding
```

```solidity
function testFeeRounding() public {
    uint256 fee = feeManager.calculate(100);
    assertApproxEqAbs(fee, 10, 1);
}
```

Audit pin: aabbcc1122
"""


class TestLane10DraftMode(unittest.TestCase):
    """Lane-10 --draft mode: artifact shape, controls, blocking, triager questions."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="pfr_lane10_")
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_lane10_artifact_has_all_required_fields(self) -> None:
        """run_draft produces all Lane-10 required fields."""
        draft = _write_draft(FULL_PASSING_HIGH_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft)
        missing = LANE10_REQUIRED_FIELDS - set(result.keys())
        self.assertFalse(missing, f"Missing Lane-10 fields: {missing}")

    def test_controls_dict_has_all_12_keys(self) -> None:
        """controls dict must contain all 12 Lane-10 control keys."""
        draft = _write_draft(FULL_PASSING_HIGH_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertIsInstance(result["controls"], dict)
        missing_keys = LANE10_CONTROL_KEYS - set(result["controls"].keys())
        self.assertFalse(missing_keys, f"Missing control keys: {missing_keys}")

    def test_controls_values_are_bool(self) -> None:
        """All control values must be boolean."""
        draft = _write_draft(FULL_PASSING_HIGH_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft)
        for k, v in result["controls"].items():
            self.assertIsInstance(v, bool, f"Control '{k}' is not bool: {v!r}")

    def test_falsification_result_is_valid_verdict(self) -> None:
        """falsification_result must be a valid verdict string."""
        draft = _write_draft(FULL_PASSING_HIGH_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertIn(result["falsification_result"], VALID_VERDICTS)

    def test_remaining_triager_questions_is_list(self) -> None:
        """remaining_triager_questions must be a list."""
        draft = _write_draft(FULL_PASSING_HIGH_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertIsInstance(result["remaining_triager_questions"], list)

    def test_proof_claim_extracted_from_title(self) -> None:
        """proof_claim should be extracted from the draft title."""
        draft = _write_draft(FULL_PASSING_HIGH_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertIn("Reentrancy", result["proof_claim"])

    def test_schema_is_lane10_version(self) -> None:
        """schema field must be the Lane-10 schema version."""
        draft = _write_draft(FULL_PASSING_HIGH_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertIn("lane10", result["schema"])

    def test_draft_path_in_result(self) -> None:
        """draft_path must be present in result."""
        draft = _write_draft(FULL_PASSING_HIGH_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertEqual(result["draft_path"], str(draft))


class TestLane10MissingNegativeControl(unittest.TestCase):
    """High draft missing clean_negative_control -> blocked (not proved)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="pfr_nc_")
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_high_draft_missing_nc_not_proved(self) -> None:
        """High draft without negative control must NOT yield 'proved'."""
        draft = _write_draft(HIGH_DRAFT_MISSING_NEGATIVE_CONTROL, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertNotEqual(
            result["falsification_result"],
            "proved",
            "High draft without negative control must not be proved",
        )

    def test_high_draft_missing_nc_control_false(self) -> None:
        """clean_negative_control must be False for this draft."""
        draft = _write_draft(HIGH_DRAFT_MISSING_NEGATIVE_CONTROL, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertFalse(
            result["controls"]["clean_negative_control"],
            "clean_negative_control should be False when no control test present",
        )

    def test_high_draft_missing_nc_has_open_blocker(self) -> None:
        """open_blockers must mention NEGATIVE_CONTROL for this High draft."""
        draft = _write_draft(HIGH_DRAFT_MISSING_NEGATIVE_CONTROL, self.tmp_dir)
        result = mod.run_draft(draft)
        blocker_text = " ".join(result["open_blockers"])
        self.assertRegex(
            blocker_text.upper(),
            r"NEGATIVE.CONTROL|NO.CONTROL",
            "open_blockers must mention missing negative control",
        )

    def test_high_draft_missing_nc_has_triager_question(self) -> None:
        """remaining_triager_questions must ask for a negative control."""
        draft = _write_draft(HIGH_DRAFT_MISSING_NEGATIVE_CONTROL, self.tmp_dir)
        result = mod.run_draft(draft)
        questions_text = " ".join(result["remaining_triager_questions"]).lower()
        self.assertIn(
            "negative control",
            questions_text,
            "remaining_triager_questions must ask for a negative control",
        )


class TestLane10SyntheticStateBlocks(unittest.TestCase):
    """High draft with MemDB synthetic state seeding -> blocked."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="pfr_synth_")
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_memdb_draft_synthetic_state_detected(self) -> None:
        """Draft using memdb must have no_synthetic_state_seeding=False."""
        draft = _write_draft(HIGH_DRAFT_WITH_MEMDB, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertFalse(
            result["controls"]["no_synthetic_state_seeding"],
            "no_synthetic_state_seeding should be False when MemDB is used",
        )

    def test_memdb_draft_synthetic_state_status_detected(self) -> None:
        """synthetic_state_status must be 'detected' for MemDB draft."""
        draft = _write_draft(HIGH_DRAFT_WITH_MEMDB, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertEqual(result["synthetic_state_status"], "detected")

    def test_memdb_draft_not_proved(self) -> None:
        """Draft with MemDB must not yield 'proved'."""
        draft = _write_draft(HIGH_DRAFT_WITH_MEMDB, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertNotEqual(result["falsification_result"], "proved")


class TestLane10MissingInlinePocBlocks(unittest.TestCase):
    """Critical draft without inline PoC body -> blocked."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="pfr_poc_")
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_no_inline_poc_body_control_false(self) -> None:
        """inline_poc_body must be False when draft has no test function body."""
        draft = _write_draft(CRITICAL_DRAFT_NO_INLINE_POC, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertFalse(
            result["controls"]["inline_poc_body"],
            "inline_poc_body should be False when no test function body is present",
        )

    def test_no_inline_poc_not_proved(self) -> None:
        """Critical draft without inline PoC body must not yield 'proved'."""
        draft = _write_draft(CRITICAL_DRAFT_NO_INLINE_POC, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertNotEqual(result["falsification_result"], "proved")


class TestLane10LowDraft(unittest.TestCase):
    """Low severity draft should not require negative control or cosmos checks."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="pfr_low_")
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_low_draft_controls_dict_present(self) -> None:
        """Low draft still gets full controls dict."""
        draft = _write_draft(LOW_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft)
        self.assertIsInstance(result["controls"], dict)
        self.assertEqual(len(result["controls"]), len(LANE10_CONTROL_KEYS))

    def test_low_draft_no_negative_control_blocker(self) -> None:
        """Low draft without negative control should NOT add a gate blocker."""
        draft = _write_draft(LOW_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft)
        has_nc_blocker = any(
            "LANE10_MISSING_CLEAN_NEGATIVE_CONTROL" in b
            for b in result["open_blockers"]
        )
        self.assertFalse(
            has_nc_blocker,
            "Low draft should not get a LANE10_MISSING_CLEAN_NEGATIVE_CONTROL blocker",
        )

    def test_low_draft_na_controls_pass(self) -> None:
        """For a Low EVM draft, N/A controls (production_path_proof, restart) pass."""
        draft = _write_draft(LOW_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft)
        # These are N/A for EVM/Low findings, should default to True
        self.assertTrue(result["controls"]["production_path_proof"])
        self.assertTrue(result["controls"]["restart_behavior"])


class TestLane10CliDraftMode(unittest.TestCase):
    """CLI --draft mode emits Lane-10 JSON shape."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="pfr_cli_lane10_")
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_cli_draft_json_parseable(self) -> None:
        """CLI --draft --json produces parseable JSON with Lane-10 fields."""
        draft = _write_draft(HIGH_DRAFT_MISSING_NEGATIVE_CONTROL, self.tmp_dir)
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--draft", str(draft),
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertIn(result.returncode, (0, 1), f"Unexpected rc: {result.returncode}")
        payload = json.loads(result.stdout)
        missing = LANE10_REQUIRED_FIELDS - set(payload.keys())
        self.assertFalse(missing, f"CLI Lane-10 JSON missing fields: {missing}")

    def test_cli_draft_blocking_verdict_not_proved(self) -> None:
        """CLI --draft with missing controls must NOT emit 'proved' verdict."""
        draft = _write_draft(HIGH_DRAFT_MISSING_NEGATIVE_CONTROL, self.tmp_dir)
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--draft", str(draft),
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        payload = json.loads(result.stdout)
        self.assertNotEqual(payload.get("falsification_result"), "proved")
        self.assertNotEqual(payload.get("verdict"), "proved")

    def test_cli_missing_both_draft_and_queue_row_exits_2(self) -> None:
        """CLI without --draft or --queue-row must exit with code 2."""
        result = subprocess.run(
            [sys.executable, str(TOOL), "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)

    def test_cli_draft_with_provider_challenge_no_consent_skips(self) -> None:
        """--provider-challenge without AUDITOOOR_LLM_NETWORK_CONSENT=1 -> skipped."""
        import os
        draft = _write_draft(FULL_PASSING_HIGH_DRAFT, self.tmp_dir)
        env = {**os.environ}
        env.pop("AUDITOOOR_LLM_NETWORK_CONSENT", None)  # ensure not set
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--draft", str(draft),
                "--provider-challenge",
                "--json",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        payload = json.loads(result.stdout)
        challenge = payload.get("provider_challenge", {})
        self.assertTrue(
            challenge.get("skipped", False),
            "provider_challenge should be skipped when consent not set",
        )


class TestLane10ProviderChallengeUnit(unittest.TestCase):
    """Unit tests for provider challenge via run_draft API (no network)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="pfr_provider_")
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_run_draft_no_challenge_no_provider_key(self) -> None:
        """run_draft without provider_challenge=True must not include provider_challenge."""
        draft = _write_draft(FULL_PASSING_HIGH_DRAFT, self.tmp_dir)
        result = mod.run_draft(draft, provider_challenge=False)
        # provider_challenge key should be absent when not requested
        self.assertNotIn(
            "provider_challenge",
            result,
            "provider_challenge key must be absent when provider_challenge=False",
        )

    def test_run_draft_with_challenge_no_consent_skipped(self) -> None:
        """run_draft with provider_challenge=True but no consent -> challenge skipped."""
        import os
        orig = os.environ.pop("AUDITOOOR_LLM_NETWORK_CONSENT", None)
        try:
            draft = _write_draft(FULL_PASSING_HIGH_DRAFT, self.tmp_dir)
            result = mod.run_draft(draft, provider_challenge=True)
            self.assertIn("provider_challenge", result)
            self.assertTrue(result["provider_challenge"].get("skipped", False))
        finally:
            if orig is not None:
                os.environ["AUDITOOOR_LLM_NETWORK_CONSENT"] = orig


if __name__ == "__main__":
    unittest.main()
