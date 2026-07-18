#!/usr/bin/env python3
"""iter12-T1 regression tests — packager emits bundle-local symbolic harness.

Locks the behavior introduced to close the iter11 T2 signal (live-mode halt
at harness-picker step 3 with `status=error / no compile-green harness
found`). After iter12 T1 ships, `submission-packager.py` inspects the
source draft for attack-angle tokens (`A-[A-Z-]+` pattern), looks each one
up in `tools/angle_map.json`, and copies the first lex-sorted `*.t.sol`
from the mapped invariant family into `<bundle>/harnesses/<angle>.t.sol`.

Hard-negative discipline (FM-002 / FM-016):
  - Unmapped angles → NO harness file is synthesized. Never fabricate.
  - Missing `angle_map.json` → NO harness file is written, no error.
  - Existing operator-authored harness at the destination → PRESERVED
    (never clobbered).

These tests are offline, use tempfile, and invoke the packager's helper
APIs directly via importlib (the dash in `submission-packager.py` blocks
a normal import).
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


ROOT = Path(__file__).resolve().parents[2]
PACKAGER_SRC = ROOT / "tools" / "submission-packager.py"
ECON_SIM_SRC = ROOT / "tools" / "econ-simulator.py"
REAL_ANGLE_MAP = ROOT / "tools" / "angle_map.json"
REAL_FAMILIES = ROOT / "tools" / "invariants" / "families"


def _load_packager_module():
    spec = importlib.util.spec_from_file_location(
        "_packager_iter12_t1", PACKAGER_SRC
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PKG = _load_packager_module()


def _make_family_fixture(root: Path) -> Path:
    """Build a minimal `invariants/families/` tree for offline tests.

    Mirrors the on-disk layout — five families, each with at least one
    `*.t.sol` file. Contents are placeholder; tests only assert file
    identity via `read_text`, not Solidity correctness.
    """
    families = {
        "amm": ["ConstantProductInvariant.t.sol", "DonationAttackResistance.t.sol"],
        "bridge": ["FinalityBeforeWithdraw.t.sol"],
        "governance": ["ProposalIdMonotonicity.t.sol"],
        "lending": ["DebtCollateralSolvency.t.sol"],
        "vault": ["RedemptionBounds.t.sol", "SharePriceMonotonicity.t.sol"],
    }
    base = root / "families"
    for family, files in families.items():
        fam_dir = base / family
        fam_dir.mkdir(parents=True, exist_ok=True)
        for i, name in enumerate(files):
            contract_name = name.replace(".t.sol", "")
            (fam_dir / name).write_text(
                f"// fixture harness for {family}/{name} marker={i}\n"
                f"contract {contract_name} {{}}\n"
            )
    return base


def _write_angle_map(path: Path, mapping: dict) -> None:
    path.write_text(json.dumps(mapping, indent=2))


def _make_draft(path: Path, angles: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "# Finding\n\n**Severity: High**\n\n## Summary\n\n"
    body += "Attack angles:\n"
    for a in angles:
        body += f"- {a}: body\n"
    path.write_text(body)


class EmitsHarnessForMappedAngleTest(unittest.TestCase):
    """T1 acceptance #1: draft with mapped angle → harness file copied."""

    def test_emits_harness_for_mapped_angle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            families = _make_family_fixture(tmpdir)
            bundle = tmpdir / "bundle"
            bundle.mkdir()
            angle_map = {"A-DONATION-CAPTURE": "vault"}

            written = PKG.bundle_symbolic_harness(
                bundle,
                ["A-DONATION-CAPTURE"],
                families,
                angle_map,
            )

            dest = bundle / "harnesses" / "A-DONATION-CAPTURE.t.sol"
            self.assertTrue(
                dest.is_file(),
                msg=f"expected {dest} to exist after bundle_symbolic_harness",
            )
            self.assertEqual(written, [dest])
            # First lex-sorted vault harness is RedemptionBounds.t.sol.
            self.assertIn(
                "vault/RedemptionBounds.t.sol",
                dest.read_text(),
            )

            manifest = json.loads((bundle / "harness-binding-manifest.json").read_text())
            self.assertEqual(manifest["draft_angle_ids"], ["A-DONATION-CAPTURE"])
            self.assertEqual(manifest["unresolved_angles"], [])
            self.assertEqual(len(manifest["entries"]), 1)
            entry = manifest["entries"][0]
            self.assertEqual(entry["angle_id"], "A-DONATION-CAPTURE")
            self.assertEqual(entry["bundle_harness"], "harnesses/A-DONATION-CAPTURE.t.sol")
            self.assertEqual(entry["family"], "vault")
            self.assertEqual(entry["contract_name"], "RedemptionBounds")
            self.assertEqual(
                entry["execution_contract"]["argv"],
                [
                    "python3",
                    "${AUDITOOOR_DIR}/tools/econ-simulator.py",
                    "--bundle",
                    "${BUNDLE_ROOT}",
                    "--angle",
                    "A-DONATION-CAPTURE",
                ],
            )


class OmitsHarnessForUnmappedAngleTest(unittest.TestCase):
    """T1 acceptance #2: unmapped angle → no `<bundle>/harnesses/` dir."""

    def test_omits_harness_for_unmapped_angle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            families = _make_family_fixture(tmpdir)
            bundle = tmpdir / "bundle"
            bundle.mkdir()
            angle_map = {"A-DONATION-CAPTURE": "vault"}

            written = PKG.bundle_symbolic_harness(
                bundle,
                ["A-UNKNOWN-ANGLE"],
                families,
                angle_map,
            )

            self.assertEqual(written, [])
            self.assertFalse(
                (bundle / "harnesses").exists(),
                msg=(
                    "unmapped angle must NOT create a `<bundle>/harnesses/` "
                    "directory (no synthesis discipline FM-016)"
                ),
            )
            manifest = json.loads((bundle / "harness-binding-manifest.json").read_text())
            self.assertEqual(manifest["entries"], [])
            self.assertEqual(
                manifest["unresolved_angles"],
                [{"angle_id": "A-UNKNOWN-ANGLE", "reason": "angle-unmapped"}],
            )


class NoHarnessSynthesisTest(unittest.TestCase):
    """T1 acceptance #3: absent `angle_map.json` → skip silently, no error."""

    def test_no_harness_synthesis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            families = _make_family_fixture(tmpdir)
            bundle = tmpdir / "bundle"
            bundle.mkdir()

            # Simulate absent `angle_map.json` by passing a path that does
            # not exist — `load_angle_map` must return {} without raising.
            absent = tmpdir / "nonexistent_angle_map.json"
            self.assertFalse(absent.exists())
            loaded = PKG.load_angle_map(absent)
            self.assertEqual(loaded, {})

            # With the empty mapping, harness emission is a no-op.
            written = PKG.bundle_symbolic_harness(
                bundle,
                ["A-DONATION-CAPTURE"],
                families,
                loaded,
            )
            self.assertEqual(written, [])
            self.assertFalse(
                (bundle / "harnesses").exists(),
                msg=(
                    "absent `angle_map.json` must NOT produce a synthesized "
                    "harness file (hard-negative FM-002 guard)"
                ),
            )
            manifest = json.loads((bundle / "harness-binding-manifest.json").read_text())
            self.assertEqual(
                manifest["unresolved_angles"],
                [{"angle_id": "A-DONATION-CAPTURE", "reason": "angle-unmapped"}],
            )


class ExistingHarnessNotOverwrittenTest(unittest.TestCase):
    """T1 acceptance #5: operator-authored harness is preserved."""

    def test_existing_harness_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            families = _make_family_fixture(tmpdir)
            bundle = tmpdir / "bundle"
            harnesses = bundle / "harnesses"
            harnesses.mkdir(parents=True)
            dest = harnesses / "A-DONATION-CAPTURE.t.sol"
            operator_body = (
                "// operator-authored harness — do not overwrite\n"
                "contract OperatorHarness {}\n"
            )
            dest.write_text(operator_body)

            angle_map = {"A-DONATION-CAPTURE": "vault"}
            written = PKG.bundle_symbolic_harness(
                bundle,
                ["A-DONATION-CAPTURE"],
                families,
                angle_map,
            )

            self.assertEqual(written, [])
            self.assertEqual(
                dest.read_text(),
                operator_body,
                msg=(
                    "operator-authored harness must be preserved verbatim; "
                    "packager must never clobber it"
                ),
            )
            manifest = json.loads((bundle / "harness-binding-manifest.json").read_text())
            self.assertEqual(manifest["entries"][0]["origin"], "preserved")
            self.assertEqual(manifest["entries"][0]["contract_name"], "OperatorHarness")


class BundleExecutionContractTest(unittest.TestCase):
    """Bundle manifests distinguish harness artifacts from runnable harnesses."""

    def test_symbolic_harness_artifact_is_blocked_until_exact_command_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            bundle = tmpdir / "bundle"
            harnesses = bundle / "harnesses"
            harnesses.mkdir(parents=True)
            (harnesses / "A-DONATION-CAPTURE.t.sol").write_text("// harness\n")

            contract = PKG.build_bundle_execution_contract(
                bundle,
                {
                    "present": True,
                    "kind": "forge",
                    "paths": ["poc-tests/ReferencedHarness.t.sol"],
                },
            )

        self.assertEqual(contract["schema"], PKG.BUNDLE_EXECUTION_CONTRACT_SCHEMA)
        self.assertEqual(contract["claim"], "blocked_harness")
        self.assertEqual(contract["status"], "blocked_missing_execution_command")
        self.assertFalse(contract["runnable"])
        self.assertFalse(contract["advisory_only"])
        self.assertIn("harness_command", contract["missing_inputs"])
        self.assertIn("harnesses/A-DONATION-CAPTURE.t.sol", contract["harness_artifacts"])
        self.assertIn("poc-tests/ReferencedHarness.t.sol", contract["harness_artifacts"])

    def test_go_harness_with_exact_commands_is_runnable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            bundle = tmpdir / "bundle"
            bundle.mkdir()

            contract = PKG.build_bundle_execution_contract(
                bundle,
                {
                    "present": True,
                    "kind": "rust_go_dlt_harness",
                    "paths": ["poc-tests/lead1_chain_watcher/watch_chain_lead1_test.go"],
                    "harness_command": (
                        "cd external/spark/spark && SKIP_POSTGRES_TESTS=true "
                        "go test -run TestLead1_ChainWatcherExitTxidValidationGap "
                        "./so/chain/ -v -count=1"
                    ),
                    "gating_test": "SKIP_POSTGRES_TESTS=true go test -run TestLead1 ./so/chain/ -v -count=1",
                    "runtime_evidence_log": "poc-tests/lead1_chain_watcher/lead1_runtime_evidence.log",
                },
            )

        self.assertEqual(contract["schema"], PKG.BUNDLE_EXECUTION_CONTRACT_SCHEMA)
        self.assertEqual(contract["claim"], "runnable_harness")
        self.assertEqual(contract["status"], "ready")
        self.assertTrue(contract["runnable"])
        self.assertFalse(contract["advisory_only"])
        self.assertTrue(contract["fail_closed"])
        self.assertEqual(contract["missing_inputs"], [])
        self.assertEqual(contract["blockers"], [])
        self.assertIn(
            "poc-tests/lead1_chain_watcher/watch_chain_lead1_test.go",
            contract["harness_artifacts"],
        )
        self.assertEqual(
            contract["commands"]["harness_command"],
            (
                "cd external/spark/spark && SKIP_POSTGRES_TESTS=true "
                "go test -run TestLead1_ChainWatcherExitTxidValidationGap "
                "./so/chain/ -v -count=1"
            ),
        )
        self.assertEqual(
            contract["commands"]["gating_test"],
            "SKIP_POSTGRES_TESTS=true go test -run TestLead1 ./so/chain/ -v -count=1",
        )
        self.assertEqual(
            contract["reproducibility_hints"]["working_directory"],
            "external/spark/spark",
        )
        self.assertEqual(
            contract["reproducibility_hints"]["prerequisite_env"],
            {"SKIP_POSTGRES_TESTS": "true"},
        )
        self.assertEqual(
            contract["reproducibility_hints"]["runtime_evidence_log"],
            "poc-tests/lead1_chain_watcher/lead1_runtime_evidence.log",
        )
        self.assertEqual(contract["reproducibility_hints"]["missing_clarity"], [])

    def test_go_harness_surfaces_missing_runtime_log_and_workdir_clarity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()

            contract = PKG.build_bundle_execution_contract(
                bundle,
                {
                    "present": True,
                    "kind": "rust_go_dlt_harness",
                    "paths": ["poc-tests/lead1_chain_watcher/watch_chain_lead1_test.go"],
                    "harness_command": "go test -run TestLead1 ./so/chain/ -v -count=1",
                    "gating_test": "Command exits 0 and output contains 'LEAD 1 PoC RUNTIME-PROVEN'.",
                },
            )

        self.assertEqual(
            contract["reproducibility_hints"]["missing_clarity"],
            ["working_directory", "runtime_evidence_log"],
        )
        self.assertEqual(
            contract["reproducibility_hints"]["verification_hint"],
            "Command exits 0 and output contains 'LEAD 1 PoC RUNTIME-PROVEN'.",
        )
        self.assertIsNone(contract["reproducibility_hints"]["working_directory"])


class FindPocEvidenceForDraftTest(unittest.TestCase):
    def test_go_draft_preserves_runtime_log_path_for_packaged_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            draft = ws / "draft.md"
            draft.write_text(
                "# FN\n\n"
                "Go runtime proof uses `poc-tests/lead1_chain_watcher/watch_chain_lead1_test.go`.\n"
                "runtime_evidence_log: poc-tests/lead1_chain_watcher/lead1_runtime_evidence.log\n"
                "harness_command: \"cd external/spark/spark && SKIP_POSTGRES_TESTS=true go test -run "
                "TestLead1 ./so/chain/ -v -count=1\"\n"
                "gating_test: \"Command exits 0 and output contains 'LEAD 1 PoC RUNTIME-PROVEN'.\"\n"
            )
            evidence = PKG.find_poc_evidence_for_draft(draft, ws)

        self.assertEqual(
            evidence["runtime_evidence_log"],
            "poc-tests/lead1_chain_watcher/lead1_runtime_evidence.log",
        )
        self.assertEqual(
            evidence["harness_command"],
            "cd external/spark/spark && SKIP_POSTGRES_TESTS=true go test -run TestLead1 ./so/chain/ -v -count=1",
        )

    def test_bundle_without_harness_artifacts_is_advisory_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle"
            bundle.mkdir()

            contract = PKG.build_bundle_execution_contract(
                bundle,
                {"present": False, "kind": "none", "paths": []},
            )

        self.assertEqual(contract["claim"], "advisory_only")
        self.assertEqual(contract["status"], "advisory_only")
        self.assertFalse(contract["runnable"])
        self.assertTrue(contract["advisory_only"])
        self.assertEqual(contract["missing_inputs"], [])


class BundlePassesEconSimulatorLiveModeAfterEmissionTest(unittest.TestCase):
    """T1 acceptance #4: end-to-end live-mode no longer reports 'no harness'.

    After `bundle_symbolic_harness` emits a harness, invoking
    `tools/econ-simulator.py --live` against the bundle must advance past
    the harness-picker (step 3 of `live_mode_run`). The observable signal:
    the error reason string is DIFFERENT from the old "no compile-green
    harness found" message — the tool now halts at a later step (e.g.
    anvil readiness, RPC connect, halmos preflight) or reports `timeout`.

    We do NOT assert a specific later error; we assert negation of the
    harness-not-found signature. A `timeout` classification is equally
    valid per the iter12 T1 plan ("any status except the old
    harness-not-found error").
    """

    def test_bundle_passes_econ_simulator_live_mode_after_emission(self) -> None:
        if not ECON_SIM_SRC.is_file():
            self.skipTest(f"econ-simulator.py not found at {ECON_SIM_SRC}")
        if not REAL_FAMILIES.is_dir():
            self.skipTest(
                f"invariants/families/ not present at {REAL_FAMILIES}"
            )
        real_map = PKG.load_angle_map(REAL_ANGLE_MAP)
        if "A-DONATION-CAPTURE" not in real_map:
            self.skipTest(
                "real angle_map.json missing A-DONATION-CAPTURE mapping"
            )

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            bundle = tmpdir / "bundle"
            bundle.mkdir()
            (bundle / "source-draft.md").write_text(
                "# Finding\n\n**Severity: Medium**\n\n"
                "Angle under analysis: A-DONATION-CAPTURE.\n"
            )
            # Emit the real symbolic harness from the committed family tree.
            written = PKG.bundle_symbolic_harness(
                bundle,
                ["A-DONATION-CAPTURE"],
                REAL_FAMILIES,
                real_map,
            )
            self.assertTrue(written, "real emission must produce a harness file")
            self.assertTrue(
                (bundle / "harnesses" / "A-DONATION-CAPTURE.t.sol").is_file()
            )

            # Invoke live-mode. We pass a bogus RPC URL + a tight deadline;
            # the tool should advance past harness-picker into later stages.
            env = os.environ.copy()
            env["ECON_SIM_DRY_RUN"] = "0"
            try:
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(ECON_SIM_SRC),
                        "--bundle", str(bundle),
                        "--angle", "A-DONATION-CAPTURE",
                        "--live",
                        "--rpc-url", "http://localhost:9999",
                    ],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=60,
                )
                combined = (proc.stdout or "") + (proc.stderr or "")
            except subprocess.TimeoutExpired as exc:
                # Timeout is a valid outcome ("anything except the old
                # harness-not-found error"). The test passes here because
                # a timeout proves the tool advanced past the sub-second
                # harness-picker step into a later, blocking phase.
                stdout_bytes = exc.stdout or b""
                combined = (
                    stdout_bytes.decode("utf-8", errors="replace")
                    if isinstance(stdout_bytes, (bytes, bytearray))
                    else str(stdout_bytes)
                )
                self.assertNotIn(
                    "no compile-green harness found",
                    combined,
                    msg=(
                        "live-mode timed out but stdout still contains the "
                        "old harness-not-found signature — emission did not "
                        "take effect"
                    ),
                )
                return

            # If econ-simulator wrote a manifest, inspect its `reason`
            # field; otherwise fall back to combined stdout/stderr.
            manifest_path = (
                bundle / "econ-simulator" / "A-DONATION-CAPTURE.json"
            )
            reason = ""
            if manifest_path.is_file():
                try:
                    manifest = json.loads(manifest_path.read_text())
                    reason = str(manifest.get("reason") or "")
                except Exception:
                    reason = ""

            self.assertNotIn(
                "no compile-green harness found",
                combined,
                msg=(
                    "live-mode stdout/stderr still carries the old "
                    "harness-not-found signal after emission"
                ),
            )
            self.assertNotIn(
                "no compile-green harness found",
                reason,
                msg=(
                    "manifest.reason still carries the old "
                    "harness-not-found signature; T1 emission failed"
                ),
            )


if __name__ == "__main__":
    unittest.main()
