#!/usr/bin/env python3
"""Regression tests for tools/submission-factory.py (capv3 iter1 T5).

Covers (per plan §Actions.3):

  1. test_all_sections_present_in_output
     — fixture bundle → output contains all 9 section headings.
  2. test_poc_command_references_actual_test_file
     — the `forge test --match-contract X` emitted matches a `contract X` that
       really exists inside a `.t.sol` file in the bundle.
  3. test_dupe_defense_cites_check7_output_not_fabricated
     — manifest WITH `gates.variant` → output cites `risk_level` verbatim.
       manifest WITHOUT `gates.variant` → output says "dupe risk unknown"
       LITERALLY (not fabricated to LOW).
  4. test_triager_risk_section_flags_poly45_class_correctly
     — draft mentioning `uint256.max` / `2^248` → output has "Likely triager
       pushback: unrealistic bounds" flag string.

Offline. No network. Shells out to `tools/submission-factory.py` via
subprocess (locks the CLI contract, not just the internal API).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FACTORY = ROOT / "tools" / "submission-factory.py"


def _build_minimal_bundle(tmp: Path,
                          *,
                          draft_body: str = "",
                          manifest: dict | None = None,
                          evidence_matrix: dict | None = None,
                          poc_contract_name: str = "SampleTest",
                          extra_files: dict[str, str] | None = None) -> Path:
    """Create a packaged-shape bundle under `tmp/bundle`. Returns bundle path."""
    bundle = tmp / "bundle"
    bundle.mkdir(parents=True)
    (tmp / "SCOPE.md").write_text("# Scope\n")
    (tmp / "SEVERITY.md").write_text(
        "# Severity\n\n"
        "## High\n"
        "- Direct theft of user funds.\n\n"
        "## Medium\n"
        "- Temporary loss of funds requiring admin recovery.\n"
    )

    body = draft_body or (
        "## Submission — #FIX-01 — Medium — VERIFIED PoC\n"
        "\n"
        "### Finding Title\n"
        "```\nSample finding title for regression\n```\n"
        "\n"
        "## Impact\n"
        "Attacker can steal ~$1,000 from victim vault.\n"
        "\n"
        "1. Victim deposits.\n"
        "2. Attacker calls steal().\n"
        "3. Attacker wins.\n"
    )
    severity = "High" if re.search(r"\bHigh\b", body) else "Medium"
    selected_impact = (
        "Direct theft of user funds."
        if severity == "High"
        else "Temporary loss of funds requiring admin recovery."
    )
    if "Impact Contract" not in body:
        body += (
            "\n"
            "## Impact Contract\n"
            f"selected_impact: {selected_impact}\n"
            f"severity_tier: {severity}\n"
            "listed_impact_proven: true\n"
            "evidence_class: forge_test\n"
            "proof_artifact: poc.t.sol\n"
            "proof_contract: executed PoC demonstrates the selected listed impact\n"
            "stop_condition: forge PoC reproduces the selected listed impact\n"
            "oos_traps:\n"
            "- no privileged/admin-only path\n"
            "downgrade_clauses:\n"
            "- downgrade if the selected listed impact is not reproduced\n"
        )
    (bundle / "source-draft.md").write_text(body)

    poc_src = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.20;\n"
        "import {Test} from \"forge-std/Test.sol\";\n"
        f"contract {poc_contract_name} is Test {{\n"
        "    function testExploit() public {}\n"
        "}\n"
    )
    (bundle / "poc.t.sol").write_text(poc_src)

    if manifest is not None:
        (bundle / "manifest.json").write_text(json.dumps(manifest))
    if evidence_matrix is not None:
        (bundle / "evidence-matrix.json").write_text(json.dumps(evidence_matrix))

    if extra_files:
        for rel, content in extra_files.items():
            p = bundle / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
    return bundle


def _run_factory(bundle: Path, extra_args: list[str] | None = None) -> tuple[int, str, str]:
    argv = [sys.executable, str(FACTORY), "--bundle", str(bundle)]
    if extra_args:
        argv.extend(extra_args)
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout, r.stderr


SECTION_HEADERS = [
    "## 1. Title + Severity",
    "## 2. Impact",
    "## 3. Attack trace",
    "## 4. PoC command",
    "## 5. Evidence matrix summary",
    "## 6. Fork-replay evidence",
    "## 7. Dupe defense (Check #7 variant-detector)",
    "## 8. Triager-risk section (iter13 rejection classifier)",
    "## 9. Appendix — raw evidence paths",
]


class TestSubmissionFactory(unittest.TestCase):

    def test_refuses_paste_ready_without_locked_proved_impact_contract(self) -> None:
        """Factory output is paste-ready, so missing impact contracts fail closed."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "SCOPE.md").write_text("# Scope\n")
            (tmp / "SEVERITY.md").write_text(
                "# Severity\n\n## High\n- Direct theft of user funds.\n"
            )
            bundle = tmp / "bundle"
            bundle.mkdir()
            (bundle / "source-draft.md").write_text(
                "## Submission — #FIX-00 — High — VERIFIED PoC\n\n"
                "### Finding Title\n```\nMissing impact contract\n```\n\n"
                "## Impact\nAttacker can steal funds.\n"
            )
            rc, out, err = _run_factory(bundle)
            self.assertEqual(rc, 2, msg=f"stdout={out}\nstderr={err}")
            self.assertIn("REFUSE", err)
            self.assertIn("locked/proved listed-impact contract", err)
            self.assertFalse((bundle / "cantina_ready.md").exists())

    def test_refuses_paste_ready_without_proof_artifact_file(self) -> None:
        """Factory output must not be platform-ready without a real proof artifact."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            bundle = _build_minimal_bundle(
                tmp,
                draft_body=(
                    "## Submission — #FIX-00 — High — VERIFIED PoC\n\n"
                    "### Finding Title\n```\nMissing proof artifact\n```\n\n"
                    "## Impact\nAttacker can steal funds.\n\n"
                    "## Impact Contract\n"
                    "selected_impact: Direct theft of user funds.\n"
                    "severity_tier: High\n"
                    "listed_impact_proven: true\n"
                    "evidence_class: forge_test\n"
                    "proof_artifact: missing-proof.txt\n"
                    "proof_contract: executed PoC demonstrates theft\n"
                    "stop_condition: forge PoC reproduces the selected listed impact\n"
                    "oos_traps:\n"
                    "- no privileged/admin-only path\n"
                    "downgrade_clauses:\n"
                    "- downgrade if not reproduced\n"
                ),
            )
            rc, out, err = _run_factory(bundle)
            self.assertEqual(rc, 2, msg=f"stdout={out}\nstderr={err}")
            self.assertIn("proof_artifact_not_found", err)
            self.assertFalse((bundle / "cantina_ready.md").exists())

    def test_refuses_paste_ready_when_draft_severity_exceeds_locked_tier(self) -> None:
        """Explicit draft severity must match the exact listed-impact tier."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            bundle = _build_minimal_bundle(
                tmp,
                draft_body=(
                    "## Submission — #FIX-00 — High — VERIFIED PoC\n\n"
                    "### Finding Title\n```\nMismatched impact tier\n```\n\n"
                    "## Impact\nAttacker temporarily freezes funds.\n\n"
                    "## Impact Contract\n"
                    "selected_impact: Temporary loss of funds requiring admin recovery.\n"
                    "severity_tier: Medium\n"
                    "listed_impact_proven: true\n"
                    "evidence_class: forge_test\n"
                    "proof_artifact: poc.t.sol\n"
                    "proof_contract: executed PoC demonstrates temporary loss\n"
                    "stop_condition: forge PoC reproduces the selected listed impact\n"
                    "oos_traps:\n"
                    "- no privileged/admin-only path\n"
                    "downgrade_clauses:\n"
                    "- downgrade if not reproduced\n"
                ),
            )
            rc, out, err = _run_factory(bundle)
            self.assertEqual(rc, 2, msg=f"stdout={out}\nstderr={err}")
            self.assertIn(
                "severity_claim_not_backed_by_selected_impact_tier",
                err,
            )
            self.assertFalse((bundle / "cantina_ready.md").exists())

    def test_all_sections_present_in_output(self) -> None:
        """Test 1 — every one of the 9 canonical sections must appear in the output."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest = {
                "workspace": "polymarket",
                "gates": {
                    "variant": {
                        "risk_level": "LOW",
                        "top_score": 10,
                        "matches": [],
                        "comparison_source": "fixture ledger",
                    }
                },
                "fork_replay": {
                    "referenced": [],
                    "resolved": [],
                    "missing": [],
                    "malformed": [],
                    "entries": [],
                },
            }
            em = {
                "schema_version": 1,
                "severity": "Medium",
                "summary": {"ready_verdict": "READY"},
                "rows": [
                    {"key": "forge_poc", "label": "Forge PoC",
                     "status": "PRESENT", "notes": "PoC copied"},
                ],
            }
            bundle = _build_minimal_bundle(tmp, manifest=manifest, evidence_matrix=em)
            rc, out, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=f"stderr={err}\nstdout={out}")
            produced = (bundle / "cantina_ready.md").read_text()
            for section in SECTION_HEADERS:
                self.assertIn(section, produced,
                              msg=f"Missing section {section!r} in output:\n{produced[:400]}")

    def test_poc_command_references_actual_test_file(self) -> None:
        """Test 2 — `--match-contract X` must match a real `contract X` in bundle."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            bundle = _build_minimal_bundle(
                tmp,
                manifest={"workspace": "polymarket", "gates": {}},
                evidence_matrix={"rows": [], "summary": {}},
                poc_contract_name="R77_06_AdapterDonationCapture",
            )
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=f"stderr={err}")
            produced = (bundle / "cantina_ready.md").read_text()
            # Extract the `--match-contract X` token from output.
            m = re.search(r"forge test --match-contract (\S+)", produced)
            self.assertIsNotNone(m, f"No forge test command in output:\n{produced}")
            contract_name = m.group(1)
            # Find it in the bundle's `.t.sol` corpus.
            found = False
            for p in bundle.rglob("*.t.sol"):
                text = p.read_text()
                if re.search(rf"^\s*contract\s+{re.escape(contract_name)}\b", text, re.MULTILINE):
                    found = True
                    break
            self.assertTrue(found,
                            f"Emitted contract name `{contract_name}` not found in any "
                            f".t.sol under {bundle}")

    def test_operator_paste_hygiene_strips_internal_comments_and_local_paths(self) -> None:
        """Operator-facing output must not leak internal comments or local paths."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            bundle = _build_minimal_bundle(tmp)
            rc, out, err = _run_factory(bundle)

            self.assertEqual(rc, 0, msg=f"stdout={out}\nstderr={err}")
            produced = (bundle / "cantina_ready.md").read_text()
            self.assertNotIn("<!--", produced)
            self.assertNotIn(str(bundle), produced)
            self.assertNotIn(str(tmp), produced)
            self.assertNotIn("manual fill required", produced.lower())
            self.assertIn("bundle: .", produced)
            self.assertIn("- Bundle root: `.`", produced)
            self.assertIn("- Source draft: `source-draft.md`", produced)

    def test_refuses_path_only_poc_evidence_without_runnable_command(self) -> None:
        """A PoC file path without a derivable runnable command is not paste-ready."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            bundle = _build_minimal_bundle(tmp)
            (bundle / "poc.t.sol").write_text(
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity 0.8.20;\n"
                "// No contract declaration, so the factory cannot derive a command.\n",
                encoding="utf-8",
            )

            rc, out, err = _run_factory(bundle)

            self.assertEqual(rc, 1, msg=f"stdout={out}\nstderr={err}")
            self.assertIn("final operator paste hygiene failed", err)
            self.assertIn("poc_path_only_or_missing_command", err)
            self.assertFalse((bundle / "cantina_ready.md").exists())

    def test_harness_execution_queue_blocks_legacy_argv_only_contract(self) -> None:
        """Legacy argv-only harness metadata is artifact evidence, not runnable proof."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest = {"workspace": "polymarket", "gates": {}}
            harness_manifest = {
                "schema_version": 1,
                "generator": "tools/submission-packager.py",
                "draft_angle_ids": ["A-DONATION-CAPTURE"],
                "entries": [
                    {
                        "angle_id": "A-DONATION-CAPTURE",
                        "family": "vault",
                        "source_harness": "tools/invariants/families/vault/RedemptionBounds.t.sol",
                        "bundle_harness": "harnesses/A-DONATION-CAPTURE.t.sol",
                        "contract_name": "RedemptionBounds",
                        "origin": "copied",
                        "execution_contract": {
                            "tool": "econ-simulator",
                            "argv": [
                                "python3",
                                "${AUDITOOOR_DIR}/tools/econ-simulator.py",
                                "--bundle",
                                "${BUNDLE_ROOT}",
                                "--angle",
                                "A-DONATION-CAPTURE",
                            ],
                            "requires": ["AUDITOOOR_DIR", "BUNDLE_ROOT"],
                        },
                    }
                ],
                "unresolved_angles": [],
            }
            bundle = _build_minimal_bundle(
                tmp,
                manifest=manifest,
                extra_files={
                    "harnesses/A-DONATION-CAPTURE.t.sol": "contract RedemptionBounds {}\n",
                    "harness-binding-manifest.json": json.dumps(harness_manifest),
                },
            )
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=err)
            produced = (bundle / "cantina_ready.md").read_text()
            self.assertIn("**Harness execution queue:**", produced)
            self.assertIn("`A-DONATION-CAPTURE`:", produced)
            self.assertIn(
                "BLOCKED — missing exact runnable harness execution contract",
                produced,
            )
            self.assertIn("invalid_or_legacy_execution_contract_schema", produced)
            self.assertIn("missing_exact_harness_command", produced)
            self.assertIn("missing_exact_gating_test", produced)
            self.assertNotIn(
                '`python3 "${AUDITOOOR_DIR}/tools/econ-simulator.py" --bundle "${BUNDLE_ROOT}" --angle A-DONATION-CAPTURE`',
                produced,
            )
            self.assertIn("selector: `harnesses/A-DONATION-CAPTURE.t.sol` / contract `RedemptionBounds`", produced)

    def test_harness_execution_queue_surfaces_exact_gate_and_harness_contract(self) -> None:
        """Runnable harness display requires auditooor.harness_execution_contract.v1 commands."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest = {"workspace": "polymarket", "gates": {}}
            harness_command = "python3 tools/econ-simulator.py --bundle /tmp/bundle --angle A-DONATION-CAPTURE"
            gating_test = "python3 -m unittest tools.tests.test_econ_simulator -v"
            harness_manifest = {
                "schema_version": 1,
                "generator": "tools/submission-packager.py",
                "draft_angle_ids": ["A-DONATION-CAPTURE"],
                "entries": [
                    {
                        "angle_id": "A-DONATION-CAPTURE",
                        "family": "vault",
                        "source_harness": "tools/invariants/families/vault/RedemptionBounds.t.sol",
                        "bundle_harness": "harnesses/A-DONATION-CAPTURE.t.sol",
                        "contract_name": "RedemptionBounds",
                        "origin": "copied",
                        "execution_contract": {
                            "schema": "auditooor.harness_execution_contract.v1",
                            "claim": "runnable_harness",
                            "runnable": True,
                            "advisory_only": False,
                            "fail_closed": True,
                            "missing_inputs": [],
                            "blockers": [],
                            "commands": {
                                "harness_command": harness_command,
                                "gating_test": gating_test,
                            },
                        },
                    }
                ],
                "unresolved_angles": [],
            }
            bundle = _build_minimal_bundle(
                tmp,
                manifest=manifest,
                extra_files={
                    "harnesses/A-DONATION-CAPTURE.t.sol": "contract RedemptionBounds {}\n",
                    "harness-binding-manifest.json": json.dumps(harness_manifest),
                },
            )
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=err)
            produced = (bundle / "cantina_ready.md").read_text()
            self.assertIn("`A-DONATION-CAPTURE`: runnable only after exact gate + harness commands pass", produced)
            self.assertIn(f"gating_test: `{gating_test}`", produced)
            self.assertIn(f"harness_command: `{harness_command}`", produced)
            self.assertNotIn("BLOCKED — missing exact runnable harness execution contract", produced)

    def test_harness_execution_queue_blocks_when_manifest_missing(self) -> None:
        """Bundled harnesses without a binding manifest must be called out as blocked."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            bundle = _build_minimal_bundle(
                tmp,
                manifest={"workspace": "polymarket", "gates": {}},
                extra_files={
                    "harnesses/A-DONATION-CAPTURE.t.sol": "contract RedemptionBounds {}\n",
                },
            )
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=err)
            produced = (bundle / "cantina_ready.md").read_text()
            self.assertIn(
                "BLOCKED — `harness-binding-manifest.json` missing for bundled harnesses",
                produced,
            )

    def test_dupe_defense_cites_check7_output_not_fabricated(self) -> None:
        """Test 3 — cite `gates.variant.risk_level` verbatim; absent → literal 'unknown'."""
        # (A) manifest WITH gates.variant — output must cite the risk_level.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest = {
                "workspace": "polymarket",
                "gates": {
                    "variant": {
                        "risk_level": "HIGH",
                        "top_score": 99.5,
                        "matches": [
                            {"title": "prior-finding-title", "status": "Pending", "score": 99.5}
                        ],
                        "comparison_source": "fixture-ledger",
                    }
                },
            }
            bundle = _build_minimal_bundle(tmp, manifest=manifest)
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=err)
            produced = (bundle / "cantina_ready.md").read_text()
            self.assertIn("`HIGH`", produced,
                          "Dupe defense must cite `HIGH` risk verbatim")
            self.assertIn("Variant-detector risk", produced)
            self.assertIn("Check #7", produced)
            # Must NOT fabricate "LOW" when the manifest says HIGH.
            self.assertNotIn("Variant-detector risk: **`LOW`**", produced)

        # (B) manifest WITHOUT gates.variant — must say "dupe risk unknown".
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest = {"workspace": "polymarket", "gates": {}}  # no variant
            bundle = _build_minimal_bundle(tmp, manifest=manifest)
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=err)
            produced = (bundle / "cantina_ready.md").read_text()
            self.assertIn("dupe risk unknown", produced,
                          "Must say 'dupe risk unknown' verbatim when no gates.variant")
            # Must not fabricate a LOW/HIGH/MEDIUM verdict out of thin air.
            self.assertNotIn("Variant-detector risk: **`LOW`**", produced)
            self.assertNotIn("Variant-detector risk: **`HIGH`**", produced)

        # (C) no manifest at all — must still say 'dupe risk unknown'.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            bundle = _build_minimal_bundle(tmp)
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=err)
            produced = (bundle / "cantina_ready.md").read_text()
            self.assertIn("dupe risk unknown", produced)

    def test_triager_risk_section_flags_poly45_class_correctly(self) -> None:
        """Test 4 — drafts with `uint256.max` / `2^248` trigger POLY-45 flag."""
        # (A) draft cites uint256.max → MUST flag POLY-45.
        draft_a = (
            "## Submission — #FIX-01 — High — VERIFIED\n\n"
            "### Finding Title\n```\nmakerAmount uint256.max overflow\n```\n\n"
            "## Impact\nSetting makerAmount to uint256.max drains vault.\n"
        )
        with tempfile.TemporaryDirectory() as td:
            bundle = _build_minimal_bundle(Path(td), draft_body=draft_a)
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=err)
            produced = (bundle / "cantina_ready.md").read_text()
            self.assertIn("[POLY-45]", produced)
            self.assertIn("Likely triager pushback: unrealistic bounds", produced)

        # (B) draft cites 2^248 → MUST flag POLY-45.
        draft_b = (
            "## Submission — #FIX-02 — High — VERIFIED\n\n"
            "### Finding Title\n```\nOrderStatus 2^248 overflow\n```\n\n"
            "## Impact\n`remaining` field at 2^248 wraps.\n"
        )
        with tempfile.TemporaryDirectory() as td:
            bundle = _build_minimal_bundle(Path(td), draft_body=draft_b)
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=err)
            produced = (bundle / "cantina_ready.md").read_text()
            self.assertIn("[POLY-45]", produced)
            self.assertIn("unrealistic bounds", produced)

        # (C) benign draft WITHOUT bounds keywords → must NOT flag POLY-45.
        draft_c = (
            "## Submission — #FIX-03 — Medium — VERIFIED\n\n"
            "### Finding Title\n```\nVault deposit frontrun\n```\n\n"
            "## Impact\nAttacker frontruns the deposit for ~$500 profit.\n"
        )
        with tempfile.TemporaryDirectory() as td:
            bundle = _build_minimal_bundle(Path(td), draft_body=draft_c)
            rc, _, err = _run_factory(bundle)
            self.assertEqual(rc, 0, msg=err)
            produced = (bundle / "cantina_ready.md").read_text()
            self.assertNotIn("[POLY-45]", produced)
            self.assertIn("No known rejection-class matches.", produced)


if __name__ == "__main__":
    unittest.main()
