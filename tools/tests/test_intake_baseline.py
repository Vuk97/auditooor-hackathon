from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "intake-baseline.py"


def _write_rubric_ready_files(ws: Path) -> None:
    (ws / "SEVERITY.md").write_text(
        "# Critical\n"
        "- Direct loss of user funds\n\n"
        "# High\n"
        "- Permanent protocol denial of service\n\n"
        "# Medium\n"
        "- Temporary denial of service\n"
    )
    (ws / "RUBRIC_COVERAGE.md").write_text(
        "# Rubric Coverage\n\n"
        "**Severity source files:**\n"
        "- `SEVERITY.md`\n\n"
        "| # | Example | Verdict | Evidence / Gap |\n"
        "|---|---|---|---|\n"
        "| C1 | Direct loss of user funds | 📋 NOT CHECKED | — |\n"
    )


def _write_operator_truth_ready_files(ws: Path) -> None:
    (ws / "SCOPE.md").write_text(
        "# Program Scope\n\n"
        "Assets in scope: Smart Contract vault and settlement modules.\n\n"
        "Out of scope: trusted-admin-only actions, social engineering, "
        "and front-running without a protocol fault.\n"
    )
    (ws / "OOS_PASTED.md").write_text(
        "# Live OOS Text\n\n"
        "- Trusted admin key compromise is excluded.\n"
        "- Natural network activity without protocol fault is excluded.\n"
    )
    (ws / "OOS_CHECKLIST.md").write_text(
        "# OOS Checklist\n\n"
        "- [ ] trusted-admin-only path\n"
        "- [ ] pure MEV/front-running path\n"
    )
    (ws / "SEVERITY_CAPS.md").write_text(
        "# Severity Caps\n\n"
        "- Critical: direct theft of user funds\n"
        "- High: permanent freezing of funds\n"
    )
    (ws / "ASSET_PLAN_Smart_Contract.md").write_text(
        "- Roots: src\n"
        "- Strategy: line-by-line + exploit proof\n"
        "- Estimated hours: 12\n"
        "- Agent hour quota pct: 100\n"
        "- Plan status: ready\n"
    )
    auditooor = ws / ".auditooor"
    auditooor.mkdir()
    (auditooor / "prior_disclosure_index.json").write_text(
        json.dumps(
            {
                "schema_version": "auditooor.prior_disclosure_index.v1",
                "summary": {"total_rows": 1},
                "rows": [{"title": "prior test row"}],
            }
        )
    )


def _load_tool():
    spec = importlib.util.spec_from_file_location("intake_baseline", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class IntakeBaselineTest(unittest.TestCase):
    def test_pdf_without_text_is_reported(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "CANTINA_COVERAGE.md").write_text("# Coverage\n")
            (ws / "report.pdf").write_bytes(b"%PDF-1.4\n")

            payload = tool.build_baseline(ws)

        self.assertEqual(payload["summary"]["pdf_count"], 1)
        self.assertEqual(payload["summary"]["pdfs_missing_extracted_text"], 1)
        self.assertEqual(payload["known_intel"], ["CANTINA_COVERAGE.md"])
        self.assertIn("PDF(s) lack extracted text", payload["warnings"][0])

    def test_pdf_with_text_sibling_clears_warning(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "KNOWN_VULNS.md").write_text("# Known\n")
            (ws / "known.pdf").write_bytes(b"%PDF-1.4\n")
            (ws / "known.txt").write_text("extracted text\n")

            payload = tool.build_baseline(ws)

        self.assertEqual(payload["summary"]["pdf_count"], 1)
        self.assertEqual(payload["summary"]["pdfs_missing_extracted_text"], 0)
        self.assertFalse(payload["pdfs_missing_extracted_text"])

    def test_cli_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "ATTACK_TREE.md").write_text("# Tree\n")
            _write_rubric_ready_files(ws)
            out_json = ws / "custom" / "baseline.json"
            out_md = ws / "custom" / "baseline.md"

            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    str(ws),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(out_json.is_file())
            self.assertTrue(out_md.is_file())
            payload = json.loads(out_json.read_text())
            self.assertEqual(payload["schema"], "auditooor.intake-baseline.v1")
            self.assertEqual(payload["summary"]["blocker_count"], 0)
            self.assertIn("ATTACK_TREE.md", out_md.read_text())

    def test_cli_blocks_placeholder_severity_without_rubric_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SEVERITY.md").write_text(
                "# Severity Rubric\n\n"
                "**TODO:** paste the bounty program's severity matrix here.\n"
            )

            result = subprocess.run(
                ["python3", str(TOOL), str(ws), "--json"],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertGreaterEqual(payload["summary"]["blocker_count"], 2)
            self.assertIn("no populated severity rubric source found", payload["blockers"][0])

    def test_missing_rubric_coverage_blocker_includes_init_hint(self):
        """I-06 (PR #158): the ``RUBRIC_COVERAGE.md missing`` blocker must
        point at ``tools/init-rubric-coverage.sh`` so first-run operators
        do not have to grep the toolset to find the scaffolder.
        """
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SEVERITY.md").write_text(
                "# Critical\n- Direct loss of user funds\n\n"
                "# High\n- Permanent protocol denial of service\n"
            )
            payload = tool.build_baseline(ws)
        rubric_blockers = [
            b for b in payload["blockers"] if "RUBRIC_COVERAGE.md" in b
        ]
        self.assertTrue(rubric_blockers, msg=payload["blockers"])
        self.assertIn("init-rubric-coverage.sh", rubric_blockers[0])

    def test_placeholder_rubric_coverage_blocker_includes_init_hint(self):
        """A present-but-placeholder RUBRIC_COVERAGE.md must surface the
        same hint (rerun the scaffolder)."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SEVERITY.md").write_text(
                "# Critical\n- Direct loss of user funds\n\n"
                "# High\n- Permanent protocol denial of service\n"
            )
            (ws / "RUBRIC_COVERAGE.md").write_text(
                "# Rubric Coverage\n\nTODO: paste rubric here.\n"
            )
            payload = tool.build_baseline(ws)
        placeholder_blockers = [
            b for b in payload["blockers"]
            if "placeholder" in b or "no rubric rows" in b
        ]
        self.assertTrue(placeholder_blockers, msg=payload["blockers"])
        self.assertIn("init-rubric-coverage.sh", placeholder_blockers[0])

    def test_missing_oos_checklist_emits_extract_oos_hint_warning(self):
        """I-15 (PR #158): downstream stages HARD-STOP on missing
        OOS_CHECKLIST.md / SEVERITY_CAPS.md. Intake-baseline must
        surface a warning + hint pointing at extract-oos.sh so first-run
        operators don't blow through 11 stages before flow-gate Step 5
        rejects them."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_rubric_ready_files(ws)
            payload = tool.build_baseline(ws)
        oos_warnings = [
            w for w in payload["warnings"]
            if "OOS_CHECKLIST.md" in w or "SEVERITY_CAPS.md" in w
        ]
        self.assertTrue(oos_warnings, msg=payload["warnings"])
        # Both files mentioned, hint cites extract-oos.sh.
        joined = " | ".join(oos_warnings)
        self.assertIn("OOS_CHECKLIST.md", joined)
        self.assertIn("SEVERITY_CAPS.md", joined)
        self.assertIn("extract-oos.sh", joined)
        # Warning, not blocker.
        oos_blockers = [
            b for b in payload["blockers"]
            if "OOS_CHECKLIST.md" in b or "SEVERITY_CAPS.md" in b
        ]
        self.assertFalse(oos_blockers)

    def test_present_oos_checklist_and_severity_caps_dont_warn(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_rubric_ready_files(ws)
            (ws / "OOS_CHECKLIST.md").write_text(
                "# Out-of-Scope Checklist\n\n"
                "**OOS-1:** Centralization risk by trusted admins\n"
            )
            (ws / "SEVERITY_CAPS.md").write_text(
                "# Severity Caps\n\nCritical $500k / High $50k / Medium $5k\n"
            )
            payload = tool.build_baseline(ws)
        oos_warnings = [
            w for w in payload["warnings"]
            if "OOS_CHECKLIST.md" in w or "SEVERITY_CAPS.md" in w
        ]
        self.assertEqual(oos_warnings, [])

    def test_strict_operator_truth_blocks_missing_scope_oos_and_prior_index(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_rubric_ready_files(ws)
            payload = tool.build_baseline(ws, strict_operator_truth=True)
        blockers = "\n".join(payload["blockers"])
        self.assertIn("SCOPE.md missing or placeholder", blockers)
        self.assertIn("no populated OOS text found", blockers)
        self.assertIn("OOS_CHECKLIST.md missing or placeholder", blockers)
        self.assertIn("SEVERITY_CAPS.md missing or placeholder", blockers)
        self.assertIn("prior disclosure index missing", blockers)
        self.assertFalse(payload["summary"]["operator_truth_ready"])

    def test_strict_operator_truth_passes_with_populated_truth_and_prior_index(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_rubric_ready_files(ws)
            _write_operator_truth_ready_files(ws)
            payload = tool.build_baseline(ws, strict_operator_truth=True)
        strict_blockers = [
            b for b in payload["blockers"]
            if "strict operator-truth blocker" in b
        ]
        self.assertEqual(strict_blockers, [], msg=payload["blockers"])
        self.assertTrue(payload["summary"]["operator_truth_ready"])
        self.assertTrue(payload["summary"]["prior_disclosure_ready"])

    def test_strict_operator_truth_accepts_explicit_no_severity_caps_marker(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_rubric_ready_files(ws)
            _write_operator_truth_ready_files(ws)
            (ws / "SEVERITY_CAPS.md").write_text(
                "# Severity Caps\n\n"
                "<!-- AUDITOOOR_AUTO_CAPS_BEGIN -->\n\n"
                "_(no program-specific severity caps listed in SCOPE.md)_\n\n"
                "<!-- AUDITOOOR_AUTO_CAPS_END -->\n"
            )
            payload = tool.build_baseline(ws, strict_operator_truth=True)
        strict_blockers = [
            b for b in payload["blockers"]
            if "strict operator-truth blocker" in b
        ]
        self.assertEqual(strict_blockers, [], msg=payload["blockers"])
        caps_state = payload["operator_truth"]["files"]["SEVERITY_CAPS.md"]
        self.assertTrue(caps_state["populated"])
        self.assertFalse(caps_state["placeholder"])
        self.assertTrue(payload["summary"]["operator_truth_ready"])

    def test_strict_operator_truth_rejects_old_no_severity_caps_placeholder(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_rubric_ready_files(ws)
            _write_operator_truth_ready_files(ws)
            (ws / "SEVERITY_CAPS.md").write_text(
                "# Severity Caps\n\n"
                "<!-- AUDITOOOR_AUTO_CAPS_BEGIN -->\n\n"
                "_(no severity caps parsed - verify SCOPE.md has explicit cap statements)_\n\n"
                "<!-- AUDITOOOR_AUTO_CAPS_END -->\n"
            )
            payload = tool.build_baseline(ws, strict_operator_truth=True)
        blockers = "\n".join(payload["blockers"])
        self.assertIn("SEVERITY_CAPS.md missing or placeholder", blockers)
        caps_state = payload["operator_truth"]["files"]["SEVERITY_CAPS.md"]
        self.assertFalse(caps_state["populated"])
        self.assertTrue(caps_state["placeholder"])

    def test_cli_strict_operator_truth_returns_nonzero_on_missing_truth(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_rubric_ready_files(ws)

            result = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    str(ws),
                    "--strict-operator-truth",
                    "--json",
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertFalse(payload["summary"]["operator_truth_ready"])

    def test_partial_oos_artifacts_warn_only_for_missing_one(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_rubric_ready_files(ws)
            (ws / "OOS_CHECKLIST.md").write_text("# OOS\n")
            # SEVERITY_CAPS.md absent.
            payload = tool.build_baseline(ws)
        oos_warnings = [
            w for w in payload["warnings"]
            if "OOS_CHECKLIST.md" in w or "SEVERITY_CAPS.md" in w
        ]
        self.assertEqual(len(oos_warnings), 1)
        self.assertIn("SEVERITY_CAPS.md", oos_warnings[0])
        self.assertNotIn("OOS_CHECKLIST.md", oos_warnings[0])

    def test_split_smart_contract_and_blockchain_dlt_rubrics_are_accepted(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SEVERITY_SMART_CONTRACTS.md").write_text(
                "# Critical\n- Theft from smart contract escrow\n\n"
                "# High\n- Permanent smart contract freeze\n"
            )
            (ws / "SEVERITY_BLOCKCHAIN_DLT.md").write_text(
                "# Critical\n- Consensus safety failure\n\n"
                "# Medium\n- Temporary sequencer liveness degradation\n"
            )
            (ws / "RUBRIC_COVERAGE.md").write_text(
                "# Rubric Coverage\n\n"
                "**Severity source files:**\n"
                "- `SEVERITY_SMART_CONTRACTS.md`\n"
                "- `SEVERITY_BLOCKCHAIN_DLT.md`\n\n"
                "| # | Example | Verdict | Evidence / Gap |\n"
                "|---|---|---|---|\n"
                "| C1 | Theft from smart contract escrow | 📋 NOT CHECKED | — |\n"
                "| C2 | Consensus safety failure | 📋 NOT CHECKED | — |\n"
            )
            # Gap E: both in-scope assets need a ready plan file, and the
            # BDL asset needs scan-rust evidence OR an explicit waiver.
            (ws / "ASSET_PLAN_Smart_Contract.md").write_text(
                "- Roots: src/contracts\n"
                "- Strategy: line-by-line + Foundry PoC\n"
                "- Estimated hours: 30\n"
                "- Agent hour quota pct: 60\n"
                "- Plan status: ready\n"
            )
            (ws / "ASSET_PLAN_Blockchain_DLT.md").write_text(
                "- Roots: external/base\n"
                "- Strategy: scanner-informed Rust review\n"
                "- Estimated hours: 20\n"
                "- Agent hour quota pct: 40\n"
                "- Plan status: ready\n"
            )
            (ws / "ASSET_WAIVER_Blockchain_DLT.md").write_text(
                "scan-rust waived: toolchain unavailable on CI runner.\n"
            )

            payload = tool.build_baseline(ws)

        self.assertEqual(payload["summary"]["severity_sources_populated"], 2)
        self.assertEqual(payload["summary"]["rubric_coverage_rows"], 2)
        self.assertFalse(payload["blockers"])
        self.assertEqual(
            payload["assets_in_scope"], ["Smart Contract", "Blockchain/DLT"]
        )


    def test_bulleted_roots_section_populates_asset_plan(self):
        """PR #120 lesson 3 — markdown `## Roots\\n- pkg/a\\n- pkg/b` must
        populate `asset_coverage_plan["Smart Contract"].roots`. Regression:
        empty roots[] caused engagement-retro Gap E to deadlock on
        Polymarket + The Graph workspaces."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_rubric_ready_files(ws)
            (ws / "SEVERITY_SMART_CONTRACTS.md").write_text(
                "# Critical\n- Theft\n\n# High\n- Freeze\n"
            )
            (ws / "ASSET_PLAN_Smart_Contract.md").write_text(
                "# Asset Coverage Plan — Smart Contract\n\n"
                "- Strategy: line-by-line + Foundry\n"
                "- Estimated hours: 40\n"
                "- Agent hour quota pct: 100\n"
                "- Plan status: ready\n\n"
                "## Roots\n\n"
                "- `external/contracts/packages/horizon/` (Horizon upgrade)\n"
                "- `external/contracts/packages/issuance/` (issuance changes)\n"
                "- `external/contracts/packages/contracts/`\n"
            )
            payload = tool.build_baseline(ws)
        plan = payload["asset_coverage_plan"]["Smart Contract"]
        self.assertEqual(
            plan["roots"],
            [
                "external/contracts/packages/horizon/",
                "external/contracts/packages/issuance/",
                "external/contracts/packages/contracts/",
            ],
        )
        self.assertEqual(plan.get("roots_parse_status"), "parsed")
        self.assertEqual(plan["plan_status"], "ready")

    def test_existing_curated_roots_are_preserved_across_intake_runs(self):
        """PR #120 lesson 3 preservation rule: if a prior INTAKE_BASELINE.json
        carries operator-curated roots[], a re-run of intake-baseline must
        not silently overwrite them (even if ASSET_PLAN's parsed roots
        differ). The plan-file roots are stashed under `roots_from_plan`
        for diff visibility."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_rubric_ready_files(ws)
            (ws / "SEVERITY_SMART_CONTRACTS.md").write_text(
                "# Critical\n- Theft\n\n# High\n- Freeze\n"
            )
            (ws / "ASSET_PLAN_Smart_Contract.md").write_text(
                "- Roots: src/v1\n"
                "- Strategy: foo\n"
                "- Estimated hours: 10\n"
                "- Agent hour quota pct: 50\n"
                "- Plan status: ready\n"
            )
            curated = {
                "asset_coverage_plan": {
                    "Smart Contract": {
                        "roots": ["operator/curated/path"],
                        "plan_status": "ready",
                    }
                }
            }
            (ws / "INTAKE_BASELINE.json").write_text(json.dumps(curated))
            payload = tool.build_baseline(ws)
        plan = payload["asset_coverage_plan"]["Smart Contract"]
        self.assertEqual(plan["roots"], ["operator/curated/path"])
        self.assertEqual(plan.get("roots_from_plan"), ["src/v1"])
        self.assertTrue(any("preserved curated roots" in w for w in payload["warnings"]))

    def test_malformed_roots_section_yields_status_not_blocker(self):
        """Malformed markdown (no bullets, just paragraph text under heading)
        must produce a parse-status warning, not block intake."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_rubric_ready_files(ws)
            (ws / "SEVERITY_SMART_CONTRACTS.md").write_text(
                "# Critical\n- Theft\n\n# High\n- Freeze\n"
            )
            (ws / "ASSET_PLAN_Smart_Contract.md").write_text(
                "## Roots\n\n"
                "Not a bullet list, just prose. Should not parse.\n\n"
                "- Strategy: line-by-line\n"
                "- Plan status: ready\n"
            )
            payload = tool.build_baseline(ws)
        plan = payload["asset_coverage_plan"]["Smart Contract"]
        self.assertEqual(plan.get("roots") or [], [])
        # Either malformed (saw heading but no bullets) or missing — both
        # acceptable; the key rule is "do not crash, do not block".
        self.assertIn(plan.get("roots_parse_status"), ("malformed", "missing", None))
        self.assertEqual(plan["plan_status"], "ready")  # plan_status still ready

class RustRootDetectionTest(unittest.TestCase):
    """V3 workflow gap #2 fix: non-audit Rust roots must not trigger the
    scan-rust blocker (Sei field run: example/, loadtest/, libwasmvm all
    produced spurious blockers)."""

    def _make_ws(self, tmp: str) -> Path:
        ws = Path(tmp)
        # Minimal rubric so the baseline does not blocker on missing severity.
        (ws / "SEVERITY.md").write_text(
            "# Critical\n- Direct loss\n\n# High\n- Chain halt\n"
        )
        (ws / "RUBRIC_COVERAGE.md").write_text(
            "| # | Example | Verdict | Evidence / Gap |\n"
            "|---|---|---|---|\n"
            "| C1 | Direct loss | 📋 NOT CHECKED | - |\n"
        )
        return ws

    def _place_cargo(self, ws: Path, rel_dir: str) -> None:
        target = ws / rel_dir
        target.mkdir(parents=True, exist_ok=True)
        (target / "Cargo.toml").write_text("[package]\nname = \"dummy\"\n")

    # Test 1: genuine in-scope Rust crate is still detected; blocker fires when
    # no scan artifact is present.
    def test_genuine_rust_crate_detected_and_blocks_without_scan_artifact(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_ws(tmp)
            self._place_cargo(ws, "src/mychain")
            payload = tool.build_baseline(ws)
        self.assertEqual(payload["summary"]["rust_roots_detected"], 1)
        self.assertIn("src/mychain", payload["rust_roots"])
        rust_blockers = [b for b in payload["blockers"] if "scan-rust" in b]
        # Blocker only fires when there is an asset that needs it (Blockchain/DLT
        # or no SC-only asset). Even if not in asset plan, the warning path fires.
        rust_warnings = [w for w in payload["warnings"] if "scan-rust" in w or "Rust root" in w]
        self.assertTrue(rust_blockers or rust_warnings,
                        msg="Expected rust-scan signal but got none")

    # Test 2: Rust under example/ is NOT flagged; no blocker.
    def test_example_rust_not_flagged(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_ws(tmp)
            self._place_cargo(ws, "src/sei-chain/example/cosmwasm/cw721")
            self._place_cargo(ws, "src/sei-chain/example/cosmwasm/iter")
            payload = tool.build_baseline(ws)
        self.assertEqual(payload["summary"]["rust_roots_detected"], 0,
                         msg=f"Unexpected rust_roots: {payload['rust_roots']}")
        rust_blockers = [b for b in payload["blockers"] if "scan-rust" in b]
        self.assertFalse(rust_blockers)

    # Test 3: Rust under loadtest/ is NOT flagged; no blocker.
    def test_loadtest_rust_not_flagged(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_ws(tmp)
            self._place_cargo(ws, "src/sei-chain/loadtest/contracts/venus")
            self._place_cargo(ws, "src/sei-chain/loadtest/contracts/saturn")
            payload = tool.build_baseline(ws)
        self.assertEqual(payload["summary"]["rust_roots_detected"], 0,
                         msg=f"Unexpected rust_roots: {payload['rust_roots']}")

    # Test 4: libwasmvm (vendored dep substring) is NOT flagged.
    def test_libwasmvm_vendored_not_flagged(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_ws(tmp)
            self._place_cargo(ws, "src/sei-chain/sei-wasmvm/libwasmvm")
            payload = tool.build_baseline(ws)
        self.assertEqual(payload["summary"]["rust_roots_detected"], 0,
                         msg=f"Unexpected rust_roots: {payload['rust_roots']}")

    # Test 5: mixed - one real + several example/loadtest/vendored -> only real one flagged.
    def test_mixed_real_and_excluded_rust_roots(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_ws(tmp)
            # Real in-scope crate
            self._place_cargo(ws, "src/mychain/runtime")
            # Non-audit-target dirs
            self._place_cargo(ws, "src/mychain/example/demo")
            self._place_cargo(ws, "src/mychain/loadtest/bench")
            self._place_cargo(ws, "src/mychain/vendor/parity-scale-codec")
            self._place_cargo(ws, "src/sei-chain/sei-wasmvm/libwasmvm")
            payload = tool.build_baseline(ws)
        self.assertEqual(payload["summary"]["rust_roots_detected"], 1,
                         msg=f"Expected 1 real root; got: {payload['rust_roots']}")
        self.assertIn("src/mychain/runtime", payload["rust_roots"])

    # Test 6: asset-plan Out-of-scope roots section is honoured.
    def test_asset_plan_oos_roots_excludes_declared_dirs(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_ws(tmp)
            # Place Cargo.toml inside a path that is NOT in the built-in exclusion list
            # but is declared OOS in the asset plan.
            self._place_cargo(ws, "src/sei-chain/parallelization/bank")
            # Declare as OOS in asset plan
            (ws / "ASSET_PLAN_Blockchain_DLT.md").write_text(
                "- Strategy: Go-only\n"
                "- Estimated hours: 10\n"
                "- Agent hour quota pct: 100\n"
                "- Plan status: ready\n\n"
                "## Out-of-scope roots\n\n"
                "- src/sei-chain/parallelization/bank\n"
            )
            payload = tool.build_baseline(ws)
        self.assertEqual(payload["summary"]["rust_roots_detected"], 0,
                         msg=f"OOS root still detected: {payload['rust_roots']}")

    # Test 7: vendor/ directory is NOT flagged.
    def test_vendor_rust_not_flagged(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_ws(tmp)
            self._place_cargo(ws, "vendor/some-crate")
            payload = tool.build_baseline(ws)
        self.assertEqual(payload["summary"]["rust_roots_detected"], 0,
                         msg=f"Unexpected rust_roots: {payload['rust_roots']}")

    # Test 8: tests/ directory is NOT flagged.
    def test_tests_dir_rust_not_flagged(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_ws(tmp)
            self._place_cargo(ws, "src/mychain/tests/integration")
            payload = tool.build_baseline(ws)
        self.assertEqual(payload["summary"]["rust_roots_detected"], 0,
                         msg=f"Unexpected rust_roots: {payload['rust_roots']}")

    def _place_cosmwasm_cargo(self, ws: Path, rel_dir: str) -> None:
        """A CosmWasm contract crate (cdylib + cosmwasm-std) - a wasm fixture."""
        target = ws / rel_dir
        target.mkdir(parents=True, exist_ok=True)
        (target / "Cargo.toml").write_text(
            "[package]\nname = \"bank\"\nversion = \"0.1.0\"\n\n"
            "[lib]\ncrate-type = [\"cdylib\", \"rlib\"]\n\n"
            "[dependencies]\ncosmwasm-std = { version = \"1.0.0\" }\n"
            "cw-storage-plus = \"0.13.2\"\n"
        )

    # Test 9 (V3 gap #2b, Sei field run 2026-07-04): CosmWasm contract crates
    # (cdylib + cosmwasm-std) inside a Go/BDL chain repo are wasm fixtures for
    # the OCC scheduler, NOT the chain's Rust audit surface -> NOT flagged.
    def test_cosmwasm_contract_crate_not_flagged(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_ws(tmp)
            # The exact Sei case: parallelization/{bank,wasm,staking} contracts.
            self._place_cosmwasm_cargo(ws, "src/sei-chain/parallelization/bank")
            self._place_cosmwasm_cargo(ws, "src/sei-chain/parallelization/wasm")
            self._place_cosmwasm_cargo(ws, "src/sei-chain/parallelization/staking")
            payload = tool.build_baseline(ws)
        self.assertEqual(payload["summary"]["rust_roots_detected"], 0,
                         msg=f"CosmWasm fixtures flagged: {payload['rust_roots']}")
        rust_blockers = [b for b in payload["blockers"] if "scan-rust" in b]
        self.assertFalse(rust_blockers, msg=f"Spurious blocker: {rust_blockers}")

    # Test 10 (never-false-pass): the exclusion keys on the CosmWasm CONTRACT
    # nature, not the path. A genuine (non-cosmwasm) Rust lib crate at the SAME
    # parallelization/ path level is STILL detected -> the scan-rust requirement
    # is not silently suppressed for real Rust.
    def test_non_cosmwasm_rust_crate_still_flagged(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_ws(tmp)
            self._place_cargo(ws, "src/mychain/parallelization/realcrate")
            payload = tool.build_baseline(ws)
        self.assertEqual(payload["summary"]["rust_roots_detected"], 1,
                         msg=f"Real Rust crate not detected: {payload['rust_roots']}")
        self.assertIn("src/mychain/parallelization/realcrate", payload["rust_roots"])


class AutoOosBlockPlaceholderTest(unittest.TestCase):
    """Guard: a populated AUDITOOOR_AUTO_OOS block overrides a legacy "TBD" stub
    that extract-oos.sh's appended-legacy mode leaves above it (2026-06-14
    regression: bean OOS_CHECKLIST.md had 9 real auto-bullets but the global
    "TBD" placeholder marker false-blocked audit-run-full's strict intake)."""

    _LEGACY_TBD = (
        "# Out-of-scope checklist\n\nTBD - operator edit.\n\n## OOS bullets\n"
        "- OOS-1: TBD - <operator edit>\n\n"
        "<!-- AUDITOOOR_AUTO_OOS_BEGIN -->\n"
        "- [ ] **OOS-1:** Any asset NOT in the Assets-in-Scope list.\n"
        "- [ ] **OOS-2:** Loss from MISUSE of Pipeline / Depot.\n"
        "<!-- AUDITOOOR_AUTO_OOS_END -->\n"
    )
    _TBD_ONLY = (
        "# Out-of-scope checklist\n\nTBD - operator edit.\n\n## OOS bullets\n"
        "- OOS-1: TBD - <operator edit>\n"
    )

    def test_populated_auto_block_overrides_legacy_tbd(self):
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "OOS_CHECKLIST.md").write_text(self._LEGACY_TBD)
            st = tool._truth_file_state(ws, "OOS_CHECKLIST.md")
        self.assertFalse(st["placeholder"], "populated auto-OOS block must not be placeholder")
        self.assertTrue(st["populated"], "populated auto-OOS block must count as populated")

    def test_tbd_only_still_placeholder(self):
        """False-green guard: no auto-block + only TBD stubs stays a placeholder."""
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "OOS_CHECKLIST.md").write_text(self._TBD_ONLY)
            st = tool._truth_file_state(ws, "OOS_CHECKLIST.md")
        self.assertTrue(st["placeholder"], "TBD-only OOS must stay placeholder")
        self.assertFalse(st["populated"])

    def test_auto_block_with_only_tbd_bullets_not_populated(self):
        """An auto-block whose only bullets are TBD stubs is NOT populated."""
        tool = _load_tool()
        text = (
            "<!-- AUDITOOOR_AUTO_OOS_BEGIN -->\n"
            "- [ ] **OOS-1:** TBD - operator edit\n"
            "<!-- AUDITOOOR_AUTO_OOS_END -->\n"
        )
        self.assertFalse(tool._auto_oos_block_populated(text))

    def test_table_severity_with_incidental_tbd_is_populated_not_blocked(self):
        # Regression: a fully-populated markdown-TABLE severity rubric that
        # carries an incidental placeholder token (a 'TBD' reward-tier note) must
        # NOT be demoted to a stub. A bootstrap stub with TBD and no rows must
        # still be flagged placeholder.
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SEVERITY.md").write_text(
                "# Severity\n\n"
                "| Severity | Impact |\n"
                "|---|---|\n"
                "| Critical | Direct theft of user funds |\n"
                "| High | Temporary freezing of funds |\n"
                "| Medium | Smart contract unable to operate |\n\n"
                "Reward tiers: max $250k; sub-Critical $ TBD from program page.\n"
            )
            sources = tool._severity_sources(ws)
            self.assertEqual(len(sources), 1)
            self.assertFalse(sources[0]["placeholder"],
                             "populated table rubric with incidental TBD must not be placeholder")
            self.assertGreaterEqual(tool._severity_rubric_row_count(
                (ws / "SEVERITY.md").read_text()), 3)
        with tempfile.TemporaryDirectory() as tmp2:
            ws2 = Path(tmp2)
            (ws2 / "SEVERITY.md").write_text(
                "# Severity\nSee default rubric. TBD - operator edit.\n")
            stub_sources = tool._severity_sources(ws2)
            self.assertTrue(stub_sources[0]["placeholder"],
                            "a TBD stub with zero rubric rows must remain placeholder")


if __name__ == "__main__":
    unittest.main()
