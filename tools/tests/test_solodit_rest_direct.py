"""Tests for tools/solodit-rest-direct.py.

Synthetic fixtures only; no network calls. All cases mark records with
record_extensions.synthetic_fixture = true so downstream consumers can
distinguish them from live ingests.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "_solodit_rest_direct",
        str(REPO_ROOT / "tools" / "solodit-rest-direct.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


SRD = _load_module()


# ---------------------------------------------------------------------------
# Synthetic API response fixtures
# ---------------------------------------------------------------------------

def _mk_finding(fid: int, severity: str = "HIGH", title: str = "Reentrancy in vault.withdraw", **extra) -> dict:
    base = {
        "id": fid,
        "severity": severity,
        "title": title,
        "description": "An attacker can re-enter withdraw() and drain user balances.",
        "url": f"https://solodit.cyfrin.io/issues/sample-{fid}",
        "language": "Solidity",
        "function": "withdraw(uint256 amount)",
        "category": "reentrancy",
        "year": 2025,
    }
    base.update(extra)
    return base


def _mk_response(findings, total_pages: int = 1) -> dict:
    return {
        "findings": findings,
        "metadata": {"totalPages": total_pages, "pageSize": 100},
    }


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestNormalization(unittest.TestCase):
    def test_build_record_minimal_fields_present(self):
        """Case 1: v1.1 record contains all 5 new provenance fields populated."""
        raw = _mk_finding(70001, severity="HIGH")
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        self.assertEqual(rec["schema_version"], "auditooor.hackerman_record.v1.1")
        self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
        self.assertEqual(rec["record_source_url"], "https://solodit.cyfrin.io/issues/sample-70001")
        # cve_id / ghsa_id are optional per schema; omitted when no valid value present
        self.assertNotIn("cve_id", rec)
        self.assertNotIn("ghsa_id", rec)
        self.assertIsInstance(rec["record_extensions"], dict)
        self.assertEqual(rec["record_extensions"]["source_method"], "solodit-rest-direct")
        self.assertEqual(rec["severity_at_finding"], "high")
        self.assertEqual(rec["target_language"], "solidity")
        self.assertEqual(rec["year"], 2025)

    def test_build_record_cve_and_ghsa_pass_through(self):
        """Case 2: CVE / GHSA IDs are propagated when valid; invalid IDs are stripped."""
        raw = _mk_finding(
            70002,
            severity="CRITICAL",
            cve_id="CVE-2022-37937",
            ghsa_id="GHSA-6447-269v-g68m",
        )
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        self.assertEqual(rec["cve_id"], "CVE-2022-37937")
        self.assertEqual(rec["ghsa_id"], "GHSA-6447-269v-g68m")
        self.assertEqual(rec["severity_at_finding"], "critical")
        self.assertEqual(rec["impact_dollar_class"], ">=$1M")

        bad = _mk_finding(70003, cve_id="not-a-cve", ghsa_id="garbage")
        rec_bad = SRD.build_v11_record(
            bad,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        # Invalid IDs are omitted (NOT emitted as empty string, which would fail schema validation)
        self.assertNotIn("cve_id", rec_bad)
        self.assertNotIn("ghsa_id", rec_bad)

    def test_build_record_uses_live_solodit_content_shape(self):
        """Case 2-bis: live Solodit rows carry body/source metadata under content/source_link keys."""
        raw = _mk_finding(
            70012,
            description="",
            content="The vulnerable Rust refund path mints shares from a stale total.",
            source_link="https://solodit.cyfrin.io/issues/refund-calculation-uses-stale-share-mint-total-70012",
            pdf_link="https://example.invalid/report.pdf",
            github_link="https://github.com/example/protocol",
            protocol_name="Example Protocol",
            firm_name="Example Audit Firm",
        )
        raw.pop("url", None)
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        self.assertIn("stale total", rec["attacker_action_sequence"])
        self.assertEqual(
            rec["record_source_url"],
            "https://solodit.cyfrin.io/issues/refund-calculation-uses-stale-share-mint-total-70012",
        )
        self.assertEqual(rec["record_extensions"]["upstream_pdf_link"], "https://example.invalid/report.pdf")
        self.assertEqual(rec["record_extensions"]["upstream_github_link"], "https://github.com/example/protocol")
        self.assertEqual(rec["record_extensions"]["upstream_protocol_name"], "Example Protocol")

    def test_missing_taxonomy_falls_back_from_title_and_narrative(self):
        """Case 2-bis-a: unknown REST taxonomy gets a conservative local fallback."""
        raw = _mk_finding(
            70014,
            title="Permit signature can be replayed across chains",
            description="A signed permit omits the chain id from the domain separator, allowing replay on another deployment.",
            category="Unknown Attack",
            attack_class="Unknown Attack",
            bug_class="Unknown Class",
        )
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        self.assertEqual(rec["attack_class"], "signature-replay")
        self.assertEqual(rec["bug_class"], "signature-validation")
        self.assertEqual(rec["record_extensions"]["taxonomy_source"], "fallback-title-narrative")
        self.assertEqual(rec["record_extensions"]["taxonomy_confidence"], "high")
        self.assertEqual(rec["record_extensions"]["taxonomy_rule"], "signature-replay")

    def test_upstream_taxonomy_is_not_overridden_by_fallback(self):
        """Case 2-bis-b: fallback classifier is used only when upstream taxonomy is missing or unknown."""
        raw = _mk_finding(
            70015,
            title="Reentrancy-like wording but upstream class is explicit",
            description="The report mentions callback risk, but Solodit supplied a category.",
            category="oracle-price-manipulation",
            attack_class="custom-upstream-class",
            bug_class="custom-bug",
        )
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        self.assertEqual(rec["attack_class"], "custom-upstream-class")
        self.assertEqual(rec["bug_class"], "custom-bug")
        self.assertEqual(rec["record_extensions"]["taxonomy_source"], "upstream-attack_class")
        self.assertEqual(rec["record_extensions"]["taxonomy_confidence"], "high")
        self.assertNotIn("taxonomy_rule", rec["record_extensions"])

    def test_fallback_taxonomy_uses_non_code_narrative(self):
        """Case 2-bis-c: code snippets do not dominate taxonomy fallback classification."""
        raw = _mk_finding(
            70016,
            title="Protocol uses stale price feed",
            description=(
                "```solidity\n"
                "function reenter() external {}\n"
                "```\n\n"
                "The oracle returns a stale price, causing incorrect collateral valuation."
            ),
            category="",
            attack_class="",
            bug_class="",
        )
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        self.assertEqual(rec["attack_class"], "stale-or-manipulated-oracle")
        self.assertEqual(rec["record_extensions"]["taxonomy_confidence"], "medium")
        self.assertEqual(rec["record_extensions"]["taxonomy_source"], "fallback-title-narrative")

    def test_callback_only_text_does_not_promote_to_reentrancy(self):
        """Case 2-bis-e: callback compatibility text is not enough for reentrancy."""
        raw = _mk_finding(
            70018,
            title="Callback is not invoked during safe mint",
            description="The receiver callback is skipped, causing contract recipients to miss validation.",
            category="",
            attack_class="",
            bug_class="",
        )
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        self.assertNotEqual(rec["attack_class"], "reentrancy")
        self.assertEqual(rec["record_extensions"]["taxonomy_source"], "unknown")

    def test_stale_oracle_without_manipulation_uses_stale_oracle_class(self):
        """Case 2-bis-f: stale oracle rows are not high-confidence manipulation."""
        raw = _mk_finding(
            70019,
            title="Oracle heartbeat is not enforced",
            description="The oracle accepts stale Chainlink rounds after the configured heartbeat expires.",
            category="",
            attack_class="",
            bug_class="",
        )
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        self.assertEqual(rec["attack_class"], "stale-or-manipulated-oracle")
        self.assertEqual(rec["record_extensions"]["taxonomy_confidence"], "medium")

    def test_permissionless_validation_text_does_not_promote_to_access_control(self):
        """Case 2-bis-g: permissionless validation wording is not auth bypass."""
        raw = _mk_finding(
            70020,
            title="Permissionless mint proceeds without slippage validation",
            description="A permissionless user can mint without validating the minimum shares.",
            category="",
            attack_class="",
            bug_class="",
        )
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        self.assertNotEqual(rec["attack_class"], "access-control-bypass")

    def test_free_form_upstream_category_is_not_high_confidence_attack_class(self):
        """Case 2-bis-h: unknown free-form categories do not poison attack_class."""
        raw = _mk_finding(
            70021,
            title="Widget settlement can drift",
            description="The settlement accounting can drift when a delayed batch is replayed.",
            category="Quality Assurance",
            attack_class="",
            bug_class="",
        )
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        self.assertNotEqual(rec["attack_class"], "Quality Assurance")
        self.assertNotEqual(rec["record_extensions"]["taxonomy_source"], "upstream-category")

    def test_language_inference_uses_obvious_non_solidity_clues(self):
        """Case 2-bis-d: unlabeled Rust/Solana/Move/Cairo rows do not collapse to Solidity."""
        cases = [
            (
                "Solana Anchor PDA authority bypass",
                "An Anchor program accepts a forged PDA seed during CPI.",
                "rust",
            ),
            (
                "Sui Move coin module lets attacker mint rewards",
                "The vulnerable Move module omits object ownership validation.",
                "move",
            ),
            (
                "Starknet Cairo account validation can be bypassed",
                "The Cairo contract fails to check the caller before execution.",
                "cairo",
            ),
            (
                "Users cannot remove liquidity after pool pause",
                "The withdrawal path can leave funds stuck after accounting drift.",
                "solidity",
            ),
            (
                "Users cannot move funds after emergency pause",
                "The Solidity vault leaves accounting stale when users try to move funds.",
                "solidity",
            ),
        ]
        for idx, (title, description, language) in enumerate(cases, start=1):
            raw = _mk_finding(70100 + idx, title=title, description=description, language="", category="")
            raw.pop("languages", None)
            rec = SRD.build_v11_record(
                raw,
                fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
            )
            self.assertEqual(rec["target_language"], language)

    def test_build_record_bounds_and_normalizes_multiline_content(self):
        """Case 2-ter: block scalar content stays under schema cap after tab normalization."""
        raw = _mk_finding(
            70013,
            description=("\tline with tabs and trailing spaces   \n" * 300),
        )
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        self.assertLessEqual(len(rec["attacker_action_sequence"]), 4900)
        self.assertNotIn("\t", rec["attacker_action_sequence"])
        self.assertNotRegex(rec["attacker_action_sequence"], r"[ \t]+$")

    def test_synthetic_fixture_flag_set(self):
        """Case 3: synthetic_fixture=true flag lands in record_extensions when ingesting from a fixture."""
        raw = _mk_finding(70004)
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
            synthetic_fixture=True,
        )
        self.assertTrue(rec["record_extensions"].get("synthetic_fixture"))


class TestYAMLEmission(unittest.TestCase):
    def test_yaml_dump_roundtrip_keys(self):
        """Case 4: yaml_dump_record emits all top-level v1.1 fields."""
        raw = _mk_finding(70005)
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
        )
        yaml_text = SRD.yaml_dump_record(rec)
        for key in [
            "schema_version:",
            "verification_tier:",
            "record_source_url:",
            "record_extensions:",
            "target_domain:",
            "target_language:",
            "function_shape:",
            "bug_class:",
            "attack_class:",
            "impact_class:",
            "severity_at_finding:",
            "year:",
        ]:
            self.assertIn(key, yaml_text, msg=f"YAML missing key {key}")


class TestCursorDiscipline(unittest.TestCase):
    def test_cursor_not_mutated_on_zero_findings(self):
        """Case 5: cursor file is NEVER updated when 0 findings ingested."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cursor_file = tmp / "cursor.json"
            cursor_file.write_text(json.dumps({"last_id": 65673}), encoding="utf-8")
            out_dir = tmp / "out"
            fixture = tmp / "empty.json"
            fixture.write_text(json.dumps({"findings": [], "metadata": {"totalPages": 1}}), encoding="utf-8")

            argv = [
                "--dry-run",
                "--inject-json",
                str(fixture),
                "--cursor-file",
                str(cursor_file),
                "--out-dir",
                str(out_dir),
                "--json-only",
            ]
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = SRD.main(argv)
            self.assertEqual(rc, 0)
            # cursor unchanged
            self.assertEqual(SRD.load_cursor(cursor_file), 65673)

    def test_cursor_advances_only_past_existing_cursor_id(self):
        """Case 6: findings with id <= cursor_id are skipped; cursor never mutated on dry-run."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cursor_file = tmp / "cursor.json"
            cursor_file.write_text(json.dumps({"last_id": 65673}), encoding="utf-8")
            out_dir = tmp / "out"
            fixture = tmp / "mixed.json"
            findings = [
                _mk_finding(65000),   # below cursor - should be skipped
                _mk_finding(65673),   # equal to cursor - should be skipped
                _mk_finding(70010),   # above cursor - should be ingested
                _mk_finding(70011),   # above cursor - should be ingested
            ]
            fixture.write_text(json.dumps(_mk_response(findings)), encoding="utf-8")

            argv = [
                "--dry-run",
                "--inject-json",
                str(fixture),
                "--cursor-file",
                str(cursor_file),
                "--out-dir",
                str(out_dir),
            ]
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = SRD.main(argv)
            self.assertEqual(rc, 0)
            verdict = json.loads(buf.getvalue())
            self.assertEqual(verdict["written"], 2)
            self.assertEqual(verdict["skipped"], 2)
            self.assertEqual(verdict["highest_id_seen"], 70011)
            # Dry-run NEVER mutates cursor
            self.assertEqual(SRD.load_cursor(cursor_file), 65673)
            # YAML files emitted
            emitted = sorted(p.name for p in out_dir.glob("solodit-finding-*.yaml"))
            self.assertEqual(emitted, ["solodit-finding-70010.yaml", "solodit-finding-70011.yaml"])

    def test_dry_run_language_filter_drops_unlabeled_and_nonmatching(self):
        """Case 6-bis: --language keeps only matching rows and drops unlabeled rows under filter."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cursor_file = tmp / "cursor.json"
            cursor_file.write_text(json.dumps({"last_id": 0}), encoding="utf-8")
            out_dir = tmp / "out"
            fixture = tmp / "languages.json"
            fixture.write_text(
                json.dumps(
                    _mk_response(
                        [
                            _mk_finding(71001, language="Solidity"),
                            _mk_finding(71002, language="Rust", title="Rust bridge replay"),
                            _mk_finding(71003, language="", title="Unlabeled finding"),
                            _mk_finding(71004, language="", languages=[{"value": "Go"}], title="Go bridge replay"),
                        ]
                    )
                ),
                encoding="utf-8",
            )

            argv = [
                "--dry-run",
                "--inject-json",
                str(fixture),
                "--cursor-file",
                str(cursor_file),
                "--out-dir",
                str(out_dir),
                "--language",
                "rust",
            ]
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = SRD.main(argv)
            self.assertEqual(rc, 0)
            verdict = json.loads(buf.getvalue())
            self.assertEqual(verdict["written"], 1)
            self.assertEqual(verdict["skipped_language"], 3)
            self.assertEqual(verdict["language_filter"], ["rust"])
            emitted = sorted(p.name for p in out_dir.glob("solodit-finding-*.yaml"))
            self.assertEqual(emitted, ["solodit-finding-71002-rust.yaml"])

    def test_dry_run_language_filter_accepts_list_shaped_go_language(self):
        """Case 6-ter: upstream list-shaped language metadata still matches --language go."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            out_dir = tmp / "out"
            fixture = tmp / "go-language.json"
            fixture.write_text(
                json.dumps(_mk_response([_mk_finding(71101, language="", languages=[{"value": "Go"}], title="Go IBC replay")])),
                encoding="utf-8",
            )

            argv = [
                "--dry-run",
                "--inject-json",
                str(fixture),
                "--cursor-id",
                "0",
                "--out-dir",
                str(out_dir),
                "--language",
                "go",
            ]
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = SRD.main(argv)
            self.assertEqual(rc, 0)
            verdict = json.loads(buf.getvalue())
            self.assertEqual(verdict["written"], 1)
            self.assertEqual(verdict["skipped_language"], 0)
            emitted = sorted(p.name for p in out_dir.glob("solodit-finding-*.yaml"))
            self.assertEqual(emitted, ["solodit-finding-71101-go.yaml"])

    def test_dry_run_language_filter_accepts_sway_language(self):
        """Case 6-quater: Sway is a first-class language filter for Fuel findings."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            out_dir = tmp / "out"
            fixture = tmp / "sway-language.json"
            fixture.write_text(
                json.dumps(_mk_response([_mk_finding(71102, language="Sway", title="Fuel Sway bridge auth bypass")])),
                encoding="utf-8",
            )

            argv = [
                "--dry-run",
                "--inject-json",
                str(fixture),
                "--cursor-id",
                "0",
                "--out-dir",
                str(out_dir),
                "--language",
                "sway",
            ]
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = SRD.main(argv)
            self.assertEqual(rc, 0)
            verdict = json.loads(buf.getvalue())
            self.assertEqual(verdict["written"], 1)
            self.assertEqual(verdict["language_filter"], ["sway"])
            emitted = sorted(p.name for p in out_dir.glob("solodit-finding-*.yaml"))
            self.assertEqual(emitted, ["solodit-finding-71102-sway.yaml"])

    def test_plan_language_backlog_emits_requested_additional_slices_without_fixture(self):
        """Case 6-quinquies: additional Solodit language slices are planning-only offline rows."""
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = SRD.main(["--plan-language-backlog"])
        self.assertEqual(rc, 0)
        plan = json.loads(buf.getvalue())
        self.assertTrue(plan["planning_only"])
        self.assertFalse(plan["network_performed"])
        self.assertEqual(
            plan["unsupported_api_filter_languages"],
            [
                "huff",
                "leo",
                "cairo-zk",
            ],
        )
        self.assertEqual(plan["safe_api_filter_languages"], ["assembly"])
        self.assertEqual(
            plan["blocker_resolution"]["blocker_id"],
            "BLK-V3-SOURCE-SOLODIT-LANGUAGE-ENUM-PROOF",
        )
        self.assertFalse(plan["blocker_resolution"]["requested_scope_can_close"])
        self.assertEqual(
            plan["blocker_resolution"]["remaining_external_state_required"],
            ["huff", "leo", "cairo-zk"],
        )
        rows = {row["target_language"]: row for row in plan["rows"]}
        self.assertNotIn("noir", rows)
        self.assertEqual(rows["assembly"]["api_filter_value"], "Yul")
        self.assertTrue(
            all(row["api_filter_value"] is None for lang, row in rows.items() if lang != "assembly")
        )

    def test_plan_language_backlog_explains_zero_result_probe_boundary(self):
        """Case 6-quinquies-bis: residual enum blocker stays open without positive evidence."""
        plan = SRD.build_language_planning_manifest(["huff", "assembly", "leo", "cairo-zk"])
        resolution = plan["blocker_resolution"]

        self.assertEqual(resolution["safe_api_filter_languages"], ["assembly"])
        self.assertEqual(resolution["remaining_external_state_required"], ["huff", "leo", "cairo-zk"])
        self.assertIn("Zero-result language probes do not prove", resolution["boundary"])
        self.assertIn("positive live probe", resolution["remaining_evidence_requirement"])

        residual_probe = _load_json(
            REPO_ROOT
            / "reports"
            / "v3_source_mining"
            / "solodit"
            / "solodit_language_enum_residual_probe_2026-05-24.json"
        )
        candidate_rows = residual_probe["candidate_results"]
        for language in resolution["remaining_external_state_required"]:
            zero_result_rows = [
                row
                for row in candidate_rows
                if row.get("target_language") == language
                and row.get("http_status") == 200
                and row.get("finding_count") == 0
            ]
            self.assertTrue(zero_result_rows, msg=f"{language} residual probe evidence missing")

    def test_plan_language_backlog_can_write_manifest_file(self):
        """Case 6-sexies: planning manifest can be persisted without requiring --inject-json."""
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "solodit-language-plan.json"
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = SRD.main([
                    "--plan-language-backlog",
                    "--language",
                    "huff,rust",
                    "--planning-manifest-out",
                    str(manifest),
                ])
            self.assertEqual(rc, 0)
            stdout_plan = json.loads(buf.getvalue())
            file_plan = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(stdout_plan["planning_manifest_out"], str(manifest.resolve()))
            self.assertEqual(file_plan["safe_api_filter_languages"], ["rust"])
            self.assertEqual(file_plan["unsupported_api_filter_languages"], ["huff"])
            rows = {row["target_language"]: row for row in file_plan["rows"]}
            self.assertEqual(rows["rust"]["api_filter_value"], "Rust")
            self.assertIsNone(rows["huff"]["api_filter_value"])
            self.assertNotIn("huff", stdout_plan["safe_api_filter_languages"])


class TestAuthHonestVerdict(unittest.TestCase):
    def test_missing_api_key_emits_negative_verdict_no_cursor_mutation(self):
        """Case 7: missing SOLODIT_API_KEY yields NEGATIVE verdict, no network call, no cursor mutation."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cursor_file = tmp / "cursor.json"
            cursor_file.write_text(json.dumps({"last_id": 65673}), encoding="utf-8")
            out_dir = tmp / "out"

            argv = [
                "--cursor-file",
                str(cursor_file),
                "--out-dir",
                str(out_dir),
                "--max-pages",
                "1",
            ]
            env = dict(os.environ)
            env.pop("SOLODIT_API_KEY", None)
            buf = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), mock.patch("sys.stdout", buf):
                rc = SRD.main(argv)
            self.assertEqual(rc, 0)
            verdict = json.loads(buf.getvalue())
            self.assertEqual(verdict["verdict"], "NEGATIVE")
            self.assertIn("SOLODIT_API_KEY", verdict["reason"])
            self.assertEqual(SRD.load_cursor(cursor_file), 65673)


class TestRESTClientMock(unittest.TestCase):
    def test_rest_client_post_body_shape_and_header(self):
        """Case 8: SoloditRESTClient sends X-Cyfrin-API-Key + JSON body to /findings."""
        client = SRD.SoloditRESTClient(api_key="sk_test_abc", timeout_seconds=5, sleep_fn=lambda _x: None)
        captured = {}

        class FakeResp:
            status = 200

            def __init__(self, payload):
                self._payload = json.dumps(payload).encode("utf-8")
                self.headers = {
                    "x-ratelimit-remaining": "19",
                    "x-ratelimit-reset": "9999999",
                }

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return self._payload

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["headers"] = {k.lower(): v for k, v in req.header_items()}
            captured["body"] = json.loads(req.data.decode("utf-8"))
            captured["method"] = req.get_method()
            return FakeResp(_mk_response([_mk_finding(80001)]))

        client._urlopen = fake_urlopen
        data = client.fetch_page(page=1, page_size=50, severity="HIGH", keyword="reentrancy", keyword_field="keyword")
        self.assertEqual(captured["url"], SRD.API_ENDPOINT_FINDINGS)
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["headers"]["x-cyfrin-api-key"], "sk_test_abc")
        self.assertEqual(captured["body"]["page"], 1)
        self.assertEqual(captured["body"]["pageSize"], 50)
        self.assertEqual(captured["body"]["filters"]["impact"], ["HIGH"])
        self.assertEqual(captured["body"]["filters"]["keyword"], "reentrancy")
        self.assertEqual(captured["body"]["filters"]["sortField"], "Quality")
        self.assertEqual(captured["body"]["filters"]["sortDirection"], "Desc")
        self.assertEqual(client.remaining, 19)
        self.assertEqual(len(data["findings"]), 1)

    def test_rest_client_can_sort_by_recency_for_cursor_refresh(self):
        """Freshness runs can request newest rows first instead of quality-ranked rows."""
        client = SRD.SoloditRESTClient(api_key="sk_test_recency", timeout_seconds=5, sleep_fn=lambda _x: None)
        captured = {}

        class FakeResp:
            status = 200

            def __init__(self, payload):
                self._payload = json.dumps(payload).encode("utf-8")
                self.headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return self._payload

        def fake_urlopen(req, timeout=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return FakeResp(_mk_response([]))

        client._urlopen = fake_urlopen
        client.fetch_page(
            page=1,
            page_size=25,
            severity="HIGH",
            sort_field="Recency",
            sort_direction="Desc",
        )

        self.assertEqual(captured["body"]["filters"]["sortField"], "Recency")
        self.assertEqual(captured["body"]["filters"]["sortDirection"], "Desc")

    def test_critical_severity_maps_to_high_on_api(self):
        """Case 9-bis: CRITICAL is mapped to HIGH because upstream API enum is {HIGH, MEDIUM, LOW, GAS} (no CRITICAL)."""
        self.assertEqual(SRD._normalize_impact_for_api("CRITICAL"), "HIGH")
        self.assertEqual(SRD._normalize_impact_for_api("critical"), "HIGH")
        self.assertEqual(SRD._normalize_impact_for_api("HIGH"), "HIGH")
        self.assertEqual(SRD._normalize_impact_for_api("MEDIUM"), "MEDIUM")
        self.assertEqual(SRD._normalize_impact_for_api(""), "HIGH")
        # Verify actual fetch_page body uses normalized value
        client = SRD.SoloditRESTClient(api_key="sk_test", timeout_seconds=5, sleep_fn=lambda _x: None)
        captured = {}

        class FakeResp:
            status = 200

            def __init__(self, payload):
                self._payload = json.dumps(payload).encode("utf-8")
                self.headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return self._payload

        def fake_urlopen(req, timeout=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return FakeResp(_mk_response([]))

        client._urlopen = fake_urlopen
        client.fetch_page(page=1, page_size=10, severity="CRITICAL")
        self.assertEqual(captured["body"]["filters"]["impact"], ["HIGH"])

    def test_keyword_field_variants_supported(self):
        """Case 9: each KEYWORD_FIELD_VARIANT is wired through to the request body."""
        for field in SRD.KEYWORD_FIELD_VARIANTS:
            client = SRD.SoloditRESTClient(api_key="sk_test_xyz", timeout_seconds=5, sleep_fn=lambda _x: None)
            captured = {}

            class FakeResp:
                status = 200

                def __init__(self, payload):
                    self._payload = json.dumps(payload).encode("utf-8")
                    self.headers = {}

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def read(self):
                    return self._payload

            def fake_urlopen(req, timeout=None):
                captured["body"] = json.loads(req.data.decode("utf-8"))
                return FakeResp(_mk_response([]))

            client._urlopen = fake_urlopen
            client.fetch_page(page=1, page_size=10, severity="HIGH", keyword="oracle", keyword_field=field)
            self.assertIn(field, captured["body"]["filters"])
            self.assertEqual(captured["body"]["filters"][field], "oracle")

    def test_fetch_page_passes_language_filter_to_api_body(self):
        """Case 9-ter: language filters are sent upstream when provided."""
        client = SRD.SoloditRESTClient(api_key="sk_test_lang", timeout_seconds=5, sleep_fn=lambda _x: None)
        captured = {}

        class FakeResp:
            status = 200

            def __init__(self, payload):
                self._payload = json.dumps(payload).encode("utf-8")
                self.headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return self._payload

        def fake_urlopen(req, timeout=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return FakeResp(_mk_response([]))

        client._urlopen = fake_urlopen
        client.fetch_page(page=1, page_size=10, severity="HIGH", language_filter=["rust", "go", "sway"])
        self.assertEqual(
            captured["body"]["filters"]["languages"],
            [{"value": "Rust"}, {"value": "Go"}, {"value": "Sway"}],
        )
        client.fetch_page(page=1, page_size=10, severity="HIGH", language_filter=["typescript-onchain", "python-onchain"])
        self.assertEqual(
            captured["body"]["filters"]["languages"],
            [{"value": "TypeScript"}, {"value": "Python"}],
        )
        client.fetch_page(page=1, page_size=10, severity="HIGH", language_filter=["assembly"])
        self.assertEqual(captured["body"]["filters"]["languages"], [{"value": "Yul"}])

    def test_fetch_page_rejects_unverified_language_filter_values(self):
        """Case 9-ter-a: do not invent Solodit API language enum values for planning-only slices."""
        sleep = mock.Mock(side_effect=AssertionError("throttle sleep should not happen before validation"))
        client = SRD.SoloditRESTClient(api_key="sk_test_lang", timeout_seconds=5, sleep_fn=sleep)
        client.remaining = 1
        client.reset_at = int(SRD.time.time()) + 60
        client._urlopen = mock.Mock(side_effect=AssertionError("network should not be reached"))
        with self.assertRaisesRegex(ValueError, "huff"):
            client.fetch_page(page=1, page_size=10, severity="HIGH", language_filter=["huff"])
        with self.assertRaisesRegex(ValueError, "leo"):
            client.fetch_page(page=1, page_size=10, severity="HIGH", language_filter=["leo"])
        sleep.assert_not_called()
        client._urlopen.assert_not_called()

    def test_non_solidity_language_enum_values_have_checked_in_live_artifact_evidence(self):
        """Case 9-ter-a-bis: allowed non-Solidity API enums are backed by checked-in live proof artifacts."""
        summary_path = (
            REPO_ROOT
            / "reports"
            / "v3_source_mining"
            / "solodit"
            / "solodit_rest_live_summary_20260522T203711Z.json"
        )
        summary = _load_json(summary_path)
        rows_by_language = {}
        for row in summary["rows"]:
            language = row.get("language")
            if isinstance(language, list) and len(language) == 1:
                rows_by_language[language[0]] = row

        residual_probe_path = (
            REPO_ROOT
            / "reports"
            / "v3_source_mining"
            / "solodit"
            / "solodit_language_enum_residual_probe_2026-05-24.json"
        )
        residual_probe = _load_json(residual_probe_path)

        noir_probe_path = (
            REPO_ROOT
            / "reports"
            / "v3_source_mining"
            / "solodit"
            / "solodit_language_enum_noir_probe_2026-05-24.json"
        )
        noir_probe = _load_json(noir_probe_path)
        supported_probe_rows = {}
        supported_probe_rows_by_language: Dict[str, list[dict[str, Any]]] = {}
        for probe in (noir_probe, residual_probe):
            supported_probe_rows.update(probe["disposition"]["verified_api_language_values_to_add"])
            for candidate_row in probe.get("candidate_results", []):
                target = candidate_row.get("target_language")
                if not target:
                    continue
                supported_probe_rows_by_language.setdefault(target, []).append(candidate_row)

        for language in sorted(SRD.API_VERIFIED_LANGUAGE_VALUES.keys()):
            if language == "solidity":
                continue
            if language in rows_by_language:
                row = rows_by_language[language]
                self.assertGreaterEqual(row.get("pages_fetched", 0), 1)
                self.assertEqual(row.get("errors"), [])
                self.assertIn(
                    row.get("verdict"),
                    {"POSITIVE", "NEGATIVE-EMPTY"},
                    msg=f"{language} live artifact did not show accepted API enum usage",
                )
                continue

            if language not in supported_probe_rows:
                self.fail(f"Missing checked-in enum evidence for {language}")

            artifact_rows = supported_probe_rows_by_language.get(language, [])
            self.assertTrue(
                any(
                    row.get("http_status") == 200
                    and row.get("total_results", 0) > 0
                    and row.get("finding_count", 0) > 0
                    for row in artifact_rows
                ),
                msg=f"{language} has no positive probe evidence in checked-in artifacts",
            )
            self.assertEqual(supported_probe_rows[language], SRD.API_VERIFIED_LANGUAGE_VALUES[language])

    def test_live_path_rejects_unverified_language_before_api_key_and_network(self):
        """Case 9-ter-b: unsupported language live runs fail closed before auth or network use."""
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"
            env = dict(os.environ)
            env["SOLODIT_API_KEY"] = "sk_test_live"
            buf = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch("urllib.request.urlopen", side_effect=AssertionError("network should not be reached")), \
                 mock.patch("sys.stdout", buf):
                rc = SRD.main(["--out-dir", str(out_dir), "--language", "huff", "--max-pages", "1"])
            self.assertEqual(rc, 0)
            verdict = json.loads(buf.getvalue())
            self.assertEqual(verdict["verdict"], "NEGATIVE")
            self.assertFalse(verdict["network_performed"])
            self.assertEqual(verdict["language_filter"], ["huff"])
            self.assertIn("huff", verdict["reason"])

    def test_yul_api_rows_infer_corpus_assembly_language(self):
        """Case 9-ter-c: Solodit's Yul enum maps back to corpus target_language=assembly."""
        raw = _mk_finding(
            81250,
            title="Inline assembly memory clobber",
            description="The vulnerable path is implemented in Yul and corrupts calldata.",
            language="Yul",
        )
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 10, "keyword": None, "keyword_field_used": None, "language_filter": ["assembly"]},
        )
        self.assertEqual(rec["target_language"], "assembly")
        self.assertEqual(rec["record_extensions"]["fetch_language_filter"], ["assembly"])

    def test_live_ingest_trusts_single_language_filter_when_api_omits_language_field(self):
        """Case 9-ter-bis: live API language filter is authoritative when rows omit language metadata."""
        class FakeClient:
            def fetch_page(self, **kwargs):
                self.kwargs = kwargs
                raw = _mk_finding(81234, title="Refund Calculation Uses Stale Share-Mint Total")
                raw.pop("language", None)
                return _mk_response([raw], total_pages=1)

        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"
            result = SRD.ingest_pages(
                FakeClient(),
                cursor_id=0,
                page_size=1,
                severity="HIGH",
                out_dir=out_dir,
                max_pages=1,
                keyword=None,
                keyword_field=None,
                language_filter=["rust"],
                json_only=False,
            )

            self.assertEqual(result["verdict"], "POSITIVE")
            self.assertEqual(result["written"], 1)
            self.assertEqual(result["skipped_language"], 0)
            emitted = (out_dir / "solodit-finding-81234-rust.yaml").read_text(encoding="utf-8")
            self.assertIn("target_language: rust", emitted)
            self.assertIn("record_id: \"solodit:81234:rust:refund-calculation-uses-stale-share-mint-total\"", emitted)
            self.assertIn("fetch_language_filter:", emitted)

    def test_language_backfill_record_ids_are_language_scoped(self):
        """Case 9-ter-ter: same upstream finding id can be safely emitted for different language slices."""
        raw = _mk_finding(81235, title="Shared bridge verifier bug")
        raw.pop("language", None)
        rust = SRD.build_v11_record(
            {"id": raw["id"], "title": raw["title"], "language": "rust"},
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None, "language_filter": ["rust"]},
        )
        move = SRD.build_v11_record(
            {"id": raw["id"], "title": raw["title"], "language": "move"},
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None, "language_filter": ["move"]},
        )

        self.assertNotEqual(rust["record_id"], move["record_id"])
        self.assertEqual(rust["source_audit_ref"], move["source_audit_ref"])
        self.assertEqual(rust["record_extensions"]["fetch_language_filter"], ["rust"])
        self.assertEqual(move["record_extensions"]["fetch_language_filter"], ["move"])

    def test_language_backfill_emitted_filenames_are_language_scoped(self):
        """Case 9-ter-quater: same upstream id from multiple language slices must not overwrite on disk."""
        class FakeClient:
            def fetch_page(self, **kwargs):
                raw = _mk_finding(81236, title="Shared bridge verifier bug")
                raw.pop("language", None)
                return _mk_response([raw], total_pages=1)

        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "out"
            for language in ("rust", "move"):
                result = SRD.ingest_pages(
                    FakeClient(),
                    cursor_id=0,
                    page_size=1,
                    severity="HIGH",
                    out_dir=out_dir,
                    max_pages=1,
                    keyword=None,
                    keyword_field=None,
                    language_filter=[language],
                    json_only=False,
                )
                self.assertEqual(result["written"], 1)

            files = sorted(path.name for path in out_dir.glob("solodit-finding-81236*.yaml"))
            self.assertEqual(files, ["solodit-finding-81236-move.yaml", "solodit-finding-81236-rust.yaml"])
            self.assertIn("target_language: rust", (out_dir / "solodit-finding-81236-rust.yaml").read_text())
            self.assertIn("target_language: move", (out_dir / "solodit-finding-81236-move.yaml").read_text())

    # r36-rebuttal: solodit-rate-limit-tighten-2026-05-26 lane registered; pathspec includes this test file
    def test_default_min_request_interval_uses_rate_limit_floor(self):
        """Case 9-quinquies: default constructor adopts RATE_LIMIT_MIN_INTERVAL_SECONDS.

        Operator-confirmed 2026-05-26: Solodit upstream rate limit is 20/min
        on a 60s window. The default constructor MUST proactively throttle
        to that ceiling so library callers (delta-runner, MCP probes,
        downstream miners) inherit safe behavior without coordinating
        ``min_request_interval_seconds=3.1`` at every call site.
        """
        # Default (no min_request_interval_seconds arg)
        client_default = SRD.SoloditRESTClient(
            api_key="sk_test_default",
            timeout_seconds=5,
            sleep_fn=lambda _x: None,
        )
        self.assertEqual(SRD.RATE_LIMIT_REQ_PER_MIN, 20)
        self.assertEqual(SRD.RATE_LIMIT_WINDOW_SECONDS, 60.0)
        self.assertGreaterEqual(SRD.RATE_LIMIT_MIN_INTERVAL_SECONDS, 3.0)
        self.assertLess(SRD.RATE_LIMIT_MIN_INTERVAL_SECONDS, 4.0)
        self.assertEqual(client_default.min_request_interval_seconds, SRD.RATE_LIMIT_MIN_INTERVAL_SECONDS)

        # Explicit 0 disables the proactive floor (tests stubbing urlopen)
        client_off = SRD.SoloditRESTClient(
            api_key="sk_test_off",
            timeout_seconds=5,
            sleep_fn=lambda _x: None,
            min_request_interval_seconds=0,
        )
        self.assertEqual(client_off.min_request_interval_seconds, 0.0)

        # Explicit positive value preserved verbatim
        client_explicit = SRD.SoloditRESTClient(
            api_key="sk_test_explicit",
            timeout_seconds=5,
            sleep_fn=lambda _x: None,
            min_request_interval_seconds=5.0,
        )
        self.assertEqual(client_explicit.min_request_interval_seconds, 5.0)

    def test_min_request_interval_sleeps_between_live_requests(self):
        """Case 9-quater: optional fixed interval keeps live pulls under external rate limits."""
        sleeps = []
        client = SRD.SoloditRESTClient(
            api_key="sk_test_rate",
            timeout_seconds=5,
            sleep_fn=sleeps.append,
            min_request_interval_seconds=3.2,
        )

        class FakeResp:
            status = 200
            headers = {"x-ratelimit-remaining": "20"}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps(_mk_response([])).encode("utf-8")

        client._urlopen = lambda req, timeout=None: FakeResp()
        with mock.patch.object(SRD.time, "time", side_effect=[100.0, 101.0, 104.2]):
            client.fetch_page(page=1, page_size=10, severity="HIGH")
            client.fetch_page(page=2, page_size=10, severity="HIGH")

        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], 2.2)


class TestLivePathCursorMutation(unittest.TestCase):
    def test_live_path_updates_cursor_when_real_findings_ingested(self):
        """Case 10: live ingest_pages updates cursor file when written > 0 AND highest_id > cursor_id."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cursor_file = tmp / "cursor.json"
            cursor_file.write_text(json.dumps({"last_id": 65673}), encoding="utf-8")
            out_dir = tmp / "out"

            # Stub urlopen to return one page then empty
            calls = {"count": 0}
            class FakeResp:
                status = 200
                def __init__(self, payload):
                    self._payload = json.dumps(payload).encode("utf-8")
                    self.headers = {"x-ratelimit-remaining": "19"}
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def read(self): return self._payload

            def fake_urlopen(req, timeout=None):
                calls["count"] += 1
                if calls["count"] == 1:
                    return FakeResp(_mk_response([_mk_finding(90001), _mk_finding(90002)], total_pages=1))
                return FakeResp(_mk_response([], total_pages=1))

            argv = [
                "--cursor-file", str(cursor_file),
                "--out-dir", str(out_dir),
                "--max-pages", "1",
                "--min-severity", "HIGH",
            ]
            env = dict(os.environ)
            env["SOLODIT_API_KEY"] = "sk_test_live"

            buf = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch("urllib.request.urlopen", fake_urlopen), \
                 mock.patch("sys.stdout", buf):
                rc = SRD.main(argv)
            self.assertEqual(rc, 0)
            verdict = json.loads(buf.getvalue())
            self.assertEqual(verdict["verdict"], "POSITIVE")
            self.assertEqual(verdict["written"], 2)
            self.assertTrue(verdict["cursor_updated"])
            self.assertEqual(SRD.load_cursor(cursor_file), 90002)

    def test_live_path_NEGATIVE_on_rest_error_leaves_cursor_intact(self):
        """Case 11: REST error path emits NEGATIVE verdict and does NOT touch cursor."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cursor_file = tmp / "cursor.json"
            cursor_file.write_text(json.dumps({"last_id": 65673}), encoding="utf-8")
            out_dir = tmp / "out"

            def fake_urlopen(req, timeout=None):
                import urllib.error
                raise urllib.error.URLError("simulated network down")

            argv = [
                "--cursor-file", str(cursor_file),
                "--out-dir", str(out_dir),
                "--max-pages", "1",
            ]
            env = dict(os.environ)
            env["SOLODIT_API_KEY"] = "sk_test_live"

            buf = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch("urllib.request.urlopen", fake_urlopen), \
                 mock.patch("sys.stdout", buf):
                rc = SRD.main(argv)
            self.assertEqual(rc, 0)
            verdict = json.loads(buf.getvalue())
            self.assertEqual(verdict["verdict"], "NEGATIVE")
            self.assertFalse(verdict.get("cursor_updated", False))
            self.assertEqual(SRD.load_cursor(cursor_file), 65673)


class TestSchemaConformance(unittest.TestCase):
    def test_record_passes_v11_schema_validation_via_internal_validator(self):
        """Case 12: emitted record validates against the v1.1 JSON schema using the repo's internal validator."""
        # Load the repo's verdict-tag-schema validator
        validator_path = REPO_ROOT / "tools" / "verdict-tag-schema.py"
        spec = importlib.util.spec_from_file_location("_vts_for_test", str(validator_path))
        vts = importlib.util.module_from_spec(spec)
        assert spec.loader
        spec.loader.exec_module(vts)

        schema_path = REPO_ROOT / "audit" / "corpus_tags" / "schemas" / "auditooor.hackerman_record.v1.1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        raw = _mk_finding(70099, severity="HIGH", cve_id="CVE-2024-12345", ghsa_id="GHSA-1234-5678-90ab")
        rec = SRD.build_v11_record(
            raw,
            fetch_meta={"page": 1, "page_size": 100, "keyword": None, "keyword_field_used": None},
            synthetic_fixture=True,
        )
        errors = list(vts.validate(rec, schema))
        self.assertEqual(errors, [], msg=f"v1.1 schema validation errors: {errors}")


if __name__ == "__main__":
    unittest.main()
