"""Tests for tools/hackerman-cve-ghsa-delta-watcher.py.

Wave-4 P0 W4.1 deliverable test suite. The tests use synthetic NVD +
GHSA fixtures so the test run never touches the live network. The
synthetic fixtures are deliberately small (1-3 advisories per source)
and include both in-scope and off-scope shapes so the scope-keyword
filter is exercised.

Discipline notes:
  - Every emitted record carries verification_tier=tier-1-officially-disclosed.
  - Synthetic-fixture records carry record_extensions.synthetic_fixture=true.
  - Records emitted in dry-run mode validate against v1.1 but write nothing.
  - Cursor file is rewritten only when dry-run is false.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-cve-ghsa-delta-watcher.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"
SCOPE_KEYWORDS_PATH = REPO_ROOT / "audit" / "corpus_scope_keywords.txt"


def _load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


WATCHER = _load_module(TOOL_PATH, "_delta_watcher_under_test")
VALIDATOR = _load_module(VALIDATOR_PATH, "_validator_for_delta_watcher")


# --- Synthetic fixtures (in-scope crypto/DeFi advisory shapes) ---


SYNTHETIC_NVD_RESPONSE: Dict[str, Any] = {
    "totalResults": 2,
    "resultsPerPage": 200,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-90001",
                "published": "2026-05-16T10:00:00.000",
                "lastModified": "2026-05-16T10:00:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "OpenZeppelin Solidity contracts library "
                            "before 5.0.2 contains a reentrancy in the "
                            "ERC4626 vault withdraw path that allows an "
                            "attacker to drain depositor funds."
                        ),
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.1,
                                "vectorString": (
                                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/"
                                    "C:H/I:H/A:N"
                                ),
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {"description": [{"value": "CWE-841"}]}
                ],
            }
        },
        {
            "cve": {
                "id": "CVE-2026-90002",
                "published": "2026-05-16T11:00:00.000",
                "lastModified": "2026-05-16T11:00:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "Unrelated photo-album CMS allows authenticated "
                            "users to upload arbitrary EXIF metadata."
                        ),
                    }
                ],
                "metrics": {},
                "weaknesses": [],
            }
        },
    ],
}


SYNTHETIC_GHSA_RESPONSE: List[Dict[str, Any]] = [
    {
        "ghsa_id": "GHSA-1aaa-2bbb-3ccc",
        "cve_id": "CVE-2026-90010",
        "summary": "Uniswap v3-core router does not validate slippage",
        "description": (
            "An attacker can sandwich Uniswap v3-core router swaps when "
            "minOut is unset, draining ETH from arbitrage searchers."
        ),
        "severity": "high",
        "published_at": "2026-05-16T08:00:00Z",
        "updated_at": "2026-05-16T08:00:00Z",
        "html_url": (
            "https://github.com/Uniswap/v3-core/security/advisories/"
            "GHSA-1aaa-2bbb-3ccc"
        ),
        "cvss": {
            "score": 7.4,
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        },
        "cwes": [{"cwe_id": "CWE-682", "name": "Incorrect Calculation"}],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": "@uniswap/v3-core"},
                "patched_versions": ">= 1.0.3",
            }
        ],
        "references": [],
    },
    {
        "ghsa_id": "GHSA-9zzz-8yyy-7xxx",
        "cve_id": "",
        "summary": "image-thumbnailer crashes on truncated PNGs",
        "description": (
            "A truncated PNG passed to image-thumbnailer triggers a panic "
            "in the unrelated photo CMS dependency."
        ),
        "severity": "low",
        "published_at": "2026-05-16T09:00:00Z",
        "updated_at": "2026-05-16T09:00:00Z",
        "html_url": (
            "https://github.com/example/image-thumbnailer/security/"
            "advisories/GHSA-9zzz-8yyy-7xxx"
        ),
        "cwes": [],
        "vulnerabilities": [
            {"package": {"ecosystem": "npm", "name": "image-thumbnailer"}}
        ],
        "references": [],
    },
]


def _nvd_fetcher_synthetic(url: str, params: Dict[str, str]) -> Dict[str, Any]:
    assert "nvd.nist.gov" in url
    # First page returns the full payload; subsequent pages return empty
    # to terminate the loop.
    if int(params.get("startIndex", "0")) == 0:
        return SYNTHETIC_NVD_RESPONSE
    return {"totalResults": 2, "resultsPerPage": 200, "vulnerabilities": []}


def _ghsa_fetcher_synthetic(url: str, params: Dict[str, str]) -> Any:
    assert "api.github.com" in url
    if int(params.get("page", "1")) == 1:
        return SYNTHETIC_GHSA_RESPONSE
    return []


def _empty_fetcher(url: str, params: Dict[str, str]) -> Any:
    if "nvd.nist.gov" in url:
        return {"totalResults": 0, "resultsPerPage": 200, "vulnerabilities": []}
    return []


class ScopeFilterTests(unittest.TestCase):
    def test_keyword_load(self) -> None:
        kws = WATCHER.load_scope_keywords(SCOPE_KEYWORDS_PATH)
        self.assertGreater(len(kws), 30)
        # Sanity-check some canonical crypto tokens.
        for tok in ("solidity", "uniswap", "ibc", "bridge", "vault"):
            self.assertIn(tok, kws)

    def test_advisory_in_scope_matches_crypto(self) -> None:
        keywords = WATCHER.load_scope_keywords(SCOPE_KEYWORDS_PATH)
        advisory = WATCHER.nvd_parse_record(
            SYNTHETIC_NVD_RESPONSE["vulnerabilities"][0]
        )
        in_scope, matched = WATCHER.advisory_in_scope(advisory, keywords)
        self.assertTrue(in_scope)
        self.assertTrue(
            any(kw in matched for kw in ("solidity", "openzeppelin", "vault"))
        )

    def test_advisory_off_scope_excluded(self) -> None:
        keywords = WATCHER.load_scope_keywords(SCOPE_KEYWORDS_PATH)
        advisory = WATCHER.nvd_parse_record(
            SYNTHETIC_NVD_RESPONSE["vulnerabilities"][1]
        )
        in_scope, matched = WATCHER.advisory_in_scope(advisory, keywords)
        self.assertFalse(in_scope)
        self.assertEqual(matched, [])


class NvdParserTests(unittest.TestCase):
    def test_nvd_parser_extracts_cve_id_and_summary(self) -> None:
        item = SYNTHETIC_NVD_RESPONSE["vulnerabilities"][0]
        parsed = WATCHER.nvd_parse_record(item)
        self.assertEqual(parsed["cve_id"], "CVE-2026-90001")
        self.assertEqual(parsed["source_kind"], "nvd")
        self.assertIn("openzeppelin", parsed["description"].lower())
        self.assertEqual(parsed["cvss_base_score"], 9.1)
        self.assertEqual(parsed["html_url"],
                         "https://nvd.nist.gov/vuln/detail/CVE-2026-90001")


class GhsaParserTests(unittest.TestCase):
    def test_ghsa_parser_extracts_ghsa_id_and_cve(self) -> None:
        parsed = WATCHER.ghsa_parse_record(SYNTHETIC_GHSA_RESPONSE[0])
        self.assertEqual(parsed["ghsa_id"], "GHSA-1aaa-2bbb-3ccc")
        self.assertEqual(parsed["cve_id"], "CVE-2026-90010")
        self.assertEqual(parsed["source_kind"], "ghsa")
        self.assertTrue(parsed["html_url"].startswith("https://github.com"))


class RecordEmissionTests(unittest.TestCase):
    def test_tier_1_officially_disclosed_marker(self) -> None:
        advisory = WATCHER.nvd_parse_record(
            SYNTHETIC_NVD_RESPONSE["vulnerabilities"][0]
        )
        record = WATCHER.advisory_to_record(
            advisory, matched_keywords=["solidity"], synthetic_fixture=True
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["verification_tier"], "tier-1-officially-disclosed")
        self.assertEqual(record["record_tier"], "tier-1-officially-disclosed")
        self.assertEqual(record["cve_id"], "CVE-2026-90001")
        self.assertEqual(record["schema_version"], WATCHER.SCHEMA_VERSION)
        self.assertTrue(record["record_extensions"]["synthetic_fixture"])

    def test_record_validates_against_v1_1_schema(self) -> None:
        advisory = WATCHER.ghsa_parse_record(SYNTHETIC_GHSA_RESPONSE[0])
        record = WATCHER.advisory_to_record(
            advisory, matched_keywords=["uniswap"], synthetic_fixture=True
        )
        errs = VALIDATOR.validate_doc(record)
        self.assertEqual(errs, [],
                         f"v1.1 schema validation must pass: {errs}")

    def test_fabricated_cve_ids_are_refused(self) -> None:
        # Defense-in-depth: even if a feed surfaces one of the six fabricated
        # IDs the Wave-3b miner invented, the watcher must refuse to emit.
        advisory = {
            "cve_id": "CVE-2022-37937",
            "source_kind": "nvd",
            "summary": "fake crypto-shaped advisory",
            "description": "uniswap solidity",
            "html_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-37937",
        }
        record = WATCHER.advisory_to_record(advisory, matched_keywords=["fake"])
        self.assertIsNone(record)


class CursorPersistenceTests(unittest.TestCase):
    def test_cursor_written_on_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_dir = tmp_path / "out"
            cursor = tmp_path / "cursor.json"
            keywords = WATCHER.load_scope_keywords(SCOPE_KEYWORDS_PATH)
            envelope = WATCHER.run_watcher(
                source="both",
                since_iso="2026-05-15T00:00:00.000Z",
                until_iso="2026-05-16T00:00:00.000Z",
                scope_keywords=keywords,
                out_dir=out_dir,
                cursor_file=cursor,
                dry_run=False,
                nvd_fetcher=_nvd_fetcher_synthetic,
                ghsa_fetcher=_ghsa_fetcher_synthetic,
                synthetic_fixture=True,
                validate=True,
                validator=VALIDATOR,
            )
            self.assertTrue(cursor.exists())
            state = json.loads(cursor.read_text(encoding="utf-8"))
            self.assertIn("nvd", state)
            self.assertIn("ghsa", state)
            self.assertEqual(
                state["nvd"]["last_until_iso"],
                "2026-05-16T00:00:00.000Z",
            )
            # The 1 OZ advisory + 1 Uniswap GHSA = 2 in-scope records.
            self.assertGreaterEqual(envelope["records_emitted"], 2)

    def test_cursor_resume_picks_up_prior_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cursor = tmp_path / "cursor.json"
            initial = {
                "nvd": {
                    "last_until_iso": "2026-05-01T00:00:00.000Z",
                    "last_run_at": "2026-05-01T00:00:01.000Z",
                }
            }
            cursor.write_text(json.dumps(initial), encoding="utf-8")
            loaded = WATCHER.load_cursor(cursor)
            self.assertEqual(
                loaded["nvd"]["last_until_iso"], "2026-05-01T00:00:00.000Z"
            )


class DryRunTests(unittest.TestCase):
    def test_dry_run_produces_zero_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_dir = tmp_path / "out"
            cursor = tmp_path / "cursor.json"
            keywords = WATCHER.load_scope_keywords(SCOPE_KEYWORDS_PATH)
            envelope = WATCHER.run_watcher(
                source="both",
                since_iso="2026-05-15T00:00:00.000Z",
                until_iso="2026-05-16T00:00:00.000Z",
                scope_keywords=keywords,
                out_dir=out_dir,
                cursor_file=cursor,
                dry_run=True,
                nvd_fetcher=_nvd_fetcher_synthetic,
                ghsa_fetcher=_ghsa_fetcher_synthetic,
                synthetic_fixture=True,
                validate=True,
                validator=VALIDATOR,
            )
            self.assertTrue(envelope["dry_run"])
            self.assertGreaterEqual(envelope["records_emitted"], 2)
            self.assertFalse(
                out_dir.exists(),
                "dry-run must not create the output directory",
            )
            self.assertFalse(
                cursor.exists(),
                "dry-run must not write the cursor file",
            )

    def test_dry_run_still_returns_emitted_paths_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            keywords = WATCHER.load_scope_keywords(SCOPE_KEYWORDS_PATH)
            envelope = WATCHER.run_watcher(
                source="nvd",
                since_iso="2026-05-15T00:00:00.000Z",
                until_iso="2026-05-16T00:00:00.000Z",
                scope_keywords=keywords,
                out_dir=tmp_path / "out",
                cursor_file=None,
                dry_run=True,
                nvd_fetcher=_nvd_fetcher_synthetic,
                ghsa_fetcher=_empty_fetcher,
                synthetic_fixture=True,
                validate=False,
            )
            self.assertEqual(envelope["emitted_paths"], [])


class EmissionAndShapeTests(unittest.TestCase):
    def test_emitted_yaml_contains_tier_1_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_dir = tmp_path / "out"
            keywords = WATCHER.load_scope_keywords(SCOPE_KEYWORDS_PATH)
            envelope = WATCHER.run_watcher(
                source="both",
                since_iso="2026-05-15T00:00:00.000Z",
                until_iso="2026-05-16T00:00:00.000Z",
                scope_keywords=keywords,
                out_dir=out_dir,
                cursor_file=None,
                dry_run=False,
                nvd_fetcher=_nvd_fetcher_synthetic,
                ghsa_fetcher=_ghsa_fetcher_synthetic,
                synthetic_fixture=True,
                validate=True,
                validator=VALIDATOR,
            )
            self.assertGreaterEqual(envelope["records_emitted"], 2)
            for emitted_path in envelope["emitted_paths"]:
                text = Path(emitted_path).read_text(encoding="utf-8")
                self.assertIn(
                    "verification_tier: tier-1-officially-disclosed",
                    text,
                )
                self.assertIn(
                    "schema_version: auditooor.hackerman_record.v1.1",
                    text,
                )
                self.assertIn("synthetic_fixture: true", text)

    def test_envelope_schema_is_v1(self) -> None:
        keywords = WATCHER.load_scope_keywords(SCOPE_KEYWORDS_PATH)
        envelope = WATCHER.run_watcher(
            source="nvd",
            since_iso="2026-05-15T00:00:00.000Z",
            until_iso="2026-05-16T00:00:00.000Z",
            scope_keywords=keywords,
            out_dir=Path(tempfile.mkdtemp()),
            cursor_file=None,
            dry_run=True,
            nvd_fetcher=_nvd_fetcher_synthetic,
            ghsa_fetcher=_empty_fetcher,
            synthetic_fixture=True,
            validate=False,
        )
        self.assertEqual(
            envelope["envelope_schema"],
            "auditooor.hackerman_cve_ghsa_delta_watcher.v1",
        )
        self.assertIn("envelope_id", envelope)
        self.assertEqual(envelope["sources_polled"], ["nvd"])

    def test_rate_limit_flag_does_not_break_run(self) -> None:
        # Synthetic fetcher returns immediately, so respect_rate_limit
        # does not actually sleep (single-page response). The flag must
        # nevertheless not cause an exception.
        keywords = WATCHER.load_scope_keywords(SCOPE_KEYWORDS_PATH)
        envelope = WATCHER.run_watcher(
            source="nvd",
            since_iso="2026-05-15T00:00:00.000Z",
            until_iso="2026-05-16T00:00:00.000Z",
            scope_keywords=keywords,
            out_dir=Path(tempfile.mkdtemp()),
            cursor_file=None,
            dry_run=True,
            nvd_fetcher=_nvd_fetcher_synthetic,
            ghsa_fetcher=_empty_fetcher,
            respect_rate_limit=True,
            synthetic_fixture=True,
            validate=False,
        )
        self.assertGreaterEqual(envelope["records_emitted"], 1)


class CliRefuseToActTests(unittest.TestCase):
    def test_cli_refuses_without_allow_live(self) -> None:
        rc = WATCHER.main([
            "--source", "nvd",
            "--since-iso", "2026-05-15T00:00:00.000Z",
            "--until-iso", "2026-05-16T00:00:00.000Z",
            "--dry-run",
            "--no-cursor",
        ])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
