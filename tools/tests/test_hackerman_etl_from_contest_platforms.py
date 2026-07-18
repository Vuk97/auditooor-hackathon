"""Unit tests for ``tools/hackerman-etl-from-contest-platforms.py``.

These tests never call ``gh api``. They drive the miner through its
``cache_file`` path with synthetic per-finding payloads modeled on real
Code4rena (``code-423n4/<contest>-findings``) and Sherlock
(``sherlock-audit/<contest>-judging``) artifacts.

Assertions cover:

* Records validate against the v1 schema.
* Severity normalisation: Code4rena ``risk`` int -> high/medium/low;
  Sherlock dir suffix -> high/medium.
* ``source_audit_ref`` is ``<platform>:<contest>:<finding_id>``.
* ``required_preconditions`` carries the resolvable URL +
  ``verification_tier=...`` marker.
* Cantina is recorded in ``platforms_intentionally_skipped``.
* Sampling rule is honoured (skipped contests recorded, not dropped).
* Determinism across reruns.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-contest-platforms.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load_tool():
    name = "_hackerman_etl_from_contest_platforms"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    name = "_hackerman_record_validate_for_contest_platforms_test"
    spec = importlib.util.spec_from_file_location(name, str(VALIDATOR_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _c4_finding(
    *,
    issue_id: int = 159,
    risk: str = "3",
    title: str = (
        "Reentrancy in OwnershipNFT.safeTransferFrom allows attacker to "
        "drain depositor collateral"
    ),
    handle: str = "0xAleko",
    contest_repo: str = "2024-08-superposition-findings",
):
    return {
        "id": str(issue_id),
        "severity_raw": risk,
        "title": title,
        "url": (
            f"https://github.com/code-423n4/{contest_repo}/issues/"
            f"{issue_id}"
        ),
        "body": "",
        "handle": handle,
        "filename": f"{handle}-{issue_id}.json",
    }


def _sherlock_finding(
    *,
    issue_id: int = 17,
    severity: str = "H",
    title: str = "Missing access control allows arbitrary admin takeover",
    body: str = (
        "## Vulnerability Detail\n\nThe contract allows an unprivileged "
        "caller to take over governance. This is a privilege escalation."
    ),
    contest_repo: str = "2022-08-sentiment-judging",
):
    return {
        "id": str(issue_id),
        "severity_raw": severity,
        "title": title,
        "url": (
            f"https://github.com/sherlock-audit/{contest_repo}/blob/main/"
            f"{issue_id:03d}-{severity}/{issue_id:03d}-{severity.lower()}.md"
        ),
        "body": body,
        "handle": None,
        "filename": f"{issue_id:03d}-{severity}/{issue_id:03d}-{severity.lower()}.md",
    }


def _build_cache():
    return {
        "code4rena": {
            "org": "code-423n4",
            "pattern": r".+-findings$",
            "skipped_by_sampling": ["2018-01-vintage-findings"],
            "repos": {
                "2024-08-superposition-findings": {
                    "updated_at": "2024-09-01T00:00:00Z",
                    "html_url": (
                        "https://github.com/code-423n4/"
                        "2024-08-superposition-findings"
                    ),
                    "findings": [
                        _c4_finding(issue_id=159, risk="3"),
                        _c4_finding(
                            issue_id=86,
                            risk="2",
                            title="Rounding loss in fee accounting",
                            handle="0xhashiman",
                        ),
                        _c4_finding(
                            issue_id=58,
                            risk="1",
                            title="Missing event emission on admin update",
                            handle="13u9",
                        ),
                    ],
                },
                "2025-11-megapot-findings": {
                    "updated_at": "2025-12-01T00:00:00Z",
                    "html_url": (
                        "https://github.com/code-423n4/2025-11-megapot-findings"
                    ),
                    "findings": [],
                },
            },
        },
        "sherlock": {
            "org": "sherlock-audit",
            "pattern": r".+-judging$",
            "skipped_by_sampling": [],
            "repos": {
                "2022-08-sentiment-judging": {
                    "updated_at": "2022-09-01T00:00:00Z",
                    "html_url": (
                        "https://github.com/sherlock-audit/2022-08-sentiment-judging"
                    ),
                    "findings": [
                        _sherlock_finding(issue_id=17, severity="H"),
                        _sherlock_finding(
                            issue_id=23,
                            severity="H",
                            title="Reentrancy in deposit allows fund theft",
                            body=(
                                "## Impact\nReentrancy enables attacker to "
                                "drain user funds."
                            ),
                        ),
                        _sherlock_finding(
                            issue_id=44,
                            severity="M",
                            title="Stale Chainlink oracle data allows price manipulation",
                            body=(
                                "## Impact\nStale oracle data enables price "
                                "manipulation attacks."
                            ),
                        ),
                    ],
                },
            },
        },
    }


class HackermanEtlFromContestPlatformsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load_tool()
        cls.validator = _load_validator()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.out_dir = self.tmp_path / "out"
        self.cache_path = self.tmp_path / "cache.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_cache(self, payload) -> Path:
        self.cache_path.write_text(json.dumps(payload), encoding="utf-8")
        return self.cache_path

    def _run(self, payload, **kwargs):
        cache = self._write_cache(payload)
        return self.tool.convert(self.out_dir, cache_file=cache, **kwargs)

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_platforms_block_lists_code4rena_and_sherlock_only(self) -> None:
        ids = {p[0] for p in self.tool.PLATFORMS}
        self.assertEqual(ids, {"code4rena", "sherlock"})
        # Schema enum sanity: every (lang, domain) must be valid for the schema.
        for platform_id, org, pattern, lang, domain in self.tool.PLATFORMS:
            self.assertEqual(lang, "solidity")
            self.assertIn(
                domain,
                {
                    "lending", "dex", "bridge", "oracle", "governance",
                    "staking", "vault", "rollup", "zk-proof", "consensus",
                    "rpc-infra", "dao", "escrow", "nft", "gaming",
                    "l1-client",
                },
                msg=f"{platform_id} default domain not in schema enum",
            )

    def test_cantina_is_in_intentionally_skipped_list(self) -> None:
        skipped_ids = {p for p, _r in self.tool.PLATFORMS_INTENTIONALLY_SKIPPED}
        self.assertIn("cantina", skipped_ids)

    def test_cache_path_emits_tier2_cache_verification_tier(self) -> None:
        cache = self._write_cache(_build_cache())
        summary = self.tool.convert(self.out_dir, cache_file=cache, dry_run=True)
        self.assertEqual(
            summary["verification_tier"], "tier-2-verified-public-archive-cache"
        )

    def test_records_validate_against_schema(self) -> None:
        summary = self._run(_build_cache())
        self.assertEqual(summary["errors"], [])
        self.assertGreater(summary["records_emitted"], 0)
        schema = self.validator.load_schema()
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            yaml_path = sub / "record.yaml"
            self.assertTrue(yaml_path.exists())
            status, errs = self.validator.validate_file(yaml_path, schema)
            self.assertEqual(
                (status, errs), ("valid", []),
                msg=f"{yaml_path}: {errs}",
            )

    def test_c4_risk3_maps_to_high_with_correct_dollar_class(self) -> None:
        cache = {
            "code4rena": {
                "org": "code-423n4",
                "pattern": ".+-findings$",
                "skipped_by_sampling": [],
                "repos": {
                    "2024-08-superposition-findings": {
                        "updated_at": "2024-09-01T00:00:00Z",
                        "html_url": "u",
                        "findings": [_c4_finding(issue_id=159, risk="3")],
                    },
                },
            }
        }
        self._run(cache)
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["severity_at_finding"], "high")
        self.assertEqual(rec["impact_dollar_class"], "$100K-$1M")
        # "drain depositor collateral" -> theft.
        self.assertEqual(rec["impact_class"], "theft")
        self.assertEqual(rec["attack_class"], "contest-platform-finding-code4rena")
        self.assertEqual(rec["target_language"], "solidity")

    def test_c4_risk1_maps_to_low_and_risk2_to_medium(self) -> None:
        cache = {
            "code4rena": {
                "org": "code-423n4",
                "pattern": ".+-findings$",
                "skipped_by_sampling": [],
                "repos": {
                    "2024-08-superposition-findings": {
                        "updated_at": "2024-09-01T00:00:00Z",
                        "html_url": "u",
                        "findings": [
                            _c4_finding(
                                issue_id=80, risk="2",
                                title="Rounding precision loss in fee calc",
                            ),
                            _c4_finding(
                                issue_id=81, risk="1",
                                title="Missing event in admin update",
                            ),
                        ],
                    },
                },
            }
        }
        self._run(cache)
        sev_by_id = {}
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            sev_by_id[rec["source_audit_ref"]] = rec["severity_at_finding"]
        self.assertEqual(
            sev_by_id["code4rena:2024-08-superposition-findings:80"], "medium"
        )
        self.assertEqual(
            sev_by_id["code4rena:2024-08-superposition-findings:81"], "low"
        )

    def test_sherlock_H_maps_to_high_and_M_to_medium(self) -> None:
        cache = {
            "sherlock": {
                "org": "sherlock-audit",
                "pattern": ".+-judging$",
                "skipped_by_sampling": [],
                "repos": {
                    "2022-08-sentiment-judging": {
                        "updated_at": "2022-09-01T00:00:00Z",
                        "html_url": "u",
                        "findings": [
                            _sherlock_finding(issue_id=23, severity="H"),
                            _sherlock_finding(
                                issue_id=44, severity="M",
                                title="Stale oracle data allows manipulation",
                            ),
                        ],
                    },
                },
            }
        }
        self._run(cache)
        sev_by_id = {}
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            sev_by_id[rec["source_audit_ref"]] = rec["severity_at_finding"]
        self.assertEqual(
            sev_by_id["sherlock:2022-08-sentiment-judging:23"], "high"
        )
        self.assertEqual(
            sev_by_id["sherlock:2022-08-sentiment-judging:44"], "medium"
        )

    def test_source_audit_ref_carries_platform_contest_finding(self) -> None:
        self._run(_build_cache())
        seen = []
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            parts = rec["source_audit_ref"].split(":")
            self.assertGreaterEqual(len(parts), 3)
            self.assertIn(parts[0], {"code4rena", "sherlock"})
            seen.append(rec["source_audit_ref"])
        self.assertGreater(len(seen), 0)
        self.assertIn(
            "code4rena:2024-08-superposition-findings:159", seen
        )

    def test_required_preconditions_contain_tier_and_resolvable_url(self) -> None:
        self._run(_build_cache())
        found = 0
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            tier_lines = [
                p for p in rec["required_preconditions"]
                if p.startswith("verification_tier=")
            ]
            self.assertEqual(len(tier_lines), 1)
            self.assertIn(
                tier_lines[0],
                {
                    "verification_tier=tier-2-verified-public-archive",
                    "verification_tier=tier-2-verified-public-archive-cache",
                },
            )
            ref_lines = [
                p for p in rec["required_preconditions"]
                if p.startswith("Reference finding at https://")
            ]
            self.assertEqual(len(ref_lines), 1)
            found += 1
        self.assertGreater(found, 0)

    def test_keyword_routing_reentrancy_maps_to_theft(self) -> None:
        cache = {
            "sherlock": {
                "org": "sherlock-audit",
                "pattern": ".+-judging$",
                "skipped_by_sampling": [],
                "repos": {
                    "2022-08-sentiment-judging": {
                        "updated_at": "2022-09-01T00:00:00Z",
                        "html_url": "u",
                        "findings": [
                            _sherlock_finding(
                                issue_id=23, severity="H",
                                title="Reentrancy in deposit drains user funds",
                                body="Reentrancy enables drain of deposits.",
                            ),
                        ],
                    },
                },
            }
        }
        self._run(cache)
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        self.assertEqual(rec["impact_class"], "theft")
        self.assertEqual(rec["impact_actor"], "arbitrary-user")

    def test_keyword_routing_oracle_manipulation_maps_to_theft(self) -> None:
        cache = {
            "sherlock": {
                "org": "sherlock-audit",
                "pattern": ".+-judging$",
                "skipped_by_sampling": [],
                "repos": {
                    "2022-08-sentiment-judging": {
                        "updated_at": "2022-09-01T00:00:00Z",
                        "html_url": "u",
                        "findings": [
                            _sherlock_finding(
                                issue_id=44, severity="M",
                                title="Stale chainlink data permits oracle manipulation",
                                body="Stale data permits price manipulation",
                            ),
                        ],
                    },
                },
            }
        }
        self._run(cache)
        sub = next(p for p in self.out_dir.iterdir() if p.is_dir())
        rec = json.loads((sub / "record.json").read_text())
        # "price manipulation" / "oracle manipulation" -> theft.
        self.assertEqual(rec["impact_class"], "theft")
        # Sherlock contest slug "2022-08-sentiment-judging" -> default
        # lending domain (no oracle/dex/bridge keyword in the slug).
        self.assertEqual(rec["target_domain"], "lending")

    def test_contests_with_zero_findings_recorded(self) -> None:
        cache = _build_cache()
        summary = self._run(cache)
        zero = summary["contests_with_zero_findings"]
        self.assertIn("code4rena", zero)
        self.assertIn("2025-11-megapot-findings", zero["code4rena"])

    def test_skipped_contests_recorded_not_dropped(self) -> None:
        cache = _build_cache()
        summary = self._run(cache)
        skipped = summary["contests_skipped_by_sampling"]
        self.assertIn("code4rena", skipped)
        self.assertIn("2018-01-vintage-findings", skipped["code4rena"])

    def test_intentionally_skipped_platforms_in_summary(self) -> None:
        summary = self._run(_build_cache(), dry_run=True)
        skipped = summary["platforms_intentionally_skipped"]
        cantina = next(
            (s for s in skipped if s["platform"] == "cantina"), None
        )
        self.assertIsNotNone(cantina)
        self.assertIn("cantina.xyz", cantina["reason"])

    def test_filter_platform_restricts_output(self) -> None:
        cache = _build_cache()
        self._write_cache(cache)
        summary = self.tool.convert(
            self.out_dir,
            cache_file=self.cache_path,
            filter_platform="sherlock",
            dry_run=True,
        )
        # The filter affects the selected list AND build_records subset.
        self.assertEqual(list(summary["by_platform"].keys()), ["sherlock"])

    def test_year_inferred_from_contest_slug(self) -> None:
        self._run(_build_cache())
        years = set()
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            years.add(rec["year"])
        # Slugs include 2024-08-..., 2022-08-..., 2025-11-... .
        self.assertIn(2024, years)
        self.assertIn(2022, years)

    def test_record_id_matches_schema_pattern(self) -> None:
        import re as _re
        self._run(_build_cache())
        pattern = _re.compile(r"^[A-Za-z0-9._:/-]{8,160}$")
        seen = 0
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            rec = json.loads((sub / "record.json").read_text())
            self.assertRegex(rec["record_id"], pattern)
            self.assertTrue(
                rec["record_id"].startswith(("code4rena:", "sherlock:")),
                msg=f"unexpected prefix: {rec['record_id']}",
            )
            seen += 1
        self.assertGreater(seen, 0)

    def test_slug_uses_double_underscore_separator(self) -> None:
        self._run(_build_cache())
        slugs = [p.name for p in self.out_dir.iterdir() if p.is_dir()]
        self.assertTrue(
            any(s.startswith("code4rena__") for s in slugs),
            msg=f"slugs: {slugs}",
        )
        self.assertTrue(
            any(s.startswith("sherlock__") for s in slugs),
            msg=f"slugs: {slugs}",
        )
        # double-underscore separator.
        for s in slugs:
            self.assertIn("__", s)

    def test_output_is_deterministic(self) -> None:
        cache = _build_cache()
        summary1 = self._run(cache)
        first = sorted(
            (p.name, (p / "record.yaml").read_text())
            for p in self.out_dir.iterdir() if p.is_dir()
        )
        for sub in list(self.out_dir.iterdir()):
            if sub.is_dir():
                for f in sub.iterdir():
                    f.unlink()
                sub.rmdir()
        summary2 = self._run(cache)
        second = sorted(
            (p.name, (p / "record.yaml").read_text())
            for p in self.out_dir.iterdir() if p.is_dir()
        )
        self.assertEqual(summary1["records_emitted"], summary2["records_emitted"])
        self.assertEqual(first, second)

    def test_cli_json_summary(self) -> None:
        cache = self._write_cache(_build_cache())
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = self.tool.main(
                [
                    "--out-dir", str(self.out_dir),
                    "--cache-file", str(cache),
                    "--dry-run",
                    "--json-summary",
                ]
            )
        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], self.tool.SUMMARY_SCHEMA)
        self.assertEqual(
            payload["verification_tier"],
            "tier-2-verified-public-archive-cache",
        )
        self.assertGreater(payload["records_emitted"], 0)
        self.assertEqual(payload["errors"], [])

    def test_dedupe_collapses_same_finding_id(self) -> None:
        adv = _c4_finding(issue_id=159, risk="3")
        cache = {
            "code4rena": {
                "org": "code-423n4",
                "pattern": ".+-findings$",
                "skipped_by_sampling": [],
                "repos": {
                    "2024-08-superposition-findings": {
                        "updated_at": "2024-09-01T00:00:00Z",
                        "html_url": "u",
                        "findings": [adv, adv],
                    },
                },
            }
        }
        summary = self._run(cache)
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(summary["errors"], [])

    def test_empty_cache_emits_zero_records_no_errors(self) -> None:
        summary = self._run({})
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["errors"], [])


if __name__ == "__main__":
    unittest.main()
