"""Hermetic tests for ``tools/hackerman-etl-from-go-vuln-db.py`` (Wave-5 L1).

The Go vulnerability database miner (``vuln.go.dev``) is exercised against
synthetic OSV-shaped fixtures injected as ``prefetched`` URL->bytes maps.
Zero live network.

Each fixture is marked ``synthetic_fixture`` in its prose so it cannot be
mistaken for a real vuln.go.dev record.

Coverage:
* honest-zero gate (BLOCKED-NO-REAL-SOURCE) when neither --fetch nor a
  cache / injected bytes are supplied;
* every emitted record carries a first-class non-empty ``verification_tier``
  (Rule 37);
* every emitted record carries a canonical ``record_source_url`` pointing
  at vuln.go.dev;
* the blockchain-module filter eats generic Go modules and keeps
  cosmos-sdk / go-ethereum modules;
* CVE / GHSA alias extraction;
* attack_class classification from the OSV summary keyword table.
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
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-go-vuln-db.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


MINER = _load(TOOL, "_hackerman_etl_from_go_vuln_db_under_test")


# ---------------------------------------------------------------------------
# Synthetic OSV fixtures (synthetic_fixture).
# Contrived vuln.go.dev-shaped JSON payloads with enough structure to
# exercise the index + per-ID + parser path. None are real advisories.
# ---------------------------------------------------------------------------

_INDEX = [
    {"id": "GO-2099-9001", "modified": "2099-01-01T00:00:00Z"},
    {"id": "GO-2099-9002", "modified": "2099-01-02T00:00:00Z"},
    {"id": "GO-2099-9003", "modified": "2099-01-03T00:00:00Z"},
]

# GO-2099-9001: cosmos-sdk DoS - should pass the blockchain filter.
_OSV_COSMOS = {
    "id": "GO-2099-9001",
    "summary": "synthetic_fixture: denial of service via infinite loop in cosmos-sdk",
    "details": "A crafted message triggers an infinite loop. synthetic_fixture only.",
    "aliases": ["CVE-2099-11111", "GHSA-aaaa-bbbb-cccc"],
    "published": "2099-01-01T00:00:00Z",
    "affected": [
        {
            "package": {"name": "github.com/cosmos/cosmos-sdk", "ecosystem": "Go"},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.50.1"}]}
            ],
        }
    ],
}

# GO-2099-9002: go-ethereum signature verification flaw -> theft/high.
_OSV_GETH = {
    "id": "GO-2099-9002",
    "summary": "synthetic_fixture: incorrect verification of cryptographic signature in go-ethereum",
    "details": "synthetic_fixture signature verification bug.",
    "aliases": ["CVE-2099-22222"],
    "published": "2099-01-02T00:00:00Z",
    "affected": [
        {
            "package": {"name": "github.com/ethereum/go-ethereum", "ecosystem": "Go"},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.14.0"}]}
            ],
        }
    ],
}

# GO-2099-9003: a generic non-blockchain Go module - should be filtered OUT.
_OSV_GENERIC = {
    "id": "GO-2099-9003",
    "summary": "synthetic_fixture: panic in net/http handler",
    "details": "synthetic_fixture generic stdlib bug.",
    "aliases": [],
    "published": "2099-01-03T00:00:00Z",
    "affected": [
        {
            "package": {"name": "stdlib", "ecosystem": "Go"},
        }
    ],
}


def _prefetched():
    base = MINER.GO_VULN_DB_BASE
    return {
        MINER.GO_VULN_DB_INDEX: json.dumps(_INDEX).encode("utf-8"),
        f"{base}/ID/GO-2099-9001.json": json.dumps(_OSV_COSMOS).encode("utf-8"),
        f"{base}/ID/GO-2099-9002.json": json.dumps(_OSV_GETH).encode("utf-8"),
        f"{base}/ID/GO-2099-9003.json": json.dumps(_OSV_GENERIC).encode("utf-8"),
    }


class GoVulnDbMinerTest(unittest.TestCase):
    def test_01_blocked_when_no_real_source(self) -> None:
        """Honest-zero gate: no --fetch, no cache, no injected bytes."""
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                summary = MINER.convert(
                    Path(tmp) / "out",
                    dry_run=True,
                    fetch_live=False,
                    cache_file=None,
                    prefetched=None,
                )
            self.assertTrue(summary["blocked"])
            self.assertEqual(summary["records_emitted"], 0)
            self.assertIn("BLOCKED-NO-REAL-SOURCE", stderr.getvalue())

    def test_02_records_emitted_from_injected_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = MINER.convert(
                Path(tmp) / "out",
                dry_run=False,
                fetch_live=False,
                prefetched=_prefetched(),
            )
            self.assertFalse(summary["blocked"])
            # 3 OSV entries, 1 generic stdlib filtered out -> 2 emitted.
            self.assertEqual(summary["records_emitted"], 2)
            self.assertEqual(summary["records_pre_filter"], 3)

    def test_03_every_record_has_first_class_verification_tier(self) -> None:
        """Rule 37: verification_tier is a first-class non-empty field."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            MINER.convert(out, dry_run=False, fetch_live=False, prefetched=_prefetched())
            jsons = sorted(out.glob("*/record.json"))
            self.assertEqual(len(jsons), 2)
            for jp in jsons:
                rec = json.loads(jp.read_text(encoding="utf-8"))
                self.assertIn("verification_tier", rec)
                self.assertEqual(
                    rec["verification_tier"], "tier-1-officially-disclosed"
                )
                self.assertNotIn(
                    "verification_tier", rec["function_shape"].get("shape_tags", []),
                    "Rule 37: tier must not be smuggled into shape_tags",
                )

    def test_04_record_source_url_points_at_vuln_go_dev(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            MINER.convert(out, dry_run=False, fetch_live=False, prefetched=_prefetched())
            for jp in sorted(out.glob("*/record.json")):
                rec = json.loads(jp.read_text(encoding="utf-8"))
                self.assertTrue(
                    rec["record_source_url"].startswith("https://vuln.go.dev/ID/GO-")
                )
                self.assertTrue(rec["record_source_url"].endswith(".json"))

    def test_05_blockchain_module_filter(self) -> None:
        records, pre = MINER.build_records(
            {"osv": {"GO-2099-9001": _OSV_COSMOS, "GO-2099-9003": _OSV_GENERIC}},
            "tier-1-officially-disclosed",
        )
        ids = {r["target_component"] for r in records}
        self.assertEqual(pre, 2)
        self.assertEqual(len(records), 1)
        self.assertTrue(any("cosmos-sdk" in c for c in ids))
        self.assertFalse(any("stdlib" in c for c in ids))

    def test_06_cve_ghsa_alias_extraction(self) -> None:
        rec = MINER.osv_to_record(
            module="github.com/cosmos/cosmos-sdk",
            go_id="GO-2099-9001",
            osv=_OSV_COSMOS,
            verification_tier="tier-1-officially-disclosed",
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec["cve_id"], "CVE-2099-11111")
        self.assertEqual(rec["ghsa_id"], "GHSA-aaaa-bbbb-cccc")

    def test_07_attack_class_classification(self) -> None:
        cosmos = MINER.osv_to_record(
            module="github.com/cosmos/cosmos-sdk",
            go_id="GO-2099-9001",
            osv=_OSV_COSMOS,
            verification_tier="tier-1-officially-disclosed",
        )
        geth = MINER.osv_to_record(
            module="github.com/ethereum/go-ethereum",
            go_id="GO-2099-9002",
            osv=_OSV_GETH,
            verification_tier="tier-1-officially-disclosed",
        )
        self.assertEqual(cosmos["attack_class"], "go-denial-of-service")
        self.assertEqual(cosmos["impact_class"], "dos")
        self.assertEqual(geth["attack_class"], "go-signature-verification-flaw")
        self.assertEqual(geth["impact_class"], "theft")

    def test_08_record_rejects_non_go_id(self) -> None:
        self.assertIsNone(
            MINER.osv_to_record(
                module="github.com/cosmos/cosmos-sdk",
                go_id="CVE-2099-99999",
                osv=_OSV_COSMOS,
                verification_tier="tier-1-officially-disclosed",
            )
        )

    def test_09_fixed_version_in_fix_pattern(self) -> None:
        rec = MINER.osv_to_record(
            module="github.com/cosmos/cosmos-sdk",
            go_id="GO-2099-9001",
            osv=_OSV_COSMOS,
            verification_tier="tier-1-officially-disclosed",
        )
        self.assertIn("0.50.1", rec["fix_pattern"])

    def test_10_cache_file_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache.json"
            payload = {
                "_meta": {"index_count": 1, "osv_fetched": 1},
                "index": [{"id": "GO-2099-9001"}],
                "osv": {"GO-2099-9001": _OSV_COSMOS},
            }
            cache.write_text(json.dumps(payload), encoding="utf-8")
            summary = MINER.convert(
                Path(tmp) / "out",
                dry_run=True,
                fetch_live=False,
                cache_file=cache,
            )
            self.assertFalse(summary["blocked"])
            self.assertEqual(summary["records_emitted"], 1)

    def test_11_cli_blocked_exit_zero(self) -> None:
        """BLOCKED is an honest verdict, not an error exit."""
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = MINER.main(["--out-dir", str(Path(tmp) / "out"), "--dry-run"])
            self.assertEqual(rc, 0)
            self.assertIn("BLOCKED-NO-REAL-SOURCE", stderr.getvalue())

    def test_12_record_core_fields(self) -> None:
        rec = MINER.osv_to_record(
            module="github.com/cosmos/cosmos-sdk",
            go_id="GO-2099-9001",
            osv=_OSV_COSMOS,
            verification_tier="tier-1-officially-disclosed",
        )
        self.assertEqual(rec["schema_version"], MINER.SCHEMA_VERSION)
        self.assertEqual(rec["target_language"], "go")
        self.assertEqual(rec["target_repo"], "vuln.go.dev")
        self.assertEqual(rec["target_domain"], "consensus")
        self.assertEqual(rec["bug_class"], "go-public-advisory")
        self.assertEqual(rec["year"], 2099)


if __name__ == "__main__":
    unittest.main()
