"""Tests for tools/defimon-tg-tx-enrichment.py (Lane P2.1, Task #172)."""

# r36-rebuttal: registered to lane lane-P2.1-DEFIMON-TG-TX-IMPL in .auditooor/agent_pathspec.json

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "defimon-tg-tx-enrichment.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "defimon_tg_tx_enrichment", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["defimon_tg_tx_enrichment"] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_record(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")


class ExtractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load_tool()

    def test_evm_tx_hash_extraction(self) -> None:
        text = (
            "Exploit confirmed in tx 0xae0670e64db402a878faf09f6c5b1d9b08f0fef85788c2a51812c14a35f49ad9 "
            "on https://etherscan.io/tx/0xae0670e64db402a878faf09f6c5b1d9b08f0fef85788c2a51812c14a35f49ad9"
        )
        hashes = self.tool.extract_tx_hashes(text)
        self.assertEqual(len(hashes), 1)
        self.assertEqual(
            hashes[0]["hash"],
            "0xae0670e64db402a878faf09f6c5b1d9b08f0fef85788c2a51812c14a35f49ad9",
        )
        self.assertEqual(hashes[0]["chain_hint"], "evm")
        self.assertIn("0xae067", hashes[0]["evidence_text"])

    def test_tron_tx_url_extraction(self) -> None:
        # Tron tx hashes only resolve via URL context (no 0x prefix).
        h = "a" * 64
        text = f"Exploit at https://tronscan.org/#/transaction/{h}"
        hashes = self.tool.extract_tx_hashes(text)
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0]["hash"], h)
        self.assertEqual(hashes[0]["chain_hint"], "tron")

    def test_evm_and_tron_mixed(self) -> None:
        evm = "0x" + "b" * 64
        tron = "c" * 64
        text = (
            f"EVM tx: {evm} and Tron https://tronscan.org/#/transaction/{tron}"
        )
        hashes = self.tool.extract_tx_hashes(text)
        self.assertEqual({h["chain_hint"] for h in hashes}, {"evm", "tron"})
        self.assertEqual(len(hashes), 2)

    def test_evm_address_with_role(self) -> None:
        text = (
            "🤕 Victim: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 "
            "🎩 Attacker: 0x839212B54d11c198beB378f7534D4225e54FA045"
        )
        addrs = self.tool.extract_contract_addresses(text)
        self.assertEqual(len(addrs), 2)
        roles = {a["address"]: a["role"] for a in addrs}
        self.assertEqual(roles["0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"], "victim")
        self.assertEqual(roles["0x839212b54d11c198beb378f7534d4225e54fa045"], "attacker")

    def test_tron_address_standalone(self) -> None:
        # 34-char base58, T-prefix.
        addr = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # USDT-TRC20 example
        text = f"Drained from {addr} via flash loan."
        addrs = self.tool.extract_contract_addresses(text)
        self.assertTrue(any(a["address"] == addr and a["chain_hint"] == "tron" for a in addrs))

    def test_dollar_million(self) -> None:
        text = "Loss estimated at $128 million per Rekt News."
        result = self.tool.refine_amount_usd(text, None)
        self.assertIsNotNone(result)
        self.assertEqual(result["value_usd"], 128_000_000)
        self.assertEqual(result["literal_match"].lower(), "$128 million")

    def test_dollar_comma_separated(self) -> None:
        text = "Balance Change: $19,850.59"
        result = self.tool.refine_amount_usd(text, 19850.59)
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result["value_usd"], 19850.59, places=2)
        self.assertTrue(result["matches_existing_amount_usd"])

    def test_dollar_billion_picks_largest(self) -> None:
        # Multiple amounts: refinement picks the largest (headline impact).
        text = "Tiny: $500. Headline: $1.2B drained from the protocol."
        result = self.tool.refine_amount_usd(text, None)
        self.assertEqual(result["value_usd"], 1_200_000_000)

    def test_dollar_thousand_k_suffix(self) -> None:
        text = "Lost $125k in 4 minutes."
        result = self.tool.refine_amount_usd(text, None)
        self.assertEqual(result["value_usd"], 125_000)

    def test_chain_inference_from_url(self) -> None:
        text = ""
        urls = ["https://etherscan.io/tx/0xabc"]
        chain = self.tool.infer_chain(text, urls)
        self.assertIsNotNone(chain)
        self.assertEqual(chain["value"], "ethereum")
        self.assertEqual(chain["source"], "explorer_url_host")

    def test_chain_inference_polygon(self) -> None:
        text = ""
        urls = ["https://polygonscan.com/address/0xabc"]
        chain = self.tool.infer_chain(text, urls)
        self.assertEqual(chain["value"], "polygon")

    def test_chain_inference_network_marker(self) -> None:
        text = "🎪 Network: avax 🎩 Attacker: 0x123"
        chain = self.tool.infer_chain(text, [])
        self.assertEqual(chain["value"], "avalanche")
        self.assertEqual(chain["source"], "network_marker")

    def test_chain_inference_mainnet_marker(self) -> None:
        text = "🎪 Network: mainnet 🎩 Attacker: 0x123"
        chain = self.tool.infer_chain(text, [])
        self.assertEqual(chain["value"], "ethereum")

    def test_chain_inference_url_beats_marker(self) -> None:
        # URL host has higher priority than text-marker.
        text = "🎪 Network: bsc"
        urls = ["https://etherscan.io/tx/0x1"]
        chain = self.tool.infer_chain(text, urls)
        self.assertEqual(chain["value"], "ethereum")  # URL won

    def test_asset_token_extraction(self) -> None:
        text = "Drained 50 WETH and 100,000 USDC from the pool. ETH price rose."
        tokens = self.tool.extract_asset_tokens(text)
        names = {t["token"] for t in tokens}
        self.assertIn("WETH", names)
        self.assertIn("USDC", names)
        self.assertIn("ETH", names)

    def test_asset_token_steth_casing(self) -> None:
        text = "Rebalance touched stETH and rETH."
        tokens = self.tool.extract_asset_tokens(text)
        names = {t["token"] for t in tokens}
        self.assertIn("stETH", names)
        self.assertIn("rETH", names)

    def test_explorer_url_extraction(self) -> None:
        text = (
            "See https://etherscan.io/tx/0xabc and https://tronscan.org/#/transaction/abc "
            "and https://snowtrace.io/address/0x1"
        )
        urls = self.tool.extract_explorer_urls(text)
        self.assertEqual(len(urls), 3)

    def test_cross_corpus_target_resolution(self) -> None:
        # Build a synthetic cross-corpus index and verify resolution.
        index = {
            "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7": [
                {
                    "project": "WAVAX (Wrapped AVAX)",
                    "record_id": "darknavy:wavax:abc",
                    "source_path": "audit/corpus_tags/tags/darknavy_web3_incidents/wavax/record.yaml",
                    "chain_hint": "evm",
                }
            ]
        }
        addrs = [
            {"address": "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7", "chain_hint": "evm",
             "role": "victim", "evidence_text": "..."}
        ]
        result = self.tool.resolve_target_via_cross_corpus(addrs, index)
        self.assertIsNotNone(result)
        self.assertEqual(result["project"], "WAVAX (Wrapped AVAX)")
        self.assertEqual(len(result["evidence"]), 1)

    def test_cross_corpus_no_hits_returns_none(self) -> None:
        addrs = [
            {"address": "0xdeadbeef" + "0" * 32, "chain_hint": "evm",
             "role": "victim", "evidence_text": "..."}
        ]
        result = self.tool.resolve_target_via_cross_corpus(addrs, {})
        self.assertIsNone(result)


class EnrichmentIntegrationTests(unittest.TestCase):
    """End-to-end on a synthetic defimon_telegram_incidents tree."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load_tool()

    def _build_workspace(self, tmp: Path) -> tuple[Path, Path]:
        input_dir = tmp / "defimon_telegram_incidents"
        cross_dir = tmp / "bridge_incidents"
        input_dir.mkdir(parents=True)
        cross_dir.mkdir(parents=True)

        # Two defimon records: one with addresses that should hit the cross-corpus,
        # one with a million-dollar amount and Tron URL.
        _write_record(
            input_dir / "defimon-tg-1-unknown" / "record.yaml",
            {
                "schema_version": "auditooor.hackerman_record.v1.1",
                "record_id": "defimon-telegram:1:unknown",
                "verification_tier": "tier-2-verified-public-archive",
                "source_url": "https://t.me/defimon_alerts/1",
                "incident_date": "2024-11-28",
                "target_project": "unknown",
                "severity": "info",
                "attack_class": "unspecified",
                "attack_vector_summary": (
                    "🟡 Alert: rug_pull 🤕 Victim: 0x7a77992da51b1d462b8bfd502f63e8385f233a10 "
                    "🎪 Network: mainnet 🎩 Attacker: 0x839212b54d11c198beb378f7534d4225e54fa045 "
                    "🪄 Exploit: 0xc6437332f4fc82b66d3c846e53358c9a1c5ae297 "
                    "💸 Balance Change: $19,850.59 Etherscan https://etherscan.io/address/0x7a77992da51b1d462b8bfd502f63e8385f233a10"
                ),
                "amount_usd": 19850.59,
                "notes": "Heuristic USD amount: ~$19,850",
            },
        )
        _write_record(
            input_dir / "defimon-tg-2-unknown" / "record.yaml",
            {
                "schema_version": "auditooor.hackerman_record.v1.1",
                "record_id": "defimon-telegram:2:unknown",
                "verification_tier": "tier-2-verified-public-archive",
                "source_url": "https://t.me/defimon_alerts/2",
                "incident_date": "2025-01-15",
                "target_project": "unknown",
                "severity": "info",
                "attack_class": "unspecified",
                "attack_vector_summary": (
                    "🟠 Tron-side drain via https://tronscan.org/#/transaction/"
                    + ("e" * 64)
                    + " Lost $1.5 Million USDT from victim."
                ),
                "notes": "",
            },
        )

        # Cross-corpus record naming the first victim address.
        _write_record(
            cross_dir / "synthetic" / "record.yaml",
            {
                "schema_version": "auditooor.hackerman_record.v1.1",
                "record_id": "bridge-incident:synthetic-1:abc",
                "target_project": "Synthetic Bridge",
                "target_repo": "synthetic/bridge",
                "required_preconditions": [
                    "Victim address 0x7a77992da51b1d462b8bfd502f63e8385f233a10 drained."
                ],
            },
        )

        return input_dir, cross_dir

    def test_end_to_end_writes_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            input_dir, cross_dir = self._build_workspace(tmp_p)
            summary = self.tool.walk_records(input_dir, [cross_dir])

            self.assertEqual(summary["records_seen"], 2)
            self.assertEqual(summary["records_enriched"], 2)
            self.assertGreaterEqual(summary["tx_hash_total"], 1)
            self.assertGreaterEqual(summary["address_total"], 3)
            self.assertGreaterEqual(summary["amount_refined"], 2)
            self.assertGreaterEqual(summary["chain_inferred"], 2)
            # Cross-corpus resolution should fire on record-1's victim address.
            self.assertGreaterEqual(summary["target_resolved_cross_corpus"], 1)

            # Verify the block was actually written.
            record1 = yaml.safe_load(
                (input_dir / "defimon-tg-1-unknown" / "record.yaml").read_text(encoding="utf-8")
            )
            self.assertIn("structured_extraction", record1)
            block = record1["structured_extraction"]
            self.assertEqual(block["schema_version"], "auditooor.defimon_tg_tx_enrichment.v1")
            self.assertTrue(block["resolution_attempted"])
            self.assertIsNotNone(block["cross_corpus_resolution"])
            self.assertEqual(
                block["cross_corpus_resolution"]["project"],
                "Synthetic Bridge",
            )

            # Verify existing fields preserved.
            self.assertEqual(record1["record_id"], "defimon-telegram:1:unknown")
            self.assertEqual(record1["verification_tier"], "tier-2-verified-public-archive")
            self.assertEqual(record1["amount_usd"], 19850.59)

    def test_dry_run_does_not_modify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            input_dir, cross_dir = self._build_workspace(tmp_p)
            original = (input_dir / "defimon-tg-1-unknown" / "record.yaml").read_text(encoding="utf-8")
            summary = self.tool.walk_records(input_dir, [cross_dir], dry_run=True)
            self.assertTrue(summary["dry_run"])
            self.assertEqual(summary["records_enriched"], 2)
            after = (input_dir / "defimon-tg-1-unknown" / "record.yaml").read_text(encoding="utf-8")
            self.assertEqual(original, after)

    def test_chain_distribution_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            input_dir, cross_dir = self._build_workspace(tmp_p)
            summary = self.tool.walk_records(input_dir, [cross_dir])
            # Record 1 -> ethereum (via URL or 'mainnet' marker). Record 2 -> tron URL.
            self.assertIn("ethereum", summary["chain_distribution"])
            self.assertIn("tron", summary["chain_distribution"])

    def test_idempotent_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            input_dir, cross_dir = self._build_workspace(tmp_p)
            self.tool.walk_records(input_dir, [cross_dir])
            payload_after_first = yaml.safe_load(
                (input_dir / "defimon-tg-1-unknown" / "record.yaml").read_text(encoding="utf-8")
            )
            self.tool.walk_records(input_dir, [cross_dir])
            payload_after_second = yaml.safe_load(
                (input_dir / "defimon-tg-1-unknown" / "record.yaml").read_text(encoding="utf-8")
            )
            # All non-timestamp fields should be identical.
            block1 = payload_after_first["structured_extraction"]
            block2 = payload_after_second["structured_extraction"]
            for key in ("tx_hashes", "contract_addresses", "amount_usd_refined",
                        "chain", "asset_tokens", "explorer_urls", "cross_corpus_resolution"):
                self.assertEqual(block1[key], block2[key], f"key {key} drifted")


class CliSmokeTest(unittest.TestCase):
    """Smoke-test the CLI entrypoint via main()."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load_tool()

    def test_main_dry_run_emits_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            input_dir = tmp_p / "defimon_telegram_incidents"
            cross_dir = tmp_p / "bridge_incidents"
            input_dir.mkdir(parents=True)
            cross_dir.mkdir(parents=True)
            _write_record(
                input_dir / "defimon-tg-only-1" / "record.yaml",
                {
                    "record_id": "x",
                    "attack_vector_summary": "🎩 Attacker: 0x" + "a" * 40
                                              + " Balance Change: $42,000",
                    "notes": "",
                },
            )

            summary_json = tmp_p / "summary.json"
            rc = self.tool.main([
                "--input-dir", str(input_dir),
                "--cross-corpus-dirs", str(cross_dir),
                "--json-summary", str(summary_json),
                "--dry-run",
            ])
            self.assertEqual(rc, 0)
            payload = json.loads(summary_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["records_seen"], 1)


if __name__ == "__main__":
    unittest.main()
