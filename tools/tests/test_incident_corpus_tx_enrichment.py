#!/usr/bin/env python3
# r36-rebuttal: lane-189-CONSOLIDATE-TX-TOOLS declared via tools/agent-pathspec-register.py at lane start (Task #189)
"""Unit tests for tools/incident-corpus-tx-enrichment.py (consolidated).

Task #189 merged the per-corpus tools so this file covers BOTH shape
families through the single consolidated module:

Generic-shape coverage (mev / darknavy / rekt / bridge / defimon-blog /
generic):

- Shared patterns: EVM tx hash, EVM addresses, $-amounts, USD-suffix,
  explorer URLs, chain inference, asset-token detection, cross-corpus
  dedup, walk-nested-strings.
- MEV-specific: sandwich / JIT / bundle phrasing (no false-positives on
  free prose).
- Darknavy-specific: Chinese-text handling (UTF-8 records survive the
  pipeline) + multi-address records.
- Rekt-specific: dollar-amount-only records, severity preservation.
- Tron T-prefix + Solana base58 with chain context.
- Bitcoin 64-hex requires bitcoin context (no false positives on
  payload_sha256 noise).
- amount_usd confidence escalation (amount_stolen field source -> high).
- Dry-run vs in-place file write.
- Cross-corpus dedup with a synthetic sibling corpus.

Defimon-TG-shape coverage (role attribution + cross-corpus target
resolution, ported from the legacy
tools/tests/test_defimon_tg_tx_enrichment.py file):

- EVM tx hash + URL extraction.
- Tron tx URL + standalone T-prefix address extraction.
- Mixed EVM + Tron tx hashes.
- EVM address role attribution from 🤕/🎩/🪄 prefixes.
- Dollar amounts: million / billion / comma-separated / k-suffix.
- Chain inference from URL host > Network: marker > inline keyword.
- Asset-token casing normalisation (stETH / rETH / wstETH / cbETH / etc).
- Cross-corpus target_project resolution via address overlap.
- End-to-end synthetic workspace: walks record.yaml only, writes blocks
  in the defimon-tg shape, idempotent re-runs.
- CLI smoke test via main(argv).
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "incident-corpus-tx-enrichment.py"

# Import the tool module by file path (filename has a hyphen).
_spec = importlib.util.spec_from_file_location(
    "incident_corpus_tx_enrichment", str(TOOL_PATH)
)
assert _spec is not None and _spec.loader is not None
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def write_record(dir_: Path, name: str, payload: dict) -> Path:
    dir_.mkdir(parents=True, exist_ok=True)
    p = dir_ / name
    with open(p, "w", encoding="utf-8") as fh:
        yaml.safe_dump(payload, fh, sort_keys=False, allow_unicode=True)
    return p


# ---------------------------------------------------------------------------
# Pure-function tests
# ---------------------------------------------------------------------------


class TestExtractors(unittest.TestCase):
    def test_evm_tx_hash(self):
        text = (
            "Attacker tx "
            "0xae0670e64db402a878faf09f6c5b1d9b08f0fef85788c2a51812c14a35f49ad9 "
            "drained funds."
        )
        out = mod._extract_tx_hashes([("notes", text)])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["kind"], "evm")
        self.assertTrue(out[0]["value"].startswith("0x"))
        self.assertEqual(len(out[0]["value"]), 66)

    def test_evm_addresses(self):
        text = (
            "Bridge contract at 0x9dce7a180c34203fee8ce8ca62f244feeb67bd30 "
            "owned by EOA 0x0b9a1391269e95162bfec8785e663258c209333b."
        )
        out = mod._extract_addresses([("notes", text)])
        self.assertEqual(len(out), 2)
        for entry in out:
            self.assertEqual(entry["kind"], "evm")
            self.assertEqual(len(entry["value"]), 42)

    def test_amount_usd_basic_dollars(self):
        text = "Total loss $608,705 with 8.879192 USDC."
        out = mod._extract_amount_usd([("impact", text)])
        self.assertIsNotNone(out)
        self.assertEqual(out["value"], 608705)
        self.assertEqual(out["confidence"], "high")

    def test_amount_usd_million_modifier(self):
        text = "Beanstalk drained for $181 million in stables."
        out = mod._extract_amount_usd([("notes", text)])
        self.assertIsNotNone(out)
        self.assertEqual(out["value"], 181_000_000)

    def test_amount_usd_billion_modifier(self):
        text = "Aggregate damage: $1.2 billion in WBTC."
        out = mod._extract_amount_usd([("notes", text)])
        self.assertIsNotNone(out)
        self.assertEqual(out["value"], 1_200_000_000)

    def test_amount_usd_picks_largest(self):
        text = "Small loss $500 first, then $50000 main drain."
        out = mod._extract_amount_usd([("notes", text)])
        self.assertEqual(out["value"], 50000)

    def test_amount_usd_ignores_under_100(self):
        text = "Saw $5 then $99, but real loss was $250000."
        out = mod._extract_amount_usd([("notes", text)])
        self.assertEqual(out["value"], 250000)

    def test_chain_inference_etherscan(self):
        text = "tx at https://etherscan.io/tx/0xabc... on Ethereum mainnet"
        out = mod._extract_chain([("notes", text)])
        self.assertEqual(out, "ethereum")

    def test_chain_inference_bsc(self):
        text = "BSC block 86066209 traced via bscscan.com link"
        out = mod._extract_chain([("notes", text)])
        self.assertEqual(out, "bsc")

    def test_chain_inference_none(self):
        text = "no chain context in this body"
        out = mod._extract_chain([("notes", text)])
        self.assertIsNone(out)

    def test_explorer_urls(self):
        text = (
            "See https://etherscan.io/tx/0xabc and "
            "https://bscscan.com/address/0xdef for details."
        )
        out = mod._extract_explorer_urls([("notes", text)])
        self.assertEqual(len(out), 2)
        urls = [e["value"] for e in out]
        self.assertTrue(any("etherscan.io" in u for u in urls))
        self.assertTrue(any("bscscan.com" in u for u in urls))

    def test_asset_tokens(self):
        text = "Swapped 100 USDT for 50 USDC then to WETH and ETH."
        out = mod._extract_asset_tokens([("notes", text)])
        tokens = sorted(e["value"] for e in out)
        self.assertEqual(tokens, ["ETH", "USDC", "USDT", "WETH"])

    def test_asset_tokens_avoid_false_positive(self):
        # "ETH" inside "ETHEREUM" must NOT match because of word boundary.
        text = "Network: ETHEREUM mainnet"
        out = mod._extract_asset_tokens([("notes", text)])
        self.assertEqual(out, [])

    def test_tron_address(self):
        text = (
            "Tron mainnet contract at TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7 "
            "linked via tronscan.org."
        )
        out = mod._extract_addresses([("notes", text)])
        kinds = {e["kind"] for e in out}
        self.assertIn("tron", kinds)

    def test_solana_address_with_context(self):
        # Solana program ids and mint addresses; require solana keyword.
        text = (
            "Solana program 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
            " interacted via solscan.io"
        )
        out = mod._extract_addresses([("notes", text)])
        kinds = {e["kind"] for e in out}
        self.assertIn("solana", kinds)

    def test_solana_no_false_positive_without_context(self):
        # Same-shape base58 string WITHOUT solana context must NOT match.
        text = "Just a random ID 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
        out = mod._extract_addresses([("notes", text)])
        kinds = {e["kind"] for e in out}
        self.assertNotIn("solana", kinds)

    def test_bitcoin_tx_requires_context(self):
        # 64-hex without bitcoin context must NOT match.
        text = "Some hash b4f5e6a3c1d2e1f5a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"
        out = mod._extract_tx_hashes([("notes", text)])
        self.assertEqual(out, [])

    def test_bitcoin_tx_with_context(self):
        text = (
            "Bitcoin tx b4f5e6a3c1d2e1f5a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"
            " via mempool.space"
        )
        out = mod._extract_tx_hashes([("notes", text)])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["kind"], "bitcoin")

    def test_walk_strings_nested(self):
        record = {
            "title": "outer",
            "record_extensions": {
                "x": "inner1",
                "y": ["inner2", "inner3"],
            },
        }
        results = list(mod._walk_strings(record["record_extensions"], "record_extensions"))
        # Expect 3 string leaves: x, y[0], y[1].
        paths = {p for p, _ in results}
        self.assertIn("record_extensions.x", paths)
        self.assertIn("record_extensions.y[0]", paths)
        self.assertIn("record_extensions.y[1]", paths)


# ---------------------------------------------------------------------------
# MEV-specific tests (sandwich / JIT / bundle phrasing)
# ---------------------------------------------------------------------------


class TestMevSpecific(unittest.TestCase):
    def test_mev_sandwich_no_false_positive(self):
        # MEV research narrative without tx hashes or addresses; the
        # extraction should be empty except possibly asset_token.
        record = {
            "attacker_action_sequence": (
                "Sandwich attack on a victim swap: searcher front-runs "
                "the victim transaction with a swap that moves the price, "
                "then back-runs with the inverse swap inside the same "
                "bundle. No on-chain extraction artifacts in this prose."
            ),
            "notes": "JIT liquidity provision via bundle inclusion.",
        }
        block, dedup = mod.enrich_record(record)
        self.assertEqual(block["tx_hashes"], [])
        self.assertEqual(block["contract_addresses"], [])
        self.assertIsNone(block["amount_usd"]["value"])
        self.assertEqual(dedup, [])

    def test_mev_with_tx_and_eth(self):
        record = {
            "attacker_action_sequence": (
                "Bundle hash "
                "0xae0670e64db402a878faf09f6c5b1d9b08f0fef85788c2a51812c14a35f49ad9 "
                "extracted 12 ETH in MEV via sandwich."
            )
        }
        block, _ = mod.enrich_record(record)
        self.assertEqual(len(block["tx_hashes"]), 1)
        self.assertIn("ETH", block["asset_token"])


# ---------------------------------------------------------------------------
# Darknavy-specific (Chinese-text handling)
# ---------------------------------------------------------------------------


class TestDarknavyChinese(unittest.TestCase):
    def test_chinese_text_no_crash(self):
        record = {
            "title": "深度分析 Aave fork 漏洞 - $608,705 loss",
            "attacker_action_sequence": (
                "攻击者使用合约 0x9dce7a180c34203fee8ce8ca62f244feeb67bd30 "
                "在以太坊主网上 (Ethereum mainnet) 提取了 187 WETH."
            ),
        }
        block, _ = mod.enrich_record(record)
        self.assertEqual(len(block["contract_addresses"]), 1)
        self.assertEqual(block["chain"], "ethereum")
        self.assertIn("WETH", block["asset_token"])
        self.assertEqual(block["amount_usd"]["value"], 608705)


# ---------------------------------------------------------------------------
# Rekt-specific (dollar amounts only)
# ---------------------------------------------------------------------------


class TestRektDollarOnly(unittest.TestCase):
    def test_rekt_million_amount(self):
        record = {
            "amount_stolen_literal_match": "$181 million",
            "attack_vector_summary": "Flash-loan governance takeover",
        }
        block, _ = mod.enrich_record(record)
        self.assertEqual(block["amount_usd"]["value"], 181_000_000)
        self.assertEqual(block["amount_usd"]["confidence"], "high")
        self.assertEqual(block["tx_hashes"], [])


# ---------------------------------------------------------------------------
# Cross-corpus dedup
# ---------------------------------------------------------------------------


class TestCrossCorpusDedup(unittest.TestCase):
    def test_dedup_hits_when_address_matches(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            primary = tdp / "primary"
            sibling = tdp / "sibling"

            write_record(
                sibling / "qubit-2022",
                "record.yaml",
                {
                    "record_id": "bridge-incident:qubit-finance-2022-01:abc",
                    "attacker_action_sequence": (
                        "Bridge 0x9dce7a180c34203fee8ce8ca62f244feeb67bd30 was drained."
                    ),
                },
            )
            write_record(
                primary / "new-finding",
                "record.yaml",
                {
                    "record_id": "mev-exploits:other:def",
                    "attacker_action_sequence": (
                        "Same contract 0x9dce7a180c34203fee8ce8ca62f244feeb67bd30 reused in MEV exploit."
                    ),
                },
            )

            summary = mod.process_corpus(
                primary, [sibling], dry_run=False
            )
            self.assertEqual(summary["cross_corpus_dedup_hits"], 1)

            # Verify the dedup entry landed in the rewritten primary file.
            written = primary / "new-finding" / "record.yaml"
            with open(written, "r", encoding="utf-8") as fh:
                rec = yaml.safe_load(fh)
            self.assertIn("cross_corpus_dedup", rec)
            self.assertEqual(rec["cross_corpus_dedup"][0]["field"], "contract_address")

    def test_dedup_skips_self(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            primary = tdp / "primary"
            sibling = tdp / "sibling"

            # Same record_id in both (legitimate same-id sibling, e.g. a
            # mirror corpus). Cross-corpus dedup should skip self-matches.
            shared_id = "incident:foo:abc"
            write_record(
                sibling / "qubit-2022",
                "record.yaml",
                {
                    "record_id": shared_id,
                    "attacker_action_sequence": (
                        "0x9dce7a180c34203fee8ce8ca62f244feeb67bd30 drained."
                    ),
                },
            )
            write_record(
                primary / "qubit-2022-mirror",
                "record.yaml",
                {
                    "record_id": shared_id,
                    "attacker_action_sequence": (
                        "0x9dce7a180c34203fee8ce8ca62f244feeb67bd30 drained."
                    ),
                },
            )

            summary = mod.process_corpus(
                primary, [sibling], dry_run=True
            )
            self.assertEqual(summary["cross_corpus_dedup_hits"], 0)


# ---------------------------------------------------------------------------
# Full per-record block shape
# ---------------------------------------------------------------------------


class TestRecordBlockShape(unittest.TestCase):
    def test_enrich_record_emits_schema_block(self):
        record = {
            "title": "Test",
            "attacker_action_sequence": (
                "Drain at 0x9dce7a180c34203fee8ce8ca62f244feeb67bd30 "
                "via https://etherscan.io/tx/0xabc on Ethereum mainnet "
                "for $1.2M USDT."
            ),
        }
        block, dedup = mod.enrich_record(record)
        self.assertEqual(block["schema_version"], mod.SCHEMA_VERSION)
        self.assertIn("enriched_at_utc", block)
        self.assertEqual(block["tool"], mod.TOOL_PATH)
        self.assertEqual(len(block["contract_addresses"]), 1)
        self.assertEqual(block["chain"], "ethereum")
        self.assertEqual(block["amount_usd"]["value"], 1_200_000)
        self.assertEqual(dedup, [])

    def test_enrich_record_empty_input(self):
        block, dedup = mod.enrich_record({})
        self.assertEqual(block["tx_hashes"], [])
        self.assertEqual(block["contract_addresses"], [])
        self.assertEqual(block["amount_usd"]["value"], None)
        self.assertEqual(block["chain"], None)
        self.assertEqual(dedup, [])


# ---------------------------------------------------------------------------
# Driver / file-IO tests
# ---------------------------------------------------------------------------


class TestDriverDryRun(unittest.TestCase):
    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td) / "input"
            yaml_path = write_record(
                tdp / "foo",
                "record.yaml",
                {
                    "title": "Test",
                    "attacker_action_sequence": (
                        "Bridge 0x9dce7a180c34203fee8ce8ca62f244feeb67bd30 drained."
                    ),
                },
            )
            mtime_before = yaml_path.stat().st_mtime
            with open(yaml_path, "r", encoding="utf-8") as fh:
                before_text = fh.read()
            summary = mod.process_corpus(tdp, [], dry_run=True)
            self.assertEqual(summary["files_written"], 0)
            with open(yaml_path, "r", encoding="utf-8") as fh:
                after_text = fh.read()
            self.assertEqual(before_text, after_text)

    def test_actual_write_appends_block(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td) / "input"
            yaml_path = write_record(
                tdp / "foo",
                "record.yaml",
                {
                    "title": "Test",
                    "attacker_action_sequence": (
                        "Bridge 0x9dce7a180c34203fee8ce8ca62f244feeb67bd30 drained for $1M."
                    ),
                },
            )
            summary = mod.process_corpus(tdp, [], dry_run=False)
            self.assertEqual(summary["files_written"], 1)
            with open(yaml_path, "r", encoding="utf-8") as fh:
                rec = yaml.safe_load(fh)
            self.assertIn("structured_extraction", rec)
            self.assertEqual(
                rec["structured_extraction"]["schema_version"],
                mod.SCHEMA_VERSION,
            )
            # Original title preserved.
            self.assertEqual(rec["title"], "Test")


class TestDriverCli(unittest.TestCase):
    def test_cli_smoke(self):
        # r36-rebuttal: lane-189-CONSOLIDATE-TX-TOOLS registered in agent_pathspec.json
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td) / "input"
            write_record(
                tdp / "foo",
                "record.yaml",
                {
                    "title": "Test",
                    "attacker_action_sequence": (
                        "Bridge 0x9dce7a180c34203fee8ce8ca62f244feeb67bd30 drained."
                    ),
                },
            )
            summary_path = Path(td) / "summary.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--input-dir",
                    str(tdp),
                    "--json-summary",
                    str(summary_path),
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(summary_path, "r", encoding="utf-8") as fh:
                summary = json.load(fh)
            self.assertEqual(summary["records_scanned"], 1)
            self.assertEqual(summary["records_enriched"], 1)


# ---------------------------------------------------------------------------
# Defimon-TG-shape coverage (ported from test_defimon_tg_tx_enrichment.py)
# r36-rebuttal: lane-189-CONSOLIDATE-TX-TOOLS registered in agent_pathspec.json
# ---------------------------------------------------------------------------


def _write_record(path: Path, payload: dict) -> None:
    """Helper for defimon-tg tests: write a record.yaml at the given path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


class DefimonTgExtractionTests(unittest.TestCase):
    """Defimon-TG shape: pure-function extraction tests."""

    def test_evm_tx_hash_extraction(self) -> None:
        text = (
            "Exploit confirmed in tx "
            "0xae0670e64db402a878faf09f6c5b1d9b08f0fef85788c2a51812c14a35f49ad9 "
            "on https://etherscan.io/tx/"
            "0xae0670e64db402a878faf09f6c5b1d9b08f0fef85788c2a51812c14a35f49ad9"
        )
        hashes = mod.extract_tx_hashes(text)
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
        hashes = mod.extract_tx_hashes(text)
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0]["hash"], h)
        self.assertEqual(hashes[0]["chain_hint"], "tron")

    def test_evm_and_tron_mixed(self) -> None:
        evm = "0x" + "b" * 64
        tron = "c" * 64
        text = (
            f"EVM tx: {evm} and Tron https://tronscan.org/#/transaction/{tron}"
        )
        hashes = mod.extract_tx_hashes(text)
        self.assertEqual({h["chain_hint"] for h in hashes}, {"evm", "tron"})
        self.assertEqual(len(hashes), 2)

    def test_evm_address_with_role(self) -> None:
        text = (
            "🤕 Victim: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 "
            "🎩 Attacker: 0x839212B54d11c198beB378f7534D4225e54FA045"
        )
        addrs = mod.extract_contract_addresses(text)
        self.assertEqual(len(addrs), 2)
        roles = {a["address"]: a["role"] for a in addrs}
        self.assertEqual(
            roles["0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"], "victim"
        )
        self.assertEqual(
            roles["0x839212b54d11c198beb378f7534d4225e54fa045"], "attacker"
        )

    def test_tron_address_standalone(self) -> None:
        # 34-char base58, T-prefix.
        addr = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # USDT-TRC20 example
        text = f"Drained from {addr} via flash loan."
        addrs = mod.extract_contract_addresses(text)
        self.assertTrue(
            any(
                a["address"] == addr and a["chain_hint"] == "tron"
                for a in addrs
            )
        )

    def test_dollar_million(self) -> None:
        text = "Loss estimated at $128 million per Rekt News."
        result = mod.refine_amount_usd(text, None)
        self.assertIsNotNone(result)
        self.assertEqual(result["value_usd"], 128_000_000)
        self.assertEqual(result["literal_match"].lower(), "$128 million")

    def test_dollar_comma_separated(self) -> None:
        text = "Balance Change: $19,850.59"
        result = mod.refine_amount_usd(text, 19850.59)
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result["value_usd"], 19850.59, places=2)
        self.assertTrue(result["matches_existing_amount_usd"])

    def test_dollar_billion_picks_largest(self) -> None:
        # Multiple amounts: refinement picks the largest (headline impact).
        text = "Tiny: $500. Headline: $1.2B drained from the protocol."
        result = mod.refine_amount_usd(text, None)
        self.assertEqual(result["value_usd"], 1_200_000_000)

    def test_dollar_thousand_k_suffix(self) -> None:
        text = "Lost $125k in 4 minutes."
        result = mod.refine_amount_usd(text, None)
        self.assertEqual(result["value_usd"], 125_000)

    def test_chain_inference_from_url(self) -> None:
        text = ""
        urls = ["https://etherscan.io/tx/0xabc"]
        chain = mod.infer_chain(text, urls)
        self.assertIsNotNone(chain)
        self.assertEqual(chain["value"], "ethereum")
        self.assertEqual(chain["source"], "explorer_url_host")

    def test_chain_inference_polygon(self) -> None:
        text = ""
        urls = ["https://polygonscan.com/address/0xabc"]
        chain = mod.infer_chain(text, urls)
        self.assertEqual(chain["value"], "polygon")

    def test_chain_inference_network_marker(self) -> None:
        text = "🎪 Network: avax 🎩 Attacker: 0x123"
        chain = mod.infer_chain(text, [])
        self.assertEqual(chain["value"], "avalanche")
        self.assertEqual(chain["source"], "network_marker")

    def test_chain_inference_mainnet_marker(self) -> None:
        text = "🎪 Network: mainnet 🎩 Attacker: 0x123"
        chain = mod.infer_chain(text, [])
        self.assertEqual(chain["value"], "ethereum")

    def test_chain_inference_url_beats_marker(self) -> None:
        # URL host has higher priority than text-marker.
        text = "🎪 Network: bsc"
        urls = ["https://etherscan.io/tx/0x1"]
        chain = mod.infer_chain(text, urls)
        self.assertEqual(chain["value"], "ethereum")  # URL won

    def test_asset_token_extraction(self) -> None:
        text = (
            "Drained 50 WETH and 100,000 USDC from the pool. "
            "ETH price rose."
        )
        tokens = mod.extract_asset_tokens(text)
        names = {t["token"] for t in tokens}
        self.assertIn("WETH", names)
        self.assertIn("USDC", names)
        self.assertIn("ETH", names)

    def test_asset_token_steth_casing(self) -> None:
        text = "Rebalance touched stETH and rETH."
        tokens = mod.extract_asset_tokens(text)
        names = {t["token"] for t in tokens}
        self.assertIn("stETH", names)
        self.assertIn("rETH", names)

    def test_explorer_url_extraction(self) -> None:
        text = (
            "See https://etherscan.io/tx/0xabc and "
            "https://tronscan.org/#/transaction/abc "
            "and https://snowtrace.io/address/0x1"
        )
        urls = mod.extract_explorer_urls(text)
        self.assertEqual(len(urls), 3)

    def test_cross_corpus_target_resolution(self) -> None:
        # Build a synthetic cross-corpus index and verify resolution.
        index = {
            "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7": [
                {
                    "project": "WAVAX (Wrapped AVAX)",
                    "record_id": "darknavy:wavax:abc",
                    "source_path": (
                        "audit/corpus_tags/tags/darknavy_web3_incidents/"
                        "wavax/record.yaml"
                    ),
                    "chain_hint": "evm",
                }
            ]
        }
        addrs = [
            {
                "address": "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7",
                "chain_hint": "evm",
                "role": "victim",
                "evidence_text": "...",
            }
        ]
        result = mod.resolve_target_via_cross_corpus(addrs, index)
        self.assertIsNotNone(result)
        self.assertEqual(result["project"], "WAVAX (Wrapped AVAX)")
        self.assertEqual(len(result["evidence"]), 1)

    def test_cross_corpus_no_hits_returns_none(self) -> None:
        addrs = [
            {
                "address": "0xdeadbeef" + "0" * 32,
                "chain_hint": "evm",
                "role": "victim",
                "evidence_text": "...",
            }
        ]
        result = mod.resolve_target_via_cross_corpus(addrs, {})
        self.assertIsNone(result)


class DefimonTgEnrichmentIntegrationTests(unittest.TestCase):
    """End-to-end defimon-TG shape on a synthetic record.yaml tree."""

    def _build_workspace(self, tmp: Path) -> tuple:
        input_dir = tmp / "defimon_telegram_incidents"
        cross_dir = tmp / "bridge_incidents"
        input_dir.mkdir(parents=True)
        cross_dir.mkdir(parents=True)

        # Two defimon records: one with addresses that should hit the
        # cross-corpus, one with a million-dollar amount and Tron URL.
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
                    "🟡 Alert: rug_pull 🤕 Victim: "
                    "0x7a77992da51b1d462b8bfd502f63e8385f233a10 "
                    "🎪 Network: mainnet 🎩 Attacker: "
                    "0x839212b54d11c198beb378f7534d4225e54fa045 "
                    "🪄 Exploit: "
                    "0xc6437332f4fc82b66d3c846e53358c9a1c5ae297 "
                    "💸 Balance Change: $19,850.59 Etherscan "
                    "https://etherscan.io/address/"
                    "0x7a77992da51b1d462b8bfd502f63e8385f233a10"
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
                    "🟠 Tron-side drain via "
                    "https://tronscan.org/#/transaction/"
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
                    "Victim address "
                    "0x7a77992da51b1d462b8bfd502f63e8385f233a10 drained."
                ],
            },
        )

        return input_dir, cross_dir

    def test_end_to_end_writes_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            input_dir, cross_dir = self._build_workspace(tmp_p)
            summary = mod.walk_records(input_dir, [cross_dir])

            self.assertEqual(summary["records_seen"], 2)
            self.assertEqual(summary["records_enriched"], 2)
            self.assertGreaterEqual(summary["tx_hash_total"], 1)
            self.assertGreaterEqual(summary["address_total"], 3)
            self.assertGreaterEqual(summary["amount_refined"], 2)
            self.assertGreaterEqual(summary["chain_inferred"], 2)
            # Cross-corpus resolution fires on record-1's victim address.
            self.assertGreaterEqual(
                summary["target_resolved_cross_corpus"], 1
            )

            # Verify the block was actually written.
            record1 = yaml.safe_load(
                (input_dir / "defimon-tg-1-unknown" / "record.yaml").read_text(
                    encoding="utf-8"
                )
            )
            self.assertIn("structured_extraction", record1)
            block = record1["structured_extraction"]
            self.assertEqual(
                block["schema_version"],
                "auditooor.defimon_tg_tx_enrichment.v1",
            )
            self.assertTrue(block["resolution_attempted"])
            self.assertIsNotNone(block["cross_corpus_resolution"])
            self.assertEqual(
                block["cross_corpus_resolution"]["project"],
                "Synthetic Bridge",
            )

            # Verify existing fields preserved.
            self.assertEqual(record1["record_id"], "defimon-telegram:1:unknown")
            self.assertEqual(
                record1["verification_tier"],
                "tier-2-verified-public-archive",
            )
            self.assertEqual(record1["amount_usd"], 19850.59)

    def test_dry_run_does_not_modify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            input_dir, cross_dir = self._build_workspace(tmp_p)
            original = (
                input_dir / "defimon-tg-1-unknown" / "record.yaml"
            ).read_text(encoding="utf-8")
            summary = mod.walk_records(
                input_dir, [cross_dir], dry_run=True
            )
            self.assertTrue(summary["dry_run"])
            self.assertEqual(summary["records_enriched"], 2)
            after = (
                input_dir / "defimon-tg-1-unknown" / "record.yaml"
            ).read_text(encoding="utf-8")
            self.assertEqual(original, after)

    def test_chain_distribution_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            input_dir, cross_dir = self._build_workspace(tmp_p)
            summary = mod.walk_records(input_dir, [cross_dir])
            # Record 1 -> ethereum (URL or 'mainnet' marker).
            # Record 2 -> tron URL.
            self.assertIn("ethereum", summary["chain_distribution"])
            self.assertIn("tron", summary["chain_distribution"])

    def test_idempotent_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            input_dir, cross_dir = self._build_workspace(tmp_p)
            mod.walk_records(input_dir, [cross_dir])
            payload_after_first = yaml.safe_load(
                (
                    input_dir / "defimon-tg-1-unknown" / "record.yaml"
                ).read_text(encoding="utf-8")
            )
            mod.walk_records(input_dir, [cross_dir])
            payload_after_second = yaml.safe_load(
                (
                    input_dir / "defimon-tg-1-unknown" / "record.yaml"
                ).read_text(encoding="utf-8")
            )
            # All non-timestamp fields should be identical.
            block1 = payload_after_first["structured_extraction"]
            block2 = payload_after_second["structured_extraction"]
            for key in (
                "tx_hashes",
                "contract_addresses",
                "amount_usd_refined",
                "chain",
                "asset_tokens",
                "explorer_urls",
                "cross_corpus_resolution",
            ):
                self.assertEqual(
                    block1[key], block2[key], f"key {key} drifted"
                )


class DefimonTgCliSmokeTest(unittest.TestCase):
    """Smoke-test the consolidated CLI with --corpus-shape defimon-tg."""

    def test_cli_dry_run_defimon_tg_shape(self) -> None:
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
                    "attack_vector_summary": (
                        "🎩 Attacker: 0x" + "a" * 40
                        + " Balance Change: $42,000"
                    ),
                    "notes": "",
                },
            )

            summary_json = tmp_p / "summary.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--input-dir",
                    str(input_dir),
                    "--corpus-shape",
                    "defimon-tg",
                    "--cross-corpus-dirs",
                    str(cross_dir),
                    "--json-summary",
                    str(summary_json),
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(summary_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["records_seen"], 1)
            self.assertEqual(payload["corpus_shape"], "defimon-tg")


if __name__ == "__main__":
    unittest.main()
