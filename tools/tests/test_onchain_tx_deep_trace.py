# r36-rebuttal: lane-LIFT-7-ONCHAIN-TX-DEEP-MINING declared in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py at lane start
"""Hermetic tests for ``tools/onchain-tx-deep-trace.py`` (LIFT-7).

All HTTP is mocked through the injected ``http_fn`` parameter; no live
network. The honest-zero gate is exercised explicitly: when no env keys
are set, every record's tx hashes return ``blocked_no_api_key``.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "onchain-tx-deep-trace.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


TRACE = _load(TOOL, "onchain_tx_deep_trace_tool")


def _make_record(slug: str, *, chain: str, tx_hashes: list[str], amount: float | None) -> dict:
    return {
        "schema_version": "auditooor.hackerman_record.v1.1",
        "record_id": f"test:{slug}",
        "verification_tier": "tier-2-verified-public-archive",
        "incident_date": "2024-01-01",
        "target_project": slug,
        "severity": "high",
        "attack_class": "unspecified",
        "attack_vector_summary": f"Test record for {slug}",
        "amount_usd": amount,
        "fix_commit_refs": [],
        "shape_tags": [],
        "notes": "",
        "structured_extraction": {
            "schema_version": "auditooor.defimon_tg_tx_enrichment.v1",
            "enriched_at_utc": "2026-05-26T00:00:00Z",
            "tx_hashes": tx_hashes,
            "chain": {"value": chain, "source": "test"},
        },
    }


def _write_record(root: Path, slug: str, **kw) -> Path:
    d = root / slug
    d.mkdir(parents=True, exist_ok=True)
    p = d / "record.yaml"
    with p.open("w") as fh:
        yaml.safe_dump(_make_record(slug, **kw), fh, sort_keys=False)
    return p


# ---------------------------------------------------------------------------
# 1. resolve_api_keys: env discovery
# ---------------------------------------------------------------------------

# r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY tools/tests/test_onchain_tx_deep_trace.py updated for V2 unified endpoint fan-out (resolve_api_keys now returns a 3-tuple incl. v2_chains)
class TestResolveApiKeys(unittest.TestCase):
    def test_all_keys_missing_returns_all_etherscan_chains_as_blocked(self):
        keys, blocked, v2_chains = TRACE.resolve_api_keys(env={})
        self.assertEqual(keys["ethereum"], "")
        self.assertIn("ethereum", blocked)
        self.assertIn("bsc", blocked)
        # tron is family=tron, NOT in blocked list (it is best-effort, key-optional)
        self.assertNotIn("tron", blocked)
        self.assertEqual(v2_chains, set())

    # r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY tools/tests/test_onchain_tx_deep_trace.py
    def test_eth_key_set_pulls_through(self):
        # With the V2 unified endpoint + legacy-v1 deprecation,
        # ETHERSCAN_API_KEY fans out to EVERY etherscan-family chain
        # (driven by chainid) INCLUDING ethereum.  The legacy v1
        # endpoint now returns a JSON migration-warning string instead
        # of a tx object, so we route everything via V2.
        keys, blocked, v2_chains = TRACE.resolve_api_keys(env={"ETHERSCAN_API_KEY": "ABC123"})
        self.assertEqual(keys["ethereum"], "ABC123")
        self.assertEqual(keys["bsc"], "ABC123")
        self.assertNotIn("ethereum", blocked)
        self.assertNotIn("bsc", blocked)
        self.assertIn("ethereum", v2_chains)
        self.assertIn("bsc", v2_chains)
        self.assertIn("polygon", v2_chains)
        self.assertIn("linea", v2_chains)

    def test_per_chain_legacy_key_overrides_unified(self):
        # Per-chain BSCSCAN_API_KEY should keep legacy v1 routing for bsc.
        keys, blocked, v2_chains = TRACE.resolve_api_keys(env={
            "ETHERSCAN_API_KEY": "UNIFIED",
            "BSCSCAN_API_KEY": "LEGACY_BSC",
        })
        self.assertEqual(keys["bsc"], "LEGACY_BSC")
        self.assertNotIn("bsc", v2_chains)
        # polygon falls back to unified key + V2.
        self.assertEqual(keys["polygon"], "UNIFIED")
        self.assertIn("polygon", v2_chains)


# ---------------------------------------------------------------------------
# 2. fetch_tx: blocked_no_api_key when key missing
# ---------------------------------------------------------------------------

class TestFetchTxBlocked(unittest.TestCase):
    def test_etherscan_family_no_key_emits_blocked(self):
        out = TRACE.fetch_tx("ethereum", "0x" + "a" * 64, api_keys={"ethereum": ""}, http_fn=lambda url: None)
        self.assertEqual(out["fetch_status"], "blocked_no_api_key")

    def test_unsupported_chain_emits_typed_error(self):
        out = TRACE.fetch_tx("unobtainium", "0x" + "a" * 64, api_keys={}, http_fn=lambda url: None)
        self.assertEqual(out["fetch_status"], "unsupported_chain")


# ---------------------------------------------------------------------------
# 3. fetch_etherscan_tx: successful fetch + normalisation
# ---------------------------------------------------------------------------

class TestFetchEtherscanTx(unittest.TestCase):
    def test_success_path_parses_all_fields(self):
        tx_hash = "0x" + "b" * 64

        def fake_http(url):
            if "eth_getTransactionByHash" in url:
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "blockNumber": "0x123",
                        "blockHash": "0xabc",
                        "from": "0xfrom",
                        "to": "0xto",
                        "value": "0xde0b6b3a7640000",  # 1 ETH in wei
                        "gasPrice": "0x12a05f200",
                        "input": "0xa9059cbb000000",
                        "transactionIndex": "0x5",
                        "nonce": "0xa",
                    },
                }
            if "eth_getTransactionReceipt" in url:
                return {
                    "jsonrpc": "2.0",
                    "result": {
                        "status": "0x1",
                        "gasUsed": "0x5208",
                        "logs": [
                            {
                                "address": "0xlog",
                                "topics": ["0xtopic1"],
                                "data": "0xdata",
                            }
                        ],
                    },
                }
            if "txlistinternal" in url:
                return {
                    "status": "1",
                    "message": "OK",
                    "result": [
                        {
                            "from": "0xinternalfrom",
                            "to": "0xinternalto",
                            "value": "1000",
                            "gas": "21000",
                            "input": "0x",
                            "type": "call",
                            "isError": "0",
                        }
                    ],
                }
            return None

        out = TRACE.fetch_etherscan_tx("ethereum", tx_hash, "KEY", http_fn=fake_http)
        self.assertEqual(out["fetch_status"], "ok")
        self.assertEqual(out["block_number"], 0x123)
        self.assertEqual(out["from_address"], "0xfrom")
        self.assertEqual(out["value_wei"], int("0xde0b6b3a7640000", 16))
        self.assertEqual(out["gas_used"], 0x5208)
        self.assertEqual(out["function_selector"], "0xa9059cbb")
        self.assertEqual(out["status"], "success")
        self.assertEqual(out["evidence_url"], f"https://etherscan.io/tx/{tx_hash}")
        self.assertEqual(len(out["internal_txs"]), 1)
        self.assertEqual(len(out["emitted_events"]), 1)

    def test_revert_status_parsed(self):
        tx_hash = "0x" + "c" * 64

        def fake_http(url):
            if "eth_getTransactionByHash" in url:
                return {"result": {"input": "0x", "value": "0x0", "blockNumber": "0x1"}}
            if "eth_getTransactionReceipt" in url:
                return {"result": {"status": "0x0", "gasUsed": "0x1"}}
            return {"result": []}

        out = TRACE.fetch_etherscan_tx("ethereum", tx_hash, "KEY", http_fn=fake_http)
        self.assertEqual(out["status"], "revert")

    def test_fetch_error_when_tx_payload_empty(self):
        tx_hash = "0x" + "d" * 64

        def fake_http(url):
            return {"jsonrpc": "2.0", "result": None}

        out = TRACE.fetch_etherscan_tx("ethereum", tx_hash, "KEY", http_fn=fake_http)
        self.assertEqual(out["fetch_status"], "fetch_error")


# ---------------------------------------------------------------------------
# 4. resolve_function_signature: 4byte fallback
# ---------------------------------------------------------------------------

class TestSelectorResolution(unittest.TestCase):
    def test_known_selector_resolved(self):
        def fake_http(url):
            return {
                "count": 1,
                "results": [{"text_signature": "transfer(address,uint256)"}],
            }

        sig = TRACE.resolve_function_signature("0xa9059cbb", http_fn=fake_http)
        self.assertEqual(sig, "transfer(address,uint256)")

    def test_invalid_selector_returns_none(self):
        sig = TRACE.resolve_function_signature("0x12", http_fn=lambda url: None)
        self.assertIsNone(sig)


# ---------------------------------------------------------------------------
# 5. throttle: respects qps cap
# ---------------------------------------------------------------------------

class TestHostThrottle(unittest.TestCase):
    def test_throttle_enforces_min_interval(self):
        # r36-rebuttal: lane-LIFT-7-ONCHAIN-TX-DEEP-MINING declared in agent_pathspec.json
        th = TRACE.HostThrottle()
        sleeps = []
        # acquire() reads now() twice per call (elapsed + record). Supply
        # enough virtual times: 1st call (no sleep) consumes 2 reads, 2nd
        # call (sleeps) consumes 2 reads.
        nows = iter([0.0, 0.0, 0.1, 0.1])

        def fake_sleep(s):
            sleeps.append(s)

        def fake_now():
            return next(nows)

        # First call (elapsed=10 vs min_interval=0.2) -> no sleep
        th._last_call["host"] = -10.0
        wait1 = th.acquire("host", qps=5.0, sleeper=fake_sleep, now=fake_now)
        self.assertEqual(wait1, 0.0)
        # Second call (elapsed=0.1 vs min_interval=0.2) -> sleeps 0.1s
        wait2 = th.acquire("host", qps=5.0, sleeper=fake_sleep, now=fake_now)
        self.assertAlmostEqual(wait2, 0.1, places=2)
        self.assertEqual(sleeps, [0.1])

    def test_throttle_qps_zero_no_sleep(self):
        th = TRACE.HostThrottle()
        wait = th.acquire("host", qps=0.0, sleeper=lambda s: None, now=lambda: 0.0)
        self.assertEqual(wait, 0.0)


# ---------------------------------------------------------------------------
# 6. Cursor IO
# ---------------------------------------------------------------------------

class TestCursorIO(unittest.TestCase):
    def test_load_missing_returns_skeleton(self):
        with tempfile.TemporaryDirectory() as td:
            cursor_path = Path(td) / "missing.json"
            cur = TRACE.load_cursor(cursor_path)
            self.assertEqual(cur["processed_tx_hashes"], [])
            self.assertEqual(cur["blocked_no_api_key"], [])
            self.assertIsNone(cur["last_run_utc"])

    def test_save_then_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            cursor_path = Path(td) / "sub" / "cursor.json"
            cur = TRACE.load_cursor(cursor_path)
            cur["processed_tx_hashes"] = ["0xabc"]
            TRACE.save_cursor(cursor_path, cur)
            cur2 = TRACE.load_cursor(cursor_path)
            self.assertEqual(cur2["processed_tx_hashes"], ["0xabc"])
            self.assertIsNotNone(cur2["last_run_utc"])

    def test_load_corrupt_returns_skeleton(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text("{not json}")
            cur = TRACE.load_cursor(p)
            self.assertEqual(cur["processed_tx_hashes"], [])


# ---------------------------------------------------------------------------
# 7. rank_candidates: top-N by amount_usd, filters
# ---------------------------------------------------------------------------

class TestRankCandidates(unittest.TestCase):
    def test_skips_null_amount(self):
        recs = [
            (Path("/a"), _make_record("a", chain="ethereum", tx_hashes=["0x" + "0" * 64], amount=None)),
            (Path("/b"), _make_record("b", chain="ethereum", tx_hashes=["0x" + "1" * 64], amount=50.0)),
        ]
        top = TRACE.rank_candidates(recs, top_n=10, sort_by="amount_usd")
        self.assertEqual(len(top), 1)
        self.assertEqual(top[0][0], Path("/b"))

    def test_skips_empty_tx_hashes(self):
        recs = [
            (Path("/a"), _make_record("a", chain="ethereum", tx_hashes=[], amount=999.0)),
        ]
        top = TRACE.rank_candidates(recs, top_n=10, sort_by="amount_usd")
        self.assertEqual(len(top), 0)

    def test_sorts_descending_by_amount(self):
        recs = [
            (Path("/lo"), _make_record("lo", chain="ethereum", tx_hashes=["0x" + "1" * 64], amount=10.0)),
            (Path("/hi"), _make_record("hi", chain="ethereum", tx_hashes=["0x" + "2" * 64], amount=1000.0)),
            (Path("/mid"), _make_record("mid", chain="ethereum", tx_hashes=["0x" + "3" * 64], amount=100.0)),
        ]
        top = TRACE.rank_candidates(recs, top_n=10, sort_by="amount_usd")
        self.assertEqual([p.name for p, _ in top], ["hi", "mid", "lo"])

    def test_top_n_ceiling(self):
        recs = [
            (Path(f"/r{i}"), _make_record(f"r{i}", chain="ethereum", tx_hashes=[f"0x{i:064x}"], amount=float(i)))
            for i in range(1, 20)
        ]
        top = TRACE.rank_candidates(recs, top_n=5, sort_by="amount_usd")
        self.assertEqual(len(top), 5)


# ---------------------------------------------------------------------------
# 8. run: end-to-end honest BLOCKED when no API keys
# ---------------------------------------------------------------------------

class TestRunHonestBlocked(unittest.TestCase):
    def test_no_keys_yields_blocked_per_record_and_cursor(self):
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus"
            corpus.mkdir()
            _write_record(corpus, "big-eth", chain="ethereum",
                          tx_hashes=["0x" + "a" * 64], amount=1_000_000.0)
            _write_record(corpus, "big-bsc", chain="bsc",
                          tx_hashes=["0x" + "b" * 64], amount=500_000.0)
            _write_record(corpus, "no-tx", chain="ethereum",
                          tx_hashes=[], amount=999.0)

            cursor = Path(td) / "cursor.json"
            summary_path = Path(td) / "summary.json"
            summary = TRACE.run(
                input_corpora=[corpus],
                top_n=100,
                sort_by="amount_usd",
                cursor_path=cursor,
                output_mode="append-to-record",
                json_summary_path=summary_path,
                env={},  # NO keys
                http_fn=lambda url: None,
                resolve_selector=False,
            )
            self.assertEqual(summary["candidates_selected"], 2)
            self.assertEqual(summary["records_updated_with_trace_block"], 0)
            self.assertEqual(summary["records_all_blocked_no_api_key"], 2)
            self.assertIn("ethereum", summary["chains_blocked_no_api_key"])
            self.assertIn("bsc", summary["chains_blocked_no_api_key"])
            self.assertEqual(summary["tx_fetch_status"].get("blocked_no_api_key"), 2)
            # cursor reflects blocked chains
            cur = json.loads(cursor.read_text())
            self.assertIn("ethereum", cur["blocked_no_api_key"])


# ---------------------------------------------------------------------------
# 9. run: end-to-end success appends trace block + dedupes via cursor
# ---------------------------------------------------------------------------

class TestRunSuccessAndResume(unittest.TestCase):
    def _fake_http_factory(self, tx_hash):
        def fake_http(url):
            if "eth_getTransactionByHash" in url:
                return {"result": {"blockNumber": "0x1", "from": "0xa", "to": "0xb",
                                   "value": "0x0", "input": "0x12345678", "transactionIndex": "0x0", "nonce": "0x0"}}
            if "eth_getTransactionReceipt" in url:
                return {"result": {"status": "0x1", "gasUsed": "0x5208", "logs": []}}
            if "txlistinternal" in url:
                return {"result": []}
            if "4byte.directory" in url:
                return {"results": [{"text_signature": "fn(uint256)"}]}
            return None
        return fake_http

    def test_success_path_writes_trace_block_and_resumes(self):
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus"
            corpus.mkdir()
            tx = "0x" + "9" * 64
            rec_path = _write_record(corpus, "happy-eth", chain="ethereum",
                                     tx_hashes=[tx], amount=1_000_000.0)
            cursor = Path(td) / "cursor.json"
            summary_path = Path(td) / "summary.json"

            summary = TRACE.run(
                input_corpora=[corpus],
                top_n=100,
                sort_by="amount_usd",
                cursor_path=cursor,
                output_mode="append-to-record",
                json_summary_path=summary_path,
                env={"ETHERSCAN_API_KEY": "TEST"},
                http_fn=self._fake_http_factory(tx),
                resolve_selector=True,
            )
            self.assertEqual(summary["records_updated_with_trace_block"], 1)
            # Record now carries onchain_trace_extraction
            with rec_path.open() as fh:
                updated = yaml.safe_load(fh)
            self.assertIn("onchain_trace_extraction", updated)
            traces = updated["onchain_trace_extraction"]["traces"]
            self.assertEqual(len(traces), 1)
            self.assertEqual(traces[0]["fetch_status"], "ok")
            self.assertEqual(traces[0]["decoded_function_signature"], "fn(uint256)")
            self.assertTrue(traces[0]["evidence_url"].startswith("https://etherscan.io/tx/"))
            # R37: verification_tier preserved
            self.assertEqual(updated["verification_tier"], "tier-2-verified-public-archive")
            # Cursor records the tx as processed
            cur = json.loads(cursor.read_text())
            self.assertIn(tx, cur["processed_tx_hashes"])

            # Resume: second run should mark as skipped_already_processed
            summary2 = TRACE.run(
                input_corpora=[corpus],
                top_n=100,
                sort_by="amount_usd",
                cursor_path=cursor,
                output_mode="append-to-record",
                json_summary_path=None,
                env={"ETHERSCAN_API_KEY": "TEST"},
                http_fn=self._fake_http_factory(tx),
                resolve_selector=False,
            )
            self.assertEqual(summary2["tx_fetch_status"].get("skipped_already_processed", 0), 1)


# ---------------------------------------------------------------------------
# 10. run: chain="" or unknown chain emits typed error
# ---------------------------------------------------------------------------

class TestRunUnsupportedChain(unittest.TestCase):
    def test_blank_chain_value_emits_unsupported(self):
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus"
            corpus.mkdir()
            _write_record(corpus, "blank-chain", chain="", tx_hashes=["0x" + "0" * 64], amount=500.0)
            cursor = Path(td) / "cursor.json"
            summary = TRACE.run(
                input_corpora=[corpus],
                top_n=10,
                sort_by="amount_usd",
                cursor_path=cursor,
                output_mode="append-to-record",
                json_summary_path=None,
                env={"ETHERSCAN_API_KEY": "TEST"},
                http_fn=lambda url: None,
                resolve_selector=False,
            )
            self.assertGreaterEqual(summary["tx_fetch_status"].get("unsupported_chain", 0), 1)


# ---------------------------------------------------------------------------
# 11. Tron path: best-effort fetch when no key
# ---------------------------------------------------------------------------

class TestTronPath(unittest.TestCase):
    def test_tron_no_key_still_attempts_fetch_and_returns_typed_error_on_none(self):
        out = TRACE.fetch_tx("tron", "0x" + "f" * 64, api_keys={"tron": ""}, http_fn=lambda url: None)
        # tron is family=tron: empty key is allowed; http_fn returns None -> fetch_error
        self.assertEqual(out["fetch_status"], "fetch_error")

    def test_tron_success_path(self):
        tx_hash = "0x" + "e" * 64
        def fake_http(url):
            return {
                "block": 12345,
                "hash": tx_hash,
                "ownerAddress": "TFrom",
                "toAddress": "TTo",
                "contractData": {"amount": 1000},
                "cost": {"net_usage": 200, "net_fee": 10},
                "data": "0xdeadbeef",
                "contractRet": "SUCCESS",
            }
        out = TRACE.fetch_tx("tron", tx_hash, api_keys={"tron": ""}, http_fn=fake_http)
        self.assertEqual(out["fetch_status"], "ok")
        self.assertEqual(out["status"], "success")
        self.assertEqual(out["block_number"], 12345)


# ---------------------------------------------------------------------------
# 12. V2 unified endpoint routing
# ---------------------------------------------------------------------------
# r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY tools/tests/test_onchain_tx_deep_trace.py

class TestV2EndpointRouting(unittest.TestCase):
    def test_v2_endpoint_used_when_chain_in_v2_chains(self):
        seen_urls: list[str] = []

        def fake_http(url: str):
            seen_urls.append(url)
            if "eth_getTransactionByHash" in url:
                return {"result": {"input": "0x", "from": "0xA", "to": "0xB", "value": "0x0",
                                   "gasPrice": "0x0", "blockNumber": "0x1", "blockHash": "0xbh",
                                   "transactionIndex": "0x0", "nonce": "0x0"}}
            if "eth_getTransactionReceipt" in url:
                return {"result": {"status": "0x1", "gasUsed": "0x5208", "logs": []}}
            if "txlistinternal" in url:
                return {"result": []}
            return {"results": []}

        tx_hash = "0x" + "b" * 64
        out = TRACE.fetch_tx(
            "bsc",
            tx_hash,
            api_keys={"bsc": "UNIFIED_KEY"},
            http_fn=fake_http,
            use_v2_chains={"bsc"},
            resolve_selector=False,
        )
        self.assertEqual(out["fetch_status"], "ok")
        # Every API URL should be the V2 unified endpoint, NOT the legacy bsc host.
        v2_seen = [u for u in seen_urls if "api.etherscan.io/v2/api" in u and "chainid=56" in u]
        self.assertEqual(len(v2_seen), 3)
        legacy_seen = [u for u in seen_urls if "api.bscscan.com" in u]
        self.assertEqual(legacy_seen, [])

    def test_legacy_endpoint_used_when_chain_absent_from_v2_chains(self):
        seen_urls: list[str] = []

        def fake_http(url: str):
            seen_urls.append(url)
            if "eth_getTransactionByHash" in url:
                return {"result": {"input": "0x", "from": "0xA", "to": "0xB", "value": "0x0",
                                   "gasPrice": "0x0", "blockNumber": "0x1", "blockHash": "0xbh",
                                   "transactionIndex": "0x0", "nonce": "0x0"}}
            if "eth_getTransactionReceipt" in url:
                return {"result": {"status": "0x1", "gasUsed": "0x5208", "logs": []}}
            if "txlistinternal" in url:
                return {"result": []}
            return None

        tx_hash = "0x" + "c" * 64
        out = TRACE.fetch_tx(
            "ethereum",
            tx_hash,
            api_keys={"ethereum": "LEGACY_KEY"},
            http_fn=fake_http,
            use_v2_chains=set(),
            resolve_selector=False,
        )
        self.assertEqual(out["fetch_status"], "ok")
        # Legacy endpoint should be used.
        legacy_seen = [u for u in seen_urls if u.startswith("https://api.etherscan.io/api")]
        self.assertEqual(len(legacy_seen), 3)
        v2_seen = [u for u in seen_urls if "/v2/api" in u]
        self.assertEqual(v2_seen, [])


# ---------------------------------------------------------------------------
# 13. Daily-cap throttle
# ---------------------------------------------------------------------------
# r36-rebuttal: lane-LIFT-7-RERUN-WITH-KEY tools/tests/test_onchain_tx_deep_trace.py

class TestDailyCapThrottle(unittest.TestCase):
    def test_acquire_returns_negative_once_daily_cap_reached(self):
        thr = TRACE.HostThrottle(global_qps=None, daily_cap=2, daily_used=0)
        # Two successful acquires fit within the cap.
        self.assertGreaterEqual(thr.acquire("h", 0.0, sleeper=lambda _w: None), 0.0)
        self.assertGreaterEqual(thr.acquire("h", 0.0, sleeper=lambda _w: None), 0.0)
        # Third acquire trips the cap; sentinel -1.0 returned.
        self.assertEqual(thr.acquire("h", 0.0, sleeper=lambda _w: None), -1.0)
        self.assertEqual(thr.daily_used, 2)

    def test_fetch_etherscan_returns_blocked_daily_cap(self):
        thr = TRACE.HostThrottle(global_qps=None, daily_cap=0, daily_used=0)

        def fake_http(url: str):
            raise AssertionError("HTTP should not fire when daily cap is exhausted")

        out = TRACE.fetch_etherscan_tx(
            "ethereum",
            "0x" + "d" * 64,
            "K",
            throttle=thr,
            http_fn=fake_http,
            use_v2=False,
        )
        self.assertEqual(out["fetch_status"], "blocked_daily_cap")


if __name__ == "__main__":
    unittest.main()
