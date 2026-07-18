"""Hermetic tests for ``tools/hackerman-etl-from-onchain-traces.py`` (W5 L3).

All trace payloads are synthetic fixtures injected via the ``prefetched``
argument to ``convert`` - the trace API is mocked, zero live network. The
honest-zero gate is exercised explicitly: with no seeds, or with seeds
but no ``--fetch`` / cache, the miner emits BLOCKED-NO-REAL-SOURCE and
zero records.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-onchain-traces.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


MINER = _load(TOOL, "hackerman_etl_from_onchain_traces")


# ---------------------------------------------------------------------------
# Synthetic fixtures (synthetic_fixture: true).
#
# Two synthetic decoded-trace payloads. The hashes are syntactically
# valid 32-byte hashes used only to drive the parser; they do not need to
# reference a real exploit because the test never reaches the network.
# ---------------------------------------------------------------------------

TX_A = "0x" + "ab" * 32  # flash-loan / reentrancy shaped
TX_B = "0x" + "cd" * 32  # oracle-manipulation shaped
TX_BAD = "0xdeadbeef"    # syntactically invalid (too short)

API_BASE = "https://api.openchain.xyz/trace/v1"


def _trace_url(chain: str, tx: str) -> str:
    return f"{API_BASE}/{chain}/{tx}"


TRACE_A = {
    "result": {
        "type": "CALL",
        "from": "0xattacker000000000000000000000000000000aa",
        "to": "0xvictimpool00000000000000000000000000000bb",
        "function": "flashLoan(uint256)",
        "value": "0",
        "calls": [
            {
                "type": "CALL",
                "from": "0xvictimpool00000000000000000000000000000bb",
                "to": "0xtoken0000000000000000000000000000000000cc",
                "function": "transfer(address,uint256)",
                "calls": [
                    {
                        "type": "CALL",
                        "from": "0xtoken0000000000000000000000000000000000cc",
                        "to": "0xvictimpool00000000000000000000000000000bb",
                        "function": "donateToReserves(uint256)",
                    }
                ],
            }
        ],
    },
    "timestamp": "2023-03-13T18:00:00Z",
}

TRACE_B = {
    "trace": {
        "callType": "CALL",
        "caller": "0xattacker000000000000000000000000000000aa",
        "target": "0xlending00000000000000000000000000000000dd",
        "method": "liquidate(address)",
        "subcalls": [
            {
                "callType": "STATICCALL",
                "caller": "0xlending00000000000000000000000000000000dd",
                "target": "0xoracle0000000000000000000000000000000000ee",
                "method": "latestAnswer()",
            }
        ],
    },
}


class TestHonestZeroGate(unittest.TestCase):
    def test_no_seeds_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            summary = MINER.convert(Path(td) / "out", seeds=[])
        self.assertTrue(summary["blocked"])
        self.assertEqual(summary["blocked_reason"], "BLOCKED-NO-REAL-SOURCE-NO-SEEDS")
        self.assertEqual(summary["records_emitted"], 0)

    def test_seeds_but_no_fetch_no_cache_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            summary = MINER.convert(
                Path(td) / "out",
                seeds=[(TX_A, "ethereum")],
                fetch_live=False,
            )
        self.assertTrue(summary["blocked"])
        self.assertEqual(summary["blocked_reason"], "BLOCKED-NO-REAL-SOURCE")
        self.assertEqual(summary["records_emitted"], 0)

    def test_cli_no_seeds_returns_zero_and_prints_blocked(self):
        # Honest-zero is an explicit verdict, not an error exit.
        with tempfile.TemporaryDirectory() as td:
            rc = MINER.main(["--out-dir", str(Path(td) / "out"), "--json-summary"])
        self.assertEqual(rc, 0)


class TestTxHashParsing(unittest.TestCase):
    def test_normalize_valid_and_invalid(self):
        self.assertEqual(MINER.normalize_tx_hash(TX_A.upper()), TX_A)
        self.assertIsNone(MINER.normalize_tx_hash(TX_BAD))
        self.assertIsNone(MINER.normalize_tx_hash("not-a-hash"))

    def test_parse_tx_arg_bare_and_chained(self):
        self.assertEqual(MINER.parse_tx_arg(TX_A), (TX_A, "ethereum"))
        self.assertEqual(MINER.parse_tx_arg(f"{TX_B}:arbitrum"), (TX_B, "arbitrum"))
        # Unknown chain falls back to ethereum.
        self.assertEqual(MINER.parse_tx_arg(f"{TX_A}:notachain"), (TX_A, "ethereum"))
        # Invalid hash -> None (no fabricated hash).
        self.assertIsNone(MINER.parse_tx_arg(TX_BAD))
        self.assertIsNone(MINER.parse_tx_arg(""))

    def test_load_tx_hashes_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "txs.txt"
            p.write_text(
                f"# comment\n{TX_A}\n{TX_B} arbitrum\n{TX_BAD}\n{TX_A}\n",
                encoding="utf-8",
            )
            seeds = MINER.load_tx_hashes(p)
        # TX_A deduped, TX_BAD dropped, TX_B chain honoured.
        self.assertEqual(seeds, [(TX_A, "ethereum"), (TX_B, "arbitrum")])

    def test_scan_seed_corpus_extracts_hashes(self):
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "corpus"
            (corpus / "incident").mkdir(parents=True)
            (corpus / "incident" / "record.json").write_text(
                json.dumps({"notes": f"exploit tx {TX_A}"}), encoding="utf-8"
            )
            (corpus / "incident" / "record.yaml").write_text(
                f"source_audit_ref: see {TX_B}\n", encoding="utf-8"
            )
            seeds = MINER.scan_seed_corpus(corpus)
        found = {tx for tx, _chain in seeds}
        self.assertIn(TX_A, found)
        self.assertIn(TX_B, found)


class TestCallPathFlattening(unittest.TestCase):
    def test_flatten_nested_result_wrapper(self):
        path = MINER.flatten_call_path(TRACE_A)
        # 3 frames: flashLoan -> transfer -> donateToReserves.
        self.assertEqual(len(path), 3)
        self.assertEqual(path[0]["depth"], 0)
        self.assertEqual(path[0]["function"], "flashLoan(uint256)")
        self.assertEqual(path[2]["depth"], 2)
        self.assertEqual(path[2]["function"], "donateToReserves(uint256)")

    def test_flatten_trace_wrapper_key_aliases(self):
        path = MINER.flatten_call_path(TRACE_B)
        self.assertEqual(len(path), 2)
        self.assertEqual(path[0]["function"], "liquidate(address)")
        self.assertEqual(path[1]["function"], "latestAnswer()")

    def test_empty_payload_yields_empty_path(self):
        self.assertEqual(MINER.flatten_call_path({}), [])
        self.assertEqual(MINER.flatten_call_path(None), [])

    def test_classify_call_path(self):
        ac, ic = MINER.classify_call_path(MINER.flatten_call_path(TRACE_A))
        # flashLoan keyword wins (table order).
        self.assertEqual(ac, "flash-loan")
        self.assertEqual(ic, "theft")
        ac2, _ic2 = MINER.classify_call_path(MINER.flatten_call_path(TRACE_B))
        self.assertIn(ac2, ("oracle-manipulation", "liquidation-abuse"))


class TestRecordEmission(unittest.TestCase):
    def _prefetched(self):
        return {
            _trace_url("ethereum", TX_A): json.dumps(TRACE_A).encode("utf-8"),
            _trace_url("arbitrum", TX_B): json.dumps(TRACE_B).encode("utf-8"),
        }

    def test_convert_emits_records_from_prefetched(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            summary = MINER.convert(
                out,
                seeds=[(TX_A, "ethereum"), (TX_B, "arbitrum")],
                prefetched=self._prefetched(),
                dry_run=False,
            )
            self.assertFalse(summary["blocked"])
            self.assertEqual(summary["records_emitted"], 2)
            self.assertEqual(summary["traces_fetched"], 2)
            # Both record.json files exist on disk.
            for f in summary["files"]:
                self.assertTrue(Path(f).exists(), f)

    def test_every_record_carries_first_class_tier2(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            MINER.convert(
                out,
                seeds=[(TX_A, "ethereum"), (TX_B, "arbitrum")],
                prefetched=self._prefetched(),
                dry_run=False,
            )
            recs = list(out.rglob("record.json"))
            self.assertEqual(len(recs), 2)
            for rp in recs:
                rec = json.loads(rp.read_text(encoding="utf-8"))
                # Rule 37: first-class non-empty verification_tier.
                self.assertEqual(
                    rec["verification_tier"], "tier-2-verified-public-archive"
                )
                self.assertEqual(rec["verification_tier"], MINER.VERIFICATION_TIER)
                # Tier must NOT be smuggled into the tag bag (Rule 37).
                self.assertNotIn(
                    "verification_tier", rec["function_shape"]["shape_tags"]
                )
                # Real-source: resolvable trace URL + real tx hash.
                ext = rec["record_extensions"]
                self.assertTrue(ext["tx_hash"].startswith("0x"))
                self.assertEqual(len(ext["tx_hash"]), 66)
                self.assertIn(ext["tx_hash"], rec["record_source_url"])
                self.assertGreater(ext["call_frame_count"], 0)
                self.assertEqual(rec["schema_version"], MINER.SCHEMA_VERSION)

    def test_record_carries_call_path_structure(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            MINER.convert(
                out,
                seeds=[(TX_A, "ethereum")],
                prefetched={_trace_url("ethereum", TX_A): json.dumps(TRACE_A).encode("utf-8")},
                dry_run=False,
            )
            rec = json.loads(next(out.rglob("record.json")).read_text(encoding="utf-8"))
        call_path = rec["record_extensions"]["call_path"]
        self.assertEqual([f["depth"] for f in call_path], [0, 1, 2])
        self.assertIn("flashLoan", rec["attacker_action_sequence"])

    def test_unparseable_trace_does_not_emit(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            summary = MINER.convert(
                out,
                seeds=[(TX_A, "ethereum")],
                prefetched={_trace_url("ethereum", TX_A): b"<<not json>>"},
                dry_run=False,
            )
        self.assertEqual(summary["records_emitted"], 0)
        self.assertTrue(summary["errors"])

    def test_empty_trace_does_not_emit_fabricated_record(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            summary = MINER.convert(
                out,
                seeds=[(TX_A, "ethereum")],
                prefetched={_trace_url("ethereum", TX_A): b"{}"},
                dry_run=False,
            )
        # Empty call path -> no fabricated trace record.
        self.assertEqual(summary["records_emitted"], 0)

    def test_dry_run_writes_no_files(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            summary = MINER.convert(
                out,
                seeds=[(TX_A, "ethereum")],
                prefetched={_trace_url("ethereum", TX_A): json.dumps(TRACE_A).encode("utf-8")},
                dry_run=True,
            )
        self.assertEqual(summary["records_emitted"], 1)
        self.assertFalse(list(out.rglob("record.json")))

    def test_cache_file_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "cache.json"
            out1 = Path(td) / "out1"
            # First pass: prefetched -> write cache.
            MINER.convert(
                out1,
                seeds=[(TX_A, "ethereum")],
                prefetched={_trace_url("ethereum", TX_A): json.dumps(TRACE_A).encode("utf-8")},
                write_cache_file=cache,
                dry_run=True,
            )
            self.assertTrue(cache.exists())
            # Second pass: offline replay from cache, no seeds, no fetch.
            out2 = Path(td) / "out2"
            summary = MINER.convert(out2, seeds=[(TX_A, "ethereum")], cache_file=cache, dry_run=False)
        self.assertFalse(summary["blocked"])
        self.assertEqual(summary["records_emitted"], 1)


if __name__ == "__main__":
    unittest.main()
