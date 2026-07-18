"""Tests for the mechanical depth-probe tools (no-agent verify/ingest + context extract)."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load(name, fname):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / fname)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


INGEST = _load("depth_probe_ingest", "depth-probe-ingest.py")
EXTRACT = _load("guard_context_extract", "guard-context-extract.py")


def _ws(tmp):
    ws = Path(tmp)
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / "src").mkdir(parents=True, exist_ok=True)
    (ws / "src" / "x.rs").write_text(
        "fn verify() {\n    let a = 1;\n    require(counteredBy == 0);\n    ok\n}\n", encoding="utf-8"
    )
    return ws


class IngestTest(unittest.TestCase):
    def _run(self, probes, ws, ingest=True):
        p = ws / "probes.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in probes) + "\n", encoding="utf-8")
        return INGEST.ingest(ws, p, ws, None, ingest)

    def test_real_excerpt_passes_r76_and_ingests(self):
        # Reason is cert-SUBSTANTIVE: it cites the file:line and the actual
        # `require(...)` code (the cert builder's authoritative substantive gate,
        # which the ingest now shares verbatim).
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            out = self._run([{"guard_id": "G1", "file_line": "src/x.rs:3",
                              "code_excerpt": "require(counteredBy == 0)", "gap_found": False,
                              "why_no_gap_or_exploit": "Checks `require(counteredBy == 0)` at src/x.rs:3; every "
                              "passing input preserves the no-challenge invariant because the slot is "
                              "content-addressed and not caller-forgeable."}], ws)
            self.assertEqual(out["r76_pass"], 1)
            self.assertEqual(out["r76_fail"], 0)
            self.assertEqual(out["genuine"], 1)
            self.assertEqual(out["ingested"], 1)
            self.assertTrue((ws / ".auditooor" / "negative_space_gaps.jsonl").is_file())

    def test_non_substantive_reason_rejected_like_cert(self):
        # A long (>80 char) reason that cites NO file:line / code / keyword is
        # NOT genuine under the cert-authoritative substantive gate, even though
        # the old length-only ingest gate would have accepted it. R76 passes
        # (real excerpt) but the row is dropped as a non-substantive stub.
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            out = self._run([{"guard_id": "NS1", "file_line": "src/x.rs:3",
                              "code_excerpt": "require(counteredBy == 0)", "gap_found": False,
                              "why_no_gap_or_exploit": "Every passing input preserves the no-challenge "
                              "invariant because the slot is content-addressed and not caller-forgeable by an "
                              "unprivileged party anywhere in this code path whatsoever."}], ws)
            self.assertEqual(out["r76_pass"], 1)
            self.assertEqual(out["genuine"], 0)
            self.assertEqual(out["ingested"], 0)

    def test_fake_excerpt_dropped_by_r76(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            out = self._run([{"guard_id": "G2", "file_line": "src/x.rs:3",
                              "code_excerpt": "TOTALLY_FAKE_SYMBOL_not_in_source_zzz", "gap_found": False,
                              "why_no_gap_or_exploit": "a long plausible-sounding reason that nonetheless cites a "
                              "code excerpt which does not exist anywhere in the real source tree."}], ws)
            self.assertEqual(out["r76_fail"], 1)
            self.assertEqual(out["genuine"], 0)

    def test_line_referenced_real_excerpt_counts_as_specific(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            out = self._run([{"guard_id": "G3", "file_line": "src/x.rs:3",
                              "code_excerpt": "require(counteredBy == 0)", "gap_found": False,
                              "why_no_gap_or_exploit": "Line 3 rejects nonzero counteredBy before ok is reached."}], ws)
            self.assertEqual(out["r76_pass"], 1)
            self.assertEqual(out["genuine"], 1)

    def test_small_sample_distinct_not_flagged_bulk(self):
        # the small-sample fix: 2 distinct SUBSTANTIVE probes must NOT be bulk.
        # Each reason cites the file:line + the actual checked statement so it
        # passes the cert-authoritative substantive gate the ingest now shares.
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            out = self._run([
                {"guard_id": "G1", "file_line": "src/x.rs:3", "code_excerpt": "require(counteredBy == 0)",
                 "gap_found": False, "why_no_gap_or_exploit": "Distinct reason: `require(counteredBy == 0)` at "
                 "src/x.rs:3 makes the counteredBy slot content-addressed and not forgeable by an unprivileged caller."},
                {"guard_id": "G1b", "file_line": "src/x.rs:1", "code_excerpt": "fn verify",
                 "gap_found": False, "why_no_gap_or_exploit": "A different distinct reason: the `fn verify` entry at "
                 "src/x.rs:1 has no value-bearing state mutation before the require check at line 3."},
            ], ws)
            self.assertFalse(out["bulk_template_detected"])
            self.assertEqual(out["genuine"], 2)

    def test_bulk_identical_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            same = ("Probed: guard adjudicated against its protected invariant; no negative-space gap found "
                    "at this site whatsoever and the check is complete.")
            probes = [{"guard_id": f"B{i}", "file_line": "src/x.rs:3", "code_excerpt": "require(counteredBy == 0)",
                       "gap_found": False, "why_no_gap_or_exploit": same} for i in range(5)]
            out = self._run(probes, ws)
            self.assertTrue(out["bulk_template_detected"])
            self.assertGreaterEqual(out["largest_template_cluster"], 3)
            self.assertEqual(out["genuine"], 0)

    def test_positive_split_for_escalation(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            out = self._run([{"guard_id": "P1", "file_line": "src/x.rs:3",
                              "code_excerpt": "require(counteredBy == 0)", "gap_found": True,
                              "why_no_gap_or_exploit": "GAP at src/x.rs:3: `require(counteredBy == 0)` checks only "
                              "counteredBy and not game resolution; a freshly-created in-progress game passes with "
                              "a forged root claim."}], ws)
            self.assertEqual(out["positives"], 1)
            self.assertIn("P1", out["positives_detail"])


class ExtractTest(unittest.TestCase):
    def test_packets_compact_and_read_once(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            wl = ws / ".auditooor" / "negative_space_worklist.jsonl"
            wl.write_text("\n".join(json.dumps(r) for r in [
                {"guard_id": "G1", "file_line": "src/x.rs:3", "checks": "counteredBy==0",
                 "invariant_hint": "game must be resolved"},
                {"guard_id": "G2", "file_line": "src/x.rs:1", "checks": "fn entry",
                 "invariant_hint": "no state mutation"},
            ]) + "\n", encoding="utf-8")
            out_path = ws / ".auditooor" / "guard_probe_packets.jsonl"
            out = EXTRACT.extract(ws, ws, 40, None, out_path)
            self.assertEqual(out["packets_written"], 2)
            self.assertEqual(out["files_read"], 1)  # x.rs read ONCE for both guards
            self.assertEqual(out["unresolved"], 0)
            packets = [json.loads(l) for l in out_path.read_text().splitlines() if l.strip()]
            self.assertIn("function_context", packets[0])
            self.assertIn("counteredBy", packets[0]["function_context"])
            # compact: a packet's context is far smaller than a full agent file read
            self.assertLess(len(packets[0]["function_context"]), 5000)

    def test_unresolved_counted_not_crashed(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            wl = ws / ".auditooor" / "negative_space_worklist.jsonl"
            wl.write_text(json.dumps({"guard_id": "G9", "file_line": "src/nope.rs:5"}) + "\n", encoding="utf-8")
            out = EXTRACT.extract(ws, ws, 40, None, ws / ".auditooor" / "p.jsonl")
            self.assertEqual(out["unresolved"], 1)
            self.assertEqual(out["packets_written"], 0)

    def test_invariant_context_incomplete_flags_generic_proxy_guard(self):
        # NS-628de923949e miss class: a mechanical overflow guard (checked_abs on
        # an i64 widened to i128) is vacuously safe in its narrow window, but the
        # real load-bearing invariant (abs <= MAX_MONEY) is defined by a generic
        # type parameter `<C: Constraint>` + a named constant OUTSIDE the guard
        # line. The packet must (a) flag invariant_context_incomplete, (b) carry
        # the impl header with the generic bound, (c) carry the MAX_MONEY def.
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            (ws / "src").mkdir(parents=True, exist_ok=True)
            (ws / "src" / "amount.rs").write_text(
                "//! amount\n"
                "pub const MAX_MONEY: i64 = 2_100_000_000_000_000;\n"
                "pub const COIN: i64 = 100_000_000;\n"
                "\n"
                "impl<C: Constraint> From<Amount<C>> for jubjub::Fr {\n"
                "    fn from(a: Amount<C>) -> Self {\n"
                "        let magnitude = i128::from(a.0).checked_abs().expect(\"abs overflow\");\n"
                "        Self::from(magnitude as u64)\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            wl = ws / ".auditooor" / "negative_space_worklist.jsonl"
            wl.write_text(json.dumps({
                "guard_id": "NS-628de923949e", "file_line": "src/amount.rs:7",
                "checks": "checked_abs overflow",
                "invariant_hint": "abs must be within the monetary range",
            }) + "\n", encoding="utf-8")
            out_path = ws / ".auditooor" / "p.jsonl"
            out = EXTRACT.extract(ws, ws, 40, None, out_path)
            self.assertEqual(out["packets_written"], 1)
            self.assertEqual(out["invariant_context_incomplete"], 1)
            pkt = json.loads(out_path.read_text().splitlines()[0])
            self.assertTrue(pkt["invariant_context_incomplete"])
            self.assertIn("impl<C: Constraint>", pkt["impl_header"])
            self.assertTrue(any("MAX_MONEY" in d for d in pkt["referenced_const_defs"]))
            self.assertIn("escalate", pkt["escalation_reason"].lower())
            # still compact: well under the 1500-token budget
            self.assertLess(out["approx_tokens_per_packet"], 1500)

    def test_parser_guard_carries_caller_and_sink_context(self):
        # HB packet-miss class (NS-b8ef09c25261 / NS-9f940d402058): a guard inside
        # a SCALE decoder is correct on its visible line, but the exploitable gap
        # is in the CALLER's dispatch loop (offset desync) or a DOWNSTREAM sink
        # (Bytes.substr / abi.decode, possibly cross-file). The packet must flag
        # windowing_incomplete and carry caller_loop_context + downstream_sink_context.
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            src = ws / "src" / "consensus"
            src.mkdir(parents=True, exist_ok=True)
            (src / "Codec.sol").write_text(
                "library Codec {\n"
                "    function DecodeHeader(bytes memory encoded) internal pure {\n"
                "        for (uint256 i = 0; i < length; i++) {\n"
                "            uint8 kind = readByte(slice);\n"
                "            if (kind == DIGEST_ITEM_CONSENSUS) { decode(slice); }\n"
                "        }\n"
                "    }\n"
                "    function readByte(ByteSlice memory self) internal pure returns (uint8) {\n"
                "        require(self.offset + 1 <= self.data.length);\n"
                "        return uint8(self.data[self.offset]);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            (src / "Types.sol").write_text(
                "library Types {\n"
                "    function stateCommitment(Header memory self) internal pure {\n"
                "        mmrRoot = Bytes.toBytes32(Bytes.substr(self.digests[j].consensus.data, 0, 32));\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            wl = ws / ".auditooor" / "negative_space_worklist.jsonl"
            wl.write_text(json.dumps({
                "guard_id": "NS-b8ef09c25261", "file_line": "src/consensus/Codec.sol:9",
                "checks": "require(self.offset + 1 <= self.data.length);",
                "invariant_hint": "length / bounds check",
            }) + "\n", encoding="utf-8")
            out_path = ws / ".auditooor" / "p.jsonl"
            out = EXTRACT.extract(ws, ws, 40, None, out_path)
            self.assertEqual(out["packets_written"], 1)
            self.assertEqual(out["windowing_incomplete"], 1)
            pkt = json.loads(out_path.read_text().splitlines()[0])
            self.assertTrue(pkt["windowing_incomplete"])
            self.assertTrue(pkt["invariant_context_incomplete"])
            # caller dispatch loop captured
            self.assertIn("readByte(slice)", pkt["caller_loop_context"])
            self.assertIn("if (kind ==", pkt["caller_loop_context"])
            # cross-file sink captured
            self.assertIn("substr", pkt["downstream_sink_context"])
            self.assertIn("Types.sol", pkt["downstream_sink_context"])
            self.assertIn("escalate", pkt["escalation_reason"].lower())
            # still within the ~1500-token packet budget
            self.assertLess(out["approx_tokens_per_packet"], 1500)

    def test_proof_router_carries_child_verifier_callee_body(self):
        # HB packet-miss class NS-e986be6f56eb: the guard is a proof-router
        # `verify(...)` that strips a leading byte and forwards `encodedProof[1:]`
        # to a CHILD verifier (sp1Beefy/ecdsaBeefy). The exploitable gap is the
        # child's `abi.decode(proof,...)` panicking on a zero-length stripped
        # proof - a body in a SIBLING file the single-guard packet cannot see.
        # The packet must carry callee_body_context with the child verify sink.
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            src = ws / "src" / "consensus"
            src.mkdir(parents=True, exist_ok=True)
            (src / "ConsensusRouter.sol").write_text(
                "contract ConsensusRouter {\n"
                "    function verify(bytes calldata previousState, bytes calldata encodedProof)\n"
                "        external view returns (bytes memory)\n"
                "    {\n"
                "        if (encodedProof.length == 0) revert EmptyProof();\n"
                "        bytes calldata actualProof = encodedProof[1:];\n"
                "        return IConsensusV2(address(ecdsaBeefy)).verify(previousState, actualProof);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            (src / "EcdsaBeefy.sol").write_text(
                "contract EcdsaBeefy {\n"
                "    function verify(bytes calldata previousState, bytes calldata proof)\n"
                "        external view returns (bytes memory)\n"
                "    {\n"
                "        (RelayChainProof memory relay) = abi.decode(proof, (RelayChainProof));\n"
                "        return relay.data;\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            wl = ws / ".auditooor" / "negative_space_worklist.jsonl"
            wl.write_text(json.dumps({
                "guard_id": "NS-e986be6f56eb", "file_line": "src/consensus/ConsensusRouter.sol:2",
                "checks": "function verify(bytes calldata previousState, bytes calldata encodedProof)",
                "invariant_hint": "unknown - agent to infer the protected invariant from context",
            }) + "\n", encoding="utf-8")
            out_path = ws / ".auditooor" / "p.jsonl"
            out = EXTRACT.extract(ws, ws, 40, None, out_path)
            self.assertEqual(out["packets_written"], 1)
            self.assertEqual(out["windowing_incomplete"], 1)
            pkt = json.loads(out_path.read_text().splitlines()[0])
            self.assertTrue(pkt["windowing_incomplete"])
            # the stripped-proof forward is in the caller/own-body view
            self.assertIn("encodedProof[1:]", pkt["caller_loop_context"])
            # the CHILD verifier body's abi.decode(proof,...) sink is pulled in
            self.assertIn("callee_body_context", pkt)
            self.assertIn("EcdsaBeefy.sol", pkt["callee_body_context"])
            self.assertIn("abi.decode(proof", pkt["callee_body_context"])
            self.assertIn("escalate", pkt["escalation_reason"].lower())
            self.assertLess(out["approx_tokens_per_packet"], 1500)

    def test_downstream_sink_ranked_by_fn_product_relevance(self):
        # NS-9f940d402058 miss: the guard fn `read()` returns bytes that flow into
        # `.consensus.data` consumed by a substr sink in Types.sol. A DISTRACTOR
        # sibling carries an unrelated abi.decode sink. The ranker must surface the
        # relevant substr-of-consensus.data sink FIRST, not the alphabetically-first
        # distractor.
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            src = ws / "src" / "consensus"
            src.mkdir(parents=True, exist_ok=True)
            (src / "Codec.sol").write_text(
                "library Codec {\n"
                "    function read(ByteSlice memory self, uint256 len) internal pure returns (bytes memory) {\n"
                "        require(self.offset + len <= self.data.length);\n"
                "        if (len == 0) { return \"\"; }\n"
                "        return slice;\n"
                "    }\n"
                "    function DecodeHeader(bytes memory e) internal pure returns (Header memory) {\n"
                "        digest.consensus = decodeDigestItem(slice);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            # distractor sibling: an abi.decode sink that does NOT reference the
            # guard fn's product (consensus.data / Header).
            (src / "AAADistractor.sol").write_text(
                "contract AAADistractor {\n"
                "    function foo(bytes memory raw) internal pure {\n"
                "        Unrelated memory u = abi.decode(raw, (Unrelated));\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            (src / "Types.sol").write_text(
                "library Types {\n"
                "    function stateCommitment(Header memory self) internal pure {\n"
                "        mmrRoot = Bytes.toBytes32(Bytes.substr(self.digests[j].consensus.data, 0, 32));\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            wl = ws / ".auditooor" / "negative_space_worklist.jsonl"
            wl.write_text(json.dumps({
                "guard_id": "NS-9f940d402058", "file_line": "src/consensus/Codec.sol:3",
                "checks": "require(self.offset + len <= self.data.length);",
                "invariant_hint": "length / bounds check",
            }) + "\n", encoding="utf-8")
            out_path = ws / ".auditooor" / "p.jsonl"
            out = EXTRACT.extract(ws, ws, 40, None, out_path)
            pkt = json.loads(out_path.read_text().splitlines()[0])
            sink = pkt["downstream_sink_context"]
            # the relevant substr-of-consensus.data sink must appear, and rank
            # ABOVE the unrelated abi.decode distractor.
            self.assertIn("consensus.data", sink)
            self.assertIn("Types.sol", sink)
            if "AAADistractor.sol" in sink:
                self.assertLess(sink.index("Types.sol"), sink.index("AAADistractor.sol"))

    def test_simple_guard_not_flagged_incomplete(self):
        # a plain non-generic guard with no out-of-window constant bound must NOT
        # be flagged incomplete - the heuristic must not fire on every guard.
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)  # src/x.rs: fn verify() { require(counteredBy == 0); }
            wl = ws / ".auditooor" / "negative_space_worklist.jsonl"
            wl.write_text(json.dumps({
                "guard_id": "G1", "file_line": "src/x.rs:3", "checks": "counteredBy==0",
                "invariant_hint": "no challenge",
            }) + "\n", encoding="utf-8")
            out_path = ws / ".auditooor" / "p.jsonl"
            out = EXTRACT.extract(ws, ws, 40, None, out_path)
            # require(counteredBy == 0) is mechanical (== 0) but no generic param
            # and no out-of-window named-constant bound -> not flagged.
            self.assertEqual(out["invariant_context_incomplete"], 0)


if __name__ == "__main__":
    unittest.main()
