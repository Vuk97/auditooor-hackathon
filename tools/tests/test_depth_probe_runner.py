"""Regression: depth-probe-runner --skip-existing must be content-aware.

A partial DRY-RUN pass (e.g. the dry-run stubs audit-deep writes so the pipeline
always advances) must NOT cause a later --live re-run to skip those batches: every
dry-run stub fails the anti-stub genuineness gate downstream, so a skipped stub
permanently pins the depth certificate at verdict=depth-pending. Under --live, a
batch on disk as dry-run stubs must be regenerated; an already-live batch is skipped.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("dpr", str(_TOOLS / "depth-probe-runner.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def _ws():
    d = Path(tempfile.mkdtemp())
    return d


def _packets(ws: Path, n: int) -> Path:
    p = ws / "guard_probe_packets.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write(json.dumps({
                "guard_id": f"g{i}", "file_line": f"src/A.sol:{i+1}",
                "code_excerpt": "function initialize(",
            }) + "\n")
    return p


def _write_batch(probes_dir: Path, bi: int, source: str, n: int = 3):
    probes_dir.mkdir(parents=True, exist_ok=True)
    rows = [json.dumps({
        "guard_id": f"g{j}", "file_line": f"src/A.sol:{j+1}",
        "code_excerpt": "function initialize(", "gap_found": False,
        "why_no_gap_or_exploit": "x", "probe_source": source,
    }) for j in range(n)]
    (probes_dir / f"batch_{bi:03d}.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")


class TestSkipExistingContentAware(unittest.TestCase):
    def _run(self, ws, probes_dir, *, live, skip_existing, fake_llm=None):
        orig_pf = m._live_provider_reachable
        if fake_llm is not None:
            orig = m._call_llm
            m._call_llm = fake_llm
            # a fake LLM means we want the live path to proceed, not fall back
            m._live_provider_reachable = lambda prov, wsp, **kw: (True, "ok")
        try:
            return m.run(
                workspace=ws,
                packets_path=_packets(ws, 3),
                probes_dir=probes_dir,
                batch_size=20,
                live=live,
                skip_existing=skip_existing,
            )
        finally:
            if fake_llm is not None:
                m._call_llm = orig
                m._live_provider_reachable = orig_pf

    def test_live_regenerates_dry_run_stub_batches(self):
        ws = _ws(); probes = ws / ".auditooor" / "asymmetry_probes"
        _write_batch(probes, 0, "depth-probe-runner-dry-run-auto")
        calls = {"n": 0}
        def fake_llm(user_msg, **kw):
            calls["n"] += 1
            return json.dumps([{
                "guard_id": "g0", "file_line": "src/A.sol:1",
                "code_excerpt": "function initialize(", "gap_found": False,
                "why_no_gap_or_exploit": "guarded by onlyProxy initializer; no unprivileged path",
                "probe_source": "depth-probe-runner-test",
            }])
        self._run(ws, probes, live=True, skip_existing=True, fake_llm=fake_llm)
        # the stale dry-run batch must have been regenerated live (LLM was called)
        self.assertEqual(calls["n"], 1, "live re-run must NOT skip a dry-run-stub batch")
        body = (probes / "batch_000.jsonl").read_text()
        self.assertNotIn("dry-run", body, "dry-run stub must be overwritten by live output")

    def test_live_skips_already_live_batches(self):
        ws = _ws(); probes = ws / ".auditooor" / "asymmetry_probes"
        _write_batch(probes, 0, "depth-probe-agent-claude")  # already live
        calls = {"n": 0}
        def fake_llm(user_msg, **kw):
            calls["n"] += 1
            return "[]"
        self._run(ws, probes, live=True, skip_existing=True, fake_llm=fake_llm)
        self.assertEqual(calls["n"], 0, "an already-live batch must still be skipped")

    def test_live_falls_back_to_agent_batches_when_no_provider(self):
        # --live with no reachable headless provider must emit agent batches for
        # orchestrator dispatch, NOT fail every batch (which pins cert depth-pending).
        ws = _ws(); probes = ws / ".auditooor" / "asymmetry_probes"
        orig = m._live_provider_reachable
        m._live_provider_reachable = lambda prov, wsp, **kw: (False, "no-api-key")
        try:
            res = m.run(
                workspace=ws, packets_path=_packets(ws, 3), probes_dir=probes,
                batch_size=20, live=True, skip_existing=False,
            )
        finally:
            m._live_provider_reachable = orig
        self.assertEqual(res["verdict"], "agent-batches-emitted")
        self.assertEqual(res["live_fallback_to_agent_batches"], "no-api-key")
        self.assertTrue((probes / "_agent_plan" / "batch_000.md").is_file())

    def test_emit_agent_batches_does_not_skip_dry_run_stub(self):
        # fallback path: emit-agent-batches with --skip-existing must still emit a
        # .md for a slot whose .jsonl on disk is a dry-run stub (else the dead-live
        # fallback can never replace stubs -> cert stays depth-pending).
        ws = _ws(); probes = ws / ".auditooor" / "asymmetry_probes"
        _write_batch(probes, 0, "depth-probe-runner-dry-run-auto")
        res = m.run(workspace=ws, packets_path=_packets(ws, 3), probes_dir=probes,
                    batch_size=20, live=False, skip_existing=True,
                    emit_agent_batches=True)
        self.assertEqual(res["verdict"], "agent-batches-emitted")
        self.assertTrue((probes / "_agent_plan" / "batch_000.md").is_file())

    def test_live_no_fallback_when_opted_out(self):
        import os
        ws = _ws(); probes = ws / ".auditooor" / "asymmetry_probes"
        orig = m._live_provider_reachable
        m._live_provider_reachable = lambda prov, wsp, **kw: (False, "no-api-key")
        os.environ["AUDITOOOR_DEPTH_PROBE_NO_AGENT_FALLBACK"] = "1"
        called = {"n": 0}
        orig_llm = m._call_llm
        def boom(*a, **k):
            called["n"] += 1
            raise RuntimeError("provider dead")
        m._call_llm = boom
        try:
            res = m.run(workspace=ws, packets_path=_packets(ws, 3), probes_dir=probes,
                        batch_size=20, live=True, skip_existing=False)
        finally:
            m._live_provider_reachable = orig
            m._call_llm = orig_llm
            del os.environ["AUDITOOOR_DEPTH_PROBE_NO_AGENT_FALLBACK"]
        # opted out: no fallback, the (dead) live path is attempted instead
        self.assertIsNone(res["live_fallback_to_agent_batches"])
        self.assertGreaterEqual(called["n"], 1)

    def test_dry_run_always_skips_existing(self):
        ws = _ws(); probes = ws / ".auditooor" / "asymmetry_probes"
        _write_batch(probes, 0, "depth-probe-runner-dry-run-auto")
        # no fake llm: dry-run must not regenerate (would be a no-op stub anyway)
        res = self._run(ws, probes, live=False, skip_existing=True)
        self.assertEqual(res["batches_ok"], 1)


class TestLiveProviderRouting(unittest.TestCase):
    def test_local_cli_command_uses_dispatch_provider_without_backend_duplication(self):
        ws = _ws()
        prompt = ws / "prompt.txt"
        cmd = m._build_dispatch_command(
            prompt,
            provider="local-cli",
            model="gpt-5-codex",
            max_tokens=123,
            workspace=ws,
        )
        self.assertEqual(cmd[cmd.index("--provider") + 1], "local-cli")
        self.assertEqual(cmd[cmd.index("--model") + 1], "gpt-5-codex")
        self.assertEqual(cmd[cmd.index("--max-tokens") + 1], "123")
        self.assertIn(str(ws / "agent_outputs"), cmd)
        self.assertNotIn("codex", cmd[:cmd.index("--provider")])

    def test_explicit_local_cli_unavailable_hard_fails_instead_of_emitting_agent_plan(self):
        ws = _ws()
        probes = ws / ".auditooor" / "depth_probes"
        calls = []
        original = m._call_llm

        def unavailable(user_msg, **kwargs):
            calls.append(kwargs["provider"])
            raise RuntimeError("llm-dispatch.py rc=2: cannot-run: local-cli unavailable")

        m._call_llm = unavailable
        try:
            result = m.run(
                workspace=ws,
                packets_path=_packets(ws, 1),
                probes_dir=probes,
                provider="local-cli",
                live=True,
            )
        finally:
            m._call_llm = original

        self.assertEqual(calls, ["local-cli"])
        self.assertEqual(result["batches_failed"], 1)
        self.assertEqual(result["verdict"], "all-batches-failed")
        self.assertIsNone(result["live_fallback_to_agent_batches"])
        self.assertFalse((probes / "_agent_plan" / "batch_000.md").exists())


def _write_kde(ws: Path, rows):
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)
    (aud / "known_dead_ends.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )


class TestDeadEndInjection(unittest.TestCase):
    """K3-deadend-injection: pre-emit drop + PRIOR DEAD-ENDS block injection."""

    def test_drops_guard_at_pinned_dead_end(self):
        ws = _ws()
        # src/A.sol:2 is a known dead-end -> the matching guard must be dropped.
        _write_kde(ws, [{"dead_end_id": "KDE-A2", "file_line": "src/A.sol:2",
                         "reason": "already drilled", "drop_class": "DROP"}])
        probes = ws / ".auditooor" / "depth_probes"
        res = m.run(workspace=ws, packets_path=_packets(ws, 3), probes_dir=probes,
                    batch_size=20, live=False, skip_existing=False)
        self.assertEqual(res["dead_ends_dropped"], 1)
        self.assertEqual(res["probes_emitted"], 2)  # 3 packets - 1 dead-end
        body = (probes / "batch_000.jsonl").read_text()
        self.assertNotIn("src/A.sol:2", body)

    def test_injects_prior_dead_end_block_into_agent_batch(self):
        ws = _ws()
        _write_kde(ws, [{"dead_end_id": "KDE-A1", "file_line": "src/A.sol:1",
                         "reason": "no unprivileged path", "drop_class": "NEGATIVE"}])
        probes = ws / ".auditooor" / "depth_probes"
        res = m.run(workspace=ws, packets_path=_packets(ws, 3), probes_dir=probes,
                    batch_size=20, emit_agent_batches=True)
        self.assertEqual(res["verdict"], "agent-batches-emitted")
        md = (probes / "_agent_plan" / "batch_000.md").read_text()
        self.assertIn("PRIOR DEAD-ENDS", md)
        self.assertIn("KDE-A1", md)
        # the dropped guard must NOT appear in the GUARD PACKETS payload.
        self.assertNotIn('"file_line": "src/A.sol:1"', md)

    def test_empty_kde_store_no_drop_no_injection(self):
        # No KDE store present -> behave exactly as today (no drop, no block).
        ws = _ws()
        probes = ws / ".auditooor" / "depth_probes"
        res = m.run(workspace=ws, packets_path=_packets(ws, 3), probes_dir=probes,
                    batch_size=20, emit_agent_batches=True)
        self.assertEqual(res["dead_ends_dropped"], 0)
        md = (probes / "_agent_plan" / "batch_000.md").read_text()
        self.assertNotIn("PRIOR DEAD-ENDS", md)
        # all 3 guards survive in the payload.
        for i in range(3):
            self.assertIn(f'"file_line": "src/A.sol:{i+1}"', md)

    def test_all_guards_dead_end_emits_empty_sentinel(self):
        ws = _ws()
        _write_kde(ws, [
            {"dead_end_id": f"KDE-{i}", "file_line": f"src/A.sol:{i+1}",
             "reason": "drilled", "drop_class": "DROP"} for i in range(3)
        ])
        probes = ws / ".auditooor" / "depth_probes"
        res = m.run(workspace=ws, packets_path=_packets(ws, 3), probes_dir=probes,
                    batch_size=20, live=False, skip_existing=False)
        self.assertEqual(res["dead_ends_dropped"], 3)
        self.assertEqual(res["probes_emitted"], 0)
        self.assertEqual(res["batches_ok"], 1)
        # empty sentinel slot exists.
        self.assertTrue((probes / "batch_000.jsonl").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestPacketSignatureInvalidation(unittest.TestCase):
    """When the candidate set changes (e.g. fork-scope keystone re-emits a smaller
    scoped manifest), --skip-existing must NOT reuse stale batch files built for the
    OLD packet set (they contaminate the cert with dropped/unscoped probes)."""

    def test_changed_packet_set_clears_stale_batches(self):
        ws = _ws()
        probes = ws / ".auditooor" / "asymmetry_probes"
        # Pre-seed a STALE batch + a signature for an OLD (different) packet set.
        _write_batch(probes, 0, "depth-probe-runner-dry-run-auto", n=20)
        (probes / ".packets_signature").write_text("OLDSIGNATURE", encoding="utf-8")
        stale_mtime = (probes / "batch_000.jsonl").stat().st_mtime
        # Run with a NEW packets file (3 packets, different content) dry-run.
        m.run(workspace=ws, packets_path=_packets(ws, 3), probes_dir=probes,
              batch_size=20, live=False, skip_existing=True)
        # signature now matches the new packets; batch_000 was cleared + regenerated
        sig = (probes / ".packets_signature").read_text().strip()
        self.assertNotEqual(sig, "OLDSIGNATURE", "signature must update to the new set")
        self.assertTrue((probes / "batch_000.jsonl").is_file())
        self.assertNotEqual((probes / "batch_000.jsonl").stat().st_mtime, stale_mtime,
                            "stale batch must be cleared + regenerated, not reused")

    def test_same_packet_set_keeps_batches(self):
        ws = _ws()
        probes = ws / ".auditooor" / "asymmetry_probes"
        pk = _packets(ws, 3)
        # First run stamps the signature + writes batches.
        m.run(workspace=ws, packets_path=pk, probes_dir=probes,
              batch_size=20, live=False, skip_existing=True)
        b0_mtime = (probes / "batch_000.jsonl").stat().st_mtime
        # Second run with the SAME packets -> signature matches -> batch kept (skip).
        m.run(workspace=ws, packets_path=pk, probes_dir=probes,
              batch_size=20, live=False, skip_existing=True)
        self.assertEqual((probes / "batch_000.jsonl").stat().st_mtime, b0_mtime,
                         "unchanged packet set must reuse (not clear) existing batches")
