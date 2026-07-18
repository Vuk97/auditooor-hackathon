#!/usr/bin/env python3
"""Tests for tools/base-block-delay-probe.py (PR #546 Wave 10 / Lane H).

Stdlib-only. Synthetic workspaces under tempdir — no dependency on
~/audits/.

Coverage matrix:
  1. Synthetic Rust handler with attacker-controlled `Vec<u8>` decode loop
     -> flagged.
  2. Synthetic with bounded fixed-array loop -> NOT flagged.
  3. Recursive proof verifier -> flagged.
  4. RPC handler with unbounded Vec<H256> input -> flagged.
  5. Output schema and file structure (results md, thresholds md, harness
     scaffold, candidates JSON).
  6. Idempotency: rerunning produces stable output.
  7. --strict exits 1 when candidates are emitted.
  8. Empty workspace produces zero candidates and still writes scaffold.
  9. Real-corpus smoke: probe runs against the auditooor repo itself
     without raising and produces deterministic output.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "base-block-delay-probe.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "base_block_delay_probe", TOOL
    )
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["base_block_delay_probe"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_module()


def _run(args: list, *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(cwd) if cwd else None,
    )


# ---------------------------------------------------------------------------
# Synthetic Rust source helpers
# ---------------------------------------------------------------------------

ATTACKER_VEC_DECODE = textwrap.dedent(
    """\
    pub fn handle_payload(input: Vec<u8>) -> Result<()> {
        for i in 0..input.len() {
            decode_chunk(input[i]);
        }
        Ok(())
    }
    """
)

BOUNDED_FIXED_ARRAY = textwrap.dedent(
    """\
    pub fn bounded_sum(input: &[u8; 32]) -> u32 {
        let mut s = 0u32;
        for b in input.iter() {
            s = s.wrapping_add(*b as u32);
        }
        s
    }
    """
)

RECURSIVE_PROOF = textwrap.dedent(
    """\
    pub fn verify_proof_inner(node: &Node) -> Result<()> {
        verify_proof_recursive(node.left())?;
        verify_proof_recursive(node.right())?;
        Ok(())
    }
    """
)

RPC_UNBOUNDED_VEC = textwrap.dedent(
    """\
    pub async fn eth_getProofs(addrs: Vec<H256>) -> Result<Vec<Proof>> {
        let mut out = Vec::new();
        for a in addrs {
            out.push(keccak(a));
        }
        Ok(out)
    }
    """
)


def _make_workspace(files: dict[str, str]) -> Path:
    ws = Path(tempfile.mkdtemp(prefix="bdp_ws_"))
    for rel, content in files.items():
        full = ws / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
    return ws


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBlockDelayProbe(unittest.TestCase):
    def test_attacker_vec_decode_flagged(self):
        ws = _make_workspace({"external/foo/src/lib.rs": ATTACKER_VEC_DECODE})
        cands = _MOD.scan_workspace(ws / "external")
        self.assertTrue(
            any(c.pattern_id == "unbounded_payload_decode" for c in cands),
            f"expected unbounded_payload_decode in {[c.pattern_id for c in cands]}",
        )

    def test_bounded_loop_not_flagged(self):
        ws = _make_workspace({"external/foo/src/lib.rs": BOUNDED_FIXED_ARRAY})
        cands = _MOD.scan_workspace(ws / "external")
        # Bounded fixed-array loop must NOT trigger any A6 pattern.
        self.assertEqual(
            cands,
            [],
            f"bounded fixed-array loop should not be flagged; got {cands}",
        )

    def test_recursive_proof_flagged(self):
        ws = _make_workspace({"external/foo/src/proof.rs": RECURSIVE_PROOF})
        cands = _MOD.scan_workspace(ws / "external")
        self.assertTrue(
            any(c.pattern_id == "recursive_proof_verification" for c in cands),
            f"expected recursive_proof_verification in {[c.pattern_id for c in cands]}",
        )

    def test_rpc_unbounded_vec_flagged(self):
        ws = _make_workspace({"external/foo/src/rpc.rs": RPC_UNBOUNDED_VEC})
        cands = _MOD.scan_workspace(ws / "external")
        self.assertTrue(
            any(c.pattern_id == "rpc_handler_unbounded_iter" for c in cands),
            f"expected rpc_handler_unbounded_iter in {[c.pattern_id for c in cands]}",
        )

    def test_skip_dirs_excluded(self):
        # A file inside `target/` or `tests/` should NOT be scanned.
        ws = _make_workspace(
            {
                "external/foo/target/release/build.rs": ATTACKER_VEC_DECODE,
                "external/foo/tests/big_input.rs": ATTACKER_VEC_DECODE,
            }
        )
        cands = _MOD.scan_workspace(ws / "external")
        self.assertEqual(
            cands, [], f"skip_dirs should suppress matches; got {cands}"
        )

    def test_outputs_written(self):
        ws = _make_workspace({"external/foo/src/lib.rs": ATTACKER_VEC_DECODE})
        result = _run(["--workspace", str(ws)])
        self.assertEqual(
            result.returncode, 0, msg=result.stdout + result.stderr
        )
        # Required artifacts.
        for rel in (
            "critical_hunt/block_delay/a6_block_delay_results.md",
            "critical_hunt/block_delay/expected_thresholds.md",
            "critical_hunt/block_delay/harness/Cargo.toml",
            "critical_hunt/block_delay/harness/benches/block_delay.rs",
            "critical_hunt/candidates/a6_block_delay.json",
        ):
            self.assertTrue(
                (ws / rel).is_file(), f"missing artifact: {rel}"
            )

    def test_candidates_json_schema(self):
        ws = _make_workspace({"external/foo/src/lib.rs": ATTACKER_VEC_DECODE})
        _run(["--workspace", str(ws)])
        payload = json.loads(
            (ws / "critical_hunt" / "candidates" / "a6_block_delay.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(payload["schema"], _MOD.SCHEMA_VERSION)
        self.assertEqual(payload["base_block_time_seconds"], 2.0)
        self.assertEqual(payload["a6_threshold_ratio"], 5.0)
        self.assertEqual(payload["a6_threshold_seconds"], 10.0)
        self.assertGreaterEqual(len(payload["candidates"]), 1)
        # Every row must carry the matrix-compatible required fields.
        for row in payload["candidates"]:
            for field in (
                "candidate_id",
                "scope_asset",
                "impact_mapping",
                "production_path",
                "required_proof",
                "artifact_refs",
            ):
                self.assertIn(field, row, f"row missing field {field}: {row}")
            self.assertIn(
                "Temporary freezing of network transactions",
                row["impact_mapping"],
            )

    def test_idempotent(self):
        ws = _make_workspace({"external/foo/src/lib.rs": ATTACKER_VEC_DECODE})
        _run(["--workspace", str(ws)])
        first = (
            ws / "critical_hunt" / "candidates" / "a6_block_delay.json"
        ).read_text(encoding="utf-8")
        _run(["--workspace", str(ws)])
        second = (
            ws / "critical_hunt" / "candidates" / "a6_block_delay.json"
        ).read_text(encoding="utf-8")
        self.assertEqual(first, second, "probe should be idempotent")

    def test_strict_fails_when_candidates_present(self):
        ws = _make_workspace({"external/foo/src/lib.rs": ATTACKER_VEC_DECODE})
        result = _run(["--workspace", str(ws), "--strict"])
        self.assertEqual(
            result.returncode,
            1,
            msg=f"strict should exit 1 when candidates emit: {result.stdout}",
        )

    def test_empty_workspace(self):
        ws = Path(tempfile.mkdtemp(prefix="bdp_empty_"))
        result = _run(["--workspace", str(ws)])
        self.assertEqual(
            result.returncode, 0, msg=result.stdout + result.stderr
        )
        # Scaffold artifacts still written even when no candidates emit.
        for rel in (
            "critical_hunt/block_delay/a6_block_delay_results.md",
            "critical_hunt/block_delay/expected_thresholds.md",
            "critical_hunt/block_delay/harness/Cargo.toml",
            "critical_hunt/block_delay/harness/benches/block_delay.rs",
            "critical_hunt/candidates/a6_block_delay.json",
        ):
            self.assertTrue((ws / rel).is_file(), f"missing artifact: {rel}")
        payload = json.loads(
            (ws / "critical_hunt" / "candidates" / "a6_block_delay.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(payload["candidates"], [])

    def test_workspace_not_directory(self):
        nonexistent = Path(tempfile.gettempdir()) / "bdp_does_not_exist_zz"
        if nonexistent.exists():
            nonexistent.unlink()
        result = _run(["--workspace", str(nonexistent)])
        self.assertEqual(result.returncode, 2)
        self.assertIn("workspace not a directory", result.stderr)

    def test_real_corpus_smoke(self):
        """Run the probe over the auditooor repo itself.

        We don't expect any A6 candidates — auditooor is Python-heavy and
        any .rs files are fixtures. The smoke test only asserts the
        probe completes without raising and writes the scaffold.
        """
        ws = Path(tempfile.mkdtemp(prefix="bdp_corpus_"))
        # Use the auditooor tools/ tree as the scan root — guaranteed to
        # exist, contains some .rs fixtures, and is bounded in size.
        scan_root = ROOT / "tools"
        result = _run(
            ["--workspace", str(ws), "--scan-root", str(scan_root)]
        )
        self.assertEqual(
            result.returncode, 0, msg=result.stdout + result.stderr
        )
        self.assertTrue(
            (ws / "critical_hunt" / "block_delay" / "a6_block_delay_results.md").is_file()
        )

    def test_threshold_constants(self):
        # Lock in the rubric constants so future edits can't silently
        # weaken them. Threshold = 10.0s = 5x the 2s Base block time.
        self.assertEqual(_MOD.BASE_BLOCK_TIME_SECONDS, 2.0)
        self.assertEqual(_MOD.A6_THRESHOLD_RATIO, 5.0)
        self.assertEqual(_MOD.A6_THRESHOLD_SECONDS, 10.0)

    def test_harness_scaffold_contents(self):
        ws = _make_workspace({"external/foo/src/lib.rs": ATTACKER_VEC_DECODE})
        _run(["--workspace", str(ws)])
        toml = (
            ws / "critical_hunt" / "block_delay" / "harness" / "Cargo.toml"
        ).read_text(encoding="utf-8")
        self.assertIn("a6-block-delay-harness", toml)
        self.assertIn("criterion", toml)
        self.assertIn("[[bench]]", toml)
        bench = (
            ws
            / "critical_hunt"
            / "block_delay"
            / "harness"
            / "benches"
            / "block_delay.rs"
        ).read_text(encoding="utf-8")
        # Hard panic when unwired — we never want a silently-empty bench
        # to look "passing".
        self.assertIn("panic!", bench)
        self.assertIn("a6_block_delay", bench)


if __name__ == "__main__":
    unittest.main()
