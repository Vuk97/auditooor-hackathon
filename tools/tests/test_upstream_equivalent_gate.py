#!/usr/bin/env python3
"""Tests for tools/upstream-equivalent-gate.py (Wave J-1A).

Stdlib-only, hermetic. Covers:
  1. Step 1 — audit-tree existence (path missing → killed)
  2. Step 2 — line content match (content mismatch → walked back)
  3. Step 3 — SCOPE.md OOS check (oos path → killed)
  4. Step 4 — SEVERITY.md verbatim (wrong tier section → walked back)
  5. Step 5 — upstream equivalent (hit found → walked back)
  6. Compose: I-1A KZG candidate → killed at Step 1 (path doesn't exist)
  7. Compose: cached_execution NOT_REAL → promotion_allowed (all steps pass)
  8. Compose: H-1 G-v01 → upstream hit via Step 5
  9. Compose: I-2 N8/N9 decode_2718 → upstream hit via Step 5
 10. --strict flag causes exit 1 on any walkback
 11. Empty candidate file → passes with rc=0
 12. Missing workspace → rc=2
 13. Invalid JSON → rc=2
 14. --print-json emits valid JSON with correct schema key
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "upstream-equivalent-gate.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("upstream_equivalent_gate", TOOL)
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["upstream_equivalent_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_module()


def _run(args: list) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def _mk_workspace(
    ws: Path,
    *,
    scope_md: str = "",
    severity_md: str = "",
    asset: str = "base",
    files: dict[str, str] | None = None,
) -> Path:
    """Create a minimal workspace fixture at ``ws``."""
    ws.mkdir(parents=True, exist_ok=True)
    ext = ws / "external" / asset
    ext.mkdir(parents=True, exist_ok=True)
    (ws / "SCOPE.md").write_text(scope_md or _DEFAULT_SCOPE_MD, encoding="utf-8")
    (ws / "SEVERITY.md").write_text(severity_md or _DEFAULT_SEVERITY_MD, encoding="utf-8")
    if files:
        for rel_path, content in files.items():
            fp = ext / rel_path
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")
    return ws


_DEFAULT_SCOPE_MD = """\
# Scope

## In-scope
- `crates/consensus/`
- `crates/execution/`
- `crates/proof/`

## Out-of-scope
- **OP Stack code**: `op-node`, `op-geth`, `op-batcher`, `op-reth`, Optimism audit code.
- **ZK prover internals + circuits** (SP1 guest programs, Succinct Prover Network).
- **Op-Succinct core** (only Base's changes to it are in-scope).
"""

_DEFAULT_SEVERITY_MD = """\
# Severity Rubric

### Critical
- Permanent freezing of user funds / bridge operations.
- Chain-level fork or CL-EL state divergence.
- Forge or bypass TEE or ZK proof verification in AggregateVerifier.

### High
- Temporary freezing of user funds.
- Network shutdown of >= 30% of nodes.

### Medium
- Bug in layer 0/1/2 network code resulting in unintended smart-contract behavior.

### Low
- Informational finding with no direct fund risk.
"""


# ---------------------------------------------------------------------------
# Test 1: Step 1 — audit-tree existence
# ---------------------------------------------------------------------------

class TestStep1AuditTreeExistence(unittest.TestCase):
    """Step 1: path must exist under external/<asset>/."""

    def test_missing_path_killed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            row = {
                "candidate_id": "test-missing",
                "production_path": "external/base/crates/succinct/utils/client/src/precompiles/custom.rs",
                "severity_tier": "Critical",
                "selected_impact": "Forge or bypass TEE or ZK proof verification in AggregateVerifier.",
            }
            result = _MOD.compute_verdict(row, ws, 0, max_queries=0)
            self.assertFalse(result["step_1_audit_tree_exists"])
            self.assertIn("killed_path_not_in_audit_tree", result["verdict"])

    def test_existing_path_passes_step1(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws", files={"crates/foo/bar.rs": "fn foo() {}"})
            row = {
                "candidate_id": "test-exists",
                "production_path": "external/base/crates/foo/bar.rs",
            }
            result = _MOD.compute_verdict(row, ws, 0, max_queries=0)
            self.assertTrue(result["step_1_audit_tree_exists"])


# ---------------------------------------------------------------------------
# Test 2: Step 2 — line content match
# ---------------------------------------------------------------------------

class TestStep2LineContentMatch(unittest.TestCase):
    """Step 2: cited line must match quoted content."""

    def test_line_mismatch_walked_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={"crates/foo/bar.rs": "fn unrelated_function() {}\nfn another() {}"},
            )
            row = {
                "candidate_id": "test-line-mismatch",
                "production_path": "external/base/crates/foo/bar.rs",
                "line": 1,
                # Long quote that won't match
                "evidence_snippet": "this_is_not_in_the_file_at_all_and_is_definitely_wrong_content_over_100_chars_long_padding_here_xyz",
            }
            result = _MOD.compute_verdict(row, ws, 0, max_queries=0)
            self.assertTrue(result["step_1_audit_tree_exists"])
            self.assertIs(result["step_2_line_content_matches"], False)
            self.assertIn("line_content_mismatch", result["verdict"])

    def test_line_match_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={"crates/foo/bar.rs": "fn is_deposits_only() -> bool { true }"},
            )
            row = {
                "candidate_id": "test-line-match",
                "production_path": "external/base/crates/foo/bar.rs",
                "line": 1,
                "evidence_snippet": "is_deposits_only",
            }
            result = _MOD.compute_verdict(row, ws, 0, max_queries=0)
            self.assertTrue(result["step_1_audit_tree_exists"])
            self.assertIs(result["step_2_line_content_matches"], True)

    def test_no_quoted_line_is_na(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws", files={"crates/foo/bar.rs": "fn foo() {}"})
            row = {
                "candidate_id": "test-no-quote",
                "production_path": "external/base/crates/foo/bar.rs",
            }
            result = _MOD.compute_verdict(row, ws, 0, max_queries=0)
            self.assertEqual(result["step_2_line_content_matches"], "n/a")


# ---------------------------------------------------------------------------
# Test 3: Step 3 — SCOPE.md OOS check (direct API)
# ---------------------------------------------------------------------------

class TestStep3ScopeOOS(unittest.TestCase):
    """Step 3: OOS path detection via check_step3_scope directly."""

    def _ws(self, tmp: Path) -> Path:
        ws = tmp / "scope_ws"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "SCOPE.md").write_text(_DEFAULT_SCOPE_MD, encoding="utf-8")
        (ws / "SEVERITY.md").write_text(_DEFAULT_SEVERITY_MD, encoding="utf-8")
        return ws

    def test_kona_path_segment_is_oos(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            # /kona/ path segment matches OOS_PATTERN r"/kona/"
            scope = _MOD.check_step3_scope(
                ws, "external/base/rust/kona/crates/node/engine/src/task_queue.rs"
            )
            self.assertEqual(scope, "oos")

    def test_op_succinct_repo_is_oos(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            # Matches OOS_PATTERN 'succinctlabs/op-succinct'
            scope = _MOD.check_step3_scope(
                ws, "succinctlabs/op-succinct/utils/client/src/precompiles/custom.rs"
            )
            self.assertEqual(scope, "oos")

    def test_consensus_path_in_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            scope = _MOD.check_step3_scope(
                ws, "external/base/crates/consensus/protocol/src/batch/type.rs"
            )
            self.assertEqual(scope, "in_scope")

    def test_proof_path_in_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            scope = _MOD.check_step3_scope(
                ws, "external/base/crates/proof/proof/src/l1/chain_provider.rs"
            )
            self.assertEqual(scope, "in_scope")

    def test_execution_path_in_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            scope = _MOD.check_step3_scope(
                ws, "external/base/crates/execution/engine-tree/src/cached_execution.rs"
            )
            self.assertEqual(scope, "in_scope")


# ---------------------------------------------------------------------------
# Test 4: Step 4 — SEVERITY.md verbatim match
# ---------------------------------------------------------------------------

class TestStep4SeverityVerbatim(unittest.TestCase):
    """Step 4: severity claim must appear verbatim in the correct section."""

    def test_severity_not_in_section_walked_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={"crates/foo/bar.rs": "fn foo() {}"},
            )
            row = {
                "candidate_id": "test-sev-wrong",
                "production_path": "external/base/crates/foo/bar.rs",
                "severity_tier": "Critical",
                # This doesn't appear in the Critical section
                "selected_impact": "Nonexistent impact sentence that is definitely not in any rubric",
            }
            result = _MOD.compute_verdict(row, ws, 0, max_queries=0)
            self.assertIs(result["step_4_severity_verbatim"], False)
            self.assertIn("severity_not_verbatim", result["verdict"])

    def test_severity_verbatim_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={"crates/foo/bar.rs": "fn foo() {}"},
            )
            row = {
                "candidate_id": "test-sev-ok",
                "production_path": "external/base/crates/foo/bar.rs",
                "severity_tier": "Critical",
                "selected_impact": "Chain-level fork or CL-EL state divergence.",
            }
            result = _MOD.compute_verdict(row, ws, 0, max_queries=0)
            self.assertIs(result["step_4_severity_verbatim"], True)

    def test_no_severity_is_na(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={"crates/foo/bar.rs": "fn foo() {}"},
            )
            row = {
                "candidate_id": "test-no-sev",
                "production_path": "external/base/crates/foo/bar.rs",
            }
            result = _MOD.compute_verdict(row, ws, 0, max_queries=0)
            self.assertEqual(result["step_4_severity_verbatim"], "n/a")


# ---------------------------------------------------------------------------
# Test 5: Step 5 — upstream equivalent (mocked)
# ---------------------------------------------------------------------------

class TestStep5UpstreamEquivalent(unittest.TestCase):
    """Step 5: upstream hit → walked_back verdict."""

    def _simple_ws(self, tmp: Path, rs_name: str = "foo.rs") -> tuple[Path, dict]:
        ws = _mk_workspace(
            tmp / "ws",
            files={f"crates/consensus/{rs_name}": "fn target_fn() {}"},
        )
        row = {
            "candidate_id": "test-upstream",
            "production_path": f"external/base/crates/consensus/{rs_name}",
            "severity_tier": "Critical",
            "bug_shape_query": "target_fn",
        }
        return ws, row

    def test_mocked_upstream_hit_walks_back(self):
        """If _gh_search returns a hit, verdict is upstream_inherited."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, row = self._simple_ws(Path(tmp))
            fake_hit = {
                "total_count": 3,
                "items": [{"html_url": "https://github.com/op-rs/kona/blob/main/foo.rs"}],
            }
            with patch.object(_MOD, "_gh_search", return_value=fake_hit):
                result = _MOD.compute_verdict(row, ws, 0, max_queries=5)
            self.assertGreater(len(result["step_5_upstream_equivalent"]), 0)
            self.assertIn("upstream_inherited", result["verdict"])

    def test_no_upstream_hit_promotion_allowed(self):
        """If _gh_search returns 0 hits everywhere, verdict is promotion_allowed."""
        with tempfile.TemporaryDirectory() as tmp:
            ws, row = self._simple_ws(Path(tmp))
            fake_miss = {"total_count": 0, "items": []}
            with patch.object(_MOD, "_gh_search", return_value=fake_miss):
                result = _MOD.compute_verdict(row, ws, 0, max_queries=5)
            self.assertEqual(result["step_5_upstream_equivalent"], [])
            self.assertEqual(result["verdict"], "promotion_allowed")


# ---------------------------------------------------------------------------
# Tests 6-9: Compose real-world overnight candidates
# ---------------------------------------------------------------------------

class TestComposeRealCandidates(unittest.TestCase):
    """Compose: real-world candidates from the overnight loop."""

    def test_i1a_kzg_killed_step1(self):
        """I-1A KZG-verify candidate: path doesn't exist → killed at Step 1."""
        with tempfile.TemporaryDirectory() as tmp:
            # The workspace does NOT have external/base/crates/succinct/...
            ws = _mk_workspace(Path(tmp) / "ws")
            row = {
                "candidate_id": "i1a_real_kzg_verify_discarded",
                "production_path": "external/base-rc28-clean/crates/succinct/utils/client/src/precompiles/custom.rs",
                "line": 33,
                "severity_tier": "Critical",
                "bug_shape_query": "verify_kzg_proof",
                "evidence_snippet": (
                    "KzgProof::verify_kzg_proof(&commitment, &z, &y, &proof, &self.kzg_settings)\n"
                    "    .map_err(|_| PrecompileError::BlobVerifyKzgProofFailed)?;\nOk(())"
                ),
            }
            result = _MOD.compute_verdict(row, ws, 0, max_queries=0)
            # Step 1 must fail — path doesn't exist
            self.assertFalse(result["step_1_audit_tree_exists"])
            self.assertEqual(result["verdict"], "killed_path_not_in_audit_tree")

    def test_cached_execution_promotion_allowed(self):
        """cached_execution NOT_REAL: path exists, in-scope, no severity → allowed."""
        with tempfile.TemporaryDirectory() as tmp:
            code = (
                "fn has_transaction_hash(&self, hash: &H256) -> bool {\n"
                "    self.transactions_by_hash.contains_key(hash)\n"
                "}\n"
            )
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={"crates/execution/engine-tree/src/cached_execution.rs": code},
            )
            row = {
                "candidate_id": "cached_execution_not_real",
                "production_path": "external/base/crates/execution/engine-tree/src/cached_execution.rs",
                "line": 1,
                "severity_tier": "Medium",
                # No bug_shape_query → Step 5 won't derive a useful pattern; max_queries=0
            }
            result = _MOD.compute_verdict(row, ws, 0, max_queries=0)
            self.assertTrue(result["step_1_audit_tree_exists"])
            self.assertEqual(result["step_3_scope_status"], "in_scope")
            self.assertEqual(result["verdict"], "promotion_allowed")

    def test_h1_gv01_upstream_hit(self):
        """H-1 G-v01: kona has identical bug → upstream hit via Step 5."""
        with tempfile.TemporaryDirectory() as tmp:
            code = (
                "pub fn is_deposits_only(&self) -> bool { "
                "self.attributes.transactions.iter().all(|tx| "
                "tx.first().is_some_and(|tx| tx[0] == 0)) }"
            )
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={"crates/consensus/protocol/src/attributes.rs": code},
            )
            row = {
                "candidate_id": "h1_gv01_deposits_only",
                "production_path": "external/base/crates/consensus/protocol/src/attributes.rs",
                "severity_tier": "Critical",
                "bug_shape_query": "is_deposits_only",
                "selected_impact": "Chain-level fork or CL-EL state divergence.",
            }
            fake_hit = {
                "total_count": 12,
                "items": [{"html_url": "https://github.com/op-rs/kona/blob/main/attributes.rs"}],
            }
            with patch.object(_MOD, "_gh_search", return_value=fake_hit):
                result = _MOD.compute_verdict(row, ws, 0, max_queries=5)
            self.assertTrue(result["step_1_audit_tree_exists"])
            self.assertEqual(result["step_3_scope_status"], "in_scope")
            self.assertGreater(len(result["step_5_upstream_equivalent"]), 0)
            self.assertIn("upstream_inherited", result["verdict"])

    def test_i2_n8_decode_2718_upstream_hit(self):
        """I-2 N8: decode_2718 byte-identical to kona → walked back via Step 5."""
        with tempfile.TemporaryDirectory() as tmp:
            code = "let envelope = ReceiptEnvelope::decode_2718(&mut rlp.as_ref())?;\n"
            ws = _mk_workspace(
                Path(tmp) / "ws",
                files={"crates/proof/proof/src/l1/chain_provider.rs": code},
            )
            row = {
                "candidate_id": "i2_n8_decode_2718",
                "production_path": "external/base/crates/proof/proof/src/l1/chain_provider.rs",
                "line": 1,
                "severity_tier": "High",
                "bug_shape_query": "decode_2718",
                "evidence_snippet": "ReceiptEnvelope::decode_2718",
            }
            fake_hit = {
                "total_count": 5,
                "items": [{"html_url": "https://github.com/op-rs/kona/blob/main/chain_provider.rs"}],
            }
            with patch.object(_MOD, "_gh_search", return_value=fake_hit):
                result = _MOD.compute_verdict(row, ws, 0, max_queries=5)
            self.assertTrue(result["step_1_audit_tree_exists"])
            self.assertIn("upstream_inherited", result["verdict"])


# ---------------------------------------------------------------------------
# Tests 10-14: CLI behavior
# ---------------------------------------------------------------------------

class TestCLIBehavior(unittest.TestCase):
    """CLI-level tests (subprocess)."""

    def test_strict_flag_exits_1_on_walkback(self):
        """--strict exits 1 when any candidate is walked back."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            cand = Path(tmp) / "c.json"
            cand.write_text(json.dumps({
                "candidates": [{
                    "candidate_id": "strict-test",
                    "production_path": "external/base/crates/succinct/nonexistent.rs",
                    "severity_tier": "Critical",
                }]
            }), encoding="utf-8")
            r = _run(["--workspace", str(ws), "--candidate", str(cand), "--strict"])
            self.assertEqual(r.returncode, 1)

    def test_empty_candidate_file_passes(self):
        """Empty candidates array → rc=0."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            cand = Path(tmp) / "empty.json"
            cand.write_text(json.dumps({"candidates": []}), encoding="utf-8")
            r = _run(["--workspace", str(ws), "--candidate", str(cand)])
            self.assertEqual(r.returncode, 0)

    def test_missing_workspace_rc2(self):
        """Missing workspace dir → rc=2."""
        with tempfile.TemporaryDirectory() as tmp:
            cand = Path(tmp) / "c.json"
            cand.write_text("{}", encoding="utf-8")
            r = _run(["--workspace", str(Path(tmp) / "nonexistent"), "--candidate", str(cand)])
            self.assertEqual(r.returncode, 2)

    def test_invalid_json_rc2(self):
        """Invalid JSON candidate file → rc=2."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            cand = Path(tmp) / "bad.json"
            cand.write_text("{invalid", encoding="utf-8")
            r = _run(["--workspace", str(ws), "--candidate", str(cand)])
            self.assertEqual(r.returncode, 2)

    def test_print_json_output(self):
        """--print-json emits valid JSON with correct schema key."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _mk_workspace(Path(tmp) / "ws")
            cand = Path(tmp) / "c.json"
            cand.write_text(json.dumps({
                "candidates": [{
                    "candidate_id": "json-test",
                    "production_path": "external/base/crates/succinct/ghost.rs",
                }]
            }), encoding="utf-8")
            r = _run(["--workspace", str(ws), "--candidate", str(cand), "--print-json"])
            try:
                data = json.loads(r.stdout)
                self.assertIn("schema", data)
                self.assertIn("results", data)
                self.assertEqual(data["schema"], "auditooor.upstream_equivalent_gate.v1")
            except json.JSONDecodeError:
                self.fail(f"--print-json did not produce valid JSON:\n{r.stdout[:500]}")


# ---------------------------------------------------------------------------
# Tests 15-16: Wave M-3 regression — Step 3 OOS regex precision
# ---------------------------------------------------------------------------

# Base Azul SCOPE.md fixture matching real lines 34, 39-41.
_BASE_AZUL_SCOPE_MD = """\
# Scope

## In-scope
- `crates/consensus/`
- `crates/execution/`
- `crates/proof/`
- Base modifications to Op-Succinct are in-scope (line 34).

## Out-of-scope
- **OP Stack code**: `op-node`, `op-geth`, `op-batcher`, `op-reth`.
- **ZK prover internals + circuits** (SP1 guest programs, Succinct Prover Network).
- **Op-Succinct core** — upstream op-succinct repo (only Base's modifications are in-scope).
"""


class TestStep3OOSRegexPrecision(unittest.TestCase):
    """Wave M-3 regression: Step 3 OOS regex must not walk back Base-prefixed paths.

    TC-1: Base's own crates/succinct/utils/client/ is IN SCOPE per SCOPE.md:34.
    TC-2: Upstream op-succinct path IS OOS (preserves original intent).
    """

    def _ws(self, tmp: Path) -> Path:
        ws = tmp / "scope_ws"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "SCOPE.md").write_text(_BASE_AZUL_SCOPE_MD, encoding="utf-8")
        (ws / "SEVERITY.md").write_text(_DEFAULT_SEVERITY_MD, encoding="utf-8")
        return ws

    def test_step3_does_not_walk_back_base_succinct_client_utils(self):
        """TC-1 (regression): Base's crates/succinct/utils/client/ is in scope.

        Wave L-1 false positive: the old r"succinct/utils" pattern fired on
        `external/base-rc28-clean/crates/succinct/utils/client/src/precompiles/mod.rs`
        and returned 'oos', despite SCOPE.md:34 declaring Base modifications to
        Op-Succinct in-scope.  After the fix it must return 'in_scope'.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            path = (
                "external/base-rc28-clean/crates/succinct/utils/client/"
                "src/precompiles/mod.rs:72"
            )
            scope = _MOD.check_step3_scope(ws, path)
            self.assertEqual(
                scope,
                "in_scope",
                msg=(
                    "Base's crates/succinct/utils/client/ is IN SCOPE per SCOPE.md:34 "
                    "('Base modifications to Op-Succinct are in-scope') but gate "
                    f"returned '{scope}'.  Fix: narrow OOS pattern to require op-succinct prefix."
                ),
            )

    def test_step3_does_walk_back_upstream_op_succinct_path(self):
        """TC-2 (intent preserved): upstream op-succinct path remains OOS.

        A path citing the upstream succinctlabs/op-succinct vendored tree should
        still be caught as OOS so the original over-claim protection is intact.
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            path = (
                "external/op-succinct-vendored/crates/utils/client/"
                "src/foo.rs"
            )
            scope = _MOD.check_step3_scope(ws, path)
            self.assertEqual(
                scope,
                "oos",
                msg=(
                    "Upstream op-succinct vendored path should be OOS but gate "
                    f"returned '{scope}'."
                ),
            )


# ---------------------------------------------------------------------------
# Tests 17-21: Wave O-A — principled Cargo-crate + SCOPE.md-section resolver
# ---------------------------------------------------------------------------

_WAVE_O_SCOPE_MD = """\
# Scope

## In scope

- `crates/execution/*`
- `crates/consensus/*`
- `crates/proof/*`
- Base modifications to Op-Succinct are in-scope (core Op-Succinct is OOS).

## Out of scope (explicitly carved out)

- OP Stack code: `op-node`, `op-geth`, `op-batcher`, `op-reth`.
- ZK prover internals + circuits (SP1 guest programs, Succinct Prover Network).
- **Op-Succinct core** (only Base's changes to it are in-scope).
"""


class TestWaveOAPrincipledStep3(unittest.TestCase):
    """Wave O-A: Step 3 uses Cargo crate name + SCOPE.md modification rules.

    TC-1: L-1 candidate (crates/succinct/utils/client/, crate=base-succinct-client-utils)
          → PASS Step 3 via modification_rule (NOT via M-3 regex band-aid).
    TC-2: Hypothetical upstream-only candidate (crates/op-succinct/..., crate=op-succinct-utils)
          → OOS.
    TC-3: compute_verdict with explicit crate_name in row → Step 3 in_scope.
    TC-4: Path has no Cargo.toml on disk → resolver returns None → falls back to
          SCOPE.md section parser (no modification_rule triggered by None).
    TC-5: crate_name=base-succinct-client-utils triggers modification_rule even
          when path contains "succinct" which appears in OOS clause.
    """

    def _ws(self, tmp: Path, scope_md: str = _WAVE_O_SCOPE_MD) -> Path:
        ws = tmp / "ws"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "SCOPE.md").write_text(scope_md, encoding="utf-8")
        (ws / "SEVERITY.md").write_text(_DEFAULT_SEVERITY_MD, encoding="utf-8")
        return ws

    def test_l1_base_succinct_client_utils_passes_step3_via_modification_rule(self):
        """TC-1: L-1 candidate passes Step 3 via modification_rule, not M-3 regex.

        crate_name='base-succinct-client-utils' is a Base fork of op-succinct →
        SCOPE.md modification rule fires → in_scope.
        Path: crates/succinct/utils/client/src/precompiles/mod.rs (line 72).
        """
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            path = (
                "external/base-rc28-clean/crates/succinct/utils/client/"
                "src/precompiles/mod.rs"
            )
            scope = _MOD.check_step3_scope(
                ws, path, crate_name="base-succinct-client-utils"
            )
            self.assertEqual(
                scope,
                "in_scope",
                msg=(
                    "L-1 candidate with crate_name='base-succinct-client-utils' should "
                    f"pass Step 3 via modification_rule. Got: {scope}"
                ),
            )

    def test_hypothetical_op_succinct_utils_is_oos(self):
        """TC-2: Upstream op-succinct-utils crate → OOS (no base- prefix)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            path = "external/op-succinct/crates/utils/client/src/foo.rs"
            scope = _MOD.check_step3_scope(
                ws, path, crate_name="op-succinct-utils"
            )
            self.assertEqual(
                scope,
                "oos",
                msg=(
                    "Upstream op-succinct-utils crate should be OOS. "
                    f"Got: {scope}"
                ),
            )

    def test_compute_verdict_uses_crate_name_from_row(self):
        """TC-3: compute_verdict passes row['crate_name'] to Step 3."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            # Create the source file so Step 1 passes
            src_dir = (
                ws / "external" / "base-rc28-clean" / "crates" / "succinct" /
                "utils" / "client" / "src" / "precompiles"
            )
            src_dir.mkdir(parents=True)
            (src_dir / "mod.rs").write_text("fn get_precompiles() {}", encoding="utf-8")
            row = {
                "candidate_id": "L1-wave-o-test",
                "production_path": (
                    "external/base-rc28-clean/crates/succinct/utils/client/"
                    "src/precompiles/mod.rs"
                ),
                "crate_name": "base-succinct-client-utils",
                "severity_tier": "High",
            }
            result = _MOD.compute_verdict(row, ws, 0, max_queries=0)
            self.assertTrue(result["step_1_audit_tree_exists"])
            self.assertEqual(
                result["step_3_scope_status"],
                "in_scope",
                msg=(
                    f"Step 3 should be in_scope via modification_rule. "
                    f"Full result: {result}"
                ),
            )

    def test_base_succinct_modification_rule_trumps_oos_substring(self):
        """TC-5: modification_rule wins even though path contains 'succinct' (OOS substring)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(Path(tmp))
            # Path contains "succinct" which appears in OOS clauses.
            # But crate_name is base-prefixed → modification_rule → in_scope.
            path = "external/base-rc28-clean/crates/succinct/custom/src/lib.rs"
            scope = _MOD.check_step3_scope(
                ws, path, crate_name="base-succinct-custom"
            )
            self.assertEqual(
                scope,
                "in_scope",
                msg=(
                    "modification_rule should trump OOS substring match for "
                    f"base-prefixed crate. Got: {scope}"
                ),
            )


if __name__ == "__main__":
    unittest.main()
