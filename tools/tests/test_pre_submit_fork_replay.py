#!/usr/bin/env python3
"""PR 102 tests — pre-submit-check.sh validates High+ fork-replay citations.

Check 22 rules enforced:
  - Valid cited deltas/manifest pass with no failure message.
  - Missing cited deltas on High+ -> script exits non-zero, message includes
    "fork replay deltas not found".
  - Malformed (non-JSON) cited deltas on High+ -> script exits non-zero,
    message includes "fork replay deltas failed to parse".
  - Source-only High+ justification with Forge PoC reference -> pass.
  - Medium severity draft citing a missing deltas file -> ADVISORY only,
    check 22 does NOT fail (but some other checks will fail — we only verify
    that check 22 emits an advisory, NOT that the overall script is green).

We run the real tools/pre-submit-check.sh. Some unrelated checks (rubric,
originality, dupe-risk subagent, scope-review) will emit errors or warnings
against our minimal fixtures — we do NOT assert on those; we scope each
assertion to the "22." prefix output only.
"""
from __future__ import annotations

import json
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "pre-submit-check.sh"
RUNNER = ROOT / "tools" / "fork-replay.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("fork_replay_test_module", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_ws(tmp: Path) -> Path:
    ws = tmp / "ws"
    (ws / "submissions" / "staging").mkdir(parents=True)
    (ws / "fork_replay").mkdir(parents=True)
    # OOS_CHECKLIST.md so the script's workspace walk resolves to this ws.
    (ws / "OOS_CHECKLIST.md").write_text("stub\n")
    return ws


def _write_valid_deltas(
    ws: Path,
    tx: str = "0x" + "ab" * 32,
    *,
    status: str = "executed",
    block: int | None = 101,
    fork_block: int | None = 100,
    assertions: list | None = None,
) -> dict:
    """Write paired manifest/deltas/summary artifacts for Check #22 fixtures.

    - manifest.status ∈ {executed, success}
    - positive int `block` and `fork_block`
    - `assertions` array must be non-empty with at least one PASS and no FAIL

    Pass explicit values through to build intentionally-broken fixtures for
    the negative tests (e.g. status="failed" or block=None).
    """
    fr = ws / "fork_replay"
    manifest_path = fr / f"{tx}_manifest.json"
    deltas_path = fr / f"{tx}_deltas.json"
    summary_path = fr / f"{tx}_replay.yaml"
    payload: dict = {"tx": tx, "status": status}
    if block is not None:
        payload["block"] = block
    if fork_block is not None:
        payload["fork_block"] = fork_block
    if assertions is not None:
        payload["assertions"] = assertions
    manifest_path.write_text(json.dumps(payload))
    deltas_path.write_text(json.dumps({"tx": tx, "addresses": {}}))
    summary_path.write_text(f"status: {status}\n")
    return {
        "tx": tx,
        "manifest": f"fork_replay/{manifest_path.name}",
        "deltas": f"fork_replay/{deltas_path.name}",
        "summary": f"fork_replay/{summary_path.name}",
    }


def _stub_forge_env(tmp: Path, ws: Path) -> dict[str, str]:
    """Return an env dict where `forge` is a stub binary that reports PASS.

    Codex PR-102 re-review hardening: the previous approach used an env-hatch
    (PRE_SUBMIT_POC_PASS_OVERRIDE=1) to simulate check #10 success without a
    real forge run. That hatch leaked into operator shells, defeating the
    point of the source-only gate. Replace it with a real PATH shim: we
    create a fake `forge` script in a tmp bin/ that prints the "1 passed"
    line pre-submit-check.sh parses, and we also install a minimal
    `foundry.toml` + `.t.sol` so check #10's file-resolution walks succeed.
    This exercises the *real* check #10 codepath end-to-end rather than
    bypassing it.
    """
    bin_dir = tmp / "fake_bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    stub = bin_dir / "forge"
    stub.write_text(
        "#!/bin/sh\n"
        # Mimic the exact output pre-submit-check.sh line 491 greps for:
        # `grep -qE '[1-9][0-9]* passed' "$FORGE_LOG"`
        'echo "[⠊] Compiling..."\n'
        'echo "Ran 1 test suites in 0.1s: 1 tests passed, 0 failed, 0 skipped"\n'
        'echo "1 passed; 0 failed; 0 skipped; finished in 10ms"\n'
        "exit 0\n"
    )
    stub.chmod(0o755)
    # Minimal foundry project so check #10's forge.toml walk succeeds.
    (ws / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\ntest = 'poc-tests'\n")
    (ws / "poc-tests").mkdir(exist_ok=True)
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["FORGE_BIN"] = str(stub)  # pre-submit-check.sh uses this if set
    return env


def _run(
    sub: Path,
    severity: str,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    run_env = env if env is not None else os.environ.copy()
    return subprocess.run(
        ["bash", str(SCRIPT), str(sub), "--severity", severity],
        capture_output=True,
        text=True,
        env=run_env,
    )


def _check22_lines(out: str) -> list[str]:
    """Return only lines that belong to check 22 (the line starting with
    '  22.' and also the '✅/❌/⚠️ 22.' variants)."""
    lines = []
    for raw in out.splitlines():
        stripped = raw.strip()
        if (
            stripped.startswith("22.")
            or stripped.startswith("✅ 22.")
            or stripped.startswith("❌ 22.")
            or stripped.startswith("⚠️  22.")
            or stripped.startswith("⚠️ 22.")
        ):
            lines.append(raw)
    return lines


class PreSubmitForkReplayCheck22(unittest.TestCase):
    def _draft(self, ws: Path, body: str, name: str = "ft.md") -> Path:
        p = ws / "submissions" / "staging" / name
        p.write_text(body)
        return p

    def test_high_valid_cited_deltas_pass_check22(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            # Codex PR-102 blocker 3: pinned block+fork_block + PASS assertion
            refs = _write_valid_deltas(
                ws,
                assertions=[{"selector": "victim", "status": "PASS"}],
            )
            draft = self._draft(ws, f"""# Valid replay cite

**Severity:** High

See `{refs['deltas']}` and `{refs['manifest']}` — both exist and parse.

PoC at poc-tests/demo.t.sol.
""")
            r = _run(draft, "High")
            c22 = "\n".join(_check22_lines(r.stdout + r.stderr))
            self.assertIn("✅ 22.", c22, msg=f"check22 output:\n{c22}\n---\nFULL:\n{r.stdout}")
            self.assertNotIn("not found", c22.lower())
            self.assertNotIn("failed to parse", c22.lower())
            self.assertNotIn("status-not-successful", c22.lower())

    def test_runner_emitted_semantic_bundle_satisfies_check22(self) -> None:
        runner = _load_runner()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            replay_json = {
                "mode": "live",
                "replay_tx": "0x" + "11" * 32,
                "replay_result": "executed",
                "block": 21500000,
                "fork_block": 21500000,
                "network": "mainnet",
                "replay_sha": "proofgrade001",
                "draft_claims": {
                    "attacker": "0x" + "aa" * 20,
                },
                "assertions": [
                    {
                        "expr": "attacker_gain > 0",
                        "status": "PASS",
                        "selector": "native:" + ("0x" + "aa" * 20),
                        "impact_bound": True,
                        "notes": "real replay assertion",
                    }
                ],
            }
            refs = runner.emit_check22_semantic_bundle(ws, replay_json)
            self.assertIsNotNone(refs)
            assert refs is not None
            self.assertTrue((ws / refs["manifest"]).is_file())
            self.assertTrue((ws / refs["deltas"]).is_file())
            self.assertTrue((ws / refs["summary"]).is_file())

            draft = self._draft(ws, f"""# Runner proof-grade replay

**Severity:** High
**Claimed attacker:** `0x{"aa" * 20}`

Cited: `{refs['manifest']}` and `{refs['deltas']}`.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            c22 = "\n".join(_check22_lines(r.stdout + r.stderr))
            self.assertIn("✅ 22.", c22, msg=f"check22 output:\n{c22}\n---\nFULL:\n{r.stdout}")

    def test_runner_hermetic_output_is_scaffolding_only_not_check22_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            r = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--hermetic",
                    "--workspace",
                    str(ws),
                    "--finding-id",
                    "HERMETIC",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 0, msg=r.stdout + r.stderr)
            self.assertFalse(any((ws / "fork_replay").glob("*_manifest.json")))
            draft = self._draft(ws, """# Hermetic history only

**Severity:** High
replay-tx: 0xdeadbeef

See `poc_execution/HERMETIC/replay_deadbeef.json`.
PoC: poc-tests/x.t.sol.
""")
            result = _run(draft, "High")
            c22 = "\n".join(_check22_lines(result.stdout + result.stderr))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("no fork_replay", c22.lower())

    def test_runner_does_not_emit_semantic_bundle_for_advisory_assertions(self) -> None:
        runner = _load_runner()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            replay_json = {
                "mode": "live",
                "replay_tx": "0x" + "22" * 32,
                "replay_result": "executed",
                "block": 21500000,
                "fork_block": 21500000,
                "assertions": [
                    {
                        "expr": "attacker_gain > 0",
                        "status": "PASS",
                        "notes": "advisory only; no selector binding",
                    }
                ],
            }
            refs = runner.emit_check22_semantic_bundle(ws, replay_json)
            self.assertIsNone(refs)
            self.assertFalse(any((ws / "fork_replay").glob("*")))

    def test_high_missing_cited_deltas_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            draft = self._draft(ws, """# Missing replay

**Severity:** Critical

See `fork_replay/0xdead_deltas.json` (not on disk).
PoC at poc-tests/x.t.sol.
""")
            r = _run(draft, "Critical")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("fork replay deltas not found", c22.lower())
            self.assertNotEqual(r.returncode, 0)

    def test_high_malformed_cited_deltas_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            tx = "0x" + "cc" * 32
            bad = ws / "fork_replay" / f"{tx}_deltas.json"
            bad.write_text("{ not-json")
            draft = self._draft(ws, f"""# Malformed replay

**Severity:** High

See `fork_replay/{bad.name}`.
PoC at poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("failed to parse", c22.lower())
            self.assertNotEqual(r.returncode, 0)

    def test_high_source_only_with_passing_poc_passes_check22(self) -> None:
        """Codex PR-102 blocker 2 + re-review hardening: source-only requires
        a PASSING check #10 executed through the real codepath. We install a
        stub `forge` on PATH + a minimal foundry.toml + a .t.sol file, so
        check #10 runs through end-to-end and sees a real "1 passed" line.
        No env-hatch override."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            ws = _make_ws(tmp_p)
            # Install a real .t.sol file so check #10's file-resolution walk
            # succeeds against the stubbed forge.
            (ws / "poc-tests").mkdir(parents=True, exist_ok=True)
            (ws / "poc-tests" / "source_only.t.sol").write_text(
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity ^0.8.0;\n"
                "contract SourceOnlyTest {\n"
                "    function test_placeholder() public pure { }\n"
                "}\n"
            )
            draft = self._draft(ws, """# Source-only justified

**Severity:** High

Fork replay is not applicable here: the bug is a pure source-only reachability
issue with no economic delta to measure. Source-only rationale stands.

PoC reference: poc-tests/source_only.t.sol
""")
            env = _stub_forge_env(tmp_p, ws)
            r = _run(draft, "High", env=env)
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("✅ 22.", c22, msg=f"check22:\n{c22}\nFULL:\n{combined}")
            # Confirm it's the source-only + PASSING PoC path, not a stale
            # generic-green advisory.
            self.assertIn("source-only", c22.lower())
            self.assertIn("passing", c22.lower())

    def test_high_source_only_rust_dlt_cargo_transcript_passes_check22(self) -> None:
        """Rust/DLT candidates should not be forced into Forge-only proof
        semantics. A source-only consensus-client draft may cite a Rust file
        plus a cargo-test transcript instead of a `.t.sol` PoC."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            (ws / "crates" / "execution" / "node" / "src").mkdir(parents=True, exist_ok=True)
            (ws / "crates" / "execution" / "node" / "src" / "engine.rs").write_text(
                "fn validates_rust_consensus_candidate() {}\n"
            )
            draft = self._draft(ws, """# Rust DLT source-only justified

**Severity:** Critical

Rubric citation: chain-level fork or CL/EL state divergence.
Economic impact: TVL at risk if invalid consensus state is accepted.
OOS: in-scope Blockchain/DLT path; no signer compromise.

Fork replay is not applicable here: this is a source-only Rust/DLT consensus
validation bug, not an EVM transaction replay.

PoC reference: crates/execution/node/src/engine.rs

Focused command:

```bash
cargo test -p base-node-core --features test-utils --lib isthmus_withdrawals_root_validation -- --nocapture
```

Observed result:

```text
running 2 tests
test engine::tests::test_isthmus_withdrawals_root_validation_skips_when_parent_state_missing ... ok
test engine::tests::test_isthmus_withdrawals_root_validation_rejects_when_parent_state_available ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 19 filtered out; finished in 0.21s
```

## Production Path

1. In-scope asset: base/base Blockchain/DLT.
2. Affected contract / function: crates/execution/node/src/engine.rs.
3. Reachability: engine_newPayloadV4 calls post-execution validation.
4. Attacker-controlled inputs: payload header.
5. Non-attacker preconditions: hardfork active.
6. Privileged roles involved: none.
7. Mock components used in PoC: Rust test provider.
8. Real component replacement for each mock: engine-tree provider.
9. OOS clauses checked: not OP Stack, not off-chain infra, not signer compromise.
10. Final in-scope impact: CL/EL state divergence.
""")
            r = _run(draft, "Critical")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("✅ 22.", c22, msg=f"check22:\n{c22}\nFULL:\n{combined}")
            self.assertIn("rust", c22.lower())
            self.assertIn("cargo-test", c22.lower())

    def test_high_source_only_go_dlt_test_transcript_passes_check22(self) -> None:
        """Go/DLT candidates should use the same source-only lane as Rust/DLT:
        an explicit source-only justification plus a passing Go test transcript
        satisfies Check #22 without forcing an EVM fork replay."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            (ws / "poc").mkdir(parents=True, exist_ok=True)
            (ws / "poc" / "coop_exit_chain_watcher_bypass_test.go").write_text(
                "package poc\n"
            )
            go_poc = "\n".join(
                [
                    "package poc",
                    "",
                    "import (",
                    '    "testing"',
                    "",
                    '    "github.com/stretchr/testify/require"',
                    ")",
                    "",
                    "type exitState struct {",
                    "    expectedTxid string",
                    "    observedTxid string",
                    "    watcherAccepted bool",
                    "    victimBefore int64",
                    "    victimAfter int64",
                    "}",
                    "",
                    "func mutateExitTxid(s exitState) exitState {",
                    "    next := s",
                    '    next.observedTxid = "coop-exit-txid"',
                    "    if next.observedTxid != next.expectedTxid {",
                    "        next.watcherAccepted = true",
                    "        next.victimAfter = 0",
                    "    }",
                    "    return next",
                    "}",
                    "",
                    "func TestCoopExitChainWatcherBypass(t *testing.T) {",
                    "    before := exitState{",
                    '        expectedTxid: "refund-txid",',
                    '        observedTxid: "refund-txid",',
                    "        watcherAccepted: false,",
                    "        victimBefore: 50_000_000,",
                    "        victimAfter: 50_000_000,",
                    "    }",
                    "    after := mutateExitTxid(before)",
                    "    require.True(t, after.watcherAccepted)",
                    "    require.Equal(t, int64(50_000_000), before.victimBefore)",
                    "    require.Equal(t, int64(0), after.victimAfter)",
                    "    if after.victimAfter >= before.victimBefore {",
                    '        t.Fatalf("expected victim balance drop, before=%d after=%d", before.victimBefore, after.victimAfter)',
                    "    }",
                    "}",
                ]
            )
            draft = self._draft(ws, f"""# Source-only Go DLT proof

**Severity:** Critical

Rubric citation: live DLT funds loss.
Economic impact: $500K of channel liquidity at risk when the watcher accepts
the wrong exit transaction identity.
OOS: in-scope Go statechain/watchtower path; no signer compromise.

Fork replay is not applicable here: this is a source-only Go/DLT validation
bug, not an EVM transaction replay.

PoC reference: poc/coop_exit_chain_watcher_bypass_test.go

```go
{go_poc}
```

Focused command:

```bash
go test ./poc -run TestCoopExitChainWatcherBypass -count=1 -v
```

Observed result:

```text
=== RUN   TestCoopExitChainWatcherBypass
--- PASS: TestCoopExitChainWatcherBypass (0.00s)
PASS
ok github.com/example/spark/poc 0.011s
```

## Production Path

1. In-scope asset: Spark Go statechain watcher.
2. Affected function: chain watcher exit transaction validation.
3. Reachability: watcher consumes the observed exit transaction.
4. Attacker-controlled inputs: cooperative-exit transaction identity.
5. Non-attacker preconditions: channel already funded.
6. Privileged roles involved: none.
7. Mock components used in PoC: in-memory watcher state.
8. Real component replacement for each mock: production watcher state.
9. OOS clauses checked: not signer compromise and not third-party infra.
10. Final in-scope impact: direct funds loss.
""")
            r = _run(draft, "Critical")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("✅ 22.", c22, msg=f"check22:\n{c22}\nFULL:\n{combined}")
            self.assertIn("go test", c22.lower())
            self.assertIn("source-only", c22.lower())

    def test_override_env_var_has_no_effect(self) -> None:
        """Codex PR-102 re-review hardening regression: setting the former
        PRE_SUBMIT_POC_PASS_OVERRIDE env var must NOT make Check #22 green
        anymore. Source-only drafts with a nonexistent PoC must fail even
        when the hatch env is set, because the hatch has been removed."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            draft = self._draft(ws, """# Source-only — nonexistent PoC

**Severity:** High

Fork replay is not applicable.

PoC reference: poc-tests/nonexistent.t.sol
""")
            env = os.environ.copy()
            env["PRE_SUBMIT_POC_PASS_OVERRIDE"] = "1"  # the removed hatch
            r = _run(draft, "High", env=env)
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertNotEqual(r.returncode, 0)

    def test_high_source_only_with_poc_ref_but_no_pass_fails_check22(self) -> None:
        """Codex PR-102 blocker 2: a `.t.sol` text mention is NOT sufficient
        proof. Without check #10 actually running + passing, this must fail."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            draft = self._draft(ws, """# Source-only — unrun PoC

**Severity:** High

Fork replay is not applicable.

PoC reference: poc-tests/not_on_disk.t.sol
""")
            r = _run(draft, "High")  # no override → forge won't pass in test env
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertNotEqual(r.returncode, 0)

    def test_high_source_only_without_poc_fails_check22(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            draft = self._draft(ws, """# Source-only missing PoC

**Severity:** High

Fork replay is not applicable.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            # New (tightened) copy mentions either ".t.sol" or "Forge PoC".
            self.assertTrue(
                "*.t.sol" in c22 or "forge poc" in c22.lower(),
                msg=f"expected PoC-related guidance:\n{c22}",
            )

    # --- Codex PR-102 blocker 1: High+ must hard-fail with neither a
    # fork_replay citation nor a source-only justification. The previous
    # behavior was to print a green advisory — that was a false green.
    def test_high_no_citation_no_source_only_hard_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            draft = self._draft(ws, """# High finding with no evidence anchor

**Severity:** High

Some bug happens. Trust me.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22 must hard-fail:\n{c22}")
            self.assertIn("no fork_replay", c22.lower())
            self.assertIn("no source-only", c22.lower())
            self.assertNotEqual(r.returncode, 0)

    # --- Codex PR-102 blocker 3: manifest.status must be successful and
    # block/fork_block must be pinned integers. A manifest that parses but
    # says status="failed" must hard-fail check 22 on High+.
    def test_high_manifest_failed_status_fails_check22(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_valid_deltas(
                ws, tx="0x" + "de" * 32, status="failed"
            )
            draft = self._draft(ws, f"""# Replay failed

**Severity:** High

Cited: `{refs['manifest']}` and `{refs['deltas']}`.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("status-not-successful", c22.lower())
            self.assertNotEqual(r.returncode, 0)

    def test_high_manifest_missing_fork_block_fails_check22(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_valid_deltas(
                ws, tx="0x" + "aa" * 32, fork_block=None
            )
            draft = self._draft(ws, f"""# Missing fork_block

**Severity:** High

Cited: `{refs['manifest']}`.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("missing-pin:fork_block", c22.lower())

    def test_high_manifest_assertion_fail_blocks_check22(self) -> None:
        """Codex PR-102 blocker 3: an assertions array containing a FAIL
        must prevent the PASS — even if everything else parses cleanly."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_valid_deltas(
                ws,
                tx="0x" + "bb" * 32,
                assertions=[
                    {"selector": "victim", "status": "PASS"},
                    {"selector": "attacker", "status": "FAIL"},
                ],
            )
            draft = self._draft(ws, f"""# Assertion FAIL

**Severity:** High

Cited: `{refs['manifest']}`.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("assertion-fail-present", c22.lower())

    def test_high_manifest_with_no_assertions_key_fails_check22(self) -> None:
        """Codex PR-102 re-review blocker: a manifest that parses cleanly,
        has status=executed + pinned block/fork_block, but NO `assertions`
        key at all must still hard-fail Check #22 for High+. Previously this
        path printed green because the validator only enforced PASS when an
        `assertions` array was present."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            # Write a manifest + deltas pair with NO `assertions` key.
            refs = _write_valid_deltas(
                ws,
                tx="0x" + "d0" * 32,
                status="executed",
                assertions=None,  # explicit — no assertions field
            )
            draft = self._draft(ws, f"""# Executed replay, no assertions

**Severity:** High

Cited: `{refs['manifest']}` and `{refs['deltas']}`.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22 must hard-fail:\n{c22}")
            self.assertIn("assertions-missing", c22.lower())
            self.assertNotEqual(r.returncode, 0)

    def test_high_manifest_with_empty_assertions_fails_check22(self) -> None:
        """Sibling to the assertions-missing regression: an empty `assertions`
        list is just as bad as a missing key — the replay executed but no
        economic delta was asserted. Must hard-fail High+."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_valid_deltas(
                ws,
                tx="0x" + "d1" * 32,
                status="executed",
                assertions=[],  # explicitly empty list
            )
            draft = self._draft(ws, f"""# Executed replay, empty assertions

**Severity:** High

Cited: `{refs['manifest']}`.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("assertions-empty", c22.lower())

    def test_high_manifest_assertion_inconclusive_blocks_check22(self) -> None:
        """Codex PR-102 re-review: INCONCLUSIVE is just as bad as FAIL for a
        High+ claim — it means `fork-replay-assert.py` couldn't confirm the
        delta (e.g. non-executed replay, or null observed value)."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_valid_deltas(
                ws,
                tx="0x" + "d2" * 32,
                assertions=[{"selector": "victim", "status": "INCONCLUSIVE",
                             "reason": "observed delta is null"}],
            )
            draft = self._draft(ws, f"""# Assertion INCONCLUSIVE

**Severity:** High

Cited: `{refs['manifest']}`.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("assertion-inconclusive-present", c22.lower())

    def test_high_manifest_executed_status_accepted(self) -> None:
        """Codex PR-102 blocker 4: the real fork-replay.sh success status
        is 'executed' (not 'success'); check 22 + evidence-matrix must both
        accept it. Require pinned block+fork_block and an assertion PASS."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_valid_deltas(
                ws,
                tx="0x" + "ee" * 32,
                status="executed",
                assertions=[{"selector": "victim", "status": "PASS"}],
            )
            draft = self._draft(ws, f"""# Executed replay

**Severity:** High

Cited: `{refs['manifest']}` and `{refs['deltas']}`.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("✅ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("semantic validation", c22.lower())

    # --- Codex PR-102 blocker 6: a deltas-only citation must discover
    # the sibling manifest by stem and validate it. Without a sibling
    # manifest we cannot verify the replay executed — must fail.
    def test_high_deltas_only_cite_discovers_sibling_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_valid_deltas(
                ws,
                tx="0x" + "ff" * 32,
                status="executed",
                assertions=[{"selector": "victim", "status": "PASS"}],
            )
            draft = self._draft(ws, f"""# Deltas-only cite

**Severity:** High

Cited only the deltas: `{refs['deltas']}` — sibling manifest must be picked
up by stem.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("✅ 22.", c22, msg=f"check22:\n{c22}")

    def test_high_deltas_only_cite_without_sibling_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            tx = "0x" + "a1" * 32
            # Write ONLY the deltas file; no sibling manifest exists.
            (ws / "fork_replay" / f"{tx}_deltas.json").write_text(
                json.dumps({"tx": tx, "addresses": {}})
            )
            draft = self._draft(ws, f"""# Orphan deltas

**Severity:** High

Cited: `fork_replay/{tx}_deltas.json`.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("no-sibling-manifest", c22.lower())

    def test_high_yaml_only_cite_discovers_sibling_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_valid_deltas(
                ws,
                tx="0x" + "a2" * 32,
                status="executed",
                assertions=[{"selector": "victim", "status": "PASS"}],
            )
            draft = self._draft(ws, f"""# YAML-only cite

**Severity:** High

Cited only the summary: `{refs['summary']}` — sibling manifest must be
picked up by stem.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("✅ 22.", c22, msg=f"check22:\n{c22}")

    def test_high_yaml_only_cite_without_sibling_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            tx = "0x" + "a3" * 32
            (ws / "fork_replay" / f"{tx}_replay.yaml").write_text("status: executed\n")
            draft = self._draft(ws, f"""# Orphan YAML

**Severity:** High

Cited: `fork_replay/{tx}_replay.yaml`.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("no-sibling-manifest", c22.lower())

    def test_high_yaml_only_cite_with_failed_sibling_manifest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            refs = _write_valid_deltas(
                ws,
                tx="0x" + "a4" * 32,
                status="failed",
                assertions=[{"selector": "victim", "status": "PASS"}],
            )
            draft = self._draft(ws, f"""# YAML failed sibling

**Severity:** High

Cited only the summary: `{refs['summary']}`.
PoC: poc-tests/x.t.sol.
""")
            r = _run(draft, "High")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertIn("❌ 22.", c22, msg=f"check22:\n{c22}")
            self.assertIn("sibling-manifest:status-not-successful", c22.lower())

    def test_medium_missing_cite_is_advisory_only(self) -> None:
        """Check 22 must NOT emit ❌ for Medium drafts citing a missing deltas
        file. It can emit ⚠️ or ✅ (advisory model). We only assert the
        negative: no ❌ 22. line."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_ws(Path(tmp))
            draft = self._draft(ws, """# Medium missing replay

**Severity:** Medium

See `fork_replay/0xnope_deltas.json` (missing).
""")
            r = _run(draft, "Medium")
            combined = r.stdout + r.stderr
            c22 = "\n".join(_check22_lines(combined))
            self.assertNotIn("❌ 22.", c22, msg=f"check22 must be advisory for Medium:\n{c22}")


if __name__ == "__main__":
    unittest.main()
