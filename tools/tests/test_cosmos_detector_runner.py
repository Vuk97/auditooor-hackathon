#!/usr/bin/env python3
"""Tests for tools/cosmos-detector-runner.py — the FIRST executor for
`backend: cosmos` DSL rows (Wave 2 capability uplift).

Coverage:
  - Positive: synthetic Cosmos-SDK bank handler with NO blocked-addr check
    fires the evmos pattern.
  - Negative: same handler but with `BlockedAddr(toAddr)` guard does NOT
    fire.
  - Workspace with `.go` files but no cosmos-sdk go.mod — runner SKIPs
    cleanly (no findings, summary records reason).
  - Workspace with cosmos-sdk go.mod but no `.go` files — SKIP.
  - Pattern containing an unsupported predicate logs `[skip predicate]`
    and produces no findings (does NOT silently fire).
  - End-to-end CLI smoke: subprocess invocation writes the findings JSON
    to <workspace>/.auditooor/cosmos_findings.json.
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
RUNNER = ROOT / "tools" / "cosmos-detector-runner.py"
EVMOS_PATTERN = ROOT / "reference" / "patterns.dsl" / "evmos-bank-send-to-blocklisted-module-account.yaml"


def _load_runner():
    spec = importlib.util.spec_from_file_location("cosmos_detector_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# Synthetic Go shapes -------------------------------------------------------

GO_MOD_COSMOS = """\
module example.com/myapp/x/bank

go 1.21

require github.com/cosmos/cosmos-sdk v0.50.5
"""

GO_MOD_NON_COSMOS = """\
module example.com/myapp

go 1.21

require github.com/some/other v1.0.0
"""

# Vulnerable bank handler: no BlockedAddr check; calls SendCoins(...).
# The evmos pattern's match list:
#   function.name_matches: ^(SendCoins|MsgSend|...)\\w*$
#   function.body_contains_regex: SendCoins\\s*\\(\\s*\\w+,\\s*\\w+,\\s*toAddr| ...
#   function.body_not_contains_regex: BlockedAddr\\(...
GO_KEEPER_VULN = """\
package bank

import (
    sdk "github.com/cosmos/cosmos-sdk/types"
)

// MsgSendVuln does NOT check BlockedAddr before calling SendCoins.
// This is the Evmos-shape bug: distribution / mint / fee_collector
// module accounts can receive coins directly, breaking invariants.
func (k Keeper) MsgSend(ctx sdk.Context, fromAddr sdk.AccAddress, toAddr sdk.AccAddress, amt sdk.Coins) error {
    if err := k.subUnlockedCoins(ctx, fromAddr, amt); err != nil {
        return err
    }
    return k.SendCoins(ctx, fromAddr, toAddr, amt)
}
"""

# Same shape, but WITH the BlockedAddr guard. Should NOT fire.
GO_KEEPER_CLEAN = """\
package bank

import (
    sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k Keeper) MsgSend(ctx sdk.Context, fromAddr sdk.AccAddress, toAddr sdk.AccAddress, amt sdk.Coins) error {
    if k.BlockedAddr(toAddr) {
        return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", toAddr)
    }
    if err := k.subUnlockedCoins(ctx, fromAddr, amt); err != nil {
        return err
    }
    return k.SendCoins(ctx, fromAddr, toAddr, amt)
}
"""


def _scaffold_workspace(tmp: Path, *, gomod: str | None, go_sources: dict[str, str]) -> Path:
    ws = tmp / "ws"
    (ws / "x" / "bank").mkdir(parents=True, exist_ok=True)
    if gomod is not None:
        (ws / "go.mod").write_text(gomod, encoding="utf-8")
    for rel, src in go_sources.items():
        path = ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src, encoding="utf-8")
    return ws


def _scaffold_patterns_dir(tmp: Path, *, copy_evmos: bool = True,
                           extra: dict[str, str] | None = None) -> Path:
    pdir = tmp / "patterns"
    pdir.mkdir(parents=True, exist_ok=True)
    if copy_evmos:
        (pdir / EVMOS_PATTERN.name).write_text(
            EVMOS_PATTERN.read_text(encoding="utf-8"), encoding="utf-8")
    if extra:
        for name, content in extra.items():
            (pdir / name).write_text(content, encoding="utf-8")
    return pdir


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class CosmosDetectorRunnerYamlTest(unittest.TestCase):
    def test_dsl_yaml_parser_ingests_evmos_pattern(self) -> None:
        """The minimal stdlib YAML parser must round-trip the live evmos
        DSL row that ships in reference/patterns.dsl."""
        mod = _load_runner()
        spec = mod.parse_dsl_yaml(EVMOS_PATTERN.read_text(encoding="utf-8"))
        self.assertEqual(spec.get("pattern"),
                         "evmos-bank-send-to-blocklisted-module-account")
        self.assertEqual(spec.get("backend"), "cosmos")
        self.assertEqual(str(spec.get("severity", "")).upper(), "HIGH")
        # `match:` is a list of single-key dicts.
        match = spec.get("match")
        self.assertIsInstance(match, list)
        self.assertTrue(any(
            isinstance(m, dict) and "function.name_matches" in m for m in match
        ), f"expected function.name_matches in match list, got: {match!r}")


class CosmosDetectorRunnerExtractTest(unittest.TestCase):
    def test_extract_go_functions_finds_named_receiver(self) -> None:
        mod = _load_runner()
        funcs = mod.extract_go_functions(GO_KEEPER_VULN)
        names = [f["name"] for f in funcs]
        self.assertIn("MsgSend", names)
        msg = next(f for f in funcs if f["name"] == "MsgSend")
        self.assertIn("SendCoins(", msg["body"])
        self.assertGreater(msg["line"], 0)

    def test_brace_scanner_handles_strings_and_comments(self) -> None:
        mod = _load_runner()
        # Body contains `}` inside a string and `{` inside a comment;
        # neither should confuse the matcher.
        src = textwrap.dedent('''\
            package x
            func F() {
                s := "}"
                // {
                _ = s
            }
        ''')
        funcs = mod.extract_go_functions(src)
        self.assertEqual(len(funcs), 1)
        self.assertEqual(funcs[0]["name"], "F")


class CosmosDetectorRunnerPositiveTest(unittest.TestCase):
    def test_vuln_bank_handler_fires(self) -> None:
        mod = _load_runner()
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _scaffold_workspace(
                tmp, gomod=GO_MOD_COSMOS,
                go_sources={"x/bank/keeper.go": GO_KEEPER_VULN},
            )
            pdir = _scaffold_patterns_dir(tmp)
            out = tmp / "findings.json"
            rc = mod.run(ws, only=None, patterns_dir=pdir, out_path=out, quiet=True)
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["findings_count"], 1)
            f = payload["findings"][0]
            self.assertEqual(f["pattern"],
                             "evmos-bank-send-to-blocklisted-module-account")
            self.assertEqual(f["function"], "MsgSend")
            self.assertEqual(f["evidence_class"], "scaffolded_unverified")
            self.assertEqual(f["backend"], "cosmos")
            self.assertTrue(f["file"].endswith("keeper.go"))


class CosmosDetectorRunnerNegativeTest(unittest.TestCase):
    def test_clean_handler_with_blocked_addr_guard_does_not_fire(self) -> None:
        mod = _load_runner()
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _scaffold_workspace(
                tmp, gomod=GO_MOD_COSMOS,
                go_sources={"x/bank/keeper.go": GO_KEEPER_CLEAN},
            )
            pdir = _scaffold_patterns_dir(tmp)
            out = tmp / "findings.json"
            rc = mod.run(ws, only=None, patterns_dir=pdir, out_path=out, quiet=True)
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["findings_count"], 0)
            self.assertEqual(payload["findings"], [])


class CosmosDetectorRunnerSkipTest(unittest.TestCase):
    def test_workspace_without_go_mod_is_skipped(self) -> None:
        mod = _load_runner()
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _scaffold_workspace(
                tmp, gomod=None,
                go_sources={"x/bank/keeper.go": GO_KEEPER_VULN},
            )
            pdir = _scaffold_patterns_dir(tmp)
            out = tmp / "findings.json"
            rc = mod.run(ws, only=None, patterns_dir=pdir, out_path=out, quiet=True)
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["findings_count"], 0)
            self.assertEqual(payload["summary"]["skipped_reason"],
                             "no cosmos-sdk go.mod found")

    def test_workspace_with_non_cosmos_go_mod_is_skipped(self) -> None:
        mod = _load_runner()
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _scaffold_workspace(
                tmp, gomod=GO_MOD_NON_COSMOS,
                go_sources={"x/bank/keeper.go": GO_KEEPER_VULN},
            )
            pdir = _scaffold_patterns_dir(tmp)
            out = tmp / "findings.json"
            rc = mod.run(ws, only=None, patterns_dir=pdir, out_path=out, quiet=True)
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["findings_count"], 0)
            self.assertEqual(payload["summary"]["skipped_reason"],
                             "no cosmos-sdk go.mod found")

    def test_workspace_with_no_cosmos_patterns_present_is_skipped(self) -> None:
        mod = _load_runner()
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _scaffold_workspace(
                tmp, gomod=GO_MOD_COSMOS,
                go_sources={"x/bank/keeper.go": GO_KEEPER_VULN},
            )
            # patterns dir has zero cosmos rows
            pdir = _scaffold_patterns_dir(tmp, copy_evmos=False)
            out = tmp / "findings.json"
            rc = mod.run(ws, only=None, patterns_dir=pdir, out_path=out, quiet=True)
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["findings_count"], 0)
            self.assertEqual(payload["summary"]["skipped_reason"],
                             "no cosmos patterns present")


class CosmosDetectorRunnerUnsupportedPredicateTest(unittest.TestCase):
    def test_pattern_with_unsupported_predicate_logs_skip(self) -> None:
        mod = _load_runner()
        # Pattern that asks for an unsupported predicate. It should be
        # parsed cleanly, BUT eval_function_match returns False and the
        # logger emits `[skip predicate]`.
        unsupported_yaml = textwrap.dedent("""\
            pattern: synthetic-cosmos-unsupported
            severity: LOW
            confidence: LOW
            backend: cosmos
            preconditions:
              - chain.is_cosmos_sdk: true
            match:
              - function.kind: cosmos_msg_handler
              - function.name_matches: '^MsgSend\\w*$'
              - function.body_dataflow_taints_external_call: true
            help: synthetic
        """)
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _scaffold_workspace(
                tmp, gomod=GO_MOD_COSMOS,
                go_sources={"x/bank/keeper.go": GO_KEEPER_VULN},
            )
            pdir = _scaffold_patterns_dir(
                tmp, copy_evmos=False,
                extra={"synthetic-cosmos-unsupported.yaml": unsupported_yaml},
            )
            out = tmp / "findings.json"
            rc = mod.run(ws, only=None, patterns_dir=pdir, out_path=out, quiet=True)
            self.assertEqual(rc, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["findings_count"], 0,
                             "unsupported predicate must NOT silently fire")
            log = "\n".join(payload["summary"]["log_excerpt"])
            self.assertIn("[skip predicate]", log,
                          "expected `[skip predicate]` log line")


class CosmosDetectorRunnerCliSmokeTest(unittest.TestCase):
    def test_subprocess_invocation_writes_findings_json(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _scaffold_workspace(
                tmp, gomod=GO_MOD_COSMOS,
                go_sources={"x/bank/keeper.go": GO_KEEPER_VULN},
            )
            pdir = _scaffold_patterns_dir(tmp)
            proc = subprocess.run(
                [sys.executable, str(RUNNER), str(ws),
                 "--patterns-dir", str(pdir), "--quiet"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0,
                             f"runner failed: {proc.stderr}")
            out = ws / ".auditooor" / "cosmos_findings.json"
            self.assertTrue(out.exists(), "default output path not written")
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["findings_count"], 1)


if __name__ == "__main__":
    unittest.main()
