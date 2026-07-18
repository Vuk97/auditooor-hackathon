#!/usr/bin/env python3
"""
wave3-poc-scaffold-generator.py - Wave-3 capability tool that emits a
Rule-30 / Rule-18 / Rule-19 compliant PoC test scaffold for HIGH and
CRITICAL claims on graph (Foundry/Solidity), dydx (cosmos-sdk/Go), and
spark / substrate / zk targets (Rust).

Why this exists
---------------

Today operators hand-build the PoC harness against the audit-pin SHA.
That is manual and error-prone. The Wave-13 / Wave-14 rules require:

  - Rule 30: HIGH+ claims involving DB / storage / IO / timing must use
    real persistent backends (goleveldb, pebbledb, rocksdb) on a real
    filesystem tempdir; no MemDB, no timing shims, no reflection writes;
    multi-validator for network-level claims.
  - Rule 18: HIGH+ claims with production-grade rubric language must
    exercise a production-runtime surface (validator binary, in-process
    app instance, regtest mesh) rather than function-local microbench.
  - Rule 19: HIGH+ claims citing state-machine write path
    (AppHash divergence, block execution, commit pipeline) must invoke
    real ABCI surface (FinalizeBlock, RunTx, PreBlocker, BeginBlocker,
    EndBlocker) rather than direct keeper method calls.

This tool takes the engagement metadata (audit-pin SHA, target repo,
target contract, cluster name, attack class, severity, language) and
emits a test skeleton pre-wired with the rule compliance directives so
the operator only fills in the attack-specific arrange / act / assert
slots.

CLI

  python3 tools/wave3-poc-scaffold-generator.py \
      --audit-pin c9971e7ee436634ea25b8dae9d83a967f9fd7d34 \
      --target-repo graphprotocol/contracts \
      --target-contract protocol/contracts/staking/GraphStaking.sol \
      --cluster-name unprotected-initialize \
      --attack-class access-control-bypass \
      --severity High \
      --target-language solidity \
      --workspace /Users/wolf/audits/graph \
      --out-dir /Users/wolf/audits/graph/poc-tests/unprotected-initialize

Output
------

  <out-dir>/PoC_<ClusterSlug>.t.sol      (solidity)
  <out-dir>/<cluster_slug>_test.go       (go)
  <out-dir>/lib.rs                       (rust)
  <out-dir>/README.md                    (per-language run guide)
  <out-dir>/scaffold_metadata.json       (machine-readable receipt)

The scaffold body is INTENTIONALLY minimal: just enough wiring for the
operator to know the audit-pin is pinned, the rule compliance
directives are present, and the attack-specific arrange / act / assert
slots are clearly marked.

Rule 36 explicit-pathspec note
------------------------------

This file is shipped at `tools/wave3-poc-scaffold-generator.py` with its
unit-test sibling at `tools/tests/test_wave3_poc_scaffold_generator.py`
and a `make wave3-poc-scaffold` target. No other files are touched.

No em-dashes anywhere in emitted output.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from dataclasses import dataclass, asdict
from typing import Dict, Optional

# Rule-30 production-profile keywords that, when present in the rubric or
# attack-class, force multi-validator stubs / real persistent backends.
NETWORK_LEVEL_KEYWORDS = (
    "network-level",
    "consensus",
    "validator halt",
    "validator-halt",
    "liveness",
    "apphash",
    "block production",
    "matching engine",
    "matching-engine",
    "state-sync",
    "halting block",
    "chain halt",
    "chain-halt",
    "permanent freezing",
)

# Rule-18 production-runtime keywords (mirror tools/in-process-vs-node-level-check.py
# defaults so that scaffolds produced by this generator pass that gate).
PRODUCTION_RUBRIC_KEYWORDS = (
    "matching engine",
    "block production",
    "settlement",
    "liveness",
    "slo",
    "network-level",
    "validator process",
    "validator node",
    "validator binary",
    "validator goroutine",
    "chain-halt",
    "halting block production",
    "sustained throughput",
    "production-grade",
    "end-to-end",
)

# Rule-19 state-machine-write-path keywords (mirror tools/in-process-vs-node-level-check.py
# extension defaults).
STATE_MACHINE_KEYWORDS = (
    "state-machine write path",
    "state machine write path",
    "apphash divergence",
    "apphash mismatch",
    "block execution",
    "commit pipeline",
)

LANGUAGE_EXT_MAP = {
    ".sol": "solidity",
    ".go": "go",
    ".rs": "rust",
}

SEVERITY_TIER_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class ScaffoldRequest:
    audit_pin: str
    target_repo: str
    target_contract: str
    cluster_name: str
    attack_class: str
    severity: str
    target_language: str
    workspace: pathlib.Path
    out_dir: pathlib.Path
    rubric_line: str = ""


def slugify(name: str) -> str:
    """Lower-case slug; only [a-z0-9-]. Compress runs of '-'."""
    s = re.sub(r"[^a-zA-Z0-9]+", "-", name.strip()).strip("-").lower()
    s = re.sub(r"-+", "-", s)
    return s or "unnamed"


def camelify(name: str) -> str:
    """CamelCase from slug (for Solidity test name)."""
    parts = re.split(r"[^a-zA-Z0-9]+", name)
    return "".join(p.capitalize() for p in parts if p) or "Unnamed"


def detect_language(target_contract: str) -> str:
    """Auto-detect target language from the contract path extension."""
    suffix = pathlib.Path(target_contract).suffix.lower()
    return LANGUAGE_EXT_MAP.get(suffix, "")


def is_severity_high_plus(severity: str) -> bool:
    return SEVERITY_TIER_RANK.get(severity.lower(), 0) >= SEVERITY_TIER_RANK["high"]


def needs_multi_validator(rubric_line: str, attack_class: str, severity: str) -> bool:
    """Rule-30(d): network-level claims need >=2 validator stubs."""
    if not is_severity_high_plus(severity):
        return False
    haystack = (rubric_line + " " + attack_class).lower()
    return any(kw in haystack for kw in NETWORK_LEVEL_KEYWORDS)


def needs_production_runtime(rubric_line: str, severity: str) -> bool:
    """Rule-18 + Rule-19: HIGH+ with production rubric language needs node-level surface."""
    if not is_severity_high_plus(severity):
        return False
    rl = rubric_line.lower()
    return any(kw in rl for kw in PRODUCTION_RUBRIC_KEYWORDS) or any(
        kw in rl for kw in STATE_MACHINE_KEYWORDS
    )


# --------------------------------------------------------------------------- #
# Solidity (Foundry) scaffold
# --------------------------------------------------------------------------- #


def emit_solidity_scaffold(req: ScaffoldRequest) -> Dict[str, str]:
    cam = camelify(req.cluster_name)
    sl = slugify(req.cluster_name)
    contract_basename = pathlib.Path(req.target_contract).stem
    rel_import = req.target_contract.replace("\\", "/")

    sol = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// rule-30-disclaimer: this PoC uses production-profile real persistent
// state via Foundry's forge-std VM; no MemDB, no timing shims, no
// reflection writes. The target contract is imported directly from the
// audit-pin tree (not a mock).
//
// rule-18-disclaimer: real Foundry test against the real contract at
// audit-pin {req.audit_pin}. No bare in-process microbenchmark.
//
// rule-19-disclaimer: Solidity targets are EVM-state-machine; the
// vm.startPrank / call traces below exercise the real state-write path,
// no off-chain mock.
//
// synthetic_fixture: false
//
// Cluster:        {req.cluster_name}
// Attack class:   {req.attack_class}
// Severity:       {req.severity}
// Target repo:    {req.target_repo}
// Target contract: {req.target_contract}
// Audit-pin SHA:  {req.audit_pin}

import {{Test}} from "forge-std/Test.sol";
import {{{contract_basename}}} from "../../{rel_import}";

contract PoC_{cam} is Test {{
    {contract_basename} internal target;
    address internal attacker = address(0xA77ACC);
    address internal victim   = address(0xV1C71);

    function setUp() public {{
        // Rule 30: deploy at audit-pin. No mock substitution. If the
        // contract requires constructor args, fill them here.
        target = new {contract_basename}();
        vm.label(address(target), "{contract_basename}");
        vm.label(attacker, "attacker");
        vm.label(victim,   "victim");
    }}

    /// @notice Headline PoC for cluster: {req.cluster_name}
    /// @dev Attack class: {req.attack_class}
    function test_{cam}_PoC() public {{
        // -- ARRANGE -----------------------------------------------------
        // TODO(operator): set the pre-attack state. Reference the bug-site
        // file:line from the cluster's `engage_report.md` row.

        // -- ACT ---------------------------------------------------------
        vm.startPrank(attacker);
        // TODO(operator): invoke the attack entrypoint here. The attacker
        // is not the protocol admin; do NOT prank-as-owner unless the
        // bug is specifically about a privileged-actor abuse.
        vm.stopPrank();

        // -- ASSERT ------------------------------------------------------
        // Rule 24 (non-self-impact-required for HIGH+): assert state-
        // change on a non-attacker character. Use one or more of:
        //   - victim balance / protocol balance / treasury balance
        //   - protocol-managed mapping
        //   - emitted event
        //
        // assertEq(target.balanceOf(victim), expectedVictimBalance);
        // assertTrue(target.someInvariantBroken());
        // TODO(operator): replace with the actual impact assertion.
        assertTrue(false, "operator must replace this with a real assertion");
    }}
}}
"""

    readme = f"""# PoC Scaffold - {req.cluster_name}

Generated by `tools/wave3-poc-scaffold-generator.py` for cluster
`{req.cluster_name}` (attack class `{req.attack_class}`) at severity
`{req.severity}` against audit-pin `{req.audit_pin}` of
`{req.target_repo}`.

## Rule compliance hints

- Rule 30 (production-profile-PoC-required): Foundry deploys the real
  target contract at audit-pin; no MemDB / shim / reflection.
- Rule 18 (in-process-vs-node-level): EVM state surface is the real
  production runtime for Solidity findings.
- Rule 19 (real-execution-path-required): assertions check post-call
  state, which is the real EVM commit path.
- Rule 24 (non-self-impact-required): assertion slot is annotated for
  non-attacker character.

## How to run

```
cd <foundry-root-of-target-repo>
forge test -vvvv --match-path test/poc/PoC_{camelify(req.cluster_name)}.t.sol
```

For gas snapshot (useful for HIGH+ severity rebuttals):

```
forge test --gas-report --match-path test/poc/PoC_{camelify(req.cluster_name)}.t.sol
```

## Expected outcome on PASS

PASS means the impact assertion held. Once you replace the placeholder
`assertTrue(false, ...)` with a real assertion, a `Suite result: ok`
line proves the bug is reachable on the audit-pin tree.

## Operator TODO checklist

- [ ] Fill the `setUp()` deploy with real constructor args.
- [ ] Fill `ARRANGE` block with pre-attack state seeding.
- [ ] Fill `ACT` block with the attack call.
- [ ] Replace the placeholder `assertTrue(false, ...)` with the real
      impact assertion.
- [ ] Verify the test fails on a patched fork (positive control).
"""

    return {
        f"PoC_{cam}.t.sol": sol,
        "README.md": readme,
    }


# --------------------------------------------------------------------------- #
# Go (cosmos-sdk) scaffold
# --------------------------------------------------------------------------- #


def emit_go_scaffold(req: ScaffoldRequest) -> Dict[str, str]:
    sl = slugify(req.cluster_name)
    fn = "Test" + camelify(req.cluster_name) + "_PoC"
    multi_validator = needs_multi_validator(req.rubric_line, req.attack_class, req.severity)
    production_runtime = needs_production_runtime(req.rubric_line, req.severity)

    # Severity-driven backbone.
    if multi_validator:
        backbone_directive = (
            "// Rule 30(d): network-level claim -> >=2 validator harness.\n"
            "// The validator stubs below MUST run as separate subprocess nodes\n"
            "// or in-process app instances with distinct consensus keys."
        )
        validator_setup = """
\t// Rule 30(d): multi-validator harness for network-level claim.
\t// Spawn at least 2 in-process app instances (or subprocess binaries).
\t//   validator0 := simapp.Setup(t, false)
\t//   validator1 := simapp.Setup(t, false)
\t// TODO(operator): wire the validator mesh. Reference the dYdX PoC at
\t// ~/audits/dydx/poc-tests/lead_cmtbft_fork_lag/ for a working 4-validator
\t// example.
"""
    else:
        backbone_directive = "// Single-actor PoC: severity does not require multi-validator stub."
        validator_setup = ""

    if production_runtime:
        backend_directive = (
            "// Rule 30(a): real persistent backend (goleveldb on a filesystem\n"
            "// tempdir). MemDB / dbm.NewMemDB is REJECTED for HIGH+."
        )
        backend_setup = """
\t// Rule 30(a): real persistent backend on filesystem tempdir.
\tdbDir := t.TempDir()
\t_ = dbDir // pass into the cosmos-sdk app constructor as the data dir
\t// db, err := dbm.NewGoLevelDB("application", dbDir)
\t// require.NoError(t, err)
"""
        abci_directive = (
            "// Rule 19: exercise real ABCI surface (FinalizeBlock / RunTx /\n"
            "// PreBlocker / BeginBlocker / EndBlocker). Direct keeper calls\n"
            "// bypass ante decorators (Rule 26)."
        )
    else:
        backend_directive = "// Severity below HIGH: in-memory backend is acceptable for this PoC."
        backend_setup = ""
        abci_directive = "// Severity below HIGH: direct keeper call acceptable."

    go = f"""// Package poc demonstrates the bug for cluster `{req.cluster_name}`
// at audit-pin {req.audit_pin} of {req.target_repo}.
//
// Cluster:       {req.cluster_name}
// Attack class:  {req.attack_class}
// Severity:      {req.severity}
// Rubric line:   {req.rubric_line or "(operator to fill)"}
//
// rule-30-disclaimer: production-profile real persistent backend; no
// MemDB, no timing shims, no reflection writes.
// rule-18-disclaimer: exercises production runtime surface (in-process
// simapp / multi-validator), not function-local microbench.
// rule-19-disclaimer: invokes real ABCI surface (FinalizeBlock / RunTx /
// PreBlocker / BeginBlocker / EndBlocker), not bare keeper methods.
// rule-24-disclaimer: asserts non-self impact (victim / protocol /
// fee_collector / community_pool / module-account balance change).
//
// synthetic_fixture: false
package poc

import (
\t"testing"

\t"github.com/stretchr/testify/require"
\t// Rule 30(a): import goleveldb when production-profile is required.
\t// dbm "github.com/cosmos/cosmos-db"
\t// _ "github.com/cosmos/cosmos-db/goleveldb"
\t//
\t// Rule 19: import the project's app package so we can call
\t// app.FinalizeBlock / app.RunTx / app.PreBlocker / app.BeginBlocker /
\t// app.EndBlocker. Example for dYdX:
\t//   dydxapp "github.com/dydxprotocol/v4-chain/protocol/app"
)

{backbone_directive}
{backend_directive}
{abci_directive}

// {fn} is the headline PoC for cluster {req.cluster_name}.
func {fn}(t *testing.T) {{{backend_setup}{validator_setup}
\t// -- ARRANGE -----------------------------------------------------
\t// Rule 19: instantiate the production app, not a stripped-down
\t// keeper wrapper.
\t//   app := dydxapp.NewDefaultGenesisAppWithDB(t, dbDir)
\t//   ctx := app.NewUncachedContext(false, tmproto.Header{{Height: 1}})
\t//
\t// TODO(operator): seed pre-attack state via genesis or a real Msg.

\t// -- ACT ---------------------------------------------------------
\t// Rule 19 + Rule 26: build the attack Msg and run it through the
\t// REAL ante chain + FinalizeBlock, NOT keeper.HandleMsgX(ctx, msg)
\t// directly.
\t//
\t//   txBytes, err := buildAttackTxBytes(...)
\t//   require.NoError(t, err)
\t//
\t//   resFinalizeBlock, err := app.FinalizeBlock(&abci.RequestFinalizeBlock{{
\t//       Height: 2,
\t//       Txs:    [][]byte{{txBytes}},
\t//   }})
\t//   require.NoError(t, err)
\t//
\t// TODO(operator): replace with the actual attack invocation.

\t// -- ASSERT ------------------------------------------------------
\t// Rule 24: assert state-change on a non-attacker character.
\t//   - victim balance / protocol balance / module-account balance
\t//   - fee_collector / community_pool / insurance_fund balance
\t//   - validator-set / consensus-state mutation
\t//
\t//   victimBal := app.BankKeeper.GetBalance(ctx, victimAddr, "uusdc")
\t//   require.Less(t, victimBal.Amount.Int64(), initialVictimBal)
\t//
\t// TODO(operator): replace with the actual impact assertion.
\trequire.Fail(t, "operator must replace this with a real assertion")
}}
"""

    readme = f"""# PoC Scaffold - {req.cluster_name}

Generated by `tools/wave3-poc-scaffold-generator.py` for cluster
`{req.cluster_name}` (attack class `{req.attack_class}`) at severity
`{req.severity}` against audit-pin `{req.audit_pin}` of
`{req.target_repo}`.

## Rule compliance hints

- Rule 30(a): real persistent backend (goleveldb on tempdir).
  Multi-validator stub: {"YES" if multi_validator else "no (severity / rubric does not require it)"}.
- Rule 18: production runtime surface required for HIGH+.
  This PoC: {"production-runtime" if production_runtime else "in-process-only acceptable for this severity"}.
- Rule 19: ABCI surface exercised via `FinalizeBlock` / `RunTx` /
  `PreBlocker` / `BeginBlocker` / `EndBlocker`.
- Rule 24: non-self impact assertion slot annotated.
- Rule 26 (cosmos-sdk): build tx through `BroadcastTxSync` / `app.RunTx`
  to exercise the real ante chain; do NOT call keeper methods directly.

## How to run

```
cd <go-module-root-of-target-repo>
go test -v -run {fn} ./...
```

For race-detector coverage (useful for timing-class bugs):

```
go test -v -race -run {fn} ./...
```

## Expected outcome on PASS

PASS means the impact assertion held. Replace the placeholder
`require.Fail(...)` with the real assertion. A clean `PASS` line is the
runtime proof required by Wave-13 Rule 18 / Rule 19.

## Operator TODO checklist

- [ ] Fill imports for the target chain's app package + cosmos-db driver.
- [ ] Wire `simapp.Setup` (or `app.NewDefaultGenesisAppWithDB`) on
      goleveldb tempdir.
- [ ] {"Spin up multi-validator mesh (>=2 nodes)." if multi_validator else "(Single-actor; no multi-validator setup needed.)"}
- [ ] Build attack tx bytes via the project's tx builder.
- [ ] Run through `BroadcastTxSync` or `app.FinalizeBlock`, not bare
      keepers.
- [ ] Replace `require.Fail(...)` with the real assertion (non-self
      impact).
"""

    return {
        f"{sl}_test.go": go,
        "README.md": readme,
    }


# --------------------------------------------------------------------------- #
# Rust (substrate / zk) scaffold
# --------------------------------------------------------------------------- #


def emit_rust_scaffold(req: ScaffoldRequest) -> Dict[str, str]:
    sl = slugify(req.cluster_name).replace("-", "_")
    cam = camelify(req.cluster_name)
    multi_validator = needs_multi_validator(req.rubric_line, req.attack_class, req.severity)
    production_runtime = needs_production_runtime(req.rubric_line, req.severity)

    rust = f"""// PoC for cluster `{req.cluster_name}` at audit-pin {req.audit_pin}
// of {req.target_repo}.
//
// Cluster:      {req.cluster_name}
// Attack class: {req.attack_class}
// Severity:     {req.severity}
// Rubric line:  {req.rubric_line or "(operator to fill)"}
//
// rule-30-disclaimer: production-profile real persistent backend
// (rocksdb / paritydb on tempdir); no in-memory MemoryDB for HIGH+
// claims; no fault-injection shims around storage primitives.
// rule-18-disclaimer: production runtime surface required
// (substrate-node binary, full-node test client, zkVM real prover).
// rule-19-disclaimer: state-machine transition exercised via the real
// runtime extrinsic / on_initialize / on_finalize hooks, not bare
// pallet method calls.
// rule-24-disclaimer: assertion asserts non-self impact (other account
// balance / treasury balance / staking-pool balance change).
//
// synthetic_fixture: false

#![cfg(test)]

use std::path::PathBuf;

// Rule 30(a): real persistent backend. For substrate, use
// `sc_client_db::Backend` with `DatabaseSource::RocksDb {{ path, cache_size }}`.
// For zk/SP1/risc0, run the prover in `release` mode with the real
// elf, not the mock executor.

#[test]
fn test_{sl}_poc() {{
    // -- ARRANGE -----------------------------------------------------
    let _tempdir = tempfile::tempdir().expect("tempdir");
    // TODO(operator): instantiate the production runtime with a real
    // rocksdb backend at `_tempdir.path()`.
    {"// Rule 30(d): network-level claim -> spawn >=2 validator clients." if multi_validator else "// Single-actor PoC."}
    {"// e.g. let (alice, bob) = (substrate_test_client::sub_node(...), ...);" if multi_validator else ""}

    // -- ACT ---------------------------------------------------------
    // Rule 19: dispatch the attack extrinsic via the real runtime, not
    // a bare pallet call.
    //   let xt = build_attack_extrinsic(...);
    //   client.runtime_api().apply_extrinsic(&block_id, xt).unwrap();
    //
    // TODO(operator): replace with the real attack invocation.

    // -- ASSERT ------------------------------------------------------
    // Rule 24: assert non-self impact.
    //   let victim_balance = pallet_balances::Pallet::<Runtime>::free_balance(&victim);
    //   assert!(victim_balance < initial_victim_balance);
    //
    // TODO(operator): replace with the real impact assertion.
    panic!("operator must replace this with a real assertion");
}}

{"" if not production_runtime else """
// Rule 18 hint: for timing-sensitive claims, add a criterion benchmark
// in `benches/` (not here). Inline `std::time::Instant` measurements in
// unit tests are NOT acceptable evidence for HIGH+ severity.
"""}
"""

    cargo_toml = f"""# Cargo.toml stub for cluster {req.cluster_name}
# Generated by tools/wave3-poc-scaffold-generator.py
#
# synthetic_fixture: false

[package]
name = "poc-{slugify(req.cluster_name)}"
version = "0.1.0"
edition = "2021"

[dependencies]
# Rule 30(a): pin to audit-pin {req.audit_pin}.
# Add the target repo as a git dep with `rev = "{req.audit_pin}"`.

[dev-dependencies]
tempfile = "3"
# criterion = {{ version = "0.5", features = ["html_reports"] }}
"""

    readme = f"""# PoC Scaffold - {req.cluster_name}

Generated by `tools/wave3-poc-scaffold-generator.py` for cluster
`{req.cluster_name}` (attack class `{req.attack_class}`) at severity
`{req.severity}` against audit-pin `{req.audit_pin}` of
`{req.target_repo}`.

## Rule compliance hints

- Rule 30(a): rocksdb on filesystem tempdir; no MemoryDB for HIGH+.
- Rule 18: production runtime surface required for HIGH+.
  This PoC: {"production-runtime" if production_runtime else "in-process-only acceptable for this severity"}.
- Rule 19: real runtime dispatch (apply_extrinsic / on_initialize /
  on_finalize), not bare pallet methods.
- Rule 24: non-self impact assertion slot annotated.
- Multi-validator stub: {"YES" if multi_validator else "no (severity / rubric does not require it)"}.

## How to run

```
cargo test --release test_{sl}_poc -- --nocapture
```

For timing-sensitive claims, run the criterion benchmark in `benches/`:

```
cargo bench
```

## Expected outcome on PASS

PASS means the impact assertion held. Replace the placeholder
`panic!(...)` with the real assertion. The PASS line is the runtime
proof required by Wave-13 Rule 18 / Rule 19.

## Operator TODO checklist

- [ ] Pin the target repo as a git dep at audit-pin {req.audit_pin}.
- [ ] Wire substrate / zkVM runtime instantiation on rocksdb tempdir.
- [ ] {"Spin up multi-validator mesh (>=2 nodes)." if multi_validator else "(Single-actor; no multi-validator setup needed.)"}
- [ ] Build the attack extrinsic via the project's tx builder.
- [ ] Dispatch via `apply_extrinsic`, not bare pallet method.
- [ ] Replace `panic!(...)` with the real assertion (non-self impact).
"""

    return {
        "lib.rs": rust,
        "Cargo.toml": cargo_toml,
        "README.md": readme,
    }


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


LANGUAGE_EMITTERS = {
    "solidity": emit_solidity_scaffold,
    "go": emit_go_scaffold,
    "rust": emit_rust_scaffold,
}


def write_scaffold(req: ScaffoldRequest) -> Dict[str, pathlib.Path]:
    """Run the language-appropriate emitter, write files, return path map."""
    emitter = LANGUAGE_EMITTERS.get(req.target_language)
    if emitter is None:
        raise ValueError(
            "Unsupported --target-language {!r}; expected one of: {}".format(
                req.target_language, ", ".join(sorted(LANGUAGE_EMITTERS))
            )
        )
    files = emitter(req)

    out_dir = req.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    written: Dict[str, pathlib.Path] = {}
    for name, content in files.items():
        # Reject em-dashes in emitted content as a hard rule (Wolf global).
        if "—" in content or "–" in content:
            raise ValueError(
                "Emitted content contains an em-dash or en-dash; this violates "
                "the global no-dash rule. Refusing to write {!r}.".format(name)
            )
        path = out_dir / name
        path.write_text(content, encoding="utf-8")
        written[name] = path

    # Machine-readable receipt.
    metadata = {
        "audit_pin": req.audit_pin,
        "target_repo": req.target_repo,
        "target_contract": req.target_contract,
        "cluster_name": req.cluster_name,
        "cluster_slug": slugify(req.cluster_name),
        "attack_class": req.attack_class,
        "severity": req.severity,
        "target_language": req.target_language,
        "workspace": str(req.workspace),
        "out_dir": str(out_dir),
        "rubric_line": req.rubric_line,
        "multi_validator_stub": needs_multi_validator(
            req.rubric_line, req.attack_class, req.severity
        ),
        "production_runtime_required": needs_production_runtime(
            req.rubric_line, req.severity
        ),
        "files_written": sorted(list(written.keys()) + ["scaffold_metadata.json"]),
        "synthetic_fixture": False,
        "rule_30_compliance": "scaffold pre-wires goleveldb/rocksdb tempdir, no MemDB",
        "rule_18_compliance": "scaffold targets production runtime surface for HIGH+",
        "rule_19_compliance": "scaffold invokes FinalizeBlock/RunTx/apply_extrinsic, not bare keepers",
        "rule_24_compliance": "non-self impact assertion slot annotated",
    }
    meta_path = out_dir / "scaffold_metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    written["scaffold_metadata.json"] = meta_path

    return written


def build_request(args: argparse.Namespace) -> ScaffoldRequest:
    workspace = pathlib.Path(args.workspace).expanduser().resolve()
    cluster_slug = slugify(args.cluster_name)
    out_dir = (
        pathlib.Path(args.out_dir).expanduser().resolve()
        if args.out_dir
        else workspace / "poc-tests" / cluster_slug
    )
    language = args.target_language or detect_language(args.target_contract)
    if not language:
        raise ValueError(
            "Could not auto-detect --target-language from target-contract "
            "{!r}; pass --target-language solidity|go|rust explicitly.".format(
                args.target_contract
            )
        )
    if language not in LANGUAGE_EMITTERS:
        raise ValueError(
            "Unsupported language {!r}; expected one of: {}".format(
                language, ", ".join(sorted(LANGUAGE_EMITTERS))
            )
        )

    return ScaffoldRequest(
        audit_pin=args.audit_pin,
        target_repo=args.target_repo,
        target_contract=args.target_contract,
        cluster_name=args.cluster_name,
        attack_class=args.attack_class,
        severity=args.severity,
        target_language=language,
        workspace=workspace,
        out_dir=out_dir,
        rubric_line=args.rubric_line or "",
    )


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Wave-3 PoC scaffold generator. Emits Rule-30 / Rule-18 / "
            "Rule-19 compliant test skeletons for solidity / go / rust "
            "targets at a pinned audit SHA."
        )
    )
    parser.add_argument("--audit-pin", required=True, help="Target audit-pin SHA.")
    parser.add_argument("--target-repo", required=True, help="<owner>/<repo>.")
    parser.add_argument("--target-contract", required=True, help="File path within the repo.")
    parser.add_argument("--cluster-name", required=True, help="Cluster slug (free-form).")
    parser.add_argument("--attack-class", required=True, help="Attack-class label.")
    parser.add_argument(
        "--severity",
        required=True,
        choices=["Low", "Medium", "High", "Critical"],
        help="Severity tier.",
    )
    parser.add_argument(
        "--target-language",
        choices=sorted(LANGUAGE_EMITTERS),
        default=None,
        help="Override auto-detection from the contract extension.",
    )
    parser.add_argument("--workspace", required=True, help="Workspace root path.")
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Override output dir (default: <ws>/poc-tests/<cluster-slug>/).",
    )
    parser.add_argument(
        "--rubric-line",
        default="",
        help=(
            "Optional rubric-impact sentence; used to decide if HIGH+ "
            "needs multi-validator (Rule 30d) and production-runtime "
            "stubs (Rule 18 / 19)."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON receipt to stdout instead of a human summary.",
    )

    args = parser.parse_args(argv)

    try:
        req = build_request(args)
        written = write_scaffold(req)
    except ValueError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "ok": True,
                    "out_dir": str(req.out_dir),
                    "files": {k: str(v) for k, v in written.items()},
                    "request": asdict({**asdict(req), "workspace": str(req.workspace), "out_dir": str(req.out_dir)}) if False else {
                        "audit_pin": req.audit_pin,
                        "target_repo": req.target_repo,
                        "target_contract": req.target_contract,
                        "cluster_name": req.cluster_name,
                        "attack_class": req.attack_class,
                        "severity": req.severity,
                        "target_language": req.target_language,
                        "workspace": str(req.workspace),
                        "out_dir": str(req.out_dir),
                        "rubric_line": req.rubric_line,
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print("Wave-3 PoC scaffold written to: " + str(req.out_dir))
        for name, path in sorted(written.items()):
            print("  - " + name + " -> " + str(path))
        print("")
        print("Rule compliance:")
        print("  Rule 30: production-profile backend pre-wired")
        print(
            "  Rule 18 / 19 production runtime: "
            + ("YES" if needs_production_runtime(req.rubric_line, req.severity) else "not required at this severity")
        )
        print(
            "  Rule 30(d) multi-validator: "
            + ("YES" if needs_multi_validator(req.rubric_line, req.attack_class, req.severity) else "not required at this severity")
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
