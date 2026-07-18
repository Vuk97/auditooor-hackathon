#!/usr/bin/env python3
"""
integration-assumptions.py — R76 D: surface hidden integration assumptions.

Top auditors ask: what does this contract *assume* about the world around it?
Integration bugs live in the assumption gap:

  * ERC20 assumes `returns bool` (USDT returns nothing, gets silently wrong)
  * Token assumes NO fee-on-transfer (balance delta != amount transferred)
  * Token assumes NO rebase (balance changes without transfer)
  * External contract assumes CEI (re-entrancy safe)
  * Oracle assumes freshness (no timeout check)
  * Chain assumes EIP-1559 basefee (breaks on non-EIP-1559 chains)
  * Chain assumes opcode availability (PUSH0 breaks on Linea/Scroll)
  * Peer assumes ordering (no replay guard expected on other side)
  * ERC-165 interface support assumed (not queried)

Output: <workspace>/integration_assumptions.md

Each entry = hypothesis + call site + "what breaks if assumption is violated"
+ severity.

Usage:
  python3 tools/integration-assumptions.py <workspace>
"""

import argparse, pathlib, re, sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _analyzer_common import iter_source_files

try:
    from slither.slither import Slither
except ImportError:
    print("[err] Slither required", file=sys.stderr); sys.exit(1)


ASSUMPTIONS = [
    # (hypothesis_name, regex in source, severity, failure_mode)
    ("erc20_returns_bool",
     r"\b(?:IERC20|ERC20)\s*\(\s*\w+\s*\)\.transfer(From)?\s*\(",
     "MEDIUM",
     "USDT / BNB / similar return nothing — call will silently pass even on revert."
     " Fix: use SafeERC20.safeTransfer."),

    ("no_fee_on_transfer",
     r"\.transferFrom\s*\(\s*\w+\s*,\s*address\s*\(\s*this\s*\)\s*,\s*\w+\s*\)\s*;\s*(?!.*balanceOf)",
     "HIGH",
     "If token has fee-on-transfer, balance-after != amount; use pre/post balance delta."),

    ("no_rebase_token",
     r"\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
     "MEDIUM",
     "Balance-of-self read assumes no rebase (stETH / aToken / sDAI grow silently)."
     " Fix: track shares separately."),

    ("oracle_fresh_no_check",
     r"(AggregatorV3Interface|IPyth|latestRoundData|latestAnswer)\s*\(.*\)",
     "HIGH",
     "Using Chainlink/Pyth price without checking updatedAt freshness."
     " Attacker can exploit stale prices during oracle downtime."),

    ("sequencer_uptime_missing",
     r"latestRoundData|latestAnswer",
     "MEDIUM",
     "On L2s (Arbitrum/Optimism/Base), must check sequencer uptime feed before trusting prices."
     " L2SequencerUptimeFeed returns 0 when up, 1 when down."),

    ("chain_id_hardcoded_eip712",
     r"bytes32\s+\w*DOMAIN_SEPARATOR\w*\s*=",
     "MEDIUM",
     "If DOMAIN_SEPARATOR is cached in constructor, chain fork invalidates signatures."
     " Fix: compute on every use OR use EIP712Upgradeable that re-caches on chainId change."),

    ("permit_no_try_catch",
     r"\.permit\s*\(\s*\w+\s*,\s*\w+\s*,",
     "MEDIUM",
     "permit() without try/catch can be griefed — attacker front-runs permit, "
     "victim's tx reverts on the permit step."),

    ("push0_opcode",
     r"pragma\s+solidity\s+\^?0\.8\.(1[9-9]|[2-9][0-9])",
     "LOW",
     "solc >= 0.8.20 emits PUSH0 by default. Breaks on Linea / Scroll / older Arbitrum."
     " Fix: set evm_version=paris in foundry.toml."),

    ("assumes_no_code_at_address_zero",
     r"address\(0\)(?!\s*\)\s*\.\s*\w)",
     "LOW",
     "Using address(0) as a sentinel. EIP-7702 / unusual chains may have code at 0."),

    ("assumes_block_timestamp_monotonic",
     r"block\.timestamp\s*[<>]",
     "LOW",
     "block.timestamp can drift ±15s across re-orgs; don't use as exact time reference."),

    ("assumes_tx_origin_is_eoa",
     r"tx\.origin",
     "MEDIUM",
     "Under EIP-7702, EOAs have code. tx.origin == msg.sender no longer implies EOA."
     " See our eip7702-tx-origin-reentrancy-guard-bypass pattern."),

    ("assumes_blockhash_randomness",
     r"blockhash\s*\(",
     "HIGH",
     "blockhash() is miner-predictable. Not a randomness source. Use Chainlink VRF."),

    ("delegatecall_no_code_check",
     r"\.delegatecall\s*\(",
     "HIGH",
     "delegatecall to address with no code is a no-op that returns success. "
     "Always check `to.code.length > 0` first."),

    ("erc165_not_queried",
     r"(onERC721Received|onERC1155Received|tokensReceived)",
     "LOW",
     "Implementing a callback hook without being reachable via ERC-165 supportsInterface."),

    ("assumes_caller_erc721_compliant",
     r"_safeTransfer|safeTransferFrom\s*\(",
     "LOW",
     "safeTransfer() calls onERC721Received — if destination is a contract, reentrancy surface."),

    ("assumes_decimals_18",
     r"(\* 1e18|\/ 1e18|decimals\(\) ==? 18)",
     "MEDIUM",
     "Hardcoded 1e18 assumes 18-decimal tokens. USDC/USDT are 6, WBTC is 8."),

    ("assumes_chainlink_answer_positive",
     r"latestRoundData\(\)[^;]*;(?![^;]*answer\s*[<>=])",
     "MEDIUM",
     "Chainlink answer can be 0 (invalid round) or negative (some feeds)."
     " Check `answer > 0` before use."),
]


def _scan_workspace(ws):
    findings = []
    for sol in iter_source_files(ws, max_files=300):  # R79 T3
        try: txt = sol.read_text()
        except Exception: continue
        for hyp, rx, sev, failure in ASSUMPTIONS:
            for m in re.finditer(rx, txt, flags=re.MULTILINE):
                line_no = txt[:m.start()].count("\n") + 1
                findings.append({
                    "file": sol, "line": line_no, "hypothesis": hyp,
                    "severity": sev, "failure_mode": failure,
                    "snippet": txt[max(m.start()-30, 0):m.end()+50].replace("\n", "↵")[:120],
                })
    return findings


def _render(findings, out):
    by_hyp = defaultdict(list)
    for fd in findings:
        by_hyp[fd["hypothesis"]].append(fd)
    with open(out, "w") as f:
        f.write("# Integration assumptions report\n\n")
        f.write("Generated by `tools/integration-assumptions.py`. Flags code "
                "shapes that depend on implicit assumptions about tokens, "
                "chains, or peer contracts. **Not all flags are bugs** — many "
                "are documented design choices. Review each hypothesis with "
                "the protocol's assumption list.\n\n")
        # Summary table
        f.write("## Summary\n\n")
        f.write("| Hypothesis | Severity | Count |\n|---|---|---:|\n")
        for hyp, fds in sorted(by_hyp.items(), key=lambda x: -len(x[1])):
            sev = fds[0]["severity"]
            f.write(f"| `{hyp}` | {sev} | {len(fds)} |\n")

        # Per-hypothesis detail
        f.write("\n## Per-hypothesis detail\n\n")
        for hyp, fds in sorted(by_hyp.items()):
            sev = fds[0]["severity"]
            fail = fds[0]["failure_mode"]
            f.write(f"\n### `{hyp}` ({sev})\n\n")
            f.write(f"**If violated:** {fail}\n\n")
            f.write(f"**Hits ({len(fds)}):**\n\n")
            for fd in fds[:40]:
                try: rel = fd["file"].relative_to(pathlib.Path.cwd())
                except Exception: rel = fd["file"]
                f.write(f"- `{rel}:{fd['line']}` — `{fd['snippet']}`\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    args = ap.parse_args()
    ws = pathlib.Path(args.workspace)
    if not ws.is_dir(): print("[err] not a dir", file=sys.stderr); sys.exit(1)
    findings = _scan_workspace(ws)
    out = ws / "integration_assumptions.md"
    _render(findings, out)
    print(f"[ok] wrote {out}")
    print(f"     total hypotheses flagged: {len(findings)}")


if __name__ == "__main__":
    main()
