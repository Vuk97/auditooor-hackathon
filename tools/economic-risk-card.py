#!/usr/bin/env python3
"""PR 111 — Economic Risk Card.

HYPOTHESIS-GENERATING, not proof. This tool reads a workspace's existing
local artifacts (ccia_report, Solidity sources under src/, swarm priorities,
deployment topology) and produces a per-engagement Markdown (and optional
JSON) card summarizing candidate economic risks in six categories:

  1. Liquidation cascade
  2. Sandwich / MEV
  3. Governance concentration
  4. Token-supply pressure
  5. Fee path
  6. Oracle dependency

Every output section uses "Hypothesis:" / "Next proof step:" framing. No
line in the output should read like a finding claim. The card becomes a
candidate finding ONLY after a Forge PoC + fork-replay delta confirm the
economic movement.

Offline only — this tool does NOT invoke forge, slither, halmos, or any
network. It does NOT invoke any subprocess that compiles the workspace.
It is NOT wired into pre-submit-check.sh or any blocking gate.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path
from typing import Any

TOOL_VERSION = 1
DISCLAIMER = (
    "This file is HYPOTHESIS-GENERATING. It is NOT a submission. Every "
    "section identifies candidate economic risks that require fork-replay "
    "/ PoC confirmation before any finding claim."
)
NO_CANDIDATE = "no candidate found"

# ---------------------------------------------------------------------------
# Section heuristics
# ---------------------------------------------------------------------------

SECTIONS = [
    ("liquidation-cascade", "Liquidation cascade"),
    ("sandwich-mev", "Sandwich / MEV"),
    ("governance-concentration", "Governance concentration"),
    ("token-supply-pressure", "Token-supply pressure"),
    ("fee-path", "Fee path"),
    ("oracle-dependency", "Oracle dependency"),
]

# Liquidation
RX_LIQ_FN = re.compile(
    r"function\s+(?:_liquidate|liquidate|isLiquidatable)\s*\(", re.IGNORECASE
)
RX_ORACLE_CALL = re.compile(
    r"(oracle\.getPrice\s*\(|getAssetPrice\s*\(|IChainlinkAggregator|"
    r"latestAnswer\s*\(|latestRoundData\s*\(|oracle\.\w+\s*\()",
)
RX_FLASHLOAN = re.compile(r"\bflashLoan\s*\(", re.IGNORECASE)

# Sandwich / MEV
RX_SWAP_FN = re.compile(
    r"function\s+(swap|addLiquidity|removeLiquidity|exactInputSingle|"
    r"exactOutputSingle)\s*\(",
)
RX_SLIPPAGE = re.compile(
    r"(amountOutMin|minOut|slippage|minAmountOut|sqrtPriceLimit)",
    re.IGNORECASE,
)
RX_DEADLINE = re.compile(r"\bdeadline\b")

# Governance
RX_GOV_MODIFIER = re.compile(
    r"(onlyOwner|onlyAdmin|onlyGovernor|"
    r"hasRole\s*\(\s*DEFAULT_ADMIN_ROLE|"
    r"hasRole\s*\(\s*[A-Z_]+_ROLE)",
)
RX_STATE_MUTATE_FN = re.compile(
    r"function\s+\w+\s*\([^)]*\)\s*(?:external|public)[^{;]*",
)
RX_INIT_FN = re.compile(
    r"function\s+(?:initialize|__\w+_init)\s*\(|constructor\s*\(",
)

# Supply pressure
RX_MINT_FN = re.compile(r"function\s+(?:_mint|mint)\s*\(")
RX_BURN_FN = re.compile(r"function\s+(?:_burn|burn)\s*\(")
RX_CAP = re.compile(r"(maxSupply|supplyCap|cap\s*\()")

# Fee path
RX_FEE_DECL = re.compile(
    r"(feeRate|protocolFee|_takeFee\s*\(|feeAmount|\bfee\s*=)",
)
RX_FEE_RECIPIENT = re.compile(
    r"(treasury|feeRecipient|feeCollector|feeTo)",
)

# Oracle dependency
RX_ORACLE_USAGE = re.compile(
    r"(IChainlinkAggregator|latestAnswer\s*\(|latestRoundData\s*\(|"
    r"getAssetPrice\s*\(|\.getPrice\s*\(|oracle\.\w+\s*\()",
)
RX_STALENESS = re.compile(
    r"(answeredInRound|updatedAt|roundId\s*[<>=!])",
)


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


def _blank_section() -> dict:
    return {"hypotheses": [], "high_signal": 0}


# ---------------------------------------------------------------------------
# Source discovery
# ---------------------------------------------------------------------------


def discover_sources(ws: Path, contract_filter: str | None) -> list[Path]:
    src_root = ws / "src"
    if not src_root.is_dir():
        return []
    results: list[Path] = []
    for p in sorted(src_root.rglob("*.sol")):
        if contract_filter:
            if p.stem != contract_filter:
                continue
        # skip obvious test + mock directories
        parts = {s.lower() for s in p.parts}
        if "test" in parts or "tests" in parts or "mocks" in parts:
            continue
        results.append(p)
    return results


# ---------------------------------------------------------------------------
# Section analyzers
# ---------------------------------------------------------------------------


def _find_fn_matches(
    text: str, rx: re.Pattern[str]
) -> list[tuple[int, str]]:
    out = []
    for m in rx.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        out.append((line_no, m.group(0)))
    return out


def _fn_body(text: str, start: int, max_lines: int = 40) -> str:
    """Return up to ~max_lines following `start` for slippage heuristic."""
    end = start
    line_count = 0
    while end < len(text) and line_count < max_lines:
        if text[end] == "\n":
            line_count += 1
        end += 1
    return text[start:end]


def analyze_liquidation(src_files: list[tuple[Path, str]]) -> dict:
    sec = _blank_section()
    for path, text in src_files:
        matches = _find_fn_matches(text, RX_LIQ_FN)
        if not matches:
            continue
        oracle_hits = list(RX_ORACLE_CALL.finditer(text))
        flashloan = RX_FLASHLOAN.search(text) is not None
        for line_no, fn in matches:
            ocall = oracle_hits[0].group(0) if oracle_hits else None
            high = bool(oracle_hits)
            sec["hypotheses"].append(
                {
                    "contract": path.stem,
                    "file": str(path),
                    "line": line_no,
                    "narrative": (
                        f"Liquidation entrypoint `{fn.rstrip('(')}` in "
                        f"`{path.name}:{line_no}` "
                        + (
                            f"co-resides with oracle read `{ocall}`."
                            if ocall
                            else "lacks an obvious oracle read in-file "
                            "(may still be indirect)."
                        )
                        + (
                            " A `flashLoan` function is also defined in the "
                            "same contract — a same-block manipulate-then-"
                            "liquidate path may be possible."
                            if flashloan
                            else ""
                        )
                    ),
                    "evidence": [f"{path}:{line_no}"]
                    + (
                        [
                            f"{path}:"
                            f"{text.count(chr(10), 0, oracle_hits[0].start()) + 1}"
                        ]
                        if oracle_hits
                        else []
                    ),
                    "next_proof_step": (
                        f"Fork-replay at a block where an attacker manipulates "
                        f"the oracle read by `{path.stem}` then calls "
                        f"`{fn.rstrip('(')}`. Gate: victim collateral lost "
                        f"> gas cost."
                    ),
                    "high_signal": high,
                }
            )
            if high:
                sec["high_signal"] += 1
    return sec


def analyze_sandwich(src_files: list[tuple[Path, str]]) -> dict:
    sec = _blank_section()
    for path, text in src_files:
        matches = _find_fn_matches(text, RX_SWAP_FN)
        for line_no, fn in matches:
            # fetch an approximate body window for heuristic
            m_start = text.find(fn)
            body = _fn_body(text, m_start)
            has_slip = RX_SLIPPAGE.search(body) is not None
            has_deadline = RX_DEADLINE.search(body) is not None
            if has_slip and has_deadline:
                continue
            missing: list[str] = []
            if not has_slip:
                missing.append("slippage (amountOutMin/minOut)")
            if not has_deadline:
                missing.append("deadline")
            high = not has_slip  # missing slippage is the stronger signal
            sec["hypotheses"].append(
                {
                    "contract": path.stem,
                    "file": str(path),
                    "line": line_no,
                    "narrative": (
                        f"`{path.stem}.{fn.rstrip('(').split()[-1]}` at "
                        f"`{path.name}:{line_no}` appears to omit "
                        f"{' and '.join(missing)} enforcement in the "
                        f"immediate function window. If invoked with a large "
                        f"amount, a sandwich attacker may extract value."
                    ),
                    "evidence": [f"{path}:{line_no}"],
                    "next_proof_step": (
                        f"Fork-replay with a sandwich bot bracket at the same "
                        f"block around `{path.stem}.{fn.rstrip('(').split()[-1]}`. "
                        f"Gate: protocol-or-user net loss."
                    ),
                    "high_signal": high,
                }
            )
            if high:
                sec["high_signal"] += 1
    return sec


def analyze_governance(src_files: list[tuple[Path, str]]) -> dict:
    sec = _blank_section()
    for path, text in src_files:
        modifier_hits = list(RX_GOV_MODIFIER.finditer(text))
        if not modifier_hits:
            continue
        # count roughly how many external/public fns the modifier gates.
        # approximation: modifier occurs on a function signature line.
        gated = 0
        for m in modifier_hits:
            ln_start = text.rfind("function ", 0, m.start())
            if ln_start == -1:
                continue
            gated += 1
        init_hit = RX_INIT_FN.search(text)
        roles = sorted({m.group(0) for m in modifier_hits})
        high = gated >= 3
        sec["hypotheses"].append(
            {
                "contract": path.stem,
                "file": str(path),
                "line": text.count("\n", 0, modifier_hits[0].start()) + 1,
                "narrative": (
                    f"Governance surface in `{path.name}`: approximately "
                    f"{gated} state-mutating function(s) gated by "
                    f"{', '.join(f'`{r}`' for r in roles)}. "
                    + (
                        f"Role set in `{init_hit.group(0).rstrip('(').strip()}`. "
                        if init_hit
                        else ""
                    )
                    + "If the role resolves to a single EOA or 1-of-N "
                    "multisig, the entire surface is unilaterally controlled."
                ),
                "evidence": [
                    f"{path}:"
                    f"{text.count(chr(10), 0, m.start()) + 1}"
                    for m in modifier_hits[:5]
                ],
                "next_proof_step": (
                    f"Run `tools/live-state-checker.py` (or the equivalent) "
                    f"against `{path.stem}` to resolve the current role "
                    f"holder. If a single EOA, cite in the Live Proof section "
                    f"of any draft."
                ),
                "high_signal": high,
            }
        )
        if high:
            sec["high_signal"] += 1
    return sec


def analyze_supply(src_files: list[tuple[Path, str]]) -> dict:
    sec = _blank_section()
    for path, text in src_files:
        mint_matches = _find_fn_matches(text, RX_MINT_FN)
        burn_matches = _find_fn_matches(text, RX_BURN_FN)
        if not mint_matches and not burn_matches:
            continue
        cap_present = RX_CAP.search(text) is not None
        for line_no, fn in mint_matches:
            high = not cap_present
            sec["hypotheses"].append(
                {
                    "contract": path.stem,
                    "file": str(path),
                    "line": line_no,
                    "narrative": (
                        f"`{path.stem}.{fn.rstrip('(').split()[-1]}` at "
                        f"`{path.name}:{line_no}`. Supply cap check: "
                        f"{'present' if cap_present else 'absent'} in-file. "
                        f"If the amount parameter is attacker-controlled "
                        f"with no supply cap, an inflation attack is "
                        f"hypothesised."
                    ),
                    "evidence": [f"{path}:{line_no}"],
                    "next_proof_step": (
                        "If cap is absent, demonstrate the inflation path "
                        "via a Forge PoC. If the cap is present but "
                        "attacker-influenceable (e.g. governance-set with a "
                        "single EOA), model the game theory before claiming."
                    ),
                    "high_signal": high,
                }
            )
            if high:
                sec["high_signal"] += 1
        for line_no, fn in burn_matches:
            sec["hypotheses"].append(
                {
                    "contract": path.stem,
                    "file": str(path),
                    "line": line_no,
                    "narrative": (
                        f"`{path.stem}.{fn.rstrip('(').split()[-1]}` at "
                        f"`{path.name}:{line_no}` — burn path. If it "
                        f"reduces a shared accounting variable without a "
                        f"corresponding user-balance decrement, share "
                        f"accounting may drift."
                    ),
                    "evidence": [f"{path}:{line_no}"],
                    "next_proof_step": (
                        "Write a Forge invariant that totalSupply == "
                        "sum(balanceOf) after a burn sequence."
                    ),
                    "high_signal": False,
                }
            )
    return sec


def analyze_fee(src_files: list[tuple[Path, str]]) -> dict:
    sec = _blank_section()
    for path, text in src_files:
        fee_hits = list(RX_FEE_DECL.finditer(text))
        if not fee_hits:
            continue
        recipient_hit = RX_FEE_RECIPIENT.search(text)
        line_no = text.count("\n", 0, fee_hits[0].start()) + 1
        high = recipient_hit is not None
        sec["hypotheses"].append(
            {
                "contract": path.stem,
                "file": str(path),
                "line": line_no,
                "narrative": (
                    f"`{path.name}:{line_no}` declares a fee variable "
                    f"(`{fee_hits[0].group(0)}`). "
                    + (
                        f"Candidate recipient identifier: "
                        f"`{recipient_hit.group(0)}`. "
                        if recipient_hit
                        else "No in-file `treasury`/`feeRecipient` identifier "
                        "found — recipient path may be inherited or "
                        "indirect. "
                    )
                    + "If the recipient is uncapped or redirectable by a "
                    "gated setter, fees may be rerouted or drained."
                ),
                "evidence": [
                    f"{path}:"
                    f"{text.count(chr(10), 0, m.start()) + 1}"
                    for m in fee_hits[:5]
                ],
                "next_proof_step": (
                    "Check whether the fee recipient can be changed by an "
                    "admin role. If yes, the same admin-concentration "
                    "concern applies — resolve the live role holder before "
                    "claiming."
                ),
                "high_signal": high,
            }
        )
        if high:
            sec["high_signal"] += 1
    return sec


def analyze_oracle(src_files: list[tuple[Path, str]]) -> dict:
    sec = _blank_section()
    for path, text in src_files:
        oracle_hits = list(RX_ORACLE_USAGE.finditer(text))
        if not oracle_hits:
            continue
        staleness = RX_STALENESS.search(text) is not None
        line_no = text.count("\n", 0, oracle_hits[0].start()) + 1
        high = not staleness
        sec["hypotheses"].append(
            {
                "contract": path.stem,
                "file": str(path),
                "line": line_no,
                "narrative": (
                    f"`{path.name}` consumes oracle data "
                    f"({len({m.group(0) for m in oracle_hits})} distinct "
                    f"oracle identifier(s) detected at this file). "
                    f"Staleness check (`answeredInRound` / `updatedAt` / "
                    f"`roundId`): "
                    f"{'present' if staleness else 'absent'} in-file. "
                    f"If absent, the contract may accept arbitrarily stale "
                    f"prices."
                ),
                "evidence": [
                    f"{path}:"
                    f"{text.count(chr(10), 0, m.start()) + 1}"
                    for m in oracle_hits[:5]
                ],
                "next_proof_step": (
                    "Fork-replay at a block where the oracle round is "
                    "stale and a user-facing action (price-sensitive) is "
                    "taken. Gate: protocol accepts stale answer → "
                    "economic delta."
                ),
                "high_signal": high,
            }
        )
        if high:
            sec["high_signal"] += 1
    return sec


ANALYZERS = {
    "liquidation-cascade": analyze_liquidation,
    "sandwich-mev": analyze_sandwich,
    "governance-concentration": analyze_governance,
    "token-supply-pressure": analyze_supply,
    "fee-path": analyze_fee,
    "oracle-dependency": analyze_oracle,
}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_markdown(
    ws: Path,
    focus: str | None,
    sections_data: dict[str, dict],
    source_count: int,
    skip_reason: str | None = None,
) -> str:
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = []
    lines.append(f"# Economic Risk Card — {ws.name}")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append(f"Workspace: {ws}")
    lines.append(f"Focus: {focus if focus else 'all'}")
    lines.append(f"Source files scanned: {source_count}")
    lines.append("")
    lines.append(f"> {DISCLAIMER}")
    lines.append("")
    if skip_reason:
        lines.append(f"> SKIP: {skip_reason}")
        lines.append("")

    for idx, (slug, title) in enumerate(SECTIONS, start=1):
        lines.append(f"## {idx}. {title}")
        lines.append("")
        data = sections_data.get(slug, _blank_section())
        hyps = data["hypotheses"]
        if not hyps:
            lines.append(f"_{NO_CANDIDATE}_")
            lines.append("")
            continue
        for i, h in enumerate(hyps, start=1):
            lines.append(f"### Hypothesis {i}")
            lines.append("")
            lines.append(f"Hypothesis: {h['narrative']}")
            lines.append("")
            lines.append(
                f"**Evidence pointers:** "
                + ", ".join(f"`{e}`" for e in h["evidence"])
            )
            lines.append("")
            lines.append(f"**Next proof step:** {h['next_proof_step']}")
            lines.append("")
            lines.append(
                "**Required gate to claim:** fork-replay or PoC showing "
                "economic movement consistent with the hypothesis before "
                "any submission claim."
            )
            lines.append("")
            lines.append(
                f"_High-signal: {'yes' if h['high_signal'] else 'no'}_"
            )
            lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(
        "| Section | Hypotheses | High-signal | Next-best proof step |"
    )
    lines.append("|---|---:|---:|---|")
    for _, (slug, title) in enumerate(SECTIONS):
        data = sections_data.get(slug, _blank_section())
        n = len(data["hypotheses"])
        m = data["high_signal"]
        nxt = (
            data["hypotheses"][0]["next_proof_step"]
            if n
            else "—"
        )
        # keep table cell short
        if len(nxt) > 120:
            nxt = nxt[:117] + "..."
        nxt = nxt.replace("|", "/")
        lines.append(f"| {title} | {n} | {m} | {nxt} |")
    lines.append("")

    lines.append("## How to upgrade a hypothesis to a finding")
    lines.append("")
    lines.append(
        "A hypothesis in this card is NOT a finding. It becomes a candidate "
        "finding only after:"
    )
    lines.append("")
    lines.append(
        "1. A passing Forge PoC demonstrating the exploit sequence."
    )
    lines.append(
        "2. Fork replay (`tools/fork-replay.sh --assert-delta ...`) showing "
        "victim/protocol/attacker economic movement consistent with the "
        "hypothesis."
    )
    lines.append(
        "3. Live proof for any deployment/config facts the hypothesis "
        "assumes."
    )
    lines.append("")
    lines.append(
        "Use `tools/attach-invariant.py <ws> --template <slug>` where a "
        "canonical invariant template applies (see "
        "`reference/invariants/MANIFEST.json`)."
    )
    lines.append("")
    return "\n".join(lines)


def render_json(
    ws: Path,
    focus: str | None,
    sections_data: dict[str, dict],
    source_count: int,
    skip_reason: str | None = None,
) -> dict[str, Any]:
    total = sum(len(sections_data.get(s, {}).get("hypotheses", []))
                for s, _ in SECTIONS)
    high = sum(sections_data.get(s, {}).get("high_signal", 0)
               for s, _ in SECTIONS)
    return {
        "schema_version": TOOL_VERSION,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "workspace": ws.name,
        "workspace_path": str(ws),
        "focus": focus,
        "source_files_scanned": source_count,
        "disclaimer": DISCLAIMER,
        "skip_reason": skip_reason,
        "sections": [
            {
                "slug": slug,
                "title": title,
                "hypotheses": sections_data.get(slug, _blank_section())[
                    "hypotheses"
                ],
                "high_signal": sections_data.get(slug, _blank_section())[
                    "high_signal"
                ],
            }
            for slug, title in SECTIONS
        ],
        "summary": {"total_hypotheses": total, "high_signal": high},
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="economic-risk-card.py",
        description=(
            "Generate a per-engagement Economic Risk Card. "
            "HYPOTHESIS-GENERATING only — not a submission claim."
        ),
    )
    p.add_argument("workspace", type=Path)
    p.add_argument("--contract", default=None, help="focus on one contract")
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--json-out", type=Path, default=None, dest="json_out")
    p.add_argument("--dry-run", action="store_true", dest="dry_run")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ws: Path = args.workspace.resolve()

    if not ws.exists():
        print(f"[economic-risk-card] workspace not found: {ws}",
              file=sys.stderr)
        return 2

    out_path = args.out or (ws / "ECONOMIC_RISK_CARD.md")
    json_path = args.json_out

    src_paths = discover_sources(ws, args.contract)
    src_files: list[tuple[Path, str]] = []
    for p in src_paths:
        try:
            src_files.append((p, p.read_text(encoding="utf-8",
                                             errors="replace")))
        except OSError:
            continue

    skip_reason = None
    if not src_files:
        skip_reason = (
            f"no Solidity source found under {ws}/src/"
            + (f" matching --contract {args.contract}" if args.contract
               else "")
            + " — emitting minimal card"
        )

    sections_data: dict[str, dict] = {}
    if src_files:
        for slug, _ in SECTIONS:
            sections_data[slug] = ANALYZERS[slug](src_files)
    else:
        for slug, _ in SECTIONS:
            sections_data[slug] = _blank_section()

    if args.dry_run:
        print(f"[economic-risk-card] plan:")
        print(f"  workspace     = {ws}")
        print(f"  focus         = {args.contract or 'all'}")
        print(f"  source files  = {len(src_files)}")
        print(f"  out           = {out_path}")
        print(f"  json_out      = {json_path or '(none)'}")
        print(f"  sections      = {len(SECTIONS)}")
        print(f"  dry-run: NOT writing output")
        return 0

    md = render_markdown(ws, args.contract, sections_data,
                         len(src_files), skip_reason)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")
    print(f"[economic-risk-card] wrote {out_path}")

    if json_path:
        data = render_json(ws, args.contract, sections_data,
                           len(src_files), skip_reason)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"[economic-risk-card] wrote {json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
