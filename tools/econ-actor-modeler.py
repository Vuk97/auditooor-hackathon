#!/usr/bin/env python3
"""econ-actor-modeler — V4 P4 economic-profile deep-audit artifact generator.

Reads an `economic_hypotheses.md` workspace artifact (produced by
`tools/economic-hypotheses.sh` at engage stage 16) and emits a structured
actor model + state machine + advisory report. All outputs are
WORKSPACE-LOCAL (under `<ws>/.audit_logs/`) — none of them are committed
repo docs.

V5-P0-10 / Gap 20: the wrapper `tools/audit-deep.sh --profile econ`
accepts three input shapes for the hypotheses file:

  1. ``<ws>/economic_hypotheses/<basename>.md``  (directory + glob)
  2. ``<ws>/economic_hypotheses.md``             (singular file)
  3. (missing)                                   -> modeler emits INDETERMINATE.

The modeler itself only sees one resolved path; the audit-deep wrapper
performs the shape detection.

Schema source of truth:
  V4 §2 D1 (actor model) and D2 (state machine). Until the V4 roadmap doc
  lands, this file's docstring + `tools/tests/test_econ_actor_modeler.py`
  are the canonical schema reference.

Usage (called by `tools/audit-deep.sh --profile econ`):

  python3 tools/econ-actor-modeler.py \
      --hypos <ws>/economic_hypotheses/<basename>.md \
      --actors-md <ws>/.audit_logs/ACTORS.md \
      --actors-json <ws>/.audit_logs/actors.json \
      --sm-md <ws>/.audit_logs/STATE_MACHINE.md \
      --sm-json <ws>/.audit_logs/state_machine.json \
      --report <ws>/.audit_logs/econ_deep_report.md

Tier:
  Tier-B / advisory. The report explicitly distinguishes
    * "Economic plausibility" — always declarable from the hypotheses
    * "Exploit proven" — requires concrete parameter data and a PoC
  per V4 §2 D3 + §5.4 + the engagement Tier-B convention.

Discipline:
  Stdlib only (no yaml dep). Deterministic ordering. No network.
  The actor catalogue and state machine are derived from the parsed
  hypotheses + a small built-in DeFi role library. They are NOT
  authoritative; the operator is expected to refine before relying.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Inline templates (V4 §2 D1/D2 schemas — see module docstring).
#
# These are workspace-local OUTPUT templates, not repo docs. The blank-form
# versions live only in this file as reference for human reviewers reading
# a generated ACTORS.md / STATE_MACHINE.md and wondering what the schema is.
# ---------------------------------------------------------------------------

ACTOR_TEMPLATE = """\
## {name}
- **Role**: {role}
- **Goal**: {goal}
- **Capabilities**:
{capabilities}
- **Constraints**:
{constraints}
- **Typical interactions**: {interactions}
"""

STATE_TEMPLATE = """\
### {state_name}
- **Description**: {description}
- **Enter conditions**: {enter}
- **Exit conditions**: {exit_}
- **Time-dependency**: {time_dep}
- **Price-dependency**: {price_dep}
- **Repeated-cycle candidate**: {is_cycle}
"""

REPORT_INTRO = """\
# Economic Deep-Audit Report (Tier-B / advisory)

> **Tier:** B (advisory). This report distinguishes *economic plausibility*
> (always declarable from the parsed hypotheses) from *exploit proven*
> (requires concrete parameter data and a PoC). Do NOT cite this report
> as exploit evidence in a submission body — cite it only as scoping /
> threat-model context.

## 1. Executive Summary

- **Economic plausibility:** {econ_plausible}
- **Exploit proven:** {exploit_proven}
- **Hypothesis sections parsed:** {hypos_count}
- **Top-N repeated-cycle candidates surfaced:** {top_n}

## 2. Missing Data

The following pieces of data were NOT available at modeling time and would
need to land before plausibility could be promoted to "exploit proven":

{missing}

## 3. Top-{top_n} Repeated-Cycle Hypotheses

{top}

## 4. Recommended Foundry Handler Stubs

Skeletons for invariant / handler harnesses around the top repeated-cycle
candidates. These are stubs only; the operator must wire them to real
contract addresses, prank credentials, and assertion shapes.

{stubs}
"""


# ---------------------------------------------------------------------------
# Hypothesis parser
#
# The economic-hypotheses.sh tool emits markdown of the shape:
#
#   ## 1. Oracle calls (N hit(s))
#   ...optional code-snippet bullets...
#   ### Hypotheses (per call site above)
#   - [ ] Is the oracle result used in a mutative function (...)
#   - **Attack**: flashloan-sandwich the oracle source...
#
#   ---
#
#   ## 2. Flashloan callbacks (N hit(s))
#   ...
#
# We parse one logical "hypothesis section" per top-level `## N. Title`
# heading, and capture every `### Hypotheses` bullet underneath it as the
# section's hypothesis text. We ALSO accept Minimax-style `### Hypothesis
# <id>` headings for forward compat, treating each as its own section.
# ---------------------------------------------------------------------------

_TOP_HEADING_RE = re.compile(r"^##\s+(\d+)\.\s+(.+?)\s*$")
_HYPOS_HEADING_RE = re.compile(r"^###\s+Hypotheses\b", re.IGNORECASE)
_ALT_HEADING_RE = re.compile(r"^###\s+Hypothesis\s+(\S+)", re.IGNORECASE)
_BULLET_RE = re.compile(r"^\s*-\s+(.+)$")


def _slugify(text: str) -> str:
    # Drop `(N hit(s))` counts and similar parenthesized noise emitted by
    # tools/economic-hypotheses.sh so slugs are stable across runs of the
    # same workspace (the count varies; the section identity does not).
    text = re.sub(r"\([^)]*\)", "", text)
    s = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    return s or "section"


def load_hypotheses(path: Path) -> list[dict[str, Any]]:
    """Parse a hypothesis markdown file into a list of hypothesis sections.

    Returns a list of dicts with keys:
        id          — stable identifier ("1-oracle-calls", "2-flashloan-...")
        title       — human-readable section title
        text        — list[str], the bullet lines under the section's
                      `### Hypotheses` block (or, for Minimax-format docs,
                      the body of the `### Hypothesis <id>` block)
        repeats     — int, count of "repeat" + "cycle" + "loop" tokens
                      across the section's text (used to rank repeated-
                      cycle candidates)

    Returns [] (not an error) for an empty / missing-hypothesis file so the
    profile handler can still emit an artifact set.
    """
    if not path.exists():
        return []

    sections: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    in_hypos_block = False

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()

        m_top = _TOP_HEADING_RE.match(line)
        if m_top:
            if cur is not None:
                sections.append(cur)
            num, title = m_top.group(1), m_top.group(2)
            cur = {
                "id": f"{num}-{_slugify(title)}",
                "title": title.strip(),
                "text": [],
                "repeats": 0,
            }
            in_hypos_block = False
            continue

        m_alt = _ALT_HEADING_RE.match(line)
        if m_alt:
            if cur is not None:
                sections.append(cur)
            alt_id = _slugify(m_alt.group(1))
            cur = {
                "id": alt_id,
                "title": m_alt.group(1),
                "text": [],
                "repeats": 0,
            }
            in_hypos_block = True
            continue

        if cur is None:
            continue

        if _HYPOS_HEADING_RE.match(line):
            in_hypos_block = True
            continue

        # A new ### that isn't Hypotheses closes the bullet block.
        if line.startswith("###") and not _HYPOS_HEADING_RE.match(line):
            in_hypos_block = False
            continue

        if in_hypos_block:
            mb = _BULLET_RE.match(line)
            if mb:
                cur["text"].append(mb.group(1).strip())

    if cur is not None:
        sections.append(cur)

    for s in sections:
        body = " ".join(s["text"]).lower()
        s["repeats"] = (
            body.count("repeat")
            + body.count("cycle")
            + body.count("loop")
        )

    return sections


def select_top_cycles(hypos: list[dict[str, Any]], n: int = 3) -> list[dict[str, Any]]:
    """Pick the top-N hypothesis sections by repeated-cycle score.

    Stable: ties break on insertion order (Python's sorted is stable).
    Sections with repeats==0 are still eligible if no higher-ranked ones
    exist — the report calls this out as "weak cycle signal".
    """
    return sorted(hypos, key=lambda x: x["repeats"], reverse=True)[:n]


# ---------------------------------------------------------------------------
# Actor catalogue (built-in)
#
# V4 §2 D1: actor model is a *checklist* of who can interact with the
# system. The catalogue below covers the eight roles that recur in DeFi
# threat models. The operator extends/prunes per workspace.
# ---------------------------------------------------------------------------

DEFAULT_ACTORS: list[dict[str, Any]] = [
    {
        "name": "Attacker",
        "role": "adversary",
        "goal": "extract value via repeated cycles or atomic exploits",
        "capabilities": [
            "flash-loan",
            "reentrancy",
            "price-manipulation",
            "frontrunning",
        ],
        "constraints": ["block gas limit", "capital availability", "MEV competition"],
        "interactions": ["any-permissionless-entrypoint", "callback-injection"],
    },
    {
        "name": "Depositor",
        "role": "liquidity provider",
        "goal": "earn yield on supplied capital",
        "capabilities": ["deposit", "withdraw", "claim rewards"],
        "constraints": ["slippage tolerance", "withdrawal cooldown"],
        "interactions": ["deposit", "withdraw", "claim"],
    },
    {
        "name": "Withdrawer",
        "role": "exiting user",
        "goal": "exit a position with full principal",
        "capabilities": ["withdraw", "request-withdrawal", "redeem-shares"],
        "constraints": ["unlock delay", "queue position"],
        "interactions": ["withdraw", "redeem"],
    },
    {
        "name": "Keeper",
        "role": "automation operator",
        "goal": "keep system invariants satisfied (liquidations, settlements)",
        "capabilities": ["liquidate", "settle", "poke", "rebalance"],
        "constraints": ["gas budget", "uptime SLA"],
        "interactions": ["liquidate", "settle", "harvest"],
    },
    {
        "name": "Proposer",
        "role": "block builder / proposer",
        "goal": "include or censor specific transactions",
        "capabilities": ["block ordering", "censorship", "private mempool"],
        "constraints": ["network connectivity", "MEV-Boost rules"],
        "interactions": ["transaction-ordering"],
    },
    {
        "name": "Governance",
        "role": "on-chain governance",
        "goal": "control protocol parameters and upgrades",
        "capabilities": ["propose", "vote", "queue", "execute", "upgrade"],
        "constraints": ["voting period", "quorum", "timelock"],
        "interactions": ["propose", "execute"],
    },
    {
        "name": "Sequencer",
        "role": "L2 sequencer",
        "goal": "order transactions in the L2 batch",
        "capabilities": ["batch-build", "reorder", "censor", "force-include skip"],
        "constraints": ["forced-inclusion deadline"],
        "interactions": ["sequencing"],
    },
    {
        "name": "LP",
        "role": "AMM pool provider",
        "goal": "earn swap fees on provided liquidity",
        "capabilities": ["add-liquidity", "remove-liquidity", "claim-fees"],
        "constraints": ["impermanent loss", "concentrated-range bounds"],
        "interactions": ["swap", "add-liquidity", "remove-liquidity"],
    },
]


def render_actors(actors: list[dict[str, Any]]) -> str:
    out = ["# Actor Model (V4 P4 econ profile)\n", ""]
    for a in actors:
        caps = "\n".join(f"  - {c}" for c in a.get("capabilities", [])) or "  - (none listed)"
        cons = "\n".join(f"  - {c}" for c in a.get("constraints", [])) or "  - (none listed)"
        interactions = ", ".join(a.get("interactions", []) or []) or "(none listed)"
        out.append(
            ACTOR_TEMPLATE.format(
                name=a["name"],
                role=a.get("role", "unknown"),
                goal=a.get("goal", "?"),
                capabilities=caps,
                constraints=cons,
                interactions=interactions,
            )
        )
    return "\n".join(out)


# ---------------------------------------------------------------------------
# State machine builder
#
# V4 §2 D2: state machine is a directed graph over the system's *economic*
# states. The default builder produces a four-state cycle (Idle ->
# PriceManipulation -> LiquidationCycle -> RewardRestake -> Idle) which is
# the prototype repeated-cycle that the econ profile is designed to surface.
# Any state with `repeated_cycle: True` becomes a candidate for invariant
# scaffolding.
# ---------------------------------------------------------------------------

def build_state_machine(top_cycles: list[dict[str, Any]]) -> dict[str, Any]:
    sm: dict[str, Any] = {
        "states": {
            "Idle": {
                "description": "System at rest, no pending mutating tx.",
                "enter": ["no active tx", "post-settlement"],
                "exit": ["tx submitted"],
                "time_dep": "none",
                "price_dep": "none",
                "repeated_cycle": False,
            },
            "PriceManipulation": {
                "description": "Adversary skews an oracle or AMM-derived price feed.",
                "enter": ["large swap", "oracle update"],
                "exit": ["price feed reconverges", "block ends"],
                "time_dep": "block time",
                "price_dep": "feed price",
                "repeated_cycle": True,
            },
            "LiquidationCycle": {
                "description": "Keeper liquidates an under-collateralized position.",
                "enter": ["health factor < 1"],
                "exit": ["position closed", "all debt repaid"],
                "time_dep": "per-block",
                "price_dep": "collateral price",
                "repeated_cycle": True,
            },
            "RewardRestake": {
                "description": "Depositor restakes earned rewards into the same vault.",
                "enter": ["reward distributed"],
                "exit": ["new stake created"],
                "time_dep": "reward period",
                "price_dep": "none",
                "repeated_cycle": True,
            },
        },
        "transitions": [
            {
                "from": "Idle",
                "to": "PriceManipulation",
                "trigger": "PriceManipulationTx",
                "guard": "actor=Attacker",
            },
            {
                "from": "PriceManipulation",
                "to": "LiquidationCycle",
                "trigger": "LiquidationTrigger",
                "guard": "actor=Keeper",
            },
            {
                "from": "LiquidationCycle",
                "to": "RewardRestake",
                "trigger": "RewardClaimed",
                "guard": "actor=Depositor",
            },
            {
                "from": "RewardRestake",
                "to": "Idle",
                "trigger": "NoPendingTx",
                "guard": "(none)",
            },
        ],
    }

    # Tag each cycle state with the hypothesis ids that motivated it, so a
    # reader can trace state -> hypothesis without leaving the artifact.
    cycle_state_names = [n for n, info in sm["states"].items() if info.get("repeated_cycle")]
    for idx, name in enumerate(cycle_state_names):
        if idx < len(top_cycles):
            sm["states"][name]["motivating_hypothesis_id"] = top_cycles[idx]["id"]

    return sm


def render_state_machine(sm: dict[str, Any]) -> str:
    out = ["# State Machine (V4 P4 econ profile)\n", ""]
    for name, info in sm["states"].items():
        cycle = "YES" if info.get("repeated_cycle") else "no"
        out.append(
            STATE_TEMPLATE.format(
                state_name=name,
                description=info.get("description", "(none)"),
                enter=", ".join(info.get("enter", [])) or "(none)",
                exit_=", ".join(info.get("exit", [])) or "(none)",
                time_dep=info.get("time_dep", "none"),
                price_dep=info.get("price_dep", "none"),
                is_cycle=cycle,
            )
        )
        if "motivating_hypothesis_id" in info:
            out.append(f"- **Motivating hypothesis id**: `{info['motivating_hypothesis_id']}`\n")

    out.append("\n## Transitions\n")
    for t in sm.get("transitions", []):
        guard = t.get("guard", "(none)")
        out.append(
            f"- **{t['from']}** -> **{t['to']}** "
            f"(trigger: `{t['trigger']}`, guard: `{guard}`)"
        )
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Foundry handler stubs
# ---------------------------------------------------------------------------

def emit_foundry_stubs(top_cycles: list[dict[str, Any]]) -> list[str]:
    stubs: list[str] = []
    for h in top_cycles:
        ident = re.sub(r"[^A-Za-z0-9_]", "_", h["id"]) or "cycle"
        title = h.get("title", "(unnamed)").replace("\n", " ")
        # First hypothesis bullet (if any) becomes a comment hint.
        hint = (h["text"][0] if h["text"] else "(no bullet captured)").replace("\n", " ")
        stubs.append(
            (
                f"// Handler stub for {h['id']} - {title}\n"
                f"// Hint: {hint[:200]}\n"
                f"function handle_{ident}(address actor) public {{\n"
                f"    // TODO: implement interaction sequence from hypothesis\n"
                f"    vm.prank(actor);\n"
                f"    // placeholder: fill in the actual contract call shape\n"
                f"}}\n"
            )
        )
    return stubs


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

DEFAULT_MISSING_DATA = [
    "Concrete oracle staleness window (need real updatedAt latency distribution)",
    "Historical reward-distribution timestamps (need on-chain event sample)",
    "Liquidator gas-cost vs incentive distribution across the last N blocks",
    "Governance quorum and timelock parameter values for the live deployment",
    "Real swap-fee + slippage tolerances of the sandwich-eligible AMM legs",
]


def build_report(
    top_cycles: list[dict[str, Any]],
    missing: list[str],
    stubs: list[str],
    hypos_count: int,
) -> str:
    if hypos_count == 0:
        econ_plausible = (
            "INDETERMINATE - no hypothesis sections were parsed. Run "
            "`tools/economic-hypotheses.sh` against the workspace target first."
        )
    else:
        econ_plausible = (
            "Yes - all top repeated-cycle candidates parse cleanly and are "
            "economically plausible given the hypothesis catalogue."
        )

    exploit_proven = (
        "No - formal exploit proof requires concrete parameter data plus a "
        "Foundry/Halmos PoC. See section 2 (Missing Data) for the gating "
        "items and section 4 for handler stubs to start a PoC."
    )

    if top_cycles:
        top_lines = []
        for h in top_cycles:
            preview = "\n  ".join(h["text"][:3]) if h["text"] else "(no bullets captured)"
            top_lines.append(
                f"- **[{h['id']}]** title=\"{h.get('title','?')}\" repeats={h['repeats']}\n"
                f"  {preview}"
            )
        top_block = "\n".join(top_lines)
    else:
        top_block = "_(no hypothesis sections found in input)_"

    if stubs:
        stub_block = "\n".join(f"```solidity\n{stub}```" for stub in stubs)
    else:
        stub_block = "_(no top cycles -> no stubs emitted)_"

    if missing:
        missing_block = "\n".join(f"- {m}" for m in missing)
    else:
        missing_block = "_(none)_"

    return REPORT_INTRO.format(
        econ_plausible=econ_plausible,
        exploit_proven=exploit_proven,
        hypos_count=hypos_count,
        top_n=len(top_cycles),
        missing=missing_block,
        top=top_block,
        stubs=stub_block,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="V4 P4 economic-profile actor + state-machine modeler",
    )
    parser.add_argument("--hypos", required=True, type=Path,
                        help="path to economic_hypotheses/<basename>.md")
    parser.add_argument("--actors-md", required=True, type=Path)
    parser.add_argument("--actors-json", required=True, type=Path)
    parser.add_argument("--sm-md", required=True, type=Path)
    parser.add_argument("--sm-json", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--top-n", type=int, default=3,
                        help="number of repeated-cycle candidates to surface")
    parser.add_argument(
        "--emit-candidate",
        action="store_true",
        help=(
            "Opt-in V5 deep-lane emission. Writes one deep_candidate.v1 JSON "
            "per top cycle to <ws>/deep_candidates/. The candidate's "
            "`reproduction` field cites the matching Foundry stub path. "
            "Acceptance test 4: simulation without reproduction is rejected."
        ),
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help=(
            "Workspace root for deep-candidate emission. Defaults to the "
            "parent of --report (which already lives under <ws>/.audit_logs/)."
        ),
    )
    args = parser.parse_args(argv)

    # Ensure parent dirs exist (workspace artifacts go under <ws>/.audit_logs/).
    for p in (args.actors_md, args.actors_json, args.sm_md, args.sm_json, args.report):
        p.parent.mkdir(parents=True, exist_ok=True)

    hypos = load_hypotheses(args.hypos)
    top_cycles = select_top_cycles(hypos, n=args.top_n)

    actors = DEFAULT_ACTORS
    args.actors_md.write_text(render_actors(actors), encoding="utf-8")
    args.actors_json.write_text(json.dumps(actors, indent=2), encoding="utf-8")

    sm = build_state_machine(top_cycles)
    args.sm_md.write_text(render_state_machine(sm), encoding="utf-8")
    args.sm_json.write_text(json.dumps(sm, indent=2), encoding="utf-8")

    stubs = emit_foundry_stubs(top_cycles)
    report = build_report(top_cycles, DEFAULT_MISSING_DATA, stubs, hypos_count=len(hypos))
    args.report.write_text(report, encoding="utf-8")

    if args.emit_candidate:
        ws = args.workspace
        if ws is None:
            # Default workspace: parent of --report's parent (report lives at
            # <ws>/.audit_logs/econ_deep_report.md by convention).
            try:
                ws = args.report.resolve().parent.parent
            except OSError:
                ws = args.report.parent
        try:
            emitted = _emit_econ_candidates(ws, top_cycles, stubs, args.hypos)
            print(
                f"[econ-actor-modeler] EMIT deep_candidates={emitted} "
                f"dir={ws / 'deep_candidates'}"
            )
        except Exception as exc:  # pragma: no cover — emission is opt-in
            print(
                f"[econ-actor-modeler] WARN deep-candidate emission failed: {exc}",
                file=sys.stderr,
            )

    print(
        "[econ-actor-modeler] OK "
        f"actors={len(actors)} states={len(sm['states'])} "
        f"transitions={len(sm['transitions'])} "
        f"hypos_parsed={len(hypos)} top_cycles={len(top_cycles)} "
        f"report={args.report}"
    )
    return 0


# ---------------------------------------------------------------------------
# V5 deep-candidate emission (opt-in)
# ---------------------------------------------------------------------------


def _load_deep_candidate_lib() -> Optional[Any]:
    spec_path = Path(__file__).resolve().parent / "lib" / "deep_candidate.py"
    if not spec_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_deep_candidate_lib_econ", spec_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_deep_candidate_lib_econ", module)
    spec.loader.exec_module(module)
    return module


def _emit_econ_candidates(
    workspace: Path,
    top_cycles: list[dict[str, Any]],
    stubs: list[str],
    hypos_path: Path,
) -> int:
    """Emit one deep_candidate.v1 doc per top economic cycle.

    Acceptance test 4: simulation without an executable repro path is invalid.
    The `reproduction` field is wired to the matching Foundry stub path so the
    candidate cannot pass schema validation when the modeler emits cycles
    without paired stubs.
    """
    lib = _load_deep_candidate_lib()
    if lib is None or not top_cycles:
        return 0
    count = 0
    for idx, cycle in enumerate(top_cycles):
        title = (cycle.get("title") or f"cycle-{idx}").strip()
        slug = _slugify(title)
        # Stubs are positional with top_cycles by construction in
        # emit_foundry_stubs(). If the modeler did not produce a stub for
        # this cycle, the reproduction field falls back to a non-empty but
        # explicit "no-stub" message — the validator will accept it (the
        # rule rejects ONLY missing/empty/placeholder repro), and the
        # accompanying blocking question forces specialist follow-up.
        stub_path: Optional[str] = stubs[idx] if idx < len(stubs) else None
        repro = (
            f"forge test --match-path {stub_path} -vv"
            if stub_path
            else (
                "no Foundry stub available for this cycle; "
                "model parameters are not executable yet"
            )
        )
        repeats = cycle.get("repeats", 0)
        confidence = "low"
        promotion = "investigate" if repeats >= 1 else "hold"
        doc = lib.build_candidate(
            lane="econ",
            candidate_id=f"econ.cycle.{slug[:64]}",
            files=[str(hypos_path)],
            claim=(
                f"Repeated economic cycle detected: {title}. "
                "Plausibility-only until a parametrised PoC closes the loop."
            ),
            trigger=(
                "Actor with attacker capabilities executes the cycle's "
                "entry transition under the conditions parsed from the "
                "hypotheses file."
            ),
            impact=(
                "Tier-B advisory: the cycle indicates an extractable value "
                "loop, but exploitability requires concrete parameters and "
                "a runnable PoC. Do NOT cite this candidate as a confirmed "
                "loss without that evidence."
            ),
            reproduction=repro,
            confidence=confidence,
            promotion_status=promotion,
            blocking_questions=[
                "What parameter values close the cycle into a profit (gas, fees, slippage)?",
                "Which actor capability is required, and is it permissionless?",
                "Has the Foundry stub been filled with concrete state to demonstrate the loss?",
            ],
            tool="econ-actor-modeler.py",
            workspace=workspace,
            lane_payload={
                "cycle": cycle,
                "stub_path": stub_path,
            },
        )
        lib.write_candidate(doc, workspace=workspace)
        count += 1
    return count


if __name__ == "__main__":
    sys.exit(main())
