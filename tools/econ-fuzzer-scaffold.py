#!/usr/bin/env python3
"""Emit runnable economic invariant fuzz scaffolds from local hypotheses."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = "auditooor.econ_fuzzer_scaffold.v1"
ACTION_TEMPLATES: dict[str, tuple[str, ...]] = {
    "oracle": ("updateOracle", "pushPriceShock", "redeemAgainstOracle"),
    "liquidity": ("addLiquidity", "removeLiquidity", "swap"),
    "debt": ("postCollateral", "borrow", "repay", "liquidate"),
    "shares": ("deposit", "mintShares", "withdraw", "redeem"),
    "fees": ("accrueFees", "collectFees", "claimFees"),
    "cycle": ("roundTrip", "repeatAction"),
    "economic": ("perturbEconomicState",),
}
FOCUS_TEMPLATES: dict[str, str] = {
    "oracle": "bind the live oracle update path and assert price-sensitive solvency or redemption bounds",
    "liquidity": "wire pool entry/exit paths and compare pool balances against LP/share accounting",
    "debt": "exercise collateral, borrow, repay, and liquidation flows while checking solvency",
    "shares": "map deposit, mint, withdraw, and redeem flows to share-price conservation checks",
    "fees": "attach fee accrual and fee collection paths, then assert non-negative value retention",
    "cycle": "compose repeated or round-trip operations and assert the protocol does not leak value",
    "economic": "bind the highest-value state-changing protocol actions and replace placeholders with protocol invariants",
}


@dataclass(frozen=True)
class InvariantSpec:
    invariant_id: str
    title: str
    source: str
    keywords: tuple[str, ...]


@dataclass(frozen=True)
class InvariantPlan:
    spec: InvariantSpec
    suggested_actions: tuple[str, ...]
    acceptance_focus: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower() or "economic_state"


def _default_hypotheses_path(workspace: Path) -> Path | None:
    directory = workspace / "economic_hypotheses"
    if directory.is_dir():
        matches = sorted(directory.glob("*.md"))
        if matches:
            return matches[0]
    singular = workspace / "economic_hypotheses.md"
    return singular if singular.is_file() else None


def _keyword_tags(text: str) -> tuple[str, ...]:
    tags = []
    lowered = text.lower()
    for tag, words in {
        "oracle": ("oracle", "price", "twap", "vwap"),
        "liquidity": ("liquidity", "pool", "amm", "swap"),
        "debt": ("debt", "borrow", "lend", "collateral", "liquidat"),
        "shares": ("share", "vault", "deposit", "withdraw", "redeem"),
        "fees": ("fee", "spread", "premium", "discount"),
        "cycle": ("repeat", "cycle", "loop", "round trip", "flash"),
    }.items():
        if any(word in lowered for word in words):
            tags.append(tag)
    return tuple(tags or ["economic"])


def parse_hypotheses(path: Path | None, max_invariants: int) -> list[InvariantSpec]:
    if path is None or not path.is_file():
        return [
            InvariantSpec(
                "econ_default_state_consistency",
                "economic state consistency",
                "missing hypotheses input",
                ("economic",),
            )
        ]
    text = path.read_text(encoding="utf-8", errors="replace")
    chunks: list[tuple[str, str]] = []
    current_title = ""
    current_body: list[str] = []
    for line in text.splitlines():
        heading = re.match(r"^#{2,3}\s+(.+?)\s*$", line)
        if heading:
            if current_title:
                chunks.append((current_title, "\n".join(current_body)))
            current_title = heading.group(1).strip()
            current_body = []
        elif current_title:
            current_body.append(line)
    if current_title:
        chunks.append((current_title, "\n".join(current_body)))
    if not chunks:
        chunks = [("economic state consistency", text)]

    specs: list[InvariantSpec] = []
    seen: set[str] = set()
    for title, body in chunks:
        normalized = _slug(title)
        if normalized in seen:
            continue
        seen.add(normalized)
        tags = _keyword_tags(f"{title}\n{body}")
        specs.append(
            InvariantSpec(
                invariant_id=f"econ_{normalized}",
                title=title,
                source=str(path),
                keywords=tags,
            )
        )
        if len(specs) >= max_invariants:
            break
    return specs


def _solidity_identifier(text: str) -> str:
    ident = re.sub(r"[^A-Za-z0-9_]", "_", text)
    if not ident or ident[0].isdigit():
        ident = f"i_{ident}"
    return ident[:80]


def _plan_for_spec(spec: InvariantSpec) -> InvariantPlan:
    actions: list[str] = []
    for keyword in spec.keywords:
        for action in ACTION_TEMPLATES.get(keyword, ()):
            if action not in actions:
                actions.append(action)
    if not actions:
        actions.extend(ACTION_TEMPLATES["economic"])
    focus = "; ".join(dict.fromkeys(FOCUS_TEMPLATES.get(keyword, FOCUS_TEMPLATES["economic"]) for keyword in spec.keywords))
    return InvariantPlan(spec=spec, suggested_actions=tuple(actions), acceptance_focus=focus)


def _render_action_stub(action: str) -> str:
    fn = _solidity_identifier(action)
    return f"""    function _action_{fn}(uint256 amount) internal {{
        amount;
        // TODO: replace with a real protocol action, e.g. {action}(amount) on the bound target.
    }}
"""


def render_harness(plans: list[InvariantPlan]) -> str:
    action_names: list[str] = []
    for plan in plans:
        for action in plan.suggested_actions:
            if action not in action_names:
                action_names.append(action)
    if not action_names:
        action_names.extend(ACTION_TEMPLATES["economic"])
    action_blocks = [_render_action_stub(action) for action in action_names]
    invariant_blocks = []
    for plan in plans:
        spec = plan.spec
        fn = _solidity_identifier(spec.invariant_id)
        invariant_blocks.append(
            f"""    /// @notice TODO: replace placeholder assertion with protocol-specific economic invariant.
    /// Source: {spec.title}
    /// Tags: {", ".join(spec.keywords)}
    /// Suggested actions: {", ".join(plan.suggested_actions)}
    /// Acceptance focus: {plan.acceptance_focus}
    function invariant_{fn}() public view {{
        assertTrue(true, "{spec.invariant_id} placeholder");
    }}
"""
        )
    handler_branches = []
    for idx, action in enumerate(action_names):
        prefix = "if" if idx == 0 else "else if"
        handler_branches.append(
            f"""        {prefix} (branch == {idx}) {{
            _action_{_solidity_identifier(action)}(amount);
        }}"""
        )
    return """// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {Test, StdInvariant} from "forge-std/Test.sol";

/// @notice AUTO-GENERATED economic invariant scaffold.
/// Wire real protocol contracts in setUp(), then replace placeholder assertions
/// with concrete conservation, solvency, oracle, fee, or repeated-cycle checks.
contract EconomicInvariantFuzz is Test, StdInvariant {
    address internal actor = address(0xA11CE);
    address internal targetProtocol;

    function setUp() public {
        // TODO: bind targetProtocol to the deployed protocol/router entrypoint you want fuzzed.
        targetContract(address(this));
    }

    function handler_step(uint256 amount, uint256 selectorSeed) public {
        amount = bound(amount, 0, 1e36);
        uint256 branch = selectorSeed % """ + str(len(action_names)) + """;
""" + "\n".join(handler_branches) + """
    }

""" + "\n".join(action_blocks) + "\n" + "\n".join(invariant_blocks) + "}\n"


def build_payload(workspace: Path, hypos: Path | None, out_dir: Path, manifest_path: Path, max_invariants: int) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    specs = parse_hypotheses(hypos, max_invariants=max_invariants)
    plans = [_plan_for_spec(spec) for spec in specs]
    harness = out_dir / "EconomicInvariantFuzz.t.sol"
    medusa_config = out_dir / "medusa_econ_fuzz.json"
    invariants_json = out_dir / "economic_invariants.json"
    harness.write_text(render_harness(plans), encoding="utf-8")
    medusa_config.write_text(
        json.dumps(
            {
                "testMode": "assertion",
                "targetContracts": ["EconomicInvariantFuzz"],
                "deploymentOrder": ["EconomicInvariantFuzz"],
                "corpusDir": "medusa-econ-corpus",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    invariants = [
        {
            "id": plan.spec.invariant_id,
            "title": plan.spec.title,
            "source": plan.spec.source,
            "keywords": list(plan.spec.keywords),
            "harness_function": f"invariant_{_solidity_identifier(plan.spec.invariant_id)}",
            "suggested_actions": list(plan.suggested_actions),
            "acceptance_focus": plan.acceptance_focus,
        }
        for plan in plans
    ]
    action_inventory = sorted({action for plan in plans for action in plan.suggested_actions})
    invariants_json.write_text(json.dumps(invariants, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    payload = {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "workspace": str(workspace),
        "hypotheses": str(hypos) if hypos else None,
        "invariants_count": len(invariants),
        "invariants": invariants,
        "harness": str(harness),
        "medusa_config": str(medusa_config),
        "invariants_json": str(invariants_json),
        "suggested_handler_actions": action_inventory,
        "acceptance_checklist": [
            "bind targetProtocol or equivalent router/entrypoint in setUp()",
            "replace each _action_* stub with a real state-changing call against the target",
            "upgrade placeholder assertTrue(true, ...) invariants to protocol-specific value conservation checks",
            "treat this output as a runnable scaffold, not exploit proof, until target-specific assertions pass",
        ],
        "tier": "scaffold-runnable-not-exploit-proof",
    }
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--hypos")
    parser.add_argument("--out-dir", default="economic_fuzz")
    parser.add_argument("--manifest", default=".auditooor/econ_fuzzer_scaffold.json")
    parser.add_argument("--max-invariants", type=int, default=8)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[econ-fuzzer-scaffold] workspace not found: {workspace}")
    hypos = Path(args.hypos).expanduser().resolve() if args.hypos else _default_hypotheses_path(workspace)
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = workspace / out_dir
    manifest = Path(args.manifest)
    if not manifest.is_absolute():
        manifest = workspace / manifest
    payload = build_payload(workspace, hypos, out_dir, manifest, max_invariants=max(args.max_invariants, 1))
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[econ-fuzzer-scaffold] wrote harness: {payload['harness']}")
        print(f"[econ-fuzzer-scaffold] wrote manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
