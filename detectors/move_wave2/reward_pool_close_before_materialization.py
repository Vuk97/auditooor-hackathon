"""
expired-reward-pool-close-refunds-accrued-yield-before-lazy-materialization.

Bug class: rewards-accounting / ordering
Language:  move (Sui)
Source:    solodit-2026-04-cycle20-move / Sherlock CurrentSUI
Source URL: https://solodit.cyfrin.io/issues/m-4-expired-reward-pool-close-can-refund-economically-accrued-borrower-yield-before-lazy-reward-materialization-sherlock-currentsui-contest-march-2026-git

Semantic anchor:
  `close_expired_reward_pool` refunds the remaining balance to the pool
  owner BEFORE running lazy reward materialization for active borrowers.
  Yield that borrowers earned but has not yet been lazily materialized
  is swept back to the owner.

Detection strategy:
  Flag Move functions that close / expire a reward pool where:
    1. A transfer / refund to the pool owner occurs.
    2. The lazy-materialization call for borrowers does NOT precede the
       owner refund in the same function body.

  Proxy signal: `transfer`/`coin::transfer`/`refund` to `owner` appears
  before or without `materialize_rewards`/`settle_rewards`/`distribute`.

M14-trap note:
  Bug class is "owner-refund before borrower-materialization in reward
  pool close" — predicate checks the ORDER of operations (refund vs
  materialize), not fixture shape.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_CLOSE_FN_RE = re.compile(
    r"fun\s+(close_expired_reward_pool|expire_reward_pool|"
    r"close_reward_pool|shutdown_pool|close_pool)\s*[(<]",
    re.IGNORECASE,
)

# Owner refund — the dangerous early operation
_REFUND_RE = re.compile(
    r"(?:coin::transfer|transfer|refund|send_coins|return_coins)"
    r"[^;{]*(?:owner|creator|admin)",
    re.IGNORECASE,
)

# Lazy materialization — should precede the refund
_MATERIALIZE_RE = re.compile(
    r"(?:materialize_rewards|settle_rewards|distribute_rewards|"
    r"accrue_rewards|apply_rewards|checkpoint_rewards)\s*\(",
    re.IGNORECASE,
)


def _line_at(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _extract_fn_body(source: str, fn_start: int) -> str:
    idx = source.find("{", fn_start)
    if idx == -1:
        return ""
    depth = 0
    for i in range(idx, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[fn_start:i + 1]
    return source[fn_start:]


def scan_text(source: str, filepath: str = "<memory>") -> list[dict]:
    hits: list[dict] = []
    for m in _CLOSE_FN_RE.finditer(source):
        body = _extract_fn_body(source, m.start())
        refund_m = _REFUND_RE.search(body)
        materialize_m = _MATERIALIZE_RE.search(body)

        has_refund = refund_m is not None
        has_materialize = materialize_m is not None

        if has_refund and not has_materialize:
            # Refund present, materialization entirely absent
            flag = True
        elif has_refund and has_materialize:
            # Both present — check ordering: refund must come AFTER materialize
            flag = refund_m.start() < materialize_m.start()
        else:
            flag = False

        if flag:
            line = _line_at(source, m.start())
            fn_name = m.group(1)
            hits.append({
                "severity": "medium",
                "filepath": filepath,
                "line": line,
                "function": fn_name,
                "message": (
                    f"`{fn_name}` refunds the owner before materializing accrued "
                    "borrower rewards. Earned yield that has not yet been materialized "
                    "is swept back to the owner, denying borrowers their rewards."
                ),
            })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding="utf-8", errors="replace"), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect reward pool close that refunds owner before borrower materialization."
    )
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    hits: list[dict] = []
    for p in args.paths:
        if p.is_dir():
            for f in sorted(p.rglob("*.move")):
                hits.extend(scan_file(f))
        elif p.suffix == ".move":
            hits.extend(scan_file(p))
    if args.json:
        print(json.dumps(hits, indent=2))
    else:
        for h in hits:
            print(f"{h['filepath']}:{h['line']}: {h['severity']}: {h['message']}")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
