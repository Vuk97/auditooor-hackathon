"""
go-state-change-between-check-and-use.py

Detects Go functions that snapshot a state-derived value, perform a later
state refresh or mutator, and then use the stale snapshot without re-reading
or revalidating it first.

Confirmed corpus anchors:
- findings-go:statechain-mercury-backup-tx-fee-rate-class:f32b092d8f25
- findings-go:ghsa-6447-269v-g68m:6ce16b851320
- sig-extract:dydx-v4-chain:protocol-x-accountplus-keeper-timestampnonce.go:ejectstaletimestampnonces:c2f3eef732c7

This is intentionally narrower than the generic Go bank-send-before-commit
shape. It only fires when a checked snapshot survives a later state-changing
call and is then used again in a value-bearing path.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-state-change-between-check-and-use"

_STATE_CONTEXT_RE = re.compile(
    r"(?i)(backup|statechain|state|snapshot|fee|rate|price|balance|nonce|"
    r"status|claim|withdraw|settle|finalize|reward|account|proposal|order|"
    r"liquidat|commit|sync|update|refresh)"
)

_SNAPSHOT_ASSIGN_RE = re.compile(
    r"^\s*(?P<lhs>[A-Za-z_]\w*)\s*(?::=|=)\s*(?P<rhs>.+)$"
)

_SNAPSHOT_RHS_RE = re.compile(
    r"(?i)(?:[A-Za-z_]\w*\.)?(?:Get|Load|Read|Fetch|Current|Latest|Snapshot|"
    r"State|Info|Status|Balance|FeeRate|Price|Nonce|Claim|Reward|Order|"
    r"Proposal|Account|Limit|Threshold|Height|Timestamp|Amount|Supply|Share|"
    r"Collateral|Debt)\b"
)

_MUTATOR_RE = re.compile(
    r"(?i)\b(sync|update|refresh|accrue|settle|checkpoint|finalize|apply|"
    r"commit|rebuild|reload|setparam|setparams|setstate|mark|consume|close|"
    r"open|repair|reprice|invalidate|recalculate)\w*\s*\("
)


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _line_has_guard(line: str, var: str) -> bool:
    return bool(
        re.search(
            rf"(?i)\b(if|require|panic|return)\b.*\b{re.escape(var)}\b.*"
            rf"(?:==|!=|<=|>=|<|>|!|nil|zero)",
            line,
        )
    )


def _line_has_use(line: str, var: str) -> bool:
    if not re.search(rf"\b{re.escape(var)}\b", line):
        return False
    if re.match(rf"^\s*{re.escape(var)}\s*(?::=|=)\b", line):
        return False
    return bool(re.search(r"[+\-*/%]|==|!=|<=|>=|<|>|\(", line))


def _line_reassigns_var(line: str, var: str) -> bool:
    if re.match(rf"^\s*{re.escape(var)}\s*(?::=|=)\b", line):
        return True
    lhs = re.match(r"^\s*(?P<lhs>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::=|=)", line)
    if lhs is None:
        return False
    return var in {part.strip() for part in lhs.group("lhs").split(",")}


def _hit(engine, fn, name: str, why: str):
    return {
        "severity": "high",
        "line": engine.line(fn),
        "col": engine.col(fn),
        "snippet": engine.text(fn).splitlines()[0][:160],
        "message": (
            f"`{name}` caches a checked state snapshot, then changes state "
            f"and later uses the stale snapshot without re-reading it: {why}. "
            f"Re-read or revalidate immediately before the value-bearing use. "
            f"(class: state-change-between-check-and-use)"
        ),
    }


def run(engine, filepath: str):
    hits = []
    path_text = filepath.replace("\\", "/")

    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = engine.text(fn)
        body_text = _strip_comments(engine.text(body))
        if not (
            _STATE_CONTEXT_RE.search(path_text)
            or _STATE_CONTEXT_RE.search(name)
            or _STATE_CONTEXT_RE.search(fn_text)
            or _STATE_CONTEXT_RE.search(body_text)
        ):
            continue

        lines = body_text.splitlines()
        for idx, line in enumerate(lines):
            snap = _SNAPSHOT_ASSIGN_RE.match(line)
            if snap is None:
                continue
            var = snap.group("lhs").strip()
            if not _SNAPSHOT_RHS_RE.search(snap.group("rhs")):
                continue

            guard_idx = None
            for j in range(idx + 1, len(lines)):
                if _line_has_guard(lines[j], var):
                    guard_idx = j
                    break
            if guard_idx is None:
                continue

            mutator_idx = None
            for j in range(guard_idx + 1, len(lines)):
                if _MUTATOR_RE.search(lines[j]):
                    mutator_idx = j
                    break
            if mutator_idx is None:
                continue

            use_idx = None
            for j in range(mutator_idx + 1, len(lines)):
                if _line_has_use(lines[j], var):
                    use_idx = j
                    break
            if use_idx is None:
                continue

            if any(
                _line_reassigns_var(lines[j], var)
                for j in range(mutator_idx + 1, use_idx)
            ):
                continue

            hits.append(
                _hit(
                    engine,
                    fn,
                    name,
                    (
                        f"guard at line {engine.line(fn) + idx} snapshots `{var}`, "
                        f"a later state-mutating call occurs at line {engine.line(fn) + mutator_idx}, "
                        f"and the stale snapshot is used again at line {engine.line(fn) + use_idx}"
                    ),
                )
            )
            break

    return hits
