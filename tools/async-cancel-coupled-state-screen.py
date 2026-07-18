#!/usr/bin/env python3
"""async-cancel-coupled-state-screen.py - the ASYNC-CANCEL COUPLED-STATE screen (R6).

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE). It instantiates the
north-star method for one delegated-and-trusted safety property that the existing
coupled-state models (A9 = EVM revert-based interruption ONLY) cannot reach:

  DELEGATED-TRUSTED INVARIANT : a must-move-together state set S = {field_a, field_b, ..}
    of one async actor is committed ATOMICALLY.
  PRIVATE INVARIANT           : if the future is cancelled / dropped at an `.await`
    that lies BETWEEN two writes of S, the half-committed state is either fully
    rolled back or fully committed - an unwind (Drop / scopeguard / explicit
    rollback) re-establishes S.
  ATTACK                      : a caller/timeout/`select!`-branch-loss drops the
    future exactly at that interior await. With no unwind the partial write of S
    persists after the future is gone (conservation break), and the cancellation is
    externally drivable.

This is the tokio cancellation-safety contract generalized (read_exact/write_all
lose data when dropped mid-op inside select!): partial write of a must-all-commit
set survives cancellation with no rollback.

Enforcement points = every interior `.await` between two writes of the same coupled
set inside an async fn. Per point the screen answers:
  {coupled_set, await_line, has_unwind?, cancel_externally_drivable?}
and flags (WARN, verdict=needs-fuzz) ONLY when has_unwind is False AND the
cancellation is externally drivable. It is ADVISORY-FIRST: every row carries
verdict='needs-fuzz', advisory=True, auto_credit=False. It NEVER auto-credits and
NEVER fail-closes in default mode. The strict env AUDITOOOR_RUST_ASYNC_CANCEL_STRICT
(opt-in) only raises the exit code; it still emits no credit.

The screen is language-general in intent but implemented for Rust async (the only
place `.await`-interior cancellation exists); it is silent on non-Rust trees.

Usage:
  --workspace <ws>            scan <ws>/src -> async_cancel_coupled_state_hypotheses.jsonl + summary
  --source <dir>              scan an arbitrary dir (test / ad-hoc), print rows as JSON
  --file <f>                  scan a single .rs file, print rows as JSON
  --check                     re-read the emitted sidecar, print cert verdict (advisory)
  --strict                    (or env) elevate exit code when an un-unwound drivable point exists
  --json                     machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.async_cancel_coupled_state_hypotheses.v2"
_SIDE_NAME = "async_cancel_coupled_state_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_RUST_ASYNC_CANCEL_STRICT"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks"}
# test / bench / example dirs+files are excluded: a cancellation there is not an
# attacker-drivable production interruption (perf harnesses drop futures benignly)
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples)(/|$)")

# --- lexical primitives (Rust) ---------------------------------------------
_ASYNC_FN_RE = re.compile(r"^\s*(pub(?:\s*\([^)]*\))?\s+)?async\s+fn\s+([A-Za-z_]\w*)")
# a write to a state slot: `self.<field> = ...` (assignment, not `==`)
_ASSIGN_RE = re.compile(r"\bself\.([A-Za-z_]\w*)\s*(?:\.[A-Za-z_]\w*)*\s*=(?![=])")
# a state MUTATION via method call: `self.<field>.<mutator>(...)`
_MUT_METHODS = ("push", "pop", "insert", "remove", "set", "clear", "take", "replace",
                "reset", "extend", "append", "put", "swap_remove", "get_or_insert",
                "drain", "retain", "truncate", "push_back", "pop_front")
_MUTCALL_RE = re.compile(
    r"\bself\.([A-Za-z_]\w*)\s*\.\s*(" + "|".join(_MUT_METHODS) + r")\s*\(")
_AWAIT_RE = re.compile(r"\.await\b")
_IMPL_DROP_RE = re.compile(r"\bimpl(?:\s*<[^>]*>)?\s+Drop\s+for\s+([A-Za-z_]\w*)")
# in-fn unwind constructs (scopeguard / on-drop guard object / cancellation drop-guard)
_GUARD_OBJ_RE = re.compile(
    r"(scopeguard|defer!|\.drop_guard\s*\(|ScopeGuard|OnDrop|DropGuard|"
    r"\blet\s+_?guard\b|\blet\s+_[a-z_]*guard\b|guard\s*!\s*\()")
# an explicit rollback / restore AFTER the interior await (compensating action)
_ROLLBACK_RE = re.compile(
    r"\b(rollback|revert|restore|unwind|undo|return_reserved|reset\b|"
    r"put_back|reinsert|reintroduce|compensat)")
# cancellation-context markers: caller can drop the future at will
_CANCEL_CTX_RE = re.compile(r"(\bselect!|\btimeout\b|tokio::spawn|\.abort\s*\(|"
                            r"FuturesUnordered|race\s*\(|with_timeout)")

# Lifecycle markers are evidence, not verdicts.  They let a proof worker choose
# the right transition schedule without turning a lexical hit into exploit proof.
_LIFECYCLE_MARKERS = {
    "cancellation": re.compile(
        r"\bselect!|(?:\b|_)timeout(?:\b|_)|tokio::spawn|\.abort\s*\(|"
        r"FuturesUnordered|race\s*\(|with_timeout", re.IGNORECASE),
    "retry": re.compile(
        r"(?:\b|_)retr(?:y|ies|ied)(?:\b|_)|(?:\b|_)attempt(?:s)?(?:\b|_)|"
        r"(?:\b|_)backoff(?:\b|_)|try_again",
        re.IGNORECASE),
    "timeout": re.compile(
        r"(?:\b|_)timeout(?:\b|_)|(?:\b|_)deadline(?:\b|_)|"
        r"(?:\b|_)elapsed(?:\b|_)|sleep_until|with_timeout",
        re.IGNORECASE),
    "cleanup": re.compile(
        r"(?:\b|_)cleanup(?:\b|_)|(?:\b|_)rollback(?:\b|_)|"
        r"(?:\b|_)revert(?:\b|_)|(?:\b|_)restore(?:\b|_)|"
        r"(?:\b|_)unwind(?:\b|_)|drop_guard|scopeguard|"
        r"(?:\b|_)finally(?:\b|_)|(?:\b|_)defer(?:\b|_)|\bimpl\s+Drop\b",
        re.IGNORECASE),
    "backlog": re.compile(
        r"(?:\b|_)backlog(?:\b|_)|(?:\b|_)pending(?:\b|_)|"
        r"(?:\b|_)queue(?:\b|_)|(?:\b|_)enqueue(?:\b|_)|"
        r"(?:\b|_)dequeue(?:\b|_)|(?:\b|_)requeue(?:\b|_)|"
        r"\bin_flight\b|\binflight\b|(?:\b|_)drain(?:\b|_)",
        re.IGNORECASE),
}


def _mask_comments(text: str) -> str:
    """Replace `//` line comments and `/* */` block comments with spaces, keeping
    the newline structure (and per-line length) so 0-based line indices stay aligned
    with the raw source. NOT string-literal aware (a `//` inside a string literal is
    over-masked) - that errs toward SILENCE (it can only DROP a would-be write/await/
    guard token, never invent one), the safe direction for an advisory screen. Without
    this, a comment that merely mentions `reset`/`restore`/`rollback` was miscredited
    as a real unwind guard (base-azul bond.rs false-silence), and a `self.x = ..` in a
    comment as a real write."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block = False
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            if f.endswith(".rs") and not _TEST_HINT.search(f):
                yield Path(dp) / f


def _async_fn_bodies(lines):
    """Yield (fn_name, is_pub, start_line_idx, body_line_list) for each async fn."""
    i = 0
    n = len(lines)
    while i < n:
        m = _ASYNC_FN_RE.match(lines[i])
        if not m:
            i += 1
            continue
        is_pub = bool(m.group(1))
        fn = m.group(2)
        # brace-match the body
        depth = 0
        started = False
        body = []
        j = i
        while j < n:
            line = lines[j]
            depth += line.count("{") - line.count("}")
            body.append(line)
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
            j += 1
        yield fn, is_pub, i, body
        i = max(j, i + 1)


def _writes_in(body):
    """Return list of (rel_line_idx, field) state writes in a body (assign+mutcall)."""
    writes = []
    for k, line in enumerate(body):
        # ignore string/comment-only false hits cheaply: skip pure comment lines
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        for m in _ASSIGN_RE.finditer(line):
            writes.append((k, m.group(1)))
        for m in _MUTCALL_RE.finditer(line):
            writes.append((k, m.group(1)))
    return writes


def _has_unwind(body, self_type, file_impl_drop_types):
    """The private-invariant guard: is there a compensating unwind for this actor?

    True if ANY of:
      - the impl's own type has an `impl Drop` in the file (Drop-based rollback), OR
      - the fn body contains a scopeguard / drop-guard object, OR
      - the fn body contains an explicit rollback/restore/reset call.
    """
    if self_type and self_type in file_impl_drop_types:
        return True, "impl_drop"
    for line in body:
        if _GUARD_OBJ_RE.search(line):
            return True, "scopeguard"
    for line in body:
        if _ROLLBACK_RE.search(line):
            return True, "explicit_rollback"
    return False, ""


def _self_type_for_line(lines, fn_start_idx):
    """Best-effort: the `impl <Type>` this async fn is nested in (nearest above)."""
    impl_re = re.compile(r"\bimpl(?:\s*<[^>]*>)?\s+(?:[\w:]+\s+for\s+)?([A-Za-z_]\w*)")
    for k in range(fn_start_idx, -1, -1):
        m = impl_re.search(lines[k])
        if m and "Drop for" not in lines[k]:
            return m.group(1)
    return None


def _stable_id(file_rel, fn, fields, await_line):
    h = hashlib.sha1()
    h.update(f"{file_rel}|{fn}|{'+'.join(sorted(fields))}|{await_line}".encode())
    return h.hexdigest()[:16]


def _lifecycle_markers(body, start_idx, is_pub, file_text):
    """Return typed, line-cited lifecycle transition evidence for one function."""
    markers = []
    seen = set()
    for kind, pattern in _LIFECYCLE_MARKERS.items():
        for rel_line, line in enumerate(body):
            match = pattern.search(line)
            if not match:
                continue
            key = (kind, start_idx + rel_line + 1, match.group(0).lower())
            if key in seen:
                continue
            seen.add(key)
            markers.append({
                "kind": kind,
                "token": match.group(0),
                "source_ref": f"<source>:{start_idx + rel_line + 1}",
            })
            break
    if is_pub:
        markers.insert(0, {
            "kind": "cancellation",
            "token": "public_async_future",
            "source_ref": f"<source>:{start_idx + 1}",
        })
    # `impl Drop` can be outside the function body but still supplies cleanup
    # evidence for the actor represented by this async method.
    if re.search(r"\bimpl(?:\s*<[^>]*>)?\s+Drop\s+for\b", file_text,
                 re.IGNORECASE) and not any(m["kind"] == "cleanup" for m in markers):
        markers.append({
            "kind": "cleanup",
            "token": "impl Drop",
            "source_ref": "<source>:file",
        })
    return markers


def _obligation_fields(rel, fn, start_idx, await_idx, coupled, markers,
                       has_unwind, cancel_drivable):
    marker_kinds = sorted({m["kind"] for m in markers})
    source_refs = [f"{rel}:{start_idx + 1}", f"{rel}:{start_idx + await_idx + 1}"]
    source_refs.extend(f"{rel}:{m['source_ref'].split(':')[-1]}" for m in markers
                       if m["source_ref"].split(":")[-1].isdigit())
    source_refs = list(dict.fromkeys(source_refs))
    preconditions = [
        f"async fn `{fn}` mutates every member of coupled set {coupled}",
        "an await or lifecycle transition can occur between coupled writes",
    ]
    if "cancellation" in marker_kinds or cancel_drivable:
        preconditions.append("the future is externally droppable or selectable")
    return {
        "obligation_type": "typed_async_lifecycle_transition",
        "lifecycle_markers": markers,
        "source_refs": source_refs,
        "preconditions": preconditions,
        "suspected_violation": (
            f"coupled state {coupled} may be partially committed when lifecycle "
            "control leaves the function at the interior await"
        ),
        "expected_invariant": (
            "every cancellation, retry, timeout, cleanup, and backlog transition "
            "preserves the coupled-set relation: all members are committed together "
            "or restored together"
        ),
        "proof_task_kind": "async_coupled_state_lifecycle_interleaving",
        "terminal_condition": (
            "terminal only after an executed schedule proves atomic commit/rollback "
            "for every emitted lifecycle marker"
        ),
        "kill_condition": (
            "kill the hypothesis if the marker is unreachable, the await is not "
            "between coupled writes, or an executed proof preserves the invariant"
        ),
        "has_unwind": has_unwind,
    }


def scan_file(path: Path, rel: str, file_text: str = None):
    """Return a list of enforcement-point rows for one .rs file."""
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    # mask comments so a `reset`/`restore` mentioned in prose is not miscredited as a
    # real unwind guard, nor a `self.x = ..` in a comment as a real write. Masking
    # preserves line indices so `await_line`/`fn_line` stay source-accurate.
    text = _mask_comments(raw)
    lines = text.split("\n")
    file_impl_drop_types = set(_IMPL_DROP_RE.findall(text))
    file_cancel_ctx = bool(_CANCEL_CTX_RE.search(text))
    rows = []
    for fn, is_pub, start_idx, body in _async_fn_bodies(lines):
        writes = _writes_in(body)
        if len({f for _, f in writes}) < 2:
            continue  # not a must-move-together set (need >=2 distinct slots)
        await_idxs = [k for k, l in enumerate(body) if _AWAIT_RE.search(l)]
        if not await_idxs:
            continue
        # interior await = an await between a write to field X and a later write to
        # a DIFFERENT field Y (partial-commit window straddles the await)
        for a in await_idxs:
            before = {f for k, f in writes if k < a}
            after = {f for k, f in writes if k > a}
            if not before or not after:
                continue
            # a genuine coupled straddle: the union has >=2 distinct fields AND at
            # least one field on each side is distinct (partial commit possible)
            coupled = sorted(before | after)
            if len(coupled) < 2:
                continue
            distinct_straddle = (before - after) or (after - before) or len(coupled) >= 2
            if not distinct_straddle:
                continue
            self_type = _self_type_for_line(lines, start_idx)
            has_unwind, unwind_kind = _has_unwind(body, self_type, file_impl_drop_types)
            # externally drivable: a pub async future the caller holds, or the file
            # uses select!/timeout/spawn/abort (cancellation surface present)
            cancel_drivable = bool(is_pub or file_cancel_ctx)
            markers = _lifecycle_markers(body, start_idx, is_pub, text)
            # A public future is cancellation-capable even when no select!/timeout
            # token appears in the same function; retain that existing analysis.
            if cancel_drivable and not any(m["kind"] == "cancellation" for m in markers):
                markers.insert(0, {
                    "kind": "cancellation",
                    "token": "externally_drivable_future",
                    "source_ref": f"<source>:{start_idx + 1}",
                })
            fires = (not has_unwind) and cancel_drivable
            row = {
                "schema": HYP_SCHEMA,
                "id": _stable_id(rel, fn, coupled, start_idx + a),
                "file": rel,
                "function": fn,
                "lang": "rust",
                "coupled_set": coupled,
                "await_line": start_idx + a + 1,          # 1-indexed source line
                "fn_line": start_idx + 1,
                "has_unwind": has_unwind,
                "unwind_kind": unwind_kind,
                "cancel_externally_drivable": cancel_drivable,
                "fires": fires,
                # advisory-first contract (never auto-credit, never fail-close)
                "verdict": "needs-fuzz",
                "advisory": True,
                "auto_credit": False,
                "question": (
                    f"async fn `{fn}` writes coupled set {coupled} with an .await between "
                    f"the writes; if the future is dropped/cancelled there, is the partial "
                    f"commit unwound (Drop/scopeguard/rollback) or does it persist?"),
            }
            obligation = _obligation_fields(
                rel, fn, start_idx, a, coupled, markers, has_unwind,
                cancel_drivable)
            obligation["unwind_kind"] = unwind_kind
            row.update(obligation)
            rows.append(row)
            break  # one row per fn is enough (dedup by first straddle)
    return rows


def scan_tree(root: Path):
    rows = []
    for p in _iter_source_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        rows.extend(scan_file(p, rel))
    return rows


def _emit_sidecar(ws: Path, rows):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "silent_unwound": sum(1 for r in rows if r.get("has_unwind")),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="R6 async-cancel coupled-state screen (advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(_STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
        print(json.dumps(rows, indent=2))
        return 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        # allow bare ws name under the fleet root
        cand = Path("/Users/wolf/audits") / args.workspace
        if cand.exists():
            ws = cand
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        # ADVISORY-FIRST: default exit 0 regardless; strict elevates on a fired point
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2) if args.json else json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
