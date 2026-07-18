#!/usr/bin/env python3
"""fuzz-target-completeness - fail-closed (advisory-first) when a value-moving
in-scope asset+fn cluster on the fuzz-target WORKLIST
(<ws>/.auditooor/fuzz_targets.jsonl) has NOT reached a terminal verdict.

THE gap this closes (orphaned-worklist, 2026-07-02, generic/all-language): the
fuzz-target corpus emitter produced auditooor.fuzz_target.v1 run-result rows but
NOTHING told the auditor which in-scope value-moving assets still NEED a campaign
- the worklist was orphaned (no runbook step, never written on real workspaces).
tools/fuzz-target-corpus.py --from-inscope now materializes the worklist; this
gate enforces that every worklist row reaches a TERMINAL verdict, one of:

  1. a real fuzz campaign  - .auditooor/fuzz_campaign_receipt.json (or the legacy
     .auditooor/medusa_campaign_receipt.json) names the asset/contract/harness;
  2. a mutation-verified harness  - a matching sidecar under .auditooor/mvc_sidecar/;
  3. a typed disposition  - a row in .auditooor/fuzz_target_dispositions.jsonl
     ({"target_id"|"asset_path"|"fn_cluster", "verdict":"disposed|oos|not-applicable|
     covered", "reason": "<>=20 chars>"}).

A worklist row with none of these is OPEN (needs a campaign).

Advisory by default (warn, rc 0); AUDITOOOR_FUZZ_TARGET_STRICT=1 makes it hard-fail
(rc 1). A ws-level rebuttal file .auditooor/fuzz_target_rebuttal.md (non-empty)
downgrades a fail to warn, mirroring the codified-rules rebuttal pattern.

Completeness-safe: an ABSENT worklist is NOT a pass - it is reported as
warn-worklist-absent (run the generator first). This never retroactively bricks a
prior audit: without the strict env it is purely advisory.

Generic + language-agnostic: reads only the worklist, the campaign receipts, the
mvc_sidecar dir, and the disposition file. No Solidity idiom.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

_TERMINAL_DISPOSITIONS = {"disposed", "oos", "not-applicable", "not_applicable",
                          "covered", "campaign-complete", "complete"}
_MIN_DISPOSITION_REASON = 20


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rows
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(s or "").lower())


def _campaign_tokens(ws: Path) -> set[str]:
    """Normalized asset/contract/harness tokens from any campaign receipt.

    A worklist row is satisfied by a campaign when its asset basename OR fn
    cluster token appears among these (a real >=1M campaign that named the
    contract/harness). Reads both the canonical and legacy receipt names.
    """
    tokens: set[str] = set()
    for rel in ("fuzz_campaign_receipt.json", "medusa_campaign_receipt.json"):
        obj = _load_json(ws / ".auditooor" / rel)
        if not isinstance(obj, dict):
            continue
        camps = obj.get("campaigns")
        if isinstance(camps, list):
            for c in camps:
                if not isinstance(c, dict):
                    continue
                for key in ("contract", "harness", "asset", "target", "name",
                            "asset_path", "target_id"):
                    v = _norm(c.get(key, ""))
                    if v:
                        tokens.add(v)
        # some receipts flatten fields at the top level
        for key in ("contract", "harness", "asset"):
            v = _norm(obj.get(key, ""))
            if v:
                tokens.add(v)
    return tokens


def _mvc_tokens(ws: Path) -> set[str]:
    """Normalized tokens from mutation-verified sidecar filenames + payloads."""
    tokens: set[str] = set()
    mvc_dir = ws / ".auditooor" / "mvc_sidecar"
    if not mvc_dir.is_dir():
        return tokens
    for p in mvc_dir.glob("*.json"):
        stem = _norm(p.stem.replace("mvc-", ""))
        if stem:
            tokens.add(stem)
        obj = _load_json(p)
        if isinstance(obj, dict):
            for key in ("contract", "harness", "asset", "target", "name"):
                v = _norm(obj.get(key, ""))
                if v:
                    tokens.add(v)
    return tokens


def _dispositions(ws: Path) -> tuple[set[str], set[str], set[str]]:
    """Return (target_ids, asset_tokens, fn_cluster_tokens) with a terminal, well-
    reasoned disposition. A bare/short reason does not count (never a free pass)."""
    tids: set[str] = set()
    assets: set[str] = set()
    clusters: set[str] = set()
    for rec in _read_jsonl(ws / ".auditooor" / "fuzz_target_dispositions.jsonl"):
        verdict = str(rec.get("verdict", "")).strip().lower()
        reason = str(rec.get("reason") or "").strip()
        if verdict not in _TERMINAL_DISPOSITIONS or len(reason) < _MIN_DISPOSITION_REASON:
            continue
        tid = str(rec.get("target_id") or "").strip()
        if tid:
            tids.add(tid)
        a = _norm(rec.get("asset_path") or rec.get("asset_basename") or "")
        if a:
            assets.add(a)
        c = _norm(rec.get("fn_cluster") or "")
        if c:
            clusters.add(c)
    return tids, assets, clusters


def _row_tokens(row: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    for key in ("asset_path", "asset_basename"):
        v = _norm(row.get(key, ""))
        if v:
            tokens.add(v)
    # basename without extension, too (contract name often == file stem)
    bn = str(row.get("asset_basename") or "")
    if bn:
        stem = _norm(Path(bn).stem)
        if stem:
            tokens.add(stem)
    fns = row.get("functions")
    if isinstance(fns, list):
        for fn in fns:
            v = _norm(fn)
            if v:
                tokens.add(v)
    return tokens


_GO_DEPTH_RE = re.compile(r"fuzztime|go\s+test\s+-fuzz|\bF\.Fuzz\b|\btesting\.F\b", re.I)
_RUST_DEPTH_RE = re.compile(r"PROPTEST_CASES|proptest_cases|cargo[-\s]?fuzz|\bproptest!\b|#\[fuzz_target\]", re.I)


def _lang_of_row(row: dict[str, Any]) -> str:
    """G-3: language of a fuzz-target worklist row from its asset path / id."""
    for k in ("asset_path", "target_id", "file", "fn_cluster"):
        v = str(row.get(k) or "").lower()
        if v.endswith(".go") or "/go/" in v or "_test.go" in v:
            return "go"
        if v.endswith(".rs") or "/rust/" in v or "/src/" in v and v.endswith(".rs"):
            return "rust"
    return ""


def _lang_depth_evidence(ws: Path, lang: str) -> bool:
    """G-3: is there language-appropriate fuzz DEPTH evidence (Go fuzztime / Rust
    PROPTEST_CASES|cargo-fuzz) in the campaign receipts or fuzz logs? Non-go/rust
    languages return True (not our concern). Conservative: any real depth token counts."""
    if lang not in ("go", "rust"):
        return True
    blobs: list[str] = []
    d = ws / ".auditooor"
    for rel in ("fuzz_campaign_receipt.json", "medusa_campaign_receipt.json"):
        p = d / rel
        if p.is_file():
            try:
                blobs.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    if d.is_dir():
        pats = list(d.glob("*fuzz*.log")) + list(d.glob("*fuzz*.txt")) + list(d.glob("*fuzz*.json"))
        for p in pats[:30]:
            try:
                blobs.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    blob = "\n".join(blobs)
    if not blob:
        return False
    return bool((_GO_DEPTH_RE if lang == "go" else _RUST_DEPTH_RE).search(blob))


def check(ws: Path) -> dict:
    worklist_path = ws / ".auditooor" / "fuzz_targets.jsonl"
    if not worklist_path.is_file():
        strict = bool(os.environ.get("AUDITOOOR_FUZZ_TARGET_STRICT"))
        # An absent worklist is NOT a silent pass - the auditor never enumerated
        # which assets need a campaign. Advisory-first so it cannot brick a prior
        # audit; strict makes it a hard fail.
        return {
            "verdict": ("fail-worklist-absent" if strict else "warn-worklist-absent"),
            "worklist_rows": 0,
            "open": [],
            "note": ("no <ws>/.auditooor/fuzz_targets.jsonl - run "
                     "`python3 tools/fuzz-target-corpus.py --from-inscope --workspace "
                     f"{ws}` to build the worklist"),
        }
    rows = _read_jsonl(worklist_path)
    # only obligation rows (needs_campaign truthy or the worklist schema); ignore
    # any stray run-result rows if the two schemas ever share a file.
    obligations = [
        r for r in rows
        if r.get("needs_campaign") is True
        or str(r.get("schema_version", "")).startswith("auditooor.fuzz_target_worklist")
    ] or rows
    if not obligations:
        return {"verdict": "pass-no-obligations", "worklist_rows": len(rows), "open": []}

    campaign = _campaign_tokens(ws)
    mvc = _mvc_tokens(ws)
    d_tids, d_assets, d_clusters = _dispositions(ws)

    open_rows: list[dict] = []
    covered = 0
    for row in obligations:
        tid = str(row.get("target_id") or "").strip()
        rtokens = _row_tokens(row)
        ckey = _norm(row.get("fn_cluster", ""))
        terminal = False
        why = ""
        if tid and tid in d_tids:
            terminal, why = True, "typed-disposition"
        elif (rtokens & d_assets) or (ckey and ckey in d_clusters):
            terminal, why = True, "typed-disposition"
        elif rtokens & campaign:
            terminal, why = True, "campaign-receipt"
        elif rtokens & mvc:
            terminal, why = True, "mvc-sidecar"
        # G-3 (enforcement-gap 2026-07-03): a Go/Rust worklist row credited via a
        # campaign receipt must ALSO show language-appropriate DEPTH (Go fuzztime /
        # Rust PROPTEST_CASES|cargo-fuzz); otherwise it is a cross-language credit with
        # NO real Go/Rust fuzzing (core-coverage defers Go/Rust to "their own axes" and
        # this gate terminalized on ANY disposition). ADVISORY-FIRST: only engages under
        # AUDITOOOR_FUZZ_TARGET_LANG_DEPTH_STRICT (default OFF -> legacy behavior). A
        # typed disposition / mvc-sidecar is untouched (those are explicit rule-outs).
        _lang = _lang_of_row(row)
        if (terminal and why == "campaign-receipt" and _lang in ("go", "rust")
                and os.environ.get("AUDITOOOR_FUZZ_TARGET_LANG_DEPTH_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
                and not _lang_depth_evidence(ws, _lang)):
            terminal, why = False, f"campaign-receipt-no-{_lang}-depth"
        if terminal:
            covered += 1
        else:
            open_rows.append({
                "target_id": tid or row.get("asset_path") or "<unknown>",
                "asset_path": row.get("asset_path"),
                "fn_cluster": row.get("fn_cluster"),
                "reason": why or "no-terminal-verdict",
            })
    if not open_rows:
        return {"verdict": "pass-fuzz-target-complete", "worklist_rows": len(obligations),
                "covered": covered, "open": []}
    strict = bool(os.environ.get("AUDITOOOR_FUZZ_TARGET_STRICT"))
    return {
        "verdict": ("fail-fuzz-target-incomplete" if strict
                    else "warn-fuzz-target-incomplete"),
        "worklist_rows": len(obligations),
        "covered": covered,
        "open": open_rows,
    }


def _rebuttal(ws: Path) -> str | None:
    p = ws / ".auditooor" / "fuzz_target_rebuttal.md"
    try:
        t = p.read_text(encoding="utf-8", errors="replace").strip()
        return t or None
    except OSError:
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ws", "--workspace", dest="ws", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    ws = Path(a.ws).expanduser()
    rep = check(ws)
    strict = bool(os.environ.get("AUDITOOOR_FUZZ_TARGET_STRICT"))
    reb = _rebuttal(ws)
    failed = str(rep.get("verdict", "")).startswith("fail-")
    if a.json:
        rep["strict"] = strict
        rep["rebuttal"] = bool(reb)
        print(json.dumps(rep, indent=2))
    else:
        print(f"[fuzz-target-completeness] verdict: {rep['verdict']} "
              f"(worklist_rows={rep.get('worklist_rows', 0)}, "
              f"covered={rep.get('covered', 0)}, open={len(rep.get('open', []))}, "
              f"strict={strict})")
        for v in rep.get("open", []):
            print(f"  OPEN {v.get('target_id')}  (asset={v.get('asset_path')} "
                  f"cluster={v.get('fn_cluster')}) - needs a campaign / mvc / disposition")
        if rep.get("note"):
            print(f"  {rep['note']}")
        if failed and reb:
            print(f"  [rebuttal downgrades to warn] {reb[:100]}")
    if failed and strict and not reb:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
