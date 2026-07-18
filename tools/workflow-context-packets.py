#!/usr/bin/env python3
"""Turn an arbitrary target list (file:line / file::symbol / whole file) into compact
~1k-token context packets, so workflow agents read PACKETS instead of full source files.

This is the GENERAL primitive behind the depth packet tooling. guard-context-extract.py
and asymmetry-context-extract.py are the specialized variants (guard worklist / sibling
asymmetries). This tool accepts ANY target list - a workflow's phase-0 emits the targets,
this emits one compact packet per target, and the analyze phase reads packets. No agent
ever runs `cat <full file>`.

RELATED TOOLS (checked before building):
  - tools/guard-context-extract.py     : guard-worklist -> guard_probe_packets.jsonl (depth layer). REUSED here for the packet-building helpers.
  - tools/asymmetry-context-extract.py : sibling-asymmetry pairs -> asymmetry_probe_packets.jsonl. Two-sided packets.
  This tool is the un-specialized form: arbitrary (file, line|symbol) targets -> one packet each.

Each packet carries: file_line, enclosing-fn signature, a bounded body window, the
enclosing impl/trait header (generic bounds), ALL_CAPS const definitions referenced
nearby, and an approx token count. Capped so the whole packet is ~1k tokens.

Input target forms (one per line in --targets, or a JSON array via --targets-json):
  path/to/file.rs:301
  path/to/file.rs::function_name
  path/to/file.rs                      (whole-file -> packetizes each top-level fn, capped)

Usage:
  workflow-context-packets.py --source-root <dir> --targets <file> --out <dir> [--window N] [--json]
  workflow-context-packets.py --source-root <dir> --targets-json '["a.rs:10","b.rs::foo"]' --out <dir>
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent


def _load(mod_filename: str):
    """Import a hyphenated sibling tool module so we can reuse its helpers."""
    path = _TOOLS / mod_filename
    spec = importlib.util.spec_from_file_location(mod_filename.replace("-", "_").replace(".py", ""), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Reuse the battle-tested packet helpers from guard-context-extract.
_gce = _load("guard-context-extract.py")
_enclosing_fn_start = _gce._enclosing_fn_start
_enclosing_impl = _gce._enclosing_impl_header
_const_defs_in_file = _gce._const_defs_in_file
_referenced_consts = _gce._referenced_consts
_snippet = _gce._snippet

SCHEMA = "auditooor.workflow_context_packet.v1"
_SYM_RE = re.compile(r"\b(fn|function|def)\s+([A-Za-z_][A-Za-z0-9_]*)")


def _read(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _build_const_index(lines: list[str]) -> dict[str, str]:
    try:
        return _const_defs_in_file(lines)
    except Exception:
        idx: dict[str, str] = {}
        cre = re.compile(r"\b(?:const|static|let)\s+([A-Z][A-Z0-9_]{2,})\b.*?=.*")
        for ln in lines:
            m = cre.search(ln)
            if m:
                idx.setdefault(m.group(1), ln.strip())
        return idx


def _find_symbol_line(lines: list[str], symbol: str) -> int | None:
    for i, ln in enumerate(lines):
        m = _SYM_RE.search(ln)
        if m and m.group(2) == symbol:
            return i + 1
    return None


def _top_level_fn_lines(lines: list[str], cap: int) -> list[int]:
    out = []
    for i, ln in enumerate(lines):
        m = _SYM_RE.search(ln)
        if m and (ln[:1] not in (" ", "\t") or ln.lstrip().startswith(("pub ", "fn ", "function ", "def "))):
            out.append(i + 1)
            if len(out) >= cap:
                break
    return out


def _packet(file_rel: str, lines: list[str], line_no: int, window: int, const_index: dict) -> dict:
    idx0 = max(0, min(line_no - 1, len(lines) - 1))
    guard_line = lines[idx0].strip() if lines else ""
    ctx = _snippet(lines, idx0, window, window, 2600)
    fn_start = _enclosing_fn_start(lines, idx0)
    sig = lines[fn_start].strip() if isinstance(fn_start, int) and 0 <= fn_start < len(lines) else ""
    impl_header = ""
    try:
        ih, _ = _enclosing_impl(lines, fn_start if isinstance(fn_start, int) else idx0)
        impl_header = ih or ""
    except Exception:
        pass
    try:
        consts = _referenced_consts(guard_line, ctx, const_index)
    except Exception:
        consts = []
    pid = "PKT-" + hashlib.sha1(f"{file_rel}:{line_no}".encode()).hexdigest()[:12]
    body = ctx if len(ctx) <= 2600 else ctx[:2600] + "\n... [truncated]"
    approx = (len(body) + len(sig) + len(impl_header) + sum(len(c) for c in consts)) // 4
    return {
        "schema": SCHEMA, "packet_id": pid, "file_line": f"{file_rel}:{line_no}",
        "signature": sig, "impl_header": impl_header,
        "referenced_consts": consts[:8], "context": body,
        "approx_tokens": approx,
        "note": "Compact packet - analyze THIS, do not cat the full file.",
    }


def run(source_root: Path, targets: list[str], out_dir: Path, window: int, whole_file_cap: int) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    cache: dict[str, list[str]] = {}
    cidx: dict[str, dict] = {}

    def lines_for(rel: str) -> tuple[Path | None, list[str]]:
        p = (source_root / rel)
        if not p.is_file():
            # best-effort suffix match
            base = Path(rel).name
            hits = list(source_root.rglob(base))
            p = hits[0] if hits else None
        if not p:
            return None, []
        key = str(p)
        if key not in cache:
            cache[key] = _read(p)
            cidx[key] = _build_const_index(cache[key])
        return p, cache[key]

    packets = []
    unresolved = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if "::" in t:
            rel, sym = t.split("::", 1)
            p, lines = lines_for(rel)
            if not lines:
                unresolved.append(t); continue
            ln = _find_symbol_line(lines, sym.strip())
            if ln is None:
                unresolved.append(t); continue
            packets.append(_packet(rel, lines, ln, window, cidx[str(p)]))
        elif re.search(r":\d+$", t):
            rel, ln = t.rsplit(":", 1)
            p, lines = lines_for(rel)
            if not lines:
                unresolved.append(t); continue
            packets.append(_packet(rel, lines, int(ln), window, cidx[str(p)]))
        else:
            rel = t
            p, lines = lines_for(rel)
            if not lines:
                unresolved.append(t); continue
            for ln in _top_level_fn_lines(lines, whole_file_cap):
                packets.append(_packet(rel, lines, ln, window, cidx[str(p)]))

    index = out_dir / "packets_index.jsonl"
    with index.open("w", encoding="utf-8") as fh:
        for pk in packets:
            (out_dir / f"{pk['packet_id']}.json").write_text(json.dumps(pk, indent=2) + "\n")
            fh.write(json.dumps({"packet_id": pk["packet_id"], "file_line": pk["file_line"],
                                 "path": str(out_dir / f"{pk['packet_id']}.json")}) + "\n")

    total = sum(p["approx_tokens"] for p in packets)
    return {
        "schema": SCHEMA, "source_root": str(source_root),
        "targets_in": len(targets), "packets_written": len(packets),
        "unresolved": unresolved, "files_read": len(cache),
        "out_dir": str(out_dir), "index": str(index),
        "approx_tokens_per_packet": (total // len(packets)) if packets else 0,
        "approx_total_tokens": total,
        "note": "Feed each packet's signature+context+consts to a cheap probe; no full-file read needed.",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--targets", type=Path, help="file with one target per line")
    ap.add_argument("--targets-json", help="JSON array of targets")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--window", type=int, default=30)
    ap.add_argument("--whole-file-cap", type=int, default=25)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    sr = args.source_root.expanduser().resolve()
    if args.targets_json:
        targets = json.loads(args.targets_json)
    elif args.targets:
        targets = args.targets.read_text(encoding="utf-8", errors="replace").splitlines()
    else:
        print("[workflow-context-packets] need --targets or --targets-json"); return 2
    out = run(sr, targets, args.out.expanduser().resolve(), args.window, args.whole_file_cap)
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"[workflow-context-packets] {out['targets_in']} targets -> {out['packets_written']} packets "
              f"(~{out['approx_tokens_per_packet']} tok/packet, {len(out['unresolved'])} unresolved, "
              f"{out['files_read']} files read once) -> {out['out_dir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
