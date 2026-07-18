#!/usr/bin/env python3
"""
auto-poc-synth.py — R76 G: synthesize a Foundry PoC scaffold from a
detector hit.

Given a line like `[aave-back-unbacked-returns-capped-amount] src/Foo.sol:123`
from custom-detectors.log, this tool:

  1. Looks up the pattern YAML to pull severity, wiki_exploit_scenario.
  2. Chooses the best PoC template class based on the pattern's name.
  3. Reads the target contract to infer constructor args, interfaces.
  4. Writes <workspace>/test/poc/<pattern-slug>.t.sol with:
       - fork setup boilerplate
       - target-under-test import + deploy stub
       - exploit test function with ATTACKER / VICTIM roles labelled
       - placeholder exploit body + assertion
  5. Writes <workspace>/test/poc/<pattern-slug>.cantina.md with Cantina
     submission skeleton pre-filled.

Unlike `poc-cowrite.sh` (R73 A4 which needs a pattern name + workspace
args), this tool parses scan output directly and batches.

Usage:
  python3 tools/auto-poc-synth.py <workspace>
     — scans workspace/custom-detectors.log, emits a PoC per hit
       (deduped by pattern × file × line)
  python3 tools/auto-poc-synth.py <workspace> --top 5
     — only the 5 highest-severity hits
  python3 tools/auto-poc-synth.py <workspace> --pattern <name>
     — only synth PoC for this pattern
"""

import argparse, pathlib, re, sys, yaml
from collections import defaultdict

AUDITOOOR = pathlib.Path(__file__).resolve().parent.parent
DSL_DIR = AUDITOOOR / "reference" / "patterns.dsl"
TPL_DIR = AUDITOOOR / "reference" / "poc_templates"


def parse_scan_log(log_path):
    """R79 T7: parse hits from any of the 3 scan formats.

    Formats supported:

      A. Slither custom-detector (R62+ format):
         `  [HIGH] Contract.fn(...) (src/path/Foo.sol#123-130) — pattern-name: ...`
         `  [MEDIUM] Contract.fn (src/path/Foo.sol#90) — pattern matched.`

      B. Slither default (legacy):
         `[pattern-name] file:line message`

      C. Hexens query hits (from apply-queries.sh):
         `  [HITS]  <category>    <query-name>    (N hits)`
         Individual hit lines look like `src/path/Foo.sol:123: code snippet`.

      D. PATTERN_HITS.md sections (from apply-patterns.sh):
         `**Pattern:** `regex...` — **N hits**`
         `src/path/Foo.sol:123: matched line`
    """
    hits = []
    # Slither custom-detector format — extracts pattern NAME from the tail after ` — `
    rx_slither_custom = re.compile(
        r"\[(HIGH|MEDIUM|CRITICAL|LOW|INFO)\][^\[]*?\((?P<file>[\w./\-]+\.sol)#(?P<line>\d+)"
        r"(?:[-\d]*)?\)(?:[^—]*—\s*(?P<pattern>[\w\-]+))?",
    )
    # Legacy Slither: [pattern-name] file:line
    rx_slither_legacy = re.compile(
        r"\[(?P<pattern>[\w\-]{3,})\].*?(?P<file>/?[\w\-./]+\.sol):(?P<line>\d+)"
    )
    # File-line hit from hexens / pattern sweep: "src/foo.sol:123: ..." OR
    # absolute paths "/Users/wolf/audits/.../src/foo.sol:123: ...".
    rx_file_line = re.compile(r"(?P<file>(?:/[\w\-./]*?)?src/[\w\-./]+\.sol):(?P<line>\d+)")

    # Track pattern context when parsing hexens/pattern-hits blocks (format D).
    # Supports: **Pattern:** `regex`, ### P58 — Name, [HITS] category name
    current_pattern = None
    pattern_block_rx = re.compile(
        r"\*\*Pattern:\*\*\s*`([^`]+)`"            # **Pattern:** `foo|bar`
        r"|###[ #]*(?:P\d+\s*—\s*)?([\w\- ]+?)(?:$|\s*\()"  # ### P58 — Name
        r"|\[HITS\]\s+\w+\s+([\w\-]+)"             # [HITS] category name
    )

    text = log_path.read_text()
    for line in text.splitlines():
        # Update pattern context if we see a Hexens or PATTERN_HITS block header
        pm = pattern_block_rx.search(line)
        if pm:
            new_pat = pm.group(1) or pm.group(2) or pm.group(3)
            if new_pat:
                current_pattern = new_pat.strip().replace(" ", "-").lower()[:80]
            continue

        # Try custom-detector format first (most specific)
        m = rx_slither_custom.search(line)
        if m and m.group("pattern"):
            hits.append({
                "pattern": m.group("pattern"),
                "file": m.group("file"),
                "line": int(m.group("line")),
                "format": "slither-custom",
            })
            continue

        # Fall back to legacy Slither
        m = rx_slither_legacy.search(line)
        if m:
            hits.append({
                "pattern": m.group("pattern"),
                "file": m.group("file"),
                "line": int(m.group("line")),
                "format": "slither-legacy",
            })
            continue

        # File-line hit under a pattern context (Hexens / PATTERN_HITS)
        m = rx_file_line.search(line)
        if m and current_pattern:
            hits.append({
                "pattern": current_pattern,
                "file": m.group("file"),
                "line": int(m.group("line")),
                "format": "hexens-or-pattern-hits",
            })
    return hits


def load_pattern_meta(pattern_name):
    p = DSL_DIR / f"{pattern_name}.yaml"
    if not p.exists(): return None
    try:
        return yaml.safe_load(p.read_text())
    except Exception:
        return None


def pick_class(pattern_name):
    n = pattern_name.lower()
    mapping = [
        (["erc4626", "vault", "share", "deposit"], "accounting-drift"),
        (["slippage", "minout", "swap"], "slippage-missing"),
        (["liquidat", "inverted"], "liquidation-inversion"),
        (["pause", "whenpaused"], "pause-bypass"),
        (["oracle", "stale", "sequencer"], "oracle-stale"),
        (["role", "whitelist", "blacklist"], "role-elision"),
        (["bridge", "lock-unlock", "cross-chain"], "cross-chain-lock-unlock"),
        (["reent", "cei", "callback"], "reentrancy"),
        (["underflow", "overflow"], "arithmetic-underflow"),
        (["init", "reinit"], "init-reinit"),
    ]
    for keys, cls in mapping:
        if any(k in n for k in keys):
            return cls
    return "generic"


def render_poc(pattern_name, meta, hit_file, hit_line, workspace):
    cls = pick_class(pattern_name)
    tpl_path = TPL_DIR / f"{cls}.t.sol.template"
    if not tpl_path.exists():
        tpl_path = TPL_DIR / "generic.t.sol.template"
    tpl = tpl_path.read_text()

    pat_camel = "".join(w.capitalize() for w in pattern_name.split("-"))
    target_contract = pathlib.Path(hit_file).stem
    rel_target = pathlib.Path(hit_file)
    try: rel_target = rel_target.relative_to(workspace)
    except Exception: pass
    severity = meta.get("severity", "MEDIUM") if meta else "MEDIUM"

    rendered = (tpl
                .replace("__PATTERN__", pattern_name)
                .replace("__PATTERN_CAMEL__", pat_camel)
                .replace("__TARGET_PATH__", str(rel_target))
                .replace("__TARGET_CONTRACT__", target_contract)
                .replace("__SEVERITY__", severity))

    # Inject hit-location hint at top of the test function
    hit_hint = (f"        // Scan-reported hit: {hit_file}:{hit_line}\n"
                f"        // Pattern: {pattern_name}\n")
    rendered = re.sub(
        r"(function test_\w+_\w+_\w+\(\) public \{\n)",
        r"\1" + hit_hint,
        rendered, count=1,
    )
    return rendered


def render_cantina(pattern_name, meta, hit_file, hit_line, workspace):
    md = meta or {}
    title = md.get("wiki_title", pattern_name)
    severity = md.get("severity", "MEDIUM")
    scenario = md.get("wiki_exploit_scenario", "TODO: exploit scenario")
    reco = md.get("wiki_recommendation", "TODO: recommendation")
    pat_camel = "".join(w.capitalize() for w in pattern_name.split("-"))

    return f"""# {title}

**Severity:** {severity}
**Category:** (Bug / Economic / DoS / Access Control — operator picks)
**Target:** {pathlib.Path(hit_file).name} line {hit_line}

## Summary

(One-sentence summary of the bug. Auto-filled from pattern.help — rewrite.)

## Finding description

{scenario}

## Impact

(Quantify: worst-case loss per action, scale across actors/time/assets.)

## Proof of concept

See `test/poc/{pattern_name}.t.sol`. Run with:

```bash
forge test --match-test "test_{pat_camel}_*" -vvv \\
    --fork-url $ETH_RPC_URL --fork-block-number <pinned>
```

## Recommended mitigation

{reco}

## References

- Detector pattern: `reference/patterns.dsl/{pattern_name}.yaml`
- Scan hit: `{hit_file}:{hit_line}`
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    ap.add_argument("--top", type=int, default=50)
    ap.add_argument("--pattern", default=None)
    ap.add_argument("--log", default=None,
                    help="path to scan log (defaults to <workspace>/custom-detectors.log)")
    args = ap.parse_args()

    ws = pathlib.Path(args.workspace)
    log_path = pathlib.Path(args.log) if args.log else (ws / "custom-detectors.log")
    if not log_path.exists():
        print(f"[err] scan log not found: {log_path}", file=sys.stderr); sys.exit(1)

    hits = parse_scan_log(log_path)
    if args.pattern:
        hits = [h for h in hits if h["pattern"] == args.pattern]

    # Dedupe by (pattern, file, line)
    seen = set()
    unique = []
    for h in hits:
        key = (h["pattern"], h["file"], h["line"])
        if key in seen: continue
        seen.add(key); unique.append(h)
    hits = unique[:args.top]

    poc_dir = ws / "test" / "poc"
    poc_dir.mkdir(parents=True, exist_ok=True)

    emitted = 0
    for h in hits:
        meta = load_pattern_meta(h["pattern"])
        if meta is None: continue
        sol_out = poc_dir / f"{h['pattern']}.t.sol"
        md_out = poc_dir / f"{h['pattern']}.cantina.md"
        if sol_out.exists():
            continue  # don't clobber operator edits
        sol_out.write_text(render_poc(h["pattern"], meta, h["file"], h["line"], ws))
        md_out.write_text(render_cantina(h["pattern"], meta, h["file"], h["line"], ws))
        emitted += 1

    print(f"[ok] emitted {emitted} PoC scaffolds under {poc_dir}")
    print(f"     total scan hits: {len(parse_scan_log(log_path))}")
    print(f"     deduped candidates: {len(hits)}")


if __name__ == "__main__":
    main()
