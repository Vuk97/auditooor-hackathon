#!/usr/bin/env bash
# bug-family-atlas.sh — R73 B5: aggregate cross-engagement TP/FP data by
# bug family into a searchable catalog.
#
# Produces reference/bug_family_atlas.md — "the catalog of things that have
# actually made money." Grows with every engagement outcome landed in the
# hits ledger.
#
# Usage:
#   bash tools/bug-family-atlas.sh            # regenerate from ledger
#   bash tools/bug-family-atlas.sh --paid     # paid findings only
#   bash tools/bug-family-atlas.sh --csv      # CSV output for spreadsheet
#
# Input:
#   detectors/_hits_ledger.yaml      — per-detector TP/FP/unknown counts + _history
#   reference/patterns.dsl/*.yaml   — pattern metadata (severity, wiki_title, family tags)
#
# Output:
#   reference/bug_family_atlas.md    — grouped by protocol-family + bug-shape class
#   reference/bug_family_atlas.csv   — if --csv

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER="$AUDITOOOR_DIR/detectors/_hits_ledger.yaml"
DSL_DIR="$AUDITOOOR_DIR/reference/patterns.dsl"
OUT_MD="$AUDITOOOR_DIR/reference/bug_family_atlas.md"
OUT_CSV="$AUDITOOOR_DIR/reference/bug_family_atlas.csv"

MODE=md
PAID_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --csv) MODE=csv; shift ;;
        --paid) PAID_ONLY=1; shift ;;
        -h|--help)
            sed -n '2,15p' "$0" | sed 's/^# //; s/^#//'
            exit 0 ;;
        *) echo "[err] unknown arg: $1" >&2; exit 1 ;;
    esac
done

[ -f "$LEDGER" ] || { echo "[err] ledger not found: $LEDGER" >&2; exit 1; }

python3 - "$LEDGER" "$DSL_DIR" "$OUT_MD" "$OUT_CSV" "$MODE" "$PAID_ONLY" <<'PY'
import sys, yaml, json, pathlib, re, datetime

ledger_p, dsl_dir, out_md, out_csv, mode, paid_only = sys.argv[1:]
paid_only = int(paid_only)

led = yaml.safe_load(open(ledger_p)) or {}
dets = led.get('detectors', led) if isinstance(led, dict) else {}

# Load pattern metadata from YAML frontmatter
patterns = {}
for yf in pathlib.Path(dsl_dir).glob('*.yaml'):
    try:
        p = yaml.safe_load(yf.read_text())
    except Exception:
        continue
    if not isinstance(p, dict):
        continue
    name = p.get('pattern', yf.stem)
    patterns[name] = {
        'severity': p.get('severity', 'UNKNOWN'),
        'wiki_title': p.get('wiki_title', ''),
        'source': p.get('source', ''),
    }

# Classify by protocol family (crude — keyword match on pattern name)
def family(name):
    n = name.lower()
    for tag, matchers in [
        ('vault/erc4626',  ['erc4626', 'vault', 'share', 'gulp', 'centrifuge']),
        ('lending',        ['morpho', 'comet', 'aave', 'euler', 'compound', 'borrow', 'lend', 'liquid']),
        ('amm/dex',        ['uniswap', 'amm', 'pool', 'swap', 'tick', 'curve', 'balancer']),
        ('bridge',         ['bridge', 'snowbridge', 'layerzero', 'wormhole', 'across', 'hop', 'cross-chain']),
        ('staking/lst',    ['kiln', 'lido', 'stader', 'eigen', 'puffer', 'swell', 'stake', 'validator']),
        ('perps',          ['gmx', 'perp', 'funding', 'liquidation-bonus', 'mark-price', 'vertex']),
        ('exchange',       ['exchange', 'order', 'fill', 'orderbook', 'ctf-exchange', 'polymarket']),
        ('proxy/upgrade',  ['proxy', 'upgrade', 'initialize', 'tup', 'erc1967']),
        ('oracle',         ['oracle', 'pricefeed', 'chainlink', 'twap']),
        ('signature',      ['permit', 'eip712', 'ecrecover', 'signature']),
        ('fee',            ['fee', 'commission', 'split', 'dispatcher']),
        ('token',          ['erc20', 'erc721', 'erc1155', 'erc6909', 'token', 'mint', 'burn']),
        ('economic',       ['ec-', 'rate-limit', 'rebase-token', 'slippage', 'mev']),
    ]:
        for m in matchers:
            if m in n:
                return tag
    return 'misc'

# Build atlas
rows = []
for name, det in (dets or {}).items():
    if not isinstance(det, dict):
        continue
    tp = det.get('tp', 0) or 0
    fp = det.get('fp', 0) or 0
    unknown = det.get('unknown', 0) or 0
    hits = det.get('hits', 0) or 0
    if paid_only and tp == 0:
        continue
    hist = det.get('_history', []) or []
    paid_outcomes = [h for h in hist if isinstance(h, dict) and h.get('verdict','').upper() == 'TP' and h.get('outcome','').lower() == 'paid']
    any_outcomes = [h.get('outcome','?') for h in hist if isinstance(h, dict) and h.get('outcome')]
    workspaces = sorted(set(h.get('workspace','?') for h in hist if isinstance(h, dict)))
    meta = patterns.get(name, {})
    rows.append({
        'pattern': name,
        'family': family(name),
        'severity': meta.get('severity','UNKNOWN'),
        'title': meta.get('wiki_title',''),
        'hits': hits,
        'tp': tp,
        'fp': fp,
        'unknown': unknown,
        'paid_count': len(paid_outcomes),
        'workspaces': ','.join(workspaces),
        'source': meta.get('source',''),
    })

# Sort: family asc, paid_count desc, tp desc, hits desc
rows.sort(key=lambda r: (r['family'], -r['paid_count'], -r['tp'], -r['hits'], r['pattern']))

if mode == 'csv':
    import csv
    with open(out_csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ['pattern'])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[ok] wrote {len(rows)} rows to {out_csv}")
else:
    with open(out_md, 'w') as f:
        f.write("# Bug-family atlas — cross-engagement TP/FP aggregator\n\n")
        f.write(f"Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n\n")
        f.write(f"**Total patterns with ledger entries: {len(rows)}**\n\n")
        f.write("Grouped by protocol family. Sorted by (family, paid_count desc, tp desc, hits desc).\n\n")
        f.write("Legend: **TP** = paid / confirmed; **FP** = rejected; **UNK** = pending triage.\n\n---\n\n")

        current_family = None
        for r in rows:
            if r['family'] != current_family:
                current_family = r['family']
                f.write(f"\n## Family: `{current_family}`\n\n")
                f.write("| Pattern | Severity | TP | FP | UNK | Hits | Paid engagements | Title |\n")
                f.write("|---|---|---:|---:|---:|---:|---|---|\n")
            paid_flag = f"**{r['paid_count']}** ({r['workspaces']})" if r['paid_count'] > 0 else ""
            f.write(f"| `{r['pattern']}` | {r['severity']} | {r['tp']} | {r['fp']} | {r['unknown']} | {r['hits']} | {paid_flag} | {r['title'][:80]} |\n")

        # Totals
        total_tp = sum(r['tp'] for r in rows)
        total_fp = sum(r['fp'] for r in rows)
        total_unk = sum(r['unknown'] for r in rows)
        total_paid = sum(r['paid_count'] for r in rows)
        f.write(f"\n---\n\n## Totals\n\n")
        f.write(f"- TP: **{total_tp}**  ·  FP: **{total_fp}**  ·  UNKNOWN (pending triage): **{total_unk}**\n")
        f.write(f"- Paid outcomes logged: **{total_paid}**\n")
        f.write(f"- Distinct patterns with any ledger entry: **{len(rows)}**\n")

        # TOP-10 paid patterns
        paid_rows = [r for r in rows if r['paid_count'] > 0]
        if paid_rows:
            f.write("\n## Top-10 paid patterns (real-money-catching detectors)\n\n")
            paid_rows.sort(key=lambda r: (-r['paid_count'], -r['tp']))
            f.write("| Pattern | Family | Severity | Paid | TP | Title |\n")
            f.write("|---|---|---|---:|---:|---|\n")
            for r in paid_rows[:10]:
                f.write(f"| `{r['pattern']}` | {r['family']} | {r['severity']} | {r['paid_count']} | {r['tp']} | {r['title'][:80]} |\n")

    print(f"[ok] wrote bug-family atlas: {out_md}")
    print(f"     {len(rows)} patterns grouped into {len(set(r['family'] for r in rows))} families")
PY
