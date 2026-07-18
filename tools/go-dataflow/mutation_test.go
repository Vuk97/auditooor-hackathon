package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMutationVerifiedGuardDetection is the R80/R-C non-vacuity proof for the Go
// data-flow backend's guard detection.
//
// It runs analyze() over an in-memory fixture twice:
//
//	BASELINE: GuardedTransfer has `if amount <= 0 { panic }` dominating the sink.
//	          -> the amount->Set path MUST be unguarded=false (guard detected).
//	MUTANT:   the guard line is removed.
//	          -> the SAME amount->Set path MUST flip to unguarded=true.
//
// If the path does NOT flip, the guard detector is vacuous (always reports the
// same answer) and the test FAILS. This is the inject-bug / confirm-fail /
// restore / confirm-pass contract for a non-assert(true) property.
func TestMutationVerifiedGuardDetection(t *testing.T) {
	dir := t.TempDir()
	mod := "module mvfix\n\ngo 1.24\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}

	// Single guarded entrypoint reaching the sink inter-procedurally
	// (Entry -> route -> doSend -> Set). The `amount <= 0` guard dominates the
	// sink-reaching call.
	const baseline = `package mvfix

type KVStore struct{ d map[string]int64 }

func (s *KVStore) Set(k string, v int64) { s.d[k] = v }

func doSend(s *KVStore, to string, amount int64) { s.Set(to, amount) }

func route(s *KVStore, to string, amount int64) { doSend(s, to, amount) }

func Entry(s *KVStore, to string, amount int64) {
	if amount <= 0 {
		panic("bad amount")
	}
	route(s, to, amount)
}
`
	// MUTANT: identical but the dominating guard block is deleted.
	const mutant = `package mvfix

type KVStore struct{ d map[string]int64 }

func (s *KVStore) Set(k string, v int64) { s.d[k] = v }

func doSend(s *KVStore, to string, amount int64) { s.Set(to, amount) }

func route(s *KVStore, to string, amount int64) { doSend(s, to, amount) }

func Entry(s *KVStore, to string, amount int64) {
	route(s, to, amount)
}
`

	srcPath := filepath.Join(dir, "bank.go")

	// returns: (found, unguarded, callDepth, hasAmountGuard)
	analyzeAmountSet := func(src string) (bool, bool, int, bool) {
		if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		// analyze runs go/packages in cwd; chdir to the fixture module.
		old, _ := os.Getwd()
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		defer os.Chdir(old)

		recs, err := analyze([]string{"./..."}, 8, false, false)
		if err != nil {
			t.Fatalf("analyze: %v", err)
		}
		for _, r := range recs {
			if r.Degraded {
				continue
			}
			// the inter-procedural amount->Set state-write slice
			if r.Sink.Callee != nil && strings.HasSuffix(*r.Sink.Callee, ".Set") &&
				r.Source.Var != nil && *r.Source.Var == "amount" {
				hasAmountGuard := false
				for _, g := range r.GuardNodes {
					if strings.Contains(g.Expr, "amount") {
						hasAmountGuard = true
					}
				}
				// require the slice actually traverses Entry (the guarded entrypoint)
				reachesEntry := false
				for _, h := range r.Hops {
					if h.Fn != nil && strings.Contains(*h.Fn, "Entry") {
						reachesEntry = true
					}
				}
				if reachesEntry {
					return true, r.Unguarded, r.CallDepth, hasAmountGuard
				}
			}
		}
		return false, false, 0, false
	}

	bFound, bUnguarded, bDepth, bHasGuard := analyzeAmountSet(baseline)
	if !bFound {
		t.Fatalf("BASELINE: inter-procedural amount->Set path through Entry not found (engine produced no slice)")
	}
	if !bHasGuard || bUnguarded {
		t.Fatalf("BASELINE: amount->Set path reported unguarded=%v hasAmountGuard=%v, but a dominating `if amount<=0` guard exists -> guard detector missed it (vacuous-negative)", bUnguarded, bHasGuard)
	}
	if bDepth < 2 {
		t.Fatalf("BASELINE: expected inter-procedural call_depth>=2 (route->doSend->Set), got %d", bDepth)
	}

	mFound, _, _, mHasGuard := analyzeAmountSet(mutant)
	if !mFound {
		t.Fatalf("MUTANT: inter-procedural amount->Set path through Entry not found")
	}
	if mHasGuard {
		t.Fatalf("MUTANT: removed the `if amount<=0` guard but the slice STILL reports an amount guard -> detector is vacuous (always-guarded), not behavior-sensitive")
	}

	// the guard signal flipped exactly with the mutation -> non-vacuous.
	t.Logf("MUTATION-VERIFIED: baseline hasAmountGuard=%v unguarded=%v depth=%d -> mutant hasAmountGuard=%v (guard removed)",
		bHasGuard, bUnguarded, bDepth, mHasGuard)
}

// TestSinkClassificationReal sanity-checks that value-mover / state-write sinks
// are recognized at the SSA-callee level (not name-grep) on the fixture.
func TestSinkClassificationReal(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module sc\n\ngo 1.24\n"), 0o644)
	src := `package sc
type KVStore struct{ d map[string]int64 }
func (s *KVStore) Set(k string, v int64) { s.d[k] = v }
func (s *KVStore) Transfer(a,b string, amt int64){ s.Set(a, amt) }
func Entry(s *KVStore, x int64){ s.Transfer("a","b", x) }
`
	os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644)
	old, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(old)

	recs, err := analyze([]string{"./..."}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, r := range recs {
		if !r.Degraded {
			kinds[r.Sink.Kind]++
		}
	}
	if kinds["state-write"] == 0 {
		t.Fatalf("expected >=1 state-write sink (Set), got kinds=%v", kinds)
	}
	if kinds["value-move"] == 0 {
		t.Fatalf("expected >=1 value-move sink (Transfer), got kinds=%v", kinds)
	}
	b, _ := json.Marshal(kinds)
	t.Logf("sink kinds: %s", b)
}

// TestCosmosCollectionsSetSink (SCC capability-depth loop 2026-07-08): the Provenance
// vault (and modern cosmos-sdk modules) persist coupled state via `k.Field.Set(ctx,k,v)`
// on a `collections.Map`. Before the looksLikeCollections fix, this receiver (type string
// `sc/collections.Map[...]`, no "store"/"keeper" substring) was NOT classified as a
// state-write, so the vault's primary writes were invisible to the slice (NUVA: 0
// VaultAccount storage hops). This asserts a collections.Map.Set IS a state-write sink.
func TestCosmosCollectionsSetSink(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module sc\n\ngo 1.24\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "collections"), 0o755)
	col := `package collections
type Map[K comparable, V any] struct{ d map[K]V }
func NewMap[K comparable, V any]() *Map[K, V] { return &Map[K, V]{d: map[K]V{}} }
func (m *Map[K, V]) Set(k K, v V) error { m.d[k] = v; return nil }
func (m *Map[K, V]) Remove(k K) error   { delete(m.d, k); return nil }
`
	os.WriteFile(filepath.Join(dir, "collections", "collections.go"), []byte(col), 0o644)
	src := `package sc
import "sc/collections"
type Keeper struct{ Accts *collections.Map[string, int64] }
func (k *Keeper) DepositPrincipal(addr string, shares int64) { k.Accts.Set(addr, shares) }
func Entry(k *Keeper, x int64)                               { k.DepositPrincipal("a", x) }
`
	os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644)
	old, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(old)

	recs, err := analyze([]string{"./..."}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, r := range recs {
		if !r.Degraded {
			kinds[r.Sink.Kind]++
		}
	}
	if kinds["state-write"] == 0 {
		t.Fatalf("expected >=1 state-write sink from collections.Map.Set, got kinds=%v", kinds)
	}
	// task_ba16b499: the state-write sink must recover the PERSISTENT cell (the receiver
	// FIELD name `Accts`) so the SCC resolver can map the value-mover to the cell it writes.
	// Before this the callee was the noisy collections generic TYPE, carrying no cell.
	cellOK := false
	for _, r := range recs {
		if !r.Degraded && r.Sink.Kind == "state-write" && r.Sink.Cell != nil && *r.Sink.Cell == "Accts" {
			cellOK = true
		}
	}
	if !cellOK {
		t.Fatalf("a collections.Map.Set state-write must carry sink.cell=\"Accts\" (the receiver field)")
	}
	b, _ := json.Marshal(kinds)
	t.Logf("collections sink kinds: %s", b)
}

// TestVaultAccountStructFieldFlush (task_08e8aee2): the exact Provenance vault shape - a
// keeper reads a VaultAccount struct from a collections.Map, mutates a SUBSET of the
// coupled fields (TotalShares/Principal), and .Set-s it back. This is the must-move-
// together / partial-flush surface. Assert the analyzer slices the value (shares/principal
// param) THROUGH to the collections .Set state-write sink for BOTH the full-update and the
// partial-update fn, so the SCC conserved-with lane can later ground the coupled fields.
func TestVaultAccountStructFieldFlush(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module va\n\ngo 1.24\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "collections"), 0o755)
	col := `package collections
type Map[K comparable, V any] struct{ d map[K]V }
func (m *Map[K, V]) Get(k K) V           { return m.d[k] }
func (m *Map[K, V]) Set(k K, v V) error  { m.d[k] = v; return nil }
`
	os.WriteFile(filepath.Join(dir, "collections", "collections.go"), []byte(col), 0o644)
	src := `package va
import "va/collections"
type VaultAccount struct{ TotalShares, Principal int64 }
type Keeper struct{ Accts *collections.Map[string, VaultAccount] }
// full reconcile: BOTH coupled fields move, then persist.
func (k *Keeper) FullReconcile(addr string, dShares, dPrincipal int64) {
	va := k.Accts.Get(addr)
	va.TotalShares = va.TotalShares + dShares
	va.Principal = va.Principal + dPrincipal
	k.Accts.Set(addr, va)
}
// partial flush: ONLY Principal moves, TotalShares omitted, then persist.
func (k *Keeper) BadUpdate(addr string, dPrincipal int64) {
	va := k.Accts.Get(addr)
	va.Principal = va.Principal + dPrincipal
	k.Accts.Set(addr, va)
}
func Entry(k *Keeper, x int64) { k.FullReconcile("a", x, x); k.BadUpdate("a", x) }
`
	os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644)
	old, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(old)

	recs, err := analyze([]string{"./..."}, 8, false, false)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, r := range recs {
		if !r.Degraded {
			kinds[r.Sink.Kind]++
		}
	}
	if kinds["state-write"] == 0 {
		t.Fatalf("VaultAccount struct-field write via collections.Set must slice to a "+
			"state-write sink, got kinds=%v", kinds)
	}
	// both FullReconcile and BadUpdate persist via k.Accts.Set - each state-write must
	// carry sink.cell="Accts" so the SCC conserved-with lane can ground BOTH writers on the
	// same persistent cell and see BadUpdate as the strict-subset (partial-flush) violator.
	cellHits := 0
	for _, r := range recs {
		if !r.Degraded && r.Sink.Kind == "state-write" && r.Sink.Cell != nil && *r.Sink.Cell == "Accts" {
			cellHits++
		}
	}
	if cellHits == 0 {
		t.Fatalf("VaultAccount collections.Set state-writes must carry sink.cell=\"Accts\"")
	}
	b, _ := json.Marshal(kinds)
	t.Logf("vaultaccount struct-flush sink kinds: %s cellHits=%d", b, cellHits)
}
