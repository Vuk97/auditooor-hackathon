package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPanicSinkEmission proves the -panic-sinks arm is a real SSA dataflow fact,
// not a text match: a param-tainted type-assert (no comma-ok) and a param-tainted
// index emit kind=="panic" records, while a COMMA-OK assert (which cannot panic)
// emits NONE. The comma-ok/plain contrast is the non-vacuity witness - if the arm
// were a `.(`-token grep it would (wrongly) fire on the comma-ok form too.
func TestPanicSinkEmission(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module pmod\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const src = `package pmod

// EndBlocker: a param-tainted UNCHECKED assert + a param-tainted index. Both are
// panic-capable SSA nodes.
func EndBlocker(payload interface{}, items []int, idx int) int {
	s := payload.(string) // type-assert w/o comma-ok -> panic node
	n := items[idx]       // index OOB -> panic node
	return len(s) + n
}

// SafeAssert: the comma-ok form CANNOT panic; it must NOT be a panic node.
func SafeAssert(payload interface{}) string {
	if s, ok := payload.(string); ok {
		return s
	}
	return ""
}
`
	if err := os.WriteFile(filepath.Join(dir, "e.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	// WITH panic-sinks: type-assert + index nodes appear for EndBlocker.
	recs, err := analyze([]string{"./..."}, 8, false, true)
	if err != nil {
		t.Fatalf("analyze(panic): %v", err)
	}
	var sawAssert, sawIndex, sawSafe bool
	for _, r := range recs {
		if r.Degraded || r.Sink.Kind != "panic" {
			continue
		}
		if r.Source.Kind != "param" {
			continue
		}
		fn := ""
		if r.Sink.Fn != nil {
			fn = *r.Sink.Fn
		}
		op := ""
		if r.Sink.PanicOp != nil {
			op = *r.Sink.PanicOp
		}
		if op == "type-assert" && containsStr(fn, "EndBlocker") {
			sawAssert = true
		}
		if op == "index" && containsStr(fn, "EndBlocker") {
			sawIndex = true
		}
		if containsStr(fn, "SafeAssert") {
			sawSafe = true
		}
	}
	if !sawAssert {
		t.Fatalf("expected a param-tainted type-assert panic node in EndBlocker")
	}
	if !sawIndex {
		t.Fatalf("expected a param-tainted index panic node in EndBlocker")
	}
	if sawSafe {
		t.Fatalf("comma-ok assert in SafeAssert must NOT emit a panic node (vacuity)")
	}

	// NON-VACUITY: WITHOUT panic-sinks the SAME source emits ZERO panic records
	// (the arm is gated, not always-on noise).
	recs2, err := analyze([]string{"./..."}, 8, false, false)
	if err != nil {
		t.Fatalf("analyze(no-panic): %v", err)
	}
	for _, r := range recs2 {
		if r.Sink.Kind == "panic" {
			t.Fatalf("panic record emitted WITHOUT -panic-sinks (flag not load-bearing)")
		}
	}
}

// TestPanicSinkCosmosStateTaint reproduces the cosmos decode idiom that made the
// -panic-sinks arm emit ZERO panic records on real cosmos code (nuva + axelar):
// the panic-capable operand is NOT a direct function parameter - it is a value
// read back from STATE / a decoded message (a keeper getter return, a struct
// field, an iterator/collection value). Cosmos populates such values through a
// codec Unmarshal that writes via a pointer-OUTPUT argument, so in SSA the decoded
// value dead-ends at a local *ssa.Alloc with NO def-use edge to a *ssa.Parameter.
// The old `originParam != nil` gate therefore dropped 100% of these asserts.
//
// The widened predicate accepts a STRUCTURED-INPUT origin (field / map / opaque
// call return) inside an EXPORTED entrypoint. This test asserts:
//   - the state-read UNCHECKED assert in EndBlocker DOES emit a panic record now
//     (source.kind == "state"), and
//   - a pure-LOCAL/const assert on a value with no field/call provenance does NOT
//     (the widening stays a dataflow fact, not a `.(`-token grep), and
//   - the comma-ok state read still emits nothing (comma-ok exclusion intact).
func TestPanicSinkCosmosStateTaint(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module cmod\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Self-contained module that STRUCTURALLY mirrors cosmos: state is read back
	// through a keeper getter whose return derives from a struct field, so the
	// asserted value has no def-use edge to a parameter (exactly the codec-decode
	// pointer-output break, minus the external cosmos-sdk dependency).
	const src = `package cmod

type Any struct{ cached interface{} } // mirrors codec types.Any (interface field)
type Ctx struct{ h int64 }
type Keeper struct{ st map[string]Any }

// getAny: a keeper getter. The returned value comes from a STRUCT FIELD of state
// (m[key].cached), not from the key parameter - so its taint origin is structured
// state, never a *ssa.Parameter.
func (k Keeper) getAny(key string) interface{} {
	v := k.st[key] // map read -> struct
	return v.cached // struct field load
}

// EndBlocker: an EXPORTED consensus entrypoint. Its only param is ctx; the
// asserted value is a STATE read, not ctx. Unchecked assert -> panic-capable node
// that today emits 0 records under the param-only gate.
func (k Keeper) EndBlocker(ctx Ctx) int {
	a := k.getAny("proposal")
	m := a.(Ctx) // UNCHECKED value type-assert on state-derived value -> panic node
	return int(m.h)
}

// SafeEndBlocker: the comma-ok form on the SAME state read must NOT emit a node.
func (k Keeper) SafeEndBlocker(ctx Ctx) int {
	a := k.getAny("proposal")
	if m, ok := a.(Ctx); ok {
		return int(m.h)
	}
	return 0
}

// LocalAssert: an exported fn whose asserted value is a pure LOCAL with no field /
// call / map provenance. structuredInput stays false -> must NOT emit (proves the
// widening is not a text match on ".(" ).
func LocalAssert() int {
	var a interface{} = Ctx{h: 1}
	m := a.(Ctx) // local const provenance -> not structured input
	return int(m.h)
}
`
	if err := os.WriteFile(filepath.Join(dir, "c.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	recs, err := analyze([]string{"./..."}, 8, false, true)
	if err != nil {
		t.Fatalf("analyze(panic): %v", err)
	}
	var sawStateAssert, sawSafe, sawLocal bool
	for _, r := range recs {
		if r.Degraded || r.Sink.Kind != "panic" {
			continue
		}
		fn := ""
		if r.Sink.Fn != nil {
			fn = *r.Sink.Fn
		}
		op := ""
		if r.Sink.PanicOp != nil {
			op = *r.Sink.PanicOp
		}
		if op == "type-assert" && containsStr(fn, "EndBlocker") && !containsStr(fn, "Safe") {
			// widened path: the cosmos state-read assert must be credited with a
			// state (or param) source, not dropped.
			if r.Source.Kind == "state" || r.Source.Kind == "param" {
				sawStateAssert = true
			}
		}
		if op == "type-assert" && containsStr(fn, "SafeEndBlocker") {
			sawSafe = true
		}
		if op == "type-assert" && containsStr(fn, "LocalAssert") {
			sawLocal = true
		}
	}
	if !sawStateAssert {
		t.Fatalf("cosmos state-read unchecked assert in EndBlocker must emit a panic node (the 0-record gap)")
	}
	if sawSafe {
		t.Fatalf("comma-ok state read in SafeEndBlocker must NOT emit a panic node (comma-ok exclusion)")
	}
	if sawLocal {
		t.Fatalf("pure-local assert in LocalAssert must NOT emit (widening must stay a dataflow fact, not a .( grep)")
	}

	// NON-VACUITY: without -panic-sinks the same source emits zero panic records.
	recs2, err := analyze([]string{"./..."}, 8, false, false)
	if err != nil {
		t.Fatalf("analyze(no-panic): %v", err)
	}
	for _, r := range recs2 {
		if r.Sink.Kind == "panic" {
			t.Fatalf("panic record emitted WITHOUT -panic-sinks (flag not load-bearing)")
		}
	}
}

func containsStr(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && indexOf(hay, needle) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
