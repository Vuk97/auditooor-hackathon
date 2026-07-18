package main

import (
	"os"
	"testing"
)

// Regression: normHops/normGuards must bound the SERIALIZED array length so a
// pathological deep slice through the cosmos-sdk codec/context graph cannot
// balloon one record to tens of MB (observed NUVA 2026-07-06: guard_nodes
// len=163722 = 23.5MB in a single record; whole slice = 543MB; the python arm's
// json.loads OOM-hung -> step-1c produced ZERO dataflow records). The cap is a
// serialization bound only; it must not touch the nil-safety contract.
func TestNormHopsGuardsEmitCap(t *testing.T) {
	// nil stays empty (unchanged contract)
	if got := normHops(nil); got == nil || len(got) != 0 {
		t.Fatalf("normHops(nil) = %v, want empty non-nil", got)
	}
	if got := normGuards(nil); got == nil || len(got) != 0 {
		t.Fatalf("normGuards(nil) = %v, want empty non-nil", got)
	}
	// oversized arrays are truncated to the default cap (96)
	bigH := make([]hopRec, 5000)
	if got := len(normHops(bigH)); got != 96 {
		t.Fatalf("normHops(5000) len = %d, want 96", got)
	}
	bigG := make([]guardRec, 163722)
	if got := len(normGuards(bigG)); got != 96 {
		t.Fatalf("normGuards(163722) len = %d, want 96 (the NUVA explosion)", got)
	}
	// under-cap arrays pass through untouched (no signal loss)
	small := make([]hopRec, 40)
	if got := len(normHops(small)); got != 40 {
		t.Fatalf("normHops(40) len = %d, want 40 (no truncation under cap)", got)
	}
	// env override is honored
	os.Setenv("AUDITOOOR_DATAFLOW_EMIT_GUARDS", "8")
	defer os.Unsetenv("AUDITOOOR_DATAFLOW_EMIT_GUARDS")
	if got := len(normGuards(bigG)); got != 8 {
		t.Fatalf("normGuards with EMIT_GUARDS=8 len = %d, want 8", got)
	}
}
