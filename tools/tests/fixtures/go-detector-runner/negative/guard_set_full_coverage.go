// Pattern 26 — NEGATIVE fixture.
//
// statusesNotAllowedFor includes every enum value still SET via
// SetStatus(...) in production code. Detector must NOT fire.
//
// Mirrors the post-fix shape introduced in SP-6286 (or the pre-shrinkage
// state).
package fixturen

import (
	"context"
)

type st struct{}

type TreeNodeStatus int

var (
	stTreeNodeStatusActive  TreeNodeStatus = 1
	stTreeNodeStatusFrozen  TreeNodeStatus = 2
	stTreeNodeStatusExited  TreeNodeStatus = 3
	stTreeNodeStatusInvalid TreeNodeStatus = 4
)

type stNS struct {
	TreeNodeStatusActive  TreeNodeStatus
	TreeNodeStatusFrozen  TreeNodeStatus
	TreeNodeStatusExited  TreeNodeStatus
	TreeNodeStatusInvalid TreeNodeStatus
}

var stPkg = stNS{
	TreeNodeStatusActive:  stTreeNodeStatusActive,
	TreeNodeStatusFrozen:  stTreeNodeStatusFrozen,
	TreeNodeStatusExited:  stTreeNodeStatusExited,
	TreeNodeStatusInvalid: stTreeNodeStatusInvalid,
}

// Guard slice — full coverage including TreeNodeStatusInvalid.
var statusesNotAllowedFor = []st.TreeNodeStatus{
	st.TreeNodeStatusFrozen,
	st.TreeNodeStatusExited,
	st.TreeNodeStatusInvalid,
}

type predicate struct{}

func (p predicate) StatusIn(_ ...TreeNodeStatus) predicate { return p }

type TreeNodeRow struct{}

type TreeNodeUpdate struct{}

func (t *TreeNodeRow) Update() *TreeNodeUpdate                       { return &TreeNodeUpdate{} }
func (t *TreeNodeUpdate) SetStatus(s TreeNodeStatus) *TreeNodeUpdate { return t }
func (t *TreeNodeUpdate) Save(ctx context.Context) error             { return nil }

func ConsumeGuard() predicate {
	var p predicate
	return p.StatusIn(statusesNotAllowedFor...)
}

// Both SetStatus sites use enum values present in the guard slice —
// no leak.
func MarkInvalid(ctx context.Context, n *TreeNodeRow) error {
	return n.Update().SetStatus(st.TreeNodeStatusInvalid).Save(ctx)
}

func MarkFrozen(ctx context.Context, n *TreeNodeRow) error {
	return n.Update().SetStatus(st.TreeNodeStatusFrozen).Save(ctx)
}
