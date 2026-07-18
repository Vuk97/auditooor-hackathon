// Pattern 26 — POSITIVE fixture for
//   go.spark.guard_set.shrinkage_status_still_set
//
// statusesNotAllowedFor (mirrors SP-6286 ``1da2e92e93``) is consumed by
// a StatusIn(...) predicate, but a SetStatus call site outside this
// guard's enum-member set is still live in production code, leaving a
// guard regression that lets formerly-protected statuses be
// force-overwritten.
package fixture

import (
	"context"
)

// st-shaped enum surface (in a real repo this would live under
// ``ent/schema/<entity>/.go`` — we inline a minimal stub for the fixture).
type st struct{}

type TreeNodeStatus int

var (
	stTreeNodeStatusActive   TreeNodeStatus = 1
	stTreeNodeStatusFrozen   TreeNodeStatus = 2
	stTreeNodeStatusExited   TreeNodeStatus = 3
	stTreeNodeStatusInvalid  TreeNodeStatus = 4
)

// Wrap into a single ``st`` namespace so the guard slice and SetStatus
// calls both reference st.<EnumValue>.
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

// Guard slice — note: TreeNodeStatusInvalid was REMOVED in the bad PR.
var statusesNotAllowedFor = []st.TreeNodeStatus{
	st.TreeNodeStatusFrozen,
	st.TreeNodeStatusExited,
}

type predicate struct{}

func (p predicate) StatusIn(_ ...TreeNodeStatus) predicate { return p }

type TreeNodeRow struct{}

type TreeNodeUpdate struct{}

func (t *TreeNodeRow) Update() *TreeNodeUpdate                                 { return &TreeNodeUpdate{} }
func (t *TreeNodeUpdate) SetStatus(s TreeNodeStatus) *TreeNodeUpdate            { return t }
func (t *TreeNodeUpdate) Save(ctx context.Context) error                        { return nil }

func ConsumeGuard() predicate {
	var p predicate
	return p.StatusIn(statusesNotAllowedFor...)
}

// Production SetStatus call sites — the bug shape is that
// ``st.TreeNodeStatusInvalid`` is still SET here even though the
// guard slice no longer contains it.
func MarkInvalid(ctx context.Context, n *TreeNodeRow) error {
	return n.Update().SetStatus(st.TreeNodeStatusInvalid).Save(ctx)
}

// A second SetStatus site for an enum value still IN the guard — this
// one should NOT cause a hit (the guard still protects it).
func MarkFrozen(ctx context.Context, n *TreeNodeRow) error {
	return n.Update().SetStatus(st.TreeNodeStatusFrozen).Save(ctx)
}
