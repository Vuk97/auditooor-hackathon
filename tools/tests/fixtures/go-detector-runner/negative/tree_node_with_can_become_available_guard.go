// Pattern 13 — NEGATIVE fixture.
//
// Two functions both advance a TreeNode to AVAILABLE, but each one calls a
// canonical guard before the mutation:
//
//   1. The first calls Status.CanBecomeAvailable() (the SP-3049 method).
//   2. The second calls the legacy package-level helper
//      TreeNodeCanBecomeAvailable(node).
//
// A third function uses an explicit hand-rolled terminal-status compare
// (Status == TreeNodeStatusExited) — also accepted by the detector.
//
// Pattern 13 must NOT fire on any of these.
package fixturen13

import "context"

type TreeNode struct {
	Status TreeNodeStatus
}

type TreeNodeStatus string

const (
	TreeNodeStatusAvailable    TreeNodeStatus = "AVAILABLE"
	TreeNodeStatusOnChain      TreeNodeStatus = "ON_CHAIN"
	TreeNodeStatusExited       TreeNodeStatus = "EXITED"
	TreeNodeStatusSplitted     TreeNodeStatus = "SPLITTED"
	TreeNodeStatusParentExited TreeNodeStatus = "PARENT_EXITED"
	TreeNodeStatusReimbursed   TreeNodeStatus = "REIMBURSED"
)

func (s TreeNodeStatus) CanBecomeAvailable() bool {
	switch s {
	case TreeNodeStatusSplitted, TreeNodeStatusOnChain, TreeNodeStatusExited,
		TreeNodeStatusParentExited, TreeNodeStatusReimbursed:
		return false
	}
	return true
}

func TreeNodeCanBecomeAvailable(node *TreeNode) bool {
	return node.Status.CanBecomeAvailable()
}

type TreeNodeUpdater struct{ node *TreeNode }

func (u *TreeNodeUpdater) SetStatus(s TreeNodeStatus) *TreeNodeUpdater {
	u.node.Status = s
	return u
}

func (u *TreeNodeUpdater) Save(ctx context.Context) (*TreeNode, error) {
	_ = ctx
	return u.node, nil
}

// 1) Method-form guard — calls .CanBecomeAvailable() before mutating.
func CancelGuardedByMethod(ctx context.Context, leaves []*TreeNode) error {
	for _, leaf := range leaves {
		if !leaf.Status.CanBecomeAvailable() {
			continue
		}
		_, err := (&TreeNodeUpdater{node: leaf}).SetStatus(TreeNodeStatusAvailable).Save(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// 2) Legacy helper-form guard — calls TreeNodeCanBecomeAvailable(node).
func CancelGuardedByHelper(ctx context.Context, leaves []*TreeNode) error {
	for _, leaf := range leaves {
		if !TreeNodeCanBecomeAvailable(leaf) {
			continue
		}
		_, err := (&TreeNodeUpdater{node: leaf}).SetStatus(TreeNodeStatusAvailable).Save(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// 3) Hand-rolled compare against TreeNodeStatusExited terminal constant.
func CancelGuardedByCompare(leaf *TreeNode) {
	if leaf.Status == TreeNodeStatusExited {
		return
	}
	leaf.Status = TreeNodeStatusAvailable
}
