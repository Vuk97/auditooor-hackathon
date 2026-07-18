// Pattern 13 — POSITIVE fixture for
//   go.spark.tree_node.terminal_state_revival
//
// Models the pre-SP-3049 shape of cancelTransferUnlockLeaves: the body
// loops over leaves and unconditionally resets each leaf's status to
// AVAILABLE — no CanBecomeAvailable() guard, no terminal-status compare,
// so a leaf already in EXITED / ON_CHAIN / SPLITTED / PARENT_EXITED /
// REIMBURSED gets revived and a sender can spend it twice. This is the
// LEAD H-D write-side mirror.
package fixturep13

import "context"

type TreeNode struct {
	Status string
}

type TreeNodeUpdater struct{ node *TreeNode }

func (u *TreeNodeUpdater) SetStatus(s string) *TreeNodeUpdater {
	u.node.Status = s
	return u
}

func (u *TreeNodeUpdater) Save(ctx context.Context) (*TreeNode, error) {
	_ = ctx
	return u.node, nil
}

type st struct{}

var (
	stTreeNodeStatusAvailable = "AVAILABLE"
)

// Mirror of the SP-3049 vulnerable shape, simplified. The body unconditionally
// calls .SetStatus(...TreeNodeStatusAvailable) inside a loop without checking
// the source state. Pattern 13 must fire here.
func CancelTransferUnlockLeavesVulnerable(ctx context.Context, leaves []*TreeNode) error {
	for _, leaf := range leaves {
		updater := &TreeNodeUpdater{node: leaf}
		_, err := updater.SetStatus(TreeNodeStatusAvailable).Save(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// Direct field-assign form of the same bug class. No CanBecomeAvailable()
// call, no compare against TreeNodeStatusExited / Splitted / etc.
func ResetLeafField(leaf *TreeNode) {
	leaf.Status = TreeNodeStatusAvailable
}

// Status-constants used by the fixture. Names match the production enum.
const (
	TreeNodeStatusAvailable    = "AVAILABLE"
	TreeNodeStatusOnChain      = "ON_CHAIN"
	TreeNodeStatusExited       = "EXITED"
	TreeNodeStatusSplitted     = "SPLITTED"
	TreeNodeStatusParentExited = "PARENT_EXITED"
	TreeNodeStatusReimbursed   = "REIMBURSED"
)
