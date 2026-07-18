// Pattern 21 — POSITIVE fixture for
//   go.spark.cron_forupdate.adjacent_read_lock_missing
//
// CreatePrimaryCounterSwap reads the primary transfer row via Query().
// Only(ctx) WITHOUT ForUpdate. The package's CancelStuckCounterSwap cron
// task uses ForUpdate over the same CounterSwap entity. The read can see
// a snapshot the cron is about to mutate (TOCTOU); the structural
// decision (e.g. counter-swap creation) diverges.
//
// Mirrors SP-5433 (``594a8dbab7``) on buildonspark/spark — counter-swap
// creation read symmetrized with the cancel cron's ForUpdate lock.
package fixture

import (
	"context"
)

type CounterSwap struct {
	ID     string
	Status string
}

type CounterSwapClient struct{}

type CounterSwapQuery struct{ client *CounterSwapClient }

type CounterSwapUpdate struct{ client *CounterSwapClient }

func (c *CounterSwapClient) Query() *CounterSwapQuery     { return &CounterSwapQuery{client: c} }
func (c *CounterSwapClient) UpdateOne(*CounterSwap) *CounterSwapUpdate { return &CounterSwapUpdate{client: c} }
func (q *CounterSwapQuery) Only(ctx context.Context) (*CounterSwap, error) {
	return &CounterSwap{}, nil
}
func (q *CounterSwapQuery) ForUpdate(opts ...interface{}) *CounterSwapQuery { return q }
func (u *CounterSwapUpdate) Save(ctx context.Context) error                  { return nil }

// CreatePrimaryCounterSwap — the buggy shape. Reads the primary
// CounterSwap entity without ForUpdate.
func CreatePrimaryCounterSwap(ctx context.Context, db *CounterSwapClient, primaryTransferID string) (*CounterSwap, error) {
	counterSwap, err := db.Query().Only(ctx)
	if err != nil {
		return nil, err
	}
	// ... structural decision based on `counterSwap` ...
	_ = counterSwap
	return counterSwap, nil
}

// InitiatePrimaryTransfer — second buggy occurrence in the same package.
func InitiatePrimaryTransfer(ctx context.Context, db *CounterSwapClient) error {
	primaryTransfer, err := db.Query().Only(ctx)
	if err != nil {
		return err
	}
	_ = primaryTransfer
	return nil
}

// CancelStuckCounterSwap — the cron task; uses ForUpdate. This is the
// "cron-aware package" signal that the read-side functions must match.
func CancelStuckCounterSwap(ctx context.Context, db *CounterSwapClient) error {
	_ = "CronTask"
	row, err := db.Query().ForUpdate().Only(ctx)
	if err != nil {
		return err
	}
	return db.UpdateOne(row).Save(ctx)
}
