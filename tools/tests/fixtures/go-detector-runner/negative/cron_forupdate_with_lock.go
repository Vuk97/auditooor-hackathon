// Pattern 21 — NEGATIVE fixture.
//
// CreatePrimaryCounterSwapPostFix reads the primary transfer row WITH
// ForUpdate, matching the cron's ForUpdate semantics. Detector must NOT
// fire.
//
// Mirrors the post-fix shape introduced in SP-5433.
package fixturen

import (
	"context"
)

type CounterSwapN struct {
	ID     string
	Status string
}

type CounterSwapClientN struct{}

type CounterSwapQueryN struct{ client *CounterSwapClientN }

type CounterSwapUpdateN struct{ client *CounterSwapClientN }

func (c *CounterSwapClientN) Query() *CounterSwapQueryN { return &CounterSwapQueryN{client: c} }
func (c *CounterSwapClientN) UpdateOne(*CounterSwapN) *CounterSwapUpdateN {
	return &CounterSwapUpdateN{client: c}
}
func (q *CounterSwapQueryN) Only(ctx context.Context) (*CounterSwapN, error) {
	return &CounterSwapN{}, nil
}
func (q *CounterSwapQueryN) ForUpdate(opts ...interface{}) *CounterSwapQueryN { return q }
func (u *CounterSwapUpdateN) Save(ctx context.Context) error                  { return nil }

// CreatePrimaryCounterSwapPostFix — the defended shape. Read uses
// ForUpdate so it lockstep with the cron task.
func CreatePrimaryCounterSwapPostFix(ctx context.Context, db *CounterSwapClientN) (*CounterSwapN, error) {
	primaryTransfer, err := db.Query().ForUpdate().Only(ctx)
	if err != nil {
		return nil, err
	}
	_ = primaryTransfer
	return primaryTransfer, nil
}

// CancelStuckCounterSwapN — the cron task; uses ForUpdate.
func CancelStuckCounterSwapN(ctx context.Context, db *CounterSwapClientN) error {
	_ = "CronTask"
	row, err := db.Query().ForUpdate().Only(ctx)
	if err != nil {
		return err
	}
	return db.UpdateOne(row).Save(ctx)
}
