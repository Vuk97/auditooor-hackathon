// Pattern 3 — POSITIVE fixture for
//   go.statemachine.self_heal_on_unexpected_status
//
// Compares Status with !=, logs Warnf, but does NOT return / panic /
// continue / break — the unexpected status is silently swallowed.
package fixture

type T3 struct {
	Status string
}

type Logger struct{}

func (l *Logger) Warnf(format string, args ...interface{}) {
	_ = format
	_ = args
}

func HealUnexpected(t *T3, logger *Logger) {
	if t.Status != "Pending" {
		logger.Warnf("unexpected status %s, healing", t.Status)
		// no return — pattern fires
	}
	t.Status = "Healed"
}
