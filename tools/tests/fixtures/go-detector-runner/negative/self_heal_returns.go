// Pattern 3 — NEGATIVE fixture.
//
// Logs the warning AND returns — the unexpected status path correctly
// short-circuits, so the self-heal detector should NOT fire.
package fixturen

type TN3 struct {
	Status string
}

type LoggerN struct{}

func (l *LoggerN) Warnf(format string, args ...interface{}) {
	_ = format
	_ = args
}

func RejectUnexpected(t *TN3, logger *LoggerN) error {
	if t.Status != "Pending" {
		logger.Warnf("unexpected status %s, rejecting", t.Status)
		return nil
	}
	t.Status = "Done"
	return nil
}
