// Faithful synthetic Go fixture for G13
// (go.consensus.ctx_cancellation_ignored_verdict). Models the SEI memiavl
// snapshot writer idiom: a state-commitment writer whose async pipeline sends
// write-ops down channels and MUST honour ctx cancellation at each blocking
// send so an aborted snapshot never commits leaves on stale state.
package consensus

import "context"

type writeOp struct {
	key   []byte
	value []byte
}

type snapshotWriter struct {
	ctx         context.Context
	cancel      context.CancelFunc
	kvChan      chan writeOp
	leafChan    chan writeOp
	writeErrors chan error
}

// CLEAN: the blocking send is guarded by a ctx.Done() escape arm. When the
// caller cancels, the writer returns ctx.Err() instead of committing a leaf
// for an abandoned snapshot. This must NOT fire.
func (w *snapshotWriter) writeLeafClean(op writeOp) error {
	select {
	case w.kvChan <- op:
	case <-w.ctx.Done():
		return w.ctx.Err()
	}
	return nil
}

// VULN: the finalizing send trusts the caller's cancellation to abort but the
// select has NO ctx.Done() arm. On a cancelled ctx it either blocks or (once a
// buffered consumer drains) commits a leaf for an aborted snapshot -> a
// trusted-but-invalid state-commitment verdict. This MUST fire.
func (w *snapshotWriter) writeLeafVuln(op writeOp) error {
	select {
	case w.leafChan <- op:
		return nil
	}
}

// DEFENDED by default: a non-blocking best-effort error send. The default arm
// means it can never hang on a cancelled ctx, so it is not a blocking-verdict
// commit. This must NOT fire.
func (w *snapshotWriter) fail(err error) {
	select {
	case w.writeErrors <- err:
	default:
	}
	w.cancel()
}

// DEFENDED: a pure receive-multiplex (no finalizing send) is not a verdict
// commit. This must NOT fire.
func (w *snapshotWriter) waitForWrites() error {
	select {
	case err := <-w.writeErrors:
		return err
	case <-w.ctx.Done():
		return w.ctx.Err()
	}
}
