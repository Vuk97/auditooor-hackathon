// fixture: negative — background goroutines observe a shutdown signal.
package coordinator

import (
	"context"
	"time"
)

// poll loop selects on ctx.Done() and returns on cancellation.
func (s *Service) StartPoller(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				s.poll()
			}
		}
	}()
}

// worker loop selects on an explicit quit channel.
func (s *Service) StartWorker() {
	go func() {
		for {
			select {
			case <-s.quit:
				return
			case job := <-s.jobs:
				s.handle(job)
			}
		}
	}()
}

// no goroutine spawned at all — must NOT flag.
func (s *Service) RunOnce() {
	s.poll()
}
