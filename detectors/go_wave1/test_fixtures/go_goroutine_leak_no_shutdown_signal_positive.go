// fixture: positive — background goroutines with no shutdown signal.
package coordinator

import "time"

// spawns a poll loop with no quit channel — never exits.
func (s *Service) StartPoller() {
	go func() {
		for {
			s.poll()
			time.Sleep(time.Second)
		}
	}()
}

// spawns a worker with for true {} and no cancellation.
func (s *Service) StartWorker() {
	go func() {
		for true {
			job := <-s.jobs
			s.handle(job)
		}
	}()
}
