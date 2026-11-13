// Package adaptiveadmission — bounded priority queue / scheduler
// (REQUIREMENTS.md §4.5), built on top of capacity.go's Controller.
//
// A request is enqueued with its fairness score (higher score = served
// first; arrival order breaks ties, and an optional aging rate lets a
// long-waiting lower score overtake fresher higher ones — see Ticket.key),
// then waits in Scheduler.Wait until it is granted, its queue_timeout
// deadline passes, or its client goes away. A single dispatch-loop goroutine repeatedly acquires one unit of
// capacity from the Controller and only then pops the current highest-
// priority ticket — never the other way around — so admission always
// reflects the queue's current priority order rather than a snapshot of
// arrival order at enqueue time. This ordering is only correct because cost
// is uniformly 1 (§4.4/§4.5): a single Acquire(1) always corresponds to
// admitting exactly one ticket, so there's no ambiguity about which queued
// ticket a given acquired unit "belongs to".
//
// Accepted tradeoff: because capacity is acquired before a ticket exists to
// grant it to, the dispatch loop holds one "lookahead" reservation whenever
// it's idle and blocked in waitPopHead waiting for the next ticket. This
// makes Controller.InFlight() (and the requests_in_flight gauge built on it,
// metrics.go) read up to 1 higher than genuinely in-flight work while idle.
// It doesn't affect admission correctness — see Controller.InFlight's doc.
package adaptiveadmission

import (
	"container/heap"
	"context"
	"sync"
	"time"
)

// RejectReason distinguishes why a request was never dispatched (§4.5):
// refused at Enqueue, or withdrawn from the queue by Wait. Each is reported
// separately in logs/metrics.
type RejectReason int

const (
	RejectNone RejectReason = iota
	// RejectQueueFull means the queue already held QueueConfig.MaxSize
	// tickets.
	RejectQueueFull
	// RejectQueueWaitExceeded means the Little's-law projected wait for a
	// request joining the queue right now already exceeds
	// QueueConfig.WaitTimeout.
	RejectQueueWaitExceeded
	// RejectQueueTimedOut means the ticket was queued, but its real wait
	// reached QueueConfig.WaitTimeout before it was granted.
	RejectQueueTimedOut
	// RejectClientGone means the request's context was cancelled (the
	// client disconnected) while it was still queued.
	RejectClientGone
)

func (r RejectReason) String() string {
	switch r {
	case RejectQueueFull:
		return "queue_full"
	case RejectQueueWaitExceeded:
		return "queue_wait_exceeded"
	case RejectQueueTimedOut:
		return "queue_timed_out"
	case RejectClientGone:
		return "client_gone"
	default:
		return "none"
	}
}

// QueueConfig tunes a Scheduler's admission bounds and ordering (§4.5).
// Zero value means "unbounded"/"off" for each field: MaxSize<=0 never
// rejects on depth, WaitTimeout<=0 never rejects on projected or real wait,
// AgingRate<=0 keeps strict score order.
type QueueConfig struct {
	MaxSize     int
	WaitTimeout time.Duration
	// AgingRate is how many score points per second of waiting a queued
	// ticket gains over a ticket that just arrived. With a rate r, a ticket
	// whose score is d below a fresh one is served first once it has waited
	// d/r seconds, so a lower score is slowed down but never starved.
	AgingRate float64
}

// Ticket represents one request's place in the queue. Score is read-only
// after creation; callers block on Granted() until the scheduler admits it.
type Ticket struct {
	Score float64

	// key is the heap's priority, higher first: Score minus AgingRate times
	// the enqueue time in seconds since the Scheduler was created. Every
	// queued ticket gains AgingRate points per second at the same pace, so
	// comparing "Score + AgingRate*waited" between two tickets reduces to
	// comparing this fixed key — the heap never needs re-sorting as time
	// passes. With AgingRate 0, key is just Score.
	key     float64
	seq     uint64 // arrival order, for FIFO tie-break within equal keys
	index   int    // heap.Interface bookkeeping; -1 once popped or removed
	granted chan struct{}
}

// Granted returns a channel that's closed once this ticket has been
// admitted (i.e. the scheduler has acquired capacity on its behalf and
// popped it as the current highest-priority ticket).
func (t *Ticket) Granted() <-chan struct{} {
	return t.granted
}

// ticketHeap is a container/heap.Interface ordering by key descending, then
// seq ascending (FIFO within equal keys) — heap.Pop always yields the
// current highest-priority ticket.
type ticketHeap []*Ticket

func (h ticketHeap) Len() int { return len(h) }
func (h ticketHeap) Less(i, j int) bool {
	if h[i].key != h[j].key {
		return h[i].key > h[j].key
	}
	return h[i].seq < h[j].seq
}
func (h ticketHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *ticketHeap) Push(x any) {
	t := x.(*Ticket)
	t.index = len(*h)
	*h = append(*h, t)
}
func (h *ticketHeap) Pop() any {
	old := *h
	n := len(old)
	t := old[n-1]
	old[n-1] = nil
	t.index = -1
	*h = old[:n-1]
	return t
}

// Scheduler is a backend-scoped bounded priority queue paired with a
// Controller (§4.5). Not safe for concurrent Start()/Stop() calls, but
// Enqueue/Wait/Cancel are safe to call concurrently from many goroutines.
type Scheduler struct {
	mu   sync.Mutex
	cond *sync.Cond
	pq   ticketHeap
	seq  uint64

	// epoch and now feed Ticket.key; now is time.Now except in tests that
	// need to control enqueue times.
	epoch time.Time
	now   func() time.Time

	cfg        QueueConfig
	controller *Controller

	stopped bool
	wg      sync.WaitGroup
}

// NewScheduler builds a Scheduler over controller. Start() must be called
// before any enqueued ticket can ever be granted.
func NewScheduler(cfg QueueConfig, controller *Controller) *Scheduler {
	s := &Scheduler{cfg: cfg, controller: controller, now: time.Now}
	s.epoch = s.now()
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Start launches the single dispatch-loop goroutine.
func (s *Scheduler) Start() {
	s.wg.Add(1)
	go s.runDispatchLoop()
}

// Stop signals the dispatch loop to exit once the queue drains, and waits
// for it. Any capacity it had acquired but not yet granted to a ticket is
// released back unused. Safe to call once after Start(); not idempotent.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	s.stopped = true
	s.cond.Signal()
	s.mu.Unlock()
	s.wg.Wait()
}

// Enqueue adds a ticket for score, or rejects it outright with a
// RejectReason if the queue is already at QueueConfig.MaxSize or the
// projected wait for a request joining right now already exceeds
// QueueConfig.WaitTimeout.
func (s *Scheduler) Enqueue(score float64) (*Ticket, RejectReason) {
	s.mu.Lock()
	defer s.mu.Unlock()

	depth := len(s.pq)
	if s.cfg.MaxSize > 0 && depth >= s.cfg.MaxSize {
		return nil, RejectQueueFull
	}
	if s.cfg.WaitTimeout > 0 {
		if projected, ok := s.projectedWaitLocked(depth); ok && projected > s.cfg.WaitTimeout {
			return nil, RejectQueueWaitExceeded
		}
	}

	s.seq++
	key := score
	if s.cfg.AgingRate > 0 {
		key -= s.cfg.AgingRate * s.now().Sub(s.epoch).Seconds()
	}
	t := &Ticket{Score: score, key: key, seq: s.seq, granted: make(chan struct{})}
	heap.Push(&s.pq, t)
	s.cond.Signal()
	return t, RejectNone
}

// Wait blocks until t is granted (RejectNone), its real wait reaches
// QueueConfig.WaitTimeout (RejectQueueTimedOut), or ctx is done
// (RejectClientGone). Only on RejectNone does the caller hold the ticket's
// unit of capacity, and it must then dispatch and Release it; on any other
// result the ticket is gone from the queue and holds no capacity.
//
// The dispatch loop can pop t at the same moment the timer fires or ctx is
// cancelled. Cancel settles that race under s.mu: if the loop got there
// first, t already owns one unit of capacity. A timed-out ticket then is
// simply served (the capacity is free right now, so dropping it would only
// waste it); a ticket whose client is gone gives the unit back via
// ReleaseUnused instead of sending work to the backend for nobody. Wait must
// be called exactly once per ticket.
func (s *Scheduler) Wait(ctx context.Context, t *Ticket) RejectReason {
	var deadline <-chan time.Time
	if s.cfg.WaitTimeout > 0 {
		timer := time.NewTimer(s.cfg.WaitTimeout)
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-t.Granted():
	case <-deadline:
		if s.Cancel(t) {
			return RejectQueueTimedOut
		}
	case <-ctx.Done():
		if s.Cancel(t) {
			return RejectClientGone
		}
	}

	// Granted, possibly in the same instant ctx was cancelled (select picks
	// among ready cases at random): don't dispatch for a client that's gone.
	if ctx.Err() != nil {
		s.controller.ReleaseUnused(1)
		return RejectClientGone
	}
	return RejectNone
}

// Cancel removes t from the queue if it's still there, returning true; t
// will then never be granted. It returns false if the dispatch loop has
// already popped t, in which case t owns one unit of capacity (Granted() is
// closed or about to be). Callers outside this file should use Wait, which
// handles both outcomes.
func (s *Scheduler) Cancel(t *Ticket) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.index < 0 {
		return false
	}
	heap.Remove(&s.pq, t.index)
	return true
}

// Depth returns the number of tickets currently queued (not yet granted) —
// used to drive the queue_size gauge (§4.8). Safe to call concurrently with
// Enqueue/the dispatch loop.
func (s *Scheduler) Depth() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pq)
}

// projectedWaitLocked estimates the wait a request joining the queue right
// now (at the given current depth) would face, Little's-law style (§4.5):
// queue_depth * mean_latency / concurrency_limit. ok=false when there isn't
// enough data yet to project anything (no completed requests recorded, or a
// zero/negative limit) — callers must not reject on an unknown projection,
// only on a computed one that actually exceeds the timeout.
func (s *Scheduler) projectedWaitLocked(depth int) (projected time.Duration, ok bool) {
	limit := s.controller.Limit()
	mean := s.controller.MeanLatency()
	if limit <= 0 || mean <= 0 {
		return 0, false
	}
	return time.Duration(float64(depth) * float64(mean) / float64(limit)), true
}

// runDispatchLoop is the single "worker" the spec describes: acquire
// capacity, then pop the queue head — always in that order, never the
// reverse, so a ticket is only ever chosen once capacity is actually free
// and the queue's priority order is current.
func (s *Scheduler) runDispatchLoop() {
	defer s.wg.Done()
	for {
		s.controller.Acquire(1)
		t, ok := s.waitPopHead()
		if !ok {
			s.controller.ReleaseUnused(1)
			return
		}
		close(t.granted)
	}
}

// waitPopHead blocks until either a ticket is available (returning it) or
// the scheduler has been stopped and the queue is empty (ok=false). A
// pending Stop() with tickets still queued drains them first.
func (s *Scheduler) waitPopHead() (*Ticket, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.pq) == 0 && !s.stopped {
		s.cond.Wait()
	}
	if len(s.pq) == 0 {
		return nil, false
	}
	return heap.Pop(&s.pq).(*Ticket), true
}
