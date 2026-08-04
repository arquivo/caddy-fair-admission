// Package adaptiveadmission — bounded priority queue / scheduler
// (REQUIREMENTS.md §4.5), built on top of capacity.go's Controller.
//
// A request is enqueued with its fairness score (higher score = served
// first; arrival order breaks ties), then blocks on its Ticket's Granted()
// channel. A single dispatch-loop goroutine repeatedly acquires one unit of
// capacity from the Controller and only then pops the current highest-
// priority ticket — never the other way around — so admission always
// reflects the queue's current priority order rather than a snapshot of
// arrival order at enqueue time. This ordering is only correct because cost
// is uniformly 1 (§4.4/§4.5): a single Acquire(1) always corresponds to
// admitting exactly one ticket, so there's no ambiguity about which queued
// ticket a given acquired unit "belongs to".
package adaptiveadmission

import (
	"container/heap"
	"sync"
	"time"
)

// RejectReason distinguishes why Enqueue refused a request (§4.5) — both
// map to an HTTP 429 at the caller, but are reported separately in
// logs/metrics.
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
)

func (r RejectReason) String() string {
	switch r {
	case RejectQueueFull:
		return "queue_full"
	case RejectQueueWaitExceeded:
		return "queue_wait_exceeded"
	default:
		return "none"
	}
}

// QueueConfig tunes a Scheduler's admission bounds (§4.5). Zero value means
// "unbounded" for either field: MaxSize<=0 never rejects on depth,
// WaitTimeout<=0 never rejects on projected wait.
type QueueConfig struct {
	MaxSize     int
	WaitTimeout time.Duration
}

// Ticket represents one request's place in the queue. Score is read-only
// after creation; callers block on Granted() until the scheduler admits it.
type Ticket struct {
	Score float64

	seq     uint64 // arrival order, for FIFO tie-break within equal scores
	index   int    // heap.Interface bookkeeping
	granted chan struct{}
}

// Granted returns a channel that's closed once this ticket has been
// admitted (i.e. the scheduler has acquired capacity on its behalf and
// popped it as the current highest-priority ticket).
func (t *Ticket) Granted() <-chan struct{} {
	return t.granted
}

// ticketHeap is a container/heap.Interface ordering by score descending,
// then seq ascending (FIFO within equal scores) — heap.Pop always yields the
// current highest-priority ticket.
type ticketHeap []*Ticket

func (h ticketHeap) Len() int { return len(h) }
func (h ticketHeap) Less(i, j int) bool {
	if h[i].Score != h[j].Score {
		return h[i].Score > h[j].Score
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
// Enqueue is safe to call concurrently from many goroutines.
type Scheduler struct {
	mu   sync.Mutex
	cond *sync.Cond
	pq   ticketHeap
	seq  uint64

	cfg        QueueConfig
	controller *Controller

	stopped bool
	wg      sync.WaitGroup
}

// NewScheduler builds a Scheduler over controller. Start() must be called
// before any enqueued ticket can ever be granted.
func NewScheduler(cfg QueueConfig, controller *Controller) *Scheduler {
	s := &Scheduler{cfg: cfg, controller: controller}
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
	t := &Ticket{Score: score, seq: s.seq, granted: make(chan struct{})}
	heap.Push(&s.pq, t)
	s.cond.Signal()
	return t, RejectNone
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
