// Package adaptiveadmission — bounded priority queue / scheduler
// (REQUIREMENTS.md §4.5), built on top of capacity.go's Controller.
//
// A request is enqueued with its fairness score (higher score = served
// first; arrival order breaks ties, and an optional aging rate lets a
// long-waiting lower score overtake fresher higher ones — see Ticket.key),
// in the priority tier if fairness flagged it as a priority request
// (priority_network): every priority ticket is served before every other
// ticket, and score and aging only order tickets within a tier. It then
// waits in Scheduler.Wait until it is granted, its queue_timeout
// deadline passes, its client goes away, or (with QueueConfig.EvictLowest)
// a better-placed arrival evicts it from a full queue. A single dispatch-loop
// goroutine repeatedly acquires one unit of capacity from the Controller and
// only then pops the current highest-priority ticket — never the other way
// around — so admission always reflects the queue's current priority order
// rather than a snapshot of arrival order at enqueue time. This ordering is
// only correct because cost is uniformly 1 (§4.4/§4.5): a single Acquire(1)
// always corresponds to admitting exactly one ticket, so there's no
// ambiguity about which queued ticket a given acquired unit "belongs to".
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
	// RejectEvicted means the ticket was queued, but a later arrival with a
	// better place in the queue removed it to make room (only with
	// QueueConfig.EvictLowest).
	RejectEvicted
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
	case RejectEvicted:
		return "evicted"
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
	// EvictLowest lets an arrival at a full queue take the place of the
	// ticket that would be served last, if the arrival would be served
	// before it. Off, a full queue rejects every arrival.
	EvictLowest bool
	// ProjectAhead computes the projected wait from the tickets that would
	// be served before the arrival, instead of from the whole queue depth.
	ProjectAhead bool
}

// Ticket represents one request's place in the queue. Score and Priority
// are read-only after creation; callers block on Granted() until the
// scheduler admits it.
type Ticket struct {
	Score float64
	// Priority puts the ticket in the priority tier, served before every
	// non-priority ticket.
	Priority bool

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
	evicted chan struct{} // closed, under Scheduler.mu, when evicted
}

// Granted returns a channel that's closed once this ticket has been
// admitted (i.e. the scheduler has acquired capacity on its behalf and
// popped it as the current highest-priority ticket).
func (t *Ticket) Granted() <-chan struct{} {
	return t.granted
}

// ahead reports whether t would be popped before a new ticket with the given
// priority and key: a priority ticket comes before a non-priority one, and
// within a tier the higher key comes first (on equal keys, t arrived first).
func (t *Ticket) ahead(priority bool, key float64) bool {
	if t.Priority != priority {
		return t.Priority
	}
	return t.key >= key
}

// wasEvicted reports whether t was removed from the queue by an eviction.
func (t *Ticket) wasEvicted() bool {
	select {
	case <-t.evicted:
		return true
	default:
		return false
	}
}

// ticketHeap is a container/heap.Interface ordering priority tickets first,
// then by key descending, then seq ascending (FIFO within equal keys) —
// heap.Pop always yields the current highest-priority ticket.
type ticketHeap []*Ticket

func (h ticketHeap) Len() int { return len(h) }
func (h ticketHeap) Less(i, j int) bool {
	if h[i].Priority != h[j].Priority {
		return h[i].Priority
	}
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

// last returns the ticket the heap would pop last (lowest tier, then lowest
// key, newest among equal keys); h must not be empty. Every parent comes
// before its children in Less order, so that ticket has no children: only
// the leaves, the second half of the slice, need scanning.
func (h ticketHeap) last() *Ticket {
	w := len(h) / 2
	for i := w + 1; i < len(h); i++ {
		if h.Less(w, i) {
			w = i
		}
	}
	return h[w]
}

// countAhead returns how many tickets in the subtree rooted at i would be
// popped before a new ticket with the given priority and key (see
// Ticket.ahead). A child is never ahead of its parent, so a subtree whose
// root isn't ahead is skipped whole, and the walk only visits the tickets
// ahead plus their direct children.
func (h ticketHeap) countAhead(priority bool, key float64, i int) int {
	if i >= len(h) || !h[i].ahead(priority, key) {
		return 0
	}
	return 1 + h.countAhead(priority, key, 2*i+1) + h.countAhead(priority, key, 2*i+2)
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

// Enqueue adds a ticket for score, in the priority tier if priority is set
// (see the package doc), or rejects it outright with a RejectReason if the
// queue is already at QueueConfig.MaxSize or the projected wait for a
// request joining right now already exceeds QueueConfig.WaitTimeout.
//
// With QueueConfig.EvictLowest, a full queue only rejects the arrival if it
// would not be served before the queue's last ticket; otherwise that last
// ticket is removed (its Wait returns RejectEvicted) and the arrival takes
// its place. Equal keys keep FIFO order, so an arrival never evicts a ticket
// with the same key in the same tier.
func (s *Scheduler) Enqueue(score float64, priority bool) (*Ticket, RejectReason) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := score
	if s.cfg.AgingRate > 0 {
		key -= s.cfg.AgingRate * s.now().Sub(s.epoch).Seconds()
	}

	depth := len(s.pq)
	var victim *Ticket
	if s.cfg.MaxSize > 0 && depth >= s.cfg.MaxSize {
		if !s.cfg.EvictLowest {
			return nil, RejectQueueFull
		}
		victim = s.pq.last()
		if victim.ahead(priority, key) {
			return nil, RejectQueueFull
		}
		depth--
	}
	if s.cfg.WaitTimeout > 0 {
		if projected, ok := s.projectedWaitLocked(priority, key, depth); ok && projected > s.cfg.WaitTimeout {
			return nil, RejectQueueWaitExceeded
		}
	}

	if victim != nil {
		heap.Remove(&s.pq, victim.index)
		close(victim.evicted)
	}
	s.seq++
	t := &Ticket{
		Score: score, Priority: priority, key: key, seq: s.seq,
		granted: make(chan struct{}), evicted: make(chan struct{}),
	}
	heap.Push(&s.pq, t)
	s.cond.Signal()
	return t, RejectNone
}

// Wait blocks until t is granted (RejectNone), its real wait reaches
// QueueConfig.WaitTimeout (RejectQueueTimedOut), ctx is done
// (RejectClientGone), or an arrival evicts it (RejectEvicted). Only on
// RejectNone does the caller hold the ticket's unit of capacity, and it must
// then dispatch and Release it; on any other result the ticket is gone from
// the queue and holds no capacity.
//
// The dispatch loop can pop t, or an arrival evict it, at the same moment
// the timer fires or ctx is cancelled. Cancel settles that race under s.mu:
// if it returns false, t left the queue first, either evicted (t.evicted is
// already closed, and t owns nothing) or popped (t owns one unit of
// capacity). A timed-out popped ticket is simply served (the capacity is
// free right now, so dropping it would only waste it); a popped ticket whose
// client is gone gives the unit back via ReleaseUnused instead of sending
// work to the backend for nobody. Wait must be called exactly once per
// ticket.
func (s *Scheduler) Wait(ctx context.Context, t *Ticket) RejectReason {
	var deadline <-chan time.Time
	if s.cfg.WaitTimeout > 0 {
		timer := time.NewTimer(s.cfg.WaitTimeout)
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-t.Granted():
	case <-t.evicted:
	case <-deadline:
		if s.Cancel(t) {
			return RejectQueueTimedOut
		}
	case <-ctx.Done():
		if s.Cancel(t) {
			return RejectClientGone
		}
	}
	// Evicted, possibly in the same instant the timer fired or ctx was
	// cancelled: t owns nothing, so there's nothing to release.
	if t.wasEvicted() {
		return RejectEvicted
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
// will then never be granted. It returns false if t already left the queue:
// evicted (t.evicted is closed and t owns nothing), or popped by the
// dispatch loop, in which case t owns one unit of capacity (Granted() is
// closed or about to be). Callers outside this file should use Wait, which
// handles every outcome.
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

// projectedWaitLocked estimates the wait a request with the given priority
// and key joining the queue right now would face, Little's-law style (§4.5):
// queued * mean_latency / concurrency_limit, where queued is depth, or with
// QueueConfig.ProjectAhead the tickets that would be served before it.
// ok=false when there isn't enough data yet to project anything (no
// completed requests recorded, or a zero/negative limit) — callers must not
// reject on an unknown projection, only on a computed one that actually
// exceeds the timeout.
func (s *Scheduler) projectedWaitLocked(priority bool, key float64, depth int) (projected time.Duration, ok bool) {
	limit := s.controller.Limit()
	mean := s.controller.MeanLatency()
	if limit <= 0 || mean <= 0 {
		return 0, false
	}
	if s.cfg.ProjectAhead {
		// An eviction victim is never ahead, so it's never counted here.
		depth = s.pq.countAhead(priority, key, 0)
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
