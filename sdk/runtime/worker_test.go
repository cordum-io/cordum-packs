package runtime

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/nats-io/nats.go"
)

// newTestWorker builds a Worker directly; the dispatch paths under test never
// touch w.conn, so no NATS connection is needed.
func newTestWorker(semCapacity int) *Worker {
	w := &Worker{
		logger:   slog.Default(),
		workerID: "test-worker",
	}
	if semCapacity > 0 {
		w.sem = make(chan struct{}, semCapacity)
	}
	return w
}

// waitFor polls cond with a deadline instead of asserting after a bare sleep.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestDispatch_SemaphoreWaitHonorsContext(t *testing.T) {
	w := newTestWorker(1)
	w.sem <- struct{}{} // occupy the only slot so dispatch must wait

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var handlerCalls int32
	handler := func(context.Context, *agentv1.JobRequest) (*agentv1.JobResult, error) {
		atomic.AddInt32(&handlerCalls, 1)
		return nil, nil
	}

	done := make(chan struct{})
	go func() {
		w.dispatch(ctx, &nats.Msg{}, handler)
		close(done)
	}()

	// Scheduling aid (not an assertion): let dispatch pass its entry check and
	// reach the semaphore acquire before we cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// dispatch returned promptly after cancellation
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch blocked on the concurrency semaphore after ctx cancellation")
	}

	if got := atomic.LoadInt32(&handlerCalls); got != 0 {
		t.Fatalf("handler invoked %d times for a canceled dispatch, want 0", got)
	}
	if got := atomic.LoadInt32(&w.active); got != 0 {
		t.Fatalf("active counter = %d after canceled dispatch, want 0", got)
	}
	if got := len(w.sem); got != 1 {
		t.Fatalf("semaphore length = %d, want 1 (only the test's own fill)", got)
	}
}

func TestDispatch_SlotReleasedOnDecodeError(t *testing.T) {
	w := newTestWorker(1)

	var handlerCalls int32
	handler := func(context.Context, *agentv1.JobRequest) (*agentv1.JobResult, error) {
		atomic.AddInt32(&handlerCalls, 1)
		return nil, nil
	}

	// 0xFF is field 31 with invalid wire type 7 — proto.Unmarshal must fail.
	w.dispatch(context.Background(), &nats.Msg{Data: []byte{0xFF, 0xFF, 0xFF}}, handler)

	waitFor(t, 2*time.Second, func() bool {
		return len(w.sem) == 0 && atomic.LoadInt32(&w.active) == 0
	}, "slot not released after decode error: semaphore or active counter never returned to 0")

	if got := atomic.LoadInt32(&handlerCalls); got != 0 {
		t.Fatalf("handler invoked %d times for an undecodable packet, want 0", got)
	}
}

func TestDispatch_EntryCancelSkips(t *testing.T) {
	w := newTestWorker(1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var handlerCalls int32
	handler := func(context.Context, *agentv1.JobRequest) (*agentv1.JobResult, error) {
		atomic.AddInt32(&handlerCalls, 1)
		return nil, nil
	}

	w.dispatch(ctx, &nats.Msg{}, handler)

	if got := len(w.sem); got != 0 {
		t.Fatalf("semaphore length = %d after entry-cancel, want 0 (no slot consumed)", got)
	}
	if got := atomic.LoadInt32(&w.active); got != 0 {
		t.Fatalf("active counter = %d after entry-cancel, want 0", got)
	}
	if got := atomic.LoadInt32(&handlerCalls); got != 0 {
		t.Fatalf("handler invoked %d times for an already-canceled ctx, want 0", got)
	}
}
