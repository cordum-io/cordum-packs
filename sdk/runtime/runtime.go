// Package runtime re-exports core CAP runtime types and helpers so that
// integration packs import a single, stable path:
//
//	import "github.com/cordum/cordum/sdk/runtime"
//
// This indirection decouples pack code from the internal CAP SDK module
// path (github.com/cordum-io/cap/v2/sdk/go/runtime). If the CAP SDK is
// restructured or versioned independently, only this file needs updating
// — every pack that imports the alias continues to compile unchanged.
package runtime

import capruntime "github.com/cordum-io/cap/v2/sdk/go/runtime"

// Agent manages worker lifecycle: NATS subscriptions, heartbeat, and
// graceful shutdown. Create with capruntime.NewAgent, then call Start.
type Agent = capruntime.Agent

// BlobStore is the interface for persisting job context and result blobs.
type BlobStore = capruntime.BlobStore

// Context carries per-job metadata (job ID, trace ID, tenant) through
// handler invocations.
type Context = capruntime.Context

// Handler is the generic function signature that pack workers implement
// to process jobs of a specific input/output type.
type Handler[TIn any, TOut any] = capruntime.Handler[TIn, TOut]

// InMemoryBlobStore is a BlobStore backed by an in-process map, useful
// for tests and local development.
type InMemoryBlobStore = capruntime.InMemoryBlobStore

// JobOption configures per-handler behaviour (retries, timeouts, etc.).
type JobOption = capruntime.JobOption

// NATSConn wraps a NATS connection with Cordum-specific defaults.
type NATSConn = capruntime.NATSConn

// RedisBlobStore is a production BlobStore backed by Redis.
type RedisBlobStore = capruntime.RedisBlobStore

// Register wires a typed handler to a topic using the CAP runtime.
func Register[TIn any, TOut any](agent *Agent, topic string, handler Handler[TIn, TOut], opts ...JobOption) {
	capruntime.Register(agent, topic, handler, opts...)
}

// WithRetries overrides the default retry count for a handler.
func WithRetries(retries int) JobOption {
	return capruntime.WithRetries(retries)
}

// NewRedisBlobStore creates a Redis-backed blob store.
func NewRedisBlobStore(redisURL string) (*RedisBlobStore, error) {
	return capruntime.NewRedisBlobStore(redisURL)
}

// NewInMemoryBlobStore returns a new in-memory blob store.
func NewInMemoryBlobStore() *InMemoryBlobStore {
	return capruntime.NewInMemoryBlobStore()
}
