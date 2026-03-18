// Package logging provides structured logging initialization for Cordum packs.
// It mirrors the core logging package behavior without importing cordum/core,
// avoiding circular dependencies.
//
// Usage in pack main.go:
//
//	logger := logging.Init("my-pack")
package logging

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// sensitiveKeys lists substrings that mark an attribute key as secret.
var sensitiveKeys = []string{
	"password", "passwd", "secret", "token",
	"api_key", "apikey", "credential", "auth",
}

// Init creates a RedactingHandler for the given component, sets it as
// slog.Default(), and returns the logger. It reads:
//   - CORDUM_LOG_LEVEL  (debug|info|warn|error, default info)
//   - CORDUM_LOG_FORMAT (text|json, default text)
func Init(component string) *slog.Logger {
	h := newHandler(component, os.Stderr)
	l := slog.New(h)
	slog.SetDefault(l)
	return l
}

// ---------- handler construction ----------

func newHandler(component string, w io.Writer) *redactingHandler {
	lvl := parseLevel(os.Getenv("CORDUM_LOG_LEVEL"))
	format := strings.ToLower(strings.TrimSpace(os.Getenv("CORDUM_LOG_FORMAT")))
	if format != "json" {
		format = "text"
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var inner slog.Handler
	if format == "json" {
		inner = slog.NewJSONHandler(w, opts)
	}

	return &redactingHandler{
		inner:     inner,
		level:     lvl,
		component: component,
		format:    format,
		writer:    w,
		mu:        &sync.Mutex{},
	}
}

func parseLevel(raw string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ---------- redactingHandler ----------

// redactingHandler is a slog.Handler that redacts sensitive attribute values
// and injects a component name into every record.
type redactingHandler struct {
	inner     slog.Handler // non-nil for JSON mode; nil for text mode
	level     slog.Level
	component string
	format    string
	writer    io.Writer
	preAttrs  []slog.Attr
	groups    []string
	mu        *sync.Mutex
}

func (h *redactingHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	r2 := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r2.AddAttrs(h.preAttrs...)
	r.Attrs(func(a slog.Attr) bool {
		r2.AddAttrs(redactAttr(a))
		return true
	})

	if h.format == "json" {
		return h.handleJSON(ctx, r2)
	}
	return h.handleText(r2)
}

func (h *redactingHandler) handleJSON(ctx context.Context, r slog.Record) error {
	inner := h.inner.WithAttrs([]slog.Attr{slog.String("component", h.component)})
	for _, g := range h.groups {
		inner = inner.WithGroup(g)
	}
	return inner.Handle(ctx, r)
}

func (h *redactingHandler) handleText(r slog.Record) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "[%s] %s %s",
		strings.ToUpper(h.component),
		r.Level.String(),
		r.Message,
	)

	prefix := strings.Join(h.groups, ".")
	if prefix != "" {
		prefix += "."
	}

	r.Attrs(func(a slog.Attr) bool {
		writeTextAttr(&buf, prefix, a)
		return true
	})

	buf.WriteByte('\n')

	h.mu.Lock()
	_, err := h.writer.Write(buf.Bytes())
	h.mu.Unlock()
	return err
}

func writeTextAttr(buf *bytes.Buffer, prefix string, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		gprefix := prefix
		if a.Key != "" {
			gprefix = prefix + a.Key + "."
		}
		for _, ga := range a.Value.Group() {
			writeTextAttr(buf, gprefix, ga)
		}
		return
	}
	buf.WriteByte(' ')
	buf.WriteString(prefix)
	buf.WriteString(a.Key)
	buf.WriteByte('=')
	buf.WriteString(a.Value.String())
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = redactAttr(a)
	}
	return &redactingHandler{
		inner:     h.inner,
		level:     h.level,
		component: h.component,
		format:    h.format,
		writer:    h.writer,
		preAttrs:  append(cloneAttrs(h.preAttrs), redacted...),
		groups:    cloneStrings(h.groups),
		mu:        h.mu,
	}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &redactingHandler{
		inner:     h.inner,
		level:     h.level,
		component: h.component,
		format:    h.format,
		writer:    h.writer,
		preAttrs:  cloneAttrs(h.preAttrs),
		groups:    append(cloneStrings(h.groups), name),
		mu:        h.mu,
	}
}

// ---------- redaction helpers ----------

func redactAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		redacted := make([]slog.Attr, len(attrs))
		for i, ga := range attrs {
			redacted[i] = redactAttr(ga)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(redacted...)}
	}
	if sensitiveKey(a.Key) {
		return slog.String(a.Key, "[REDACTED]")
	}
	return a
}

func sensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func cloneAttrs(a []slog.Attr) []slog.Attr {
	if a == nil {
		return nil
	}
	out := make([]slog.Attr, len(a))
	copy(out, a)
	return out
}

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}
