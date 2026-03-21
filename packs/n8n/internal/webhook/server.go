package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cordum-io/cordum-packs/packs/n8n/internal/config"
)

const maxWebhookBodyBytes int64 = 1 << 20

// RunStarter triggers a Cordum workflow run from the webhook server.
type RunStarter interface {
	StartRun(ctx context.Context, workflowID string, payload any, idempotencyKey string) (string, error)
}

// Server receives n8n webhook callbacks and forwards them to Cordum workflows.
type Server struct {
	cfg     config.Config
	starter RunStarter
}

// New creates a webhook bridge server.
func New(cfg config.Config, starter RunStarter) *Server {
	return &Server{cfg: cfg, starter: starter}
}

// Handler returns the HTTP handler for the webhook bridge.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	for webhookPath, workflowID := range s.cfg.WebhookWorkflowMap {
		webhookPath := webhookPath
		workflowID := workflowID
		mux.HandleFunc(webhookPath, s.handleWebhook(webhookPath, workflowID))
	}
	return mux
}

// ListenAndServe starts the HTTP server and shuts it down when ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              s.cfg.WebhookListen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	err := httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) handleWebhook(webhookPath, workflowID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if strings.TrimSpace(workflowID) == "" {
			http.Error(w, "workflow mapping missing", http.StatusInternalServerError)
			return
		}
		if s.starter == nil {
			http.Error(w, "workflow starter unavailable", http.StatusServiceUnavailable)
			return
		}

		reader := http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes)
		defer reader.Close()
		body, err := io.ReadAll(reader)
		if err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if s.cfg.WebhookSecret != "" {
			if err := VerifySignature(s.cfg.WebhookSecret, body, r.Header.Get(SignatureHeader)); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		}

		payload := buildWebhookPayload(webhookPath, r, body)
		idempotencyKey := firstNonEmpty(
			strings.TrimSpace(r.Header.Get("Idempotency-Key")),
			stringField(payload["execution_id"]),
		)

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		runID, err := s.starter.StartRun(ctx, workflowID, payload, idempotencyKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("gateway start run: %v", err), http.StatusBadGateway)
			return
		}

		writeJSON(w, http.StatusAccepted, map[string]any{
			"ok":           true,
			"run_id":       runID,
			"workflow_id":  payload["workflow_id"],
			"execution_id": payload["execution_id"],
		})
	}
}

func buildWebhookPayload(webhookPath string, r *http.Request, body []byte) map[string]any {
	decoded := parseBody(body)
	workflowID := firstNonEmpty(
		lookupString(decoded, "workflow_id"),
		lookupString(decoded, "workflowId"),
		strings.TrimSpace(r.URL.Query().Get("workflow_id")),
		webhookPath,
	)
	executionID := firstNonEmpty(
		lookupString(decoded, "execution_id"),
		lookupString(decoded, "executionId"),
		strings.TrimSpace(r.URL.Query().Get("execution_id")),
		strings.TrimSpace(r.Header.Get("X-N8N-Execution-Id")),
	)

	payload := map[string]any{
		"source":       "n8n",
		"workflow_id":  workflowID,
		"received_at":  time.Now().UTC().Format(time.RFC3339),
		"data":         decoded,
		"headers":      flattenHeaders(r.Header),
		"webhook_path": webhookPath,
	}
	if executionID != "" {
		payload["execution_id"] = executionID
	}
	return payload
}

func parseBody(body []byte) any {
	if len(body) == 0 {
		return map[string]any{}
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err == nil {
		return decoded
	}
	return strings.TrimSpace(string(body))
}

func flattenHeaders(headers http.Header) map[string]string {
	out := map[string]string{}
	for key, values := range headers {
		if len(values) > 0 {
			out[key] = strings.Join(values, ",")
		}
	}
	return out
}

func lookupString(value any, key string) string {
	mapped, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	return stringField(mapped[key])
}

func stringField(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
