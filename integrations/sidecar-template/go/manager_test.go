package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSidecarManagerStartStop(t *testing.T) {
	t.Helper()

	manager := newTestManager(t, map[string]string{
		"SIDECAR_HELPER_CALLBACK_ECHO": "1",
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := manager.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer func() {
		if err := manager.Stop(); err != nil {
			t.Fatalf("stop failed: %v", err)
		}
	}()

	if manager.Port() == 0 {
		t.Fatalf("expected allocated port")
	}
	if !manager.IsHealthy() {
		t.Fatalf("expected manager to become healthy")
	}

	health := readHealth(t, manager.Port())
	if got := health["callback_url"]; got != "http://127.0.0.1:9090/tool-call" {
		t.Fatalf("expected callback URL to be injected, got %v", got)
	}

	if err := manager.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	if manager.IsHealthy() {
		t.Fatalf("expected manager to be unhealthy after stop")
	}
}

func TestSidecarManagerRestartsAfterCrash(t *testing.T) {
	t.Helper()

	startLog := filepath.Join(t.TempDir(), "starts.log")
	crashMarker := filepath.Join(t.TempDir(), "crash.once")
	var launches atomic.Int32

	manager := newTestManager(t, map[string]string{
		"SIDECAR_HELPER_START_LOG":    startLog,
		"SIDECAR_HELPER_CRASH_AFTER":  "150ms",
		"SIDECAR_HELPER_CRASH_MARKER": crashMarker,
	}, &launches)
	manager.restartBackoff = 100 * time.Millisecond
	manager.maxRestartBackoff = 250 * time.Millisecond
	manager.healthCheckTimeout = 5 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := manager.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer func() {
		if err := manager.Stop(); err != nil {
			t.Fatalf("stop failed: %v", err)
		}
	}()

	if err := waitFor(t, 6*time.Second, func() error {
		data, err := os.ReadFile(startLog)
		if err != nil {
			return err
		}
		lines := strings.Fields(strings.TrimSpace(string(data)))
		if len(lines) < 2 {
			return fmt.Errorf("expected at least two launches, got %d", len(lines))
		}
		if !manager.IsHealthy() {
			return fmt.Errorf("manager not healthy after restart")
		}
		return nil
	}); err != nil {
		t.Fatalf("restart check failed: %v", err)
	}

	if launches.Load() < 2 {
		t.Fatalf("expected command factory to launch at least twice, got %d", launches.Load())
	}
}

func TestSidecarManagerContextCancellationStopsProcess(t *testing.T) {
	t.Helper()

	manager := newTestManager(t, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	cancel()

	if err := waitFor(t, 5*time.Second, func() error {
		if manager.IsHealthy() {
			return fmt.Errorf("manager still healthy")
		}
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", manager.Port())) // #nosec G107 -- localhost test helper endpoint.
		if err == nil {
			_ = resp.Body.Close()
			return fmt.Errorf("health endpoint still reachable")
		}
		return nil
	}); err != nil {
		t.Fatalf("context cancellation did not stop process: %v", err)
	}
}

func TestSidecarManagerUsesConfiguredPort(t *testing.T) {
	t.Helper()

	manager := newTestManager(t, nil, nil)
	manager.port = 46231

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := manager.Start(ctx); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer func() {
		if err := manager.Stop(); err != nil {
			t.Fatalf("stop failed: %v", err)
		}
	}()

	if got := manager.Port(); got != 46231 {
		t.Fatalf("expected configured port 46231, got %d", got)
	}
}

func TestSidecarHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SIDECAR_HELPER") != "1" {
		return
	}

	port := helperPort(os.Args)
	startLog := strings.TrimSpace(os.Getenv("SIDECAR_HELPER_START_LOG"))
	if startLog != "" {
		f, err := os.OpenFile(filepath.Clean(startLog), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintln(f, time.Now().UnixNano())
			_ = f.Close()
		}
	}

	crashAfter := strings.TrimSpace(os.Getenv("SIDECAR_HELPER_CRASH_AFTER"))
	crashMarker := strings.TrimSpace(os.Getenv("SIDECAR_HELPER_CRASH_MARKER"))
	if crashAfter != "" && shouldCrash(crashMarker) {
		if duration, err := time.ParseDuration(crashAfter); err == nil {
			time.AfterFunc(duration, func() {
				os.Exit(1)
			})
		}
	}

	server := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", port),
		ReadHeaderTimeout: 2 * time.Second,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "ok",
			"callback_url": os.Getenv("CORDUM_CALLBACK_URL"),
			"port":         port,
		})
	})
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "shutting_down"})
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
			os.Exit(0)
		}()
	})
	server.Handler = mux

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "helper server failed: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func newTestManager(t *testing.T, extraEnv map[string]string, launches *atomic.Int32) *SidecarManager {
	t.Helper()

	cfg := ManagerConfig{
		Command:             os.Args[0],
		CallbackURL:         "http://127.0.0.1:9090/tool-call",
		Env:                 extraEnv,
		HealthCheckInterval: 100 * time.Millisecond,
		HealthCheckTimeout:  5 * time.Second,
		ShutdownTimeout:     2 * time.Second,
		RestartBackoff:      100 * time.Millisecond,
		MaxRestartBackoff:   500 * time.Millisecond,
		CommandFactory: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			if launches != nil {
				launches.Add(1)
			}
			helperArgs := []string{"-test.run=TestSidecarHelperProcess", "--"}
			helperArgs = append(helperArgs, args...)

			cmd := exec.CommandContext(ctx, name, helperArgs...)
			cmd.Env = append(os.Environ(), "GO_WANT_SIDECAR_HELPER=1")
			for key, value := range extraEnv {
				cmd.Env = append(cmd.Env, key+"="+value)
			}
			return cmd
		},
	}

	manager, err := NewSidecarManager(cfg)
	if err != nil {
		t.Fatalf("new manager failed: %v", err)
	}
	return manager
}

func readHealth(t *testing.T, port int) map[string]any {
	t.Helper()

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port)) // #nosec G107 -- localhost test helper endpoint.
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer resp.Body.Close()

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode health payload failed: %v", err)
	}
	return payload
}

func waitFor(t *testing.T, timeout time.Duration, fn func() error) error {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("condition not met before timeout")
	}
	return lastErr
}

func helperPort(args []string) int {
	for index := 0; index < len(args)-1; index++ {
		if args[index] == "--port" {
			if port, err := strconv.Atoi(args[index+1]); err == nil {
				return port
			}
		}
	}
	fmt.Fprintln(os.Stderr, "missing --port")
	os.Exit(2)
	return 0
}

func shouldCrash(marker string) bool {
	if strings.TrimSpace(marker) == "" {
		return true
	}
	f, err := os.OpenFile(filepath.Clean(marker), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
