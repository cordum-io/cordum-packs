package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultHealthCheckInterval = 500 * time.Millisecond
	defaultHealthCheckTimeout  = 30 * time.Second
	defaultShutdownTimeout     = 10 * time.Second
	defaultRestartBackoff      = 2 * time.Second
	defaultMaxRestartBackoff   = 30 * time.Second
)

// CommandFactory allows tests to replace subprocess creation.
type CommandFactory func(ctx context.Context, name string, args ...string) *exec.Cmd

// ManagerConfig controls subprocess lifecycle behavior.
type ManagerConfig struct {
	Command             string
	Args                []string
	Port                int
	CallbackURL         string
	Env                 map[string]string
	HTTPClient          *http.Client
	Logger              *slog.Logger
	HealthCheckInterval time.Duration
	HealthCheckTimeout  time.Duration
	ShutdownTimeout     time.Duration
	RestartBackoff      time.Duration
	MaxRestartBackoff   time.Duration
	CommandFactory      CommandFactory
	PortFinder          func() (int, error)
}

// SidecarManager supervises a Python sidecar subprocess.
// The template is intended to be copied into framework packs and customized.
type SidecarManager struct {
	cmd       string
	args      []string
	port      int
	process   *exec.Cmd
	healthURL string

	callbackURL string
	env         map[string]string
	httpClient  *http.Client
	logger      *slog.Logger

	healthCheckInterval time.Duration
	healthCheckTimeout  time.Duration
	shutdownTimeout     time.Duration
	restartBackoff      time.Duration
	maxRestartBackoff   time.Duration

	commandFactory CommandFactory
	portFinder     func() (int, error)

	mu               sync.RWMutex
	exitCh           chan error
	runCtx           context.Context
	runCancel        context.CancelFunc
	stopping         bool
	restartScheduled atomic.Bool
	healthy          atomic.Bool
}

// NewSidecarManager creates a manager with production-safe defaults.
func NewSidecarManager(cfg ManagerConfig) (*SidecarManager, error) {
	command := strings.TrimSpace(cfg.Command)
	if command == "" {
		return nil, fmt.Errorf("command is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	commandFactory := cfg.CommandFactory
	if commandFactory == nil {
		commandFactory = exec.CommandContext
	}

	portFinder := cfg.PortFinder
	if portFinder == nil {
		portFinder = findFreePort
	}

	manager := &SidecarManager{
		cmd:                 command,
		args:                append([]string(nil), cfg.Args...),
		port:                cfg.Port,
		callbackURL:         strings.TrimSpace(cfg.CallbackURL),
		env:                 copyEnv(cfg.Env),
		httpClient:          httpClient,
		logger:              logger,
		healthCheckInterval: durationOrDefault(cfg.HealthCheckInterval, defaultHealthCheckInterval),
		healthCheckTimeout:  durationOrDefault(cfg.HealthCheckTimeout, defaultHealthCheckTimeout),
		shutdownTimeout:     durationOrDefault(cfg.ShutdownTimeout, defaultShutdownTimeout),
		restartBackoff:      durationOrDefault(cfg.RestartBackoff, defaultRestartBackoff),
		maxRestartBackoff:   durationOrDefault(cfg.MaxRestartBackoff, defaultMaxRestartBackoff),
		commandFactory:      commandFactory,
		portFinder:          portFinder,
	}

	return manager, nil
}

// Start launches the sidecar, waits for /health, and arranges cleanup on ctx cancellation.
func (m *SidecarManager) Start(ctx context.Context) error {
	m.mu.RLock()
	if m.process != nil && m.runCtx != nil && m.runCtx.Err() == nil {
		m.mu.RUnlock()
		return nil
	}
	m.mu.RUnlock()

	runCtx, runCancel := context.WithCancel(context.Background())

	m.mu.Lock()
	if m.process != nil && m.runCtx != nil && m.runCtx.Err() == nil {
		m.mu.Unlock()
		runCancel()
		return nil
	}
	m.runCtx = runCtx
	m.runCancel = runCancel
	m.stopping = false
	m.mu.Unlock()

	go func() {
		select {
		case <-ctx.Done():
			if err := m.Stop(); err != nil && !errors.Is(err, context.Canceled) {
				m.logger.Warn("sidecar stop on context cancellation failed", "error", err)
			}
		case <-runCtx.Done():
		}
	}()

	if err := m.startProcess(); err != nil {
		runCancel()
		m.mu.Lock()
		if m.runCtx == runCtx {
			m.runCtx = nil
			m.runCancel = nil
		}
		m.mu.Unlock()
		return err
	}

	if err := m.waitForHealth(ctx); err != nil {
		_ = m.Stop()
		return err
	}

	m.healthy.Store(true)
	return nil
}

// Stop gracefully shuts down the subprocess and prevents automatic restarts.
func (m *SidecarManager) Stop() error {
	m.mu.Lock()
	runCancel := m.runCancel
	cmd := m.process
	exitCh := m.exitCh
	healthURL := m.healthURL
	if runCancel == nil && cmd == nil {
		m.mu.Unlock()
		return nil
	}
	m.stopping = true
	m.mu.Unlock()

	if strings.TrimSpace(healthURL) != "" {
		m.requestShutdown(healthURL)
	}

	waitErr := m.waitForExit(exitCh, m.shutdownTimeout)
	if waitErr != nil && cmd != nil && cmd.Process != nil {
		if err := signalTerminate(cmd.Process); err != nil {
			m.logger.Debug("sidecar terminate signal failed", "error", err)
		}
		waitErr = m.waitForExit(exitCh, m.shutdownTimeout)
	}
	if waitErr != nil && cmd != nil && cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			m.logger.Warn("sidecar kill failed", "error", err)
		}
		waitErr = m.waitForExit(exitCh, m.shutdownTimeout)
	}

	if runCancel != nil {
		runCancel()
	}

	m.healthy.Store(false)
	m.mu.Lock()
	m.process = nil
	m.exitCh = nil
	m.healthURL = ""
	m.runCtx = nil
	m.runCancel = nil
	m.stopping = false
	m.mu.Unlock()

	if waitErr != nil && !errors.Is(waitErr, os.ErrProcessDone) && !errors.Is(waitErr, context.Canceled) {
		return waitErr
	}
	return nil
}

// Restart forces a stop then launches the sidecar again.
func (m *SidecarManager) Restart(ctx context.Context) error {
	if err := m.Stop(); err != nil {
		return err
	}
	return m.Start(ctx)
}

// IsHealthy returns the last observed health state.
func (m *SidecarManager) IsHealthy() bool {
	return m.healthy.Load()
}

// Port returns the currently assigned sidecar port.
func (m *SidecarManager) Port() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.port
}

func (m *SidecarManager) startProcess() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.runCtx == nil {
		return fmt.Errorf("manager has no run context")
	}
	if m.process != nil {
		return nil
	}
	if m.port == 0 {
		port, err := m.portFinder()
		if err != nil {
			return fmt.Errorf("allocate port: %w", err)
		}
		m.port = port
	}

	args := append([]string(nil), m.args...)
	args = append(args, "--port", strconv.Itoa(m.port))

	cmd := m.commandFactory(m.runCtx, m.cmd, args...)
	baseEnv := os.Environ()
	if len(cmd.Env) > 0 {
		baseEnv = cmd.Env
	}
	cmd.Env = mergeEnv(baseEnv, m.env, map[string]string{
		"CORDUM_CALLBACK_URL": m.callbackURL,
		"CORDUM_SIDECAR_PORT": strconv.Itoa(m.port),
	})
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sidecar: %w", err)
	}

	m.process = cmd
	m.healthURL = fmt.Sprintf("http://127.0.0.1:%d/health", m.port)
	m.exitCh = make(chan error, 1)

	go m.watchProcess(cmd, m.exitCh)
	return nil
}

func (m *SidecarManager) watchProcess(cmd *exec.Cmd, exitCh chan error) {
	err := cmd.Wait()
	select {
	case exitCh <- err:
	default:
	}

	m.healthy.Store(false)

	m.mu.Lock()
	current := m.process == cmd
	runCtx := m.runCtx
	shouldRestart := current && !m.stopping && runCtx != nil && runCtx.Err() == nil
	if current {
		m.process = nil
		m.exitCh = nil
		m.healthURL = ""
	}
	m.mu.Unlock()

	if shouldRestart {
		m.scheduleRestart()
	}
}

func (m *SidecarManager) scheduleRestart() {
	if !m.restartScheduled.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer m.restartScheduled.Store(false)

		backoff := m.restartBackoff
		for {
			m.mu.RLock()
			runCtx := m.runCtx
			stopping := m.stopping
			m.mu.RUnlock()

			if stopping || runCtx == nil || runCtx.Err() != nil {
				return
			}

			timer := time.NewTimer(backoff)
			select {
			case <-runCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			if err := m.startProcess(); err != nil {
				m.logger.Warn("sidecar restart failed", "error", err, "backoff", backoff)
				backoff = minDuration(backoff*2, m.maxRestartBackoff)
				continue
			}

			if err := m.waitForHealth(runCtx); err != nil {
				m.logger.Warn("sidecar health check failed after restart", "error", err)
				_ = m.stopCurrentProcess()
				backoff = minDuration(backoff*2, m.maxRestartBackoff)
				continue
			}

			m.healthy.Store(true)
			m.logger.Info("sidecar restarted", "port", m.Port())
			return
		}
	}()
}

func (m *SidecarManager) waitForHealth(ctx context.Context) error {
	healthCtx, cancel := context.WithTimeout(ctx, m.healthCheckTimeout)
	defer cancel()

	ticker := time.NewTicker(m.healthCheckInterval)
	defer ticker.Stop()

	for {
		if err := m.checkHealth(healthCtx); err == nil {
			return nil
		}

		select {
		case <-healthCtx.Done():
			return fmt.Errorf("sidecar health check timed out after %s", m.healthCheckTimeout)
		case <-ticker.C:
		}
	}
}

func (m *SidecarManager) checkHealth(ctx context.Context) error {
	m.mu.RLock()
	healthURL := m.healthURL
	m.mu.RUnlock()
	if strings.TrimSpace(healthURL) == "" {
		return fmt.Errorf("health url unavailable")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return err
	}

	resp, err := m.httpClient.Do(req) // #nosec G107 -- URL is manager-controlled localhost health probe.
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected health status %d", resp.StatusCode)
	}
	return nil
}

func (m *SidecarManager) requestShutdown(healthURL string) {
	shutdownURL := strings.TrimSuffix(healthURL, "/health") + "/shutdown"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, shutdownURL, nil)
	if err != nil {
		return
	}
	resp, err := m.httpClient.Do(req) // #nosec G107 -- URL is manager-controlled localhost shutdown endpoint.
	if err != nil {
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}

func (m *SidecarManager) stopCurrentProcess() error {
	m.mu.RLock()
	cmd := m.process
	exitCh := m.exitCh
	healthURL := m.healthURL
	m.mu.RUnlock()

	if cmd == nil {
		return nil
	}

	if strings.TrimSpace(healthURL) != "" {
		m.requestShutdown(healthURL)
	}
	if err := m.waitForExit(exitCh, 2*time.Second); err == nil {
		return nil
	}
	if cmd.Process != nil {
		if err := signalTerminate(cmd.Process); err != nil {
			m.logger.Debug("terminate during restart cleanup failed", "error", err)
		}
		if err := m.waitForExit(exitCh, 2*time.Second); err == nil {
			return nil
		}
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
	}
	return m.waitForExit(exitCh, 2*time.Second)
}

func (m *SidecarManager) waitForExit(exitCh chan error, timeout time.Duration) error {
	if exitCh == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = defaultShutdownTimeout
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-exitCh:
		return err
	case <-timer.C:
		return fmt.Errorf("timed out waiting for sidecar exit")
	}
}

func signalTerminate(proc *os.Process) error {
	if proc == nil {
		return nil
	}
	switch runtime.GOOS {
	case "windows":
		if err := proc.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
	default:
		if err := proc.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
	}
	return nil
}

func findFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected listener address %T", listener.Addr())
	}
	return addr.Port, nil
}

func mergeEnv(base []string, current map[string]string, overrides map[string]string) []string {
	values := map[string]string{}
	for _, item := range base {
		key, value, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		values[key] = value
	}
	for key, value := range current {
		if strings.TrimSpace(key) == "" {
			continue
		}
		values[key] = value
	}
	for key, value := range overrides {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		values[key] = value
	}

	env := make([]string, 0, len(values))
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}

func copyEnv(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for key, value := range src {
		if strings.TrimSpace(key) == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func durationOrDefault(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
