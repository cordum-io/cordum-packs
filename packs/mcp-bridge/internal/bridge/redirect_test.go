package bridge

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// handshakeOnlyNATS supports the connection handshake used by New. These tests
// exercise gateway HTTP routing; no jobs are published to this listener.
func handshakeOnlyNATS(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(conn, "INFO {\"server_id\":\"test\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}\r\n")
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "PING" {
				_, _ = fmt.Fprint(conn, "PONG\r\n")
			}
		}
	}()
	return "nats://" + listener.Addr().String()
}

func TestUnsignedGatewayRejectsRedirectWithoutForwardingCredentials(t *testing.T) {
	testGatewayRedirect(t, true)
}

func TestDefaultGatewayPreservesRedirectBehavior(t *testing.T) {
	testGatewayRedirect(t, false)
}

func testGatewayRedirect(t *testing.T, allowUnsigned bool) {
	t.Helper()
	t.Setenv("CORDUM_ENV", "development")
	t.Setenv("CORDUM_CAP_PROFILE", "compat")
	t.Setenv("CORDUM_PRODUCTION", "")
	var targetCalls atomic.Int32
	var credentialSeen atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		credentialSeen.Store(r.Header.Get("X-API-Key") != "")
		_, _ = fmt.Fprint(w, `{}`)
	}))
	defer target.Close()
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer gateway.Close()
	cfg := unsignedTestConfig(t)
	cfg.AllowUnsigned = allowUnsigned
	cfg.GatewayURL = gateway.URL
	cfg.NatsURL = handshakeOnlyNATS(t)
	cfg.APIKey = "fixture-credential"
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.natsConn.Close()
	defer b.agent.Store.Close()
	if b.agent.AllowUnsigned != allowUnsigned {
		t.Fatal("unsigned transport configuration did not reach the CAP runtime")
	}
	var result map[string]any
	err = b.client.doJSON(context.Background(), http.MethodGet, "/redirect", nil, &result)
	if !allowUnsigned {
		if err != nil || targetCalls.Load() != 1 {
			t.Fatalf("default redirect behavior changed: calls=%d, error=%v", targetCalls.Load(), err)
		}
		return
	}
	if err == nil {
		t.Error("expected the gateway redirect to return an error")
	}
	if targetCalls.Load() != 0 || credentialSeen.Load() {
		t.Fatalf("redirect target received %d requests; credential forwarded=%v", targetCalls.Load(), credentialSeen.Load())
	}
}
