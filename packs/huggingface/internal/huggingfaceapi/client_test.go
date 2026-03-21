package huggingfaceapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer hf_test" {
			t.Errorf("expected Bearer hf_test, got %q", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode([]map[string]any{{"generated_text": "hello"}})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, "hf_test")
	result, status, err := c.Inference(context.Background(), "test-model", map[string]any{"inputs": "hi"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 {
		t.Errorf("expected 200, got %d", status)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestWaitForModelHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Wait-For-Model") != "true" {
			t.Error("expected X-Wait-For-Model header")
		}
		json.NewEncoder(w).Encode([]map[string]any{{"generated_text": "ok"}})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, "key")
	_, _, err := c.Inference(context.Background(), "model", map[string]any{"inputs": "test"}, true)
	if err != nil {
		t.Fatal(err)
	}
}

func TestModelLoading503(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		json.NewEncoder(w).Encode(map[string]any{
			"error":          "Model is loading",
			"estimated_time": 30.5,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, "key")
	result, status, err := c.Inference(context.Background(), "model", map[string]any{"inputs": "test"}, false)
	if status != 503 {
		t.Errorf("expected 503, got %d", status)
	}
	if err == nil {
		t.Fatal("expected error")
	}
	if result == nil {
		t.Fatal("expected loading result")
	}
	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["estimated_time"] != 30.5 {
		t.Errorf("expected estimated_time=30.5, got %v", resultMap["estimated_time"])
	}
}

func TestDualBaseURL(t *testing.T) {
	inferenceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models/test-model" {
			t.Errorf("inference: expected /models/test-model, got %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode([]map[string]any{{"text": "inferred"}})
	}))
	defer inferenceSrv.Close()

	hubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Errorf("hub: expected /models, got %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode([]map[string]any{{"modelId": "test-model"}})
	}))
	defer hubSrv.Close()

	c := NewClient(inferenceSrv.URL, hubSrv.URL, "key")

	// Inference → inference server
	_, _, err := c.Inference(context.Background(), "test-model", map[string]any{"inputs": "test"}, false)
	if err != nil {
		t.Fatalf("inference error: %v", err)
	}

	// Model search → hub server
	_, _, err = c.SearchModels(context.Background(), map[string]any{"search": "llama"})
	if err != nil {
		t.Fatalf("search error: %v", err)
	}
}

func TestModelRequired(t *testing.T) {
	c := NewClient("http://localhost", "http://localhost", "key")
	_, _, err := c.Inference(context.Background(), "", nil, false)
	if err == nil || err.Error() != "model is required" {
		t.Errorf("expected 'model is required', got %v", err)
	}
}

func TestEmbedEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pipeline/feature-extraction/sentence-transformers/all-MiniLM-L6-v2" {
			t.Errorf("expected feature-extraction path, got %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode([][]float64{{0.1, 0.2, 0.3}})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, "key")
	result, _, err := c.Embed(context.Background(), "sentence-transformers/all-MiniLM-L6-v2", "hello", false)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Error("expected embeddings")
	}
}

func TestGetModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models/meta-llama/Llama-3-8b" {
			t.Errorf("expected /models/meta-llama/Llama-3-8b, got %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"modelId": "meta-llama/Llama-3-8b", "downloads": 1000000})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, "key")
	result, _, err := c.GetModel(context.Background(), "meta-llama/Llama-3-8b")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Error("expected model data")
	}
}

func TestSpaceOperations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": "user/my-space", "status": "RUNNING"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, "key")

	_, _, err := c.GetSpace(context.Background(), "user/my-space")
	if err != nil {
		t.Fatalf("GetSpace: %v", err)
	}

	_, _, err = c.RestartSpace(context.Background(), "user/my-space")
	if err != nil {
		t.Fatalf("RestartSpace: %v", err)
	}
}

func TestAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL, "bad")
	_, status, err := c.Inference(context.Background(), "model", map[string]any{"inputs": "test"}, false)
	if status != 401 {
		t.Errorf("expected 401, got %d", status)
	}
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestConnectionPooling(t *testing.T) {
	c := NewClient("https://api-inference.huggingface.co", "https://huggingface.co/api", "key")
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.MaxIdleConns != 100 {
		t.Errorf("expected 100, got %d", transport.MaxIdleConns)
	}
}
