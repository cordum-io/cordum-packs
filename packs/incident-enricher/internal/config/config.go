package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultNATSURL    = "nats://localhost:4222"
	defaultGatewayURL = "http://localhost:8081"
	defaultRedisAddr  = "localhost:6379"
	defaultWorkerPool = "incident-enricher-default"
	defaultDataTTL    = 24 * time.Hour
	defaultOllamaURL  = "http://localhost:11434"
)

type Env struct {
	Service             string
	NATSURL             string
	RedisURL            string
	GatewayURL          string
	APIKey              string
	WorkerPool          string
	WorkerID            string
	MaxParallelJobs     int
	DataTTL             time.Duration
	LLMProvider         string
	OpenAIAPIKey        string
	OpenAIModel         string
	OllamaURL           string
	OllamaModel         string
	OllamaTemp          float64
	SlackWebhookURL     string
	LLMMaxInputBytes    int
	LLMMaxEvidenceBytes int
	LLMMaxEvidenceItems int
}

func Load(service string) Env {
	cfg := Env{Service: service}
	cfg.NATSURL = getenv("NATS_URL", defaultNATSURL)
	cfg.GatewayURL = firstNonEmpty(
		os.Getenv("CORDUM_GATEWAY_URL"),
		os.Getenv("CORDUM_GATEWAY"),
		defaultGatewayURL,
	)
	cfg.APIKey = strings.TrimSpace(os.Getenv("CORDUM_API_KEY"))

	redisURL := strings.TrimSpace(os.Getenv("REDIS_URL"))
	if redisURL == "" {
		redisURL = strings.TrimSpace(os.Getenv("REDIS_ADDR"))
		if redisURL == "" {
			redisURL = defaultRedisAddr
		}
		if !strings.Contains(redisURL, "://") {
			redisURL = "redis://" + redisURL
		}
	}
	cfg.RedisURL = redisURL

	cfg.WorkerPool = getenv("WORKER_POOL", defaultWorkerPool)
	cfg.WorkerID = strings.TrimSpace(os.Getenv("WORKER_ID"))
	if cfg.WorkerID == "" {
		host := strings.TrimSpace(os.Getenv("HOSTNAME"))
		if host == "" {
			host = "local"
		}
		cfg.WorkerID = service + "-" + host
	}
	cfg.MaxParallelJobs = getenvInt("WORKER_MAX_PARALLEL", 1)
	cfg.DataTTL = parseDataTTL()

	cfg.LLMProvider = strings.TrimSpace(os.Getenv("LLM_PROVIDER"))
	cfg.OpenAIAPIKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	cfg.OpenAIModel = strings.TrimSpace(os.Getenv("OPENAI_MODEL"))
	cfg.OllamaURL = getenv("OLLAMA_URL", defaultOllamaURL)
	cfg.OllamaModel = strings.TrimSpace(os.Getenv("OLLAMA_MODEL"))
	cfg.OllamaTemp = getenvFloat("OLLAMA_TEMPERATURE", 0.2)
	cfg.SlackWebhookURL = strings.TrimSpace(os.Getenv("SLACK_WEBHOOK_URL"))
	cfg.LLMMaxInputBytes = getenvInt("LLM_MAX_INPUT_BYTES", 65536)
	cfg.LLMMaxEvidenceBytes = getenvInt("LLM_MAX_EVIDENCE_BYTES", 32768)
	cfg.LLMMaxEvidenceItems = getenvInt("LLM_MAX_EVIDENCE_ITEMS", 4)

	return cfg
}

func getenv(key, fallback string) string {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	return val
}

func getenvInt(key string, fallback int) int {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return parsed
}

func getenvFloat(key string, fallback float64) float64 {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func parseDataTTL() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("REDIS_DATA_TTL_SECONDS")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	if raw := strings.TrimSpace(os.Getenv("REDIS_DATA_TTL")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			return d
		}
	}
	return defaultDataTTL
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
