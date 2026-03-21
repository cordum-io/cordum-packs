package worker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/openai/internal/config"
	"github.com/cordum-io/cordum-packs/packs/openai/internal/openaiapi"
)

const (
	actionChatCompletions       = "chat.completions"
	actionChatCompletionsStream = "chat.completions.stream"
	actionEmbeddings            = "embeddings"
	actionImagesGenerate        = "images.generate"
	actionAudioTranscriptions   = "audio.transcriptions"
	actionAudioSpeech           = "audio.speech"
	actionFineTuningCreate      = "fine_tuning.jobs.create"
	actionFineTuningList        = "fine_tuning.jobs.list"
	actionFineTuningGet         = "fine_tuning.jobs.get"
	actionFineTuningCancel      = "fine_tuning.jobs.cancel"
	actionModelsList            = "models.list"
)

type actionSpec struct {
	Topic         string
	Intent        string
	ModelRequired bool
	Stream        bool
}

var actionSpecs = map[string]actionSpec{
	actionChatCompletions:       {Topic: "job.openai.chat", Intent: "read", ModelRequired: true},
	actionChatCompletionsStream: {Topic: "job.openai.chat.stream", Intent: "read", ModelRequired: true, Stream: true},
	actionEmbeddings:            {Topic: "job.openai.embed", Intent: "read", ModelRequired: true},
	actionImagesGenerate:        {Topic: "job.openai.image.generate", Intent: "write", ModelRequired: true},
	actionAudioTranscriptions:   {Topic: "job.openai.audio.transcribe", Intent: "read", ModelRequired: true},
	actionAudioSpeech:           {Topic: "job.openai.audio.tts", Intent: "write", ModelRequired: true},
	actionFineTuningCreate:      {Topic: "job.openai.finetune", Intent: "write", ModelRequired: true},
	actionFineTuningList:        {Topic: "job.openai.finetune.read", Intent: "read"},
	actionFineTuningGet:         {Topic: "job.openai.finetune.read", Intent: "read"},
	actionFineTuningCancel:      {Topic: "job.openai.finetune", Intent: "write"},
	actionModelsList:            {Topic: "job.openai.finetune.read", Intent: "read"},
}

type openAIClient interface {
	ChatCompletion(ctx context.Context, req openaiapi.ChatCompletionRequest) (openaiapi.JSONResponse, error)
	ChatCompletionStream(ctx context.Context, req openaiapi.ChatCompletionRequest) (openaiapi.StreamResponse, error)
	CreateEmbedding(ctx context.Context, req openaiapi.EmbeddingRequest) (openaiapi.JSONResponse, error)
	GenerateImage(ctx context.Context, req openaiapi.ImageGenerateRequest) (openaiapi.JSONResponse, error)
	TranscribeAudio(ctx context.Context, req openaiapi.AudioTranscribeRequest) (openaiapi.JSONResponse, error)
	TextToSpeech(ctx context.Context, req openaiapi.AudioSpeechRequest) (openaiapi.BinaryResponse, error)
	CreateFineTune(ctx context.Context, req openaiapi.FineTuneCreateRequest) (openaiapi.JSONResponse, error)
	ListFineTunes(ctx context.Context) (openaiapi.JSONResponse, error)
	GetFineTune(ctx context.Context, id string) (openaiapi.JSONResponse, error)
	CancelFineTune(ctx context.Context, id string) (openaiapi.JSONResponse, error)
	ListModels(ctx context.Context) (openaiapi.JSONResponse, error)
}

type clientFactory func(config.Profile) openAIClient

type Worker struct {
	cfg       config.Config
	agent     *runtime.Agent
	natsConn  *nats.Conn
	workerID  string
	sem       chan struct{}
	active    int32
	newClient clientFactory
}

type InlineAuth struct {
	APIKey          string `json:"api_key"` // #nosec G101 -- runtime-supplied credential field; no hardcoded secret value
	APIKeyEnv       string `json:"api_key_env"`
	Organization    string `json:"organization"`
	OrganizationEnv string `json:"organization_env"`
}

type JobInput struct {
	Profile         string           `json:"profile"`
	Action          string           `json:"action"`
	Model           string           `json:"model"`
	Messages        []map[string]any `json:"messages"`
	Temperature     *float64         `json:"temperature"`
	MaxTokens       int              `json:"max_tokens"`
	Tools           []any            `json:"tools"`
	ToolChoice      any              `json:"tool_choice"`
	ResponseFormat  any              `json:"response_format"`
	Stream          bool             `json:"stream"`
	Input           any              `json:"input"`
	Dimensions      int              `json:"dimensions"`
	EncodingFormat  string           `json:"encoding_format"`
	Prompt          string           `json:"prompt"`
	Size            string           `json:"size"`
	Quality         string           `json:"quality"`
	Style           string           `json:"style"`
	N               int              `json:"n"`
	FileURL         string           `json:"file_url"`
	Language        string           `json:"language"`
	Voice           string           `json:"voice"`
	Speed           *float64         `json:"speed"`
	Format          string           `json:"format"`
	FineTuneID      string           `json:"fine_tune_id"`
	TrainingFile    string           `json:"training_file"`
	ValidationFile  string           `json:"validation_file"`
	Suffix          string           `json:"suffix"`
	Hyperparameters map[string]any   `json:"hyperparameters"`
	Auth            InlineAuth       `json:"auth"`
}

type callResult struct {
	JobID        string              `json:"job_id"`
	Profile      string              `json:"profile"`
	Action       string              `json:"action"`
	Model        string              `json:"model,omitempty"`
	StatusCode   int                 `json:"status_code"`
	RequestID    string              `json:"request_id,omitempty"`
	DurationMs   int64               `json:"duration_ms"`
	RateLimit    openaiapi.RateLimit `json:"rate_limit,omitempty"`
	Usage        openaiapi.Usage     `json:"usage"`
	CostEstimate float64             `json:"cost_estimate,omitempty"`
	Stream       bool                `json:"stream,omitempty"`
	Result       any                 `json:"result,omitempty"`
	Error        string              `json:"error,omitempty"`
}

type executionResult struct {
	Model        string
	StatusCode   int
	RequestID    string
	RateLimit    openaiapi.RateLimit
	Usage        openaiapi.Usage
	CostEstimate float64
	Stream       bool
	Result       any
}

func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "openai")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, err
	}
	store, err := newRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
		return nil, err
	}

	agent := &runtime.Agent{
		NATS:     nc,
		Store:    store,
		RedisURL: cfg.RedisURL,
		SenderID: workerID,
	}

	w := &Worker{
		cfg:      cfg,
		agent:    agent,
		natsConn: nc,
		workerID: workerID,
	}
	w.newClient = func(profile config.Profile) openAIClient {
		return openaiapi.NewClient(profile.BaseURL, profile.APIKey, openaiapi.Options{
			Organization:     profile.Organization,
			Headers:          profile.Headers,
			Timeout:          w.requestTimeout(profile),
			MaxRetries:       w.profileMaxRetries(profile),
			RetryOnRateLimit: w.profileRateLimitRetry(profile),
		})
	}
	if cfg.MaxParallel > 0 {
		w.sem = make(chan struct{}, cfg.MaxParallel)
	}
	return w, nil
}

func (w *Worker) Close() error {
	if w.agent != nil {
		_ = w.agent.Close()
	}
	return nil
}

func (w *Worker) Run(ctx context.Context) error {
	if w.agent == nil {
		return fmt.Errorf("runtime agent unavailable")
	}
	subjects := w.cfg.Subjects
	if len(subjects) == 0 {
		subjects = []string{"job.openai.*"}
	}
	for _, subject := range subjects {
		runtime.Register(w.agent, subject, w.handleJob)
	}
	runtime.Register(w.agent, runtime.DirectSubject(w.workerID), w.handleJob)

	if err := w.agent.Start(); err != nil {
		return err
	}
	if w.natsConn != nil {
		heartbeatFn := func() ([]byte, error) {
			active := int(atomic.LoadInt32(&w.active))
			return runtime.HeartbeatPayload(w.workerID, w.cfg.Pool, active, int(w.cfg.MaxParallel), 0)
		}
		if payload, err := heartbeatFn(); err == nil {
			_ = runtime.EmitHeartbeat(w.natsConn, payload)
		}
		go runtime.HeartbeatLoop(ctx, w.natsConn, heartbeatFn)
	}

	<-ctx.Done()
	return ctx.Err()
}

func (w *Worker) handleJob(ctx runtime.Context, payload map[string]any) (callResult, error) {
	if w.sem != nil {
		w.sem <- struct{}{}
		atomic.AddInt32(&w.active, 1)
		defer func() {
			<-w.sem
			atomic.AddInt32(&w.active, -1)
		}()
	} else {
		atomic.AddInt32(&w.active, 1)
		defer atomic.AddInt32(&w.active, -1)
	}

	jobID := ""
	jobTopic := ""
	if ctx.Job != nil {
		jobID = ctx.Job.GetJobId()
		jobTopic = ctx.Job.GetTopic()
	}

	payload = normalizePayload(payload)

	var input JobInput
	if err := decodePayload(payload, &input); err != nil {
		return callResult{}, err
	}
	if err := validateInlineAuth(input.Auth, w.cfg.AllowInlineAuth, w.cfg.AllowInlineSecrets); err != nil {
		return callResult{}, err
	}

	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action == "" {
		return callResult{}, fmt.Errorf("action required")
	}
	spec, ok := actionSpecs[action]
	if !ok {
		return callResult{}, fmt.Errorf("unsupported action: %s", action)
	}
	if err := w.enforceTopic(jobTopic, spec); err != nil {
		return callResult{}, err
	}
	if err := validateActionInput(action, input); err != nil {
		return callResult{}, err
	}

	profile, err := w.resolveProfile(input.Profile)
	if err != nil {
		return callResult{}, err
	}
	profile, err = w.resolveAuth(profile, input.Auth)
	if err != nil {
		return callResult{}, err
	}
	if spec.ModelRequired {
		if err := enforceModelPolicy(profile, input.Model); err != nil {
			return callResult{}, err
		}
	}
	if profile.MaxTokensLimit > 0 && input.MaxTokens > profile.MaxTokensLimit {
		input.MaxTokens = profile.MaxTokensLimit
	}

	client := w.newClient(profile)
	callCtx, cancel := context.WithTimeout(context.Background(), w.requestTimeout(profile))
	defer cancel()

	start := time.Now()
	execution, execErr := w.execute(callCtx, ctx, client, profile, action, spec, input)
	result := callResult{
		JobID:      jobID,
		Profile:    profile.Name,
		Action:     action,
		Model:      firstNonEmpty(execution.Model, input.Model),
		StatusCode: execution.StatusCode,
		RequestID:  execution.RequestID,
		DurationMs: time.Since(start).Milliseconds(),
		RateLimit:  execution.RateLimit,
		Usage:      execution.Usage,
		Stream:     execution.Stream,
		Result:     execution.Result,
	}
	if w.profileCostTracking(profile) {
		result.CostEstimate = execution.CostEstimate
	}
	if execErr != nil {
		result.Error = execErr.Error()
	}
	return result, execErr
}

func normalizePayload(payload map[string]any) map[string]any {
	if payload == nil {
		return map[string]any{}
	}
	if ctxPayload, ok := payload["context"].(map[string]any); ok {
		return ctxPayload
	}
	return payload
}

func decodePayload(payload map[string]any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func (w *Worker) resolveProfile(name string) (config.Profile, error) {
	profileName := strings.TrimSpace(name)
	if profileName == "" {
		profileName = w.cfg.DefaultProfile
	}
	if profileName == "" {
		return config.Profile{}, fmt.Errorf("profile required")
	}
	profile, ok := w.cfg.Profiles[profileName]
	if !ok {
		return config.Profile{}, fmt.Errorf("unknown profile: %s", profileName)
	}
	if profile.Name == "" {
		profile.Name = profileName
	}
	return profile, nil
}

func (w *Worker) resolveAuth(profile config.Profile, inline InlineAuth) (config.Profile, error) {
	resolved := profile
	resolved.APIKey = resolveSecret(profile.APIKey, profile.APIKeyEnv)
	resolved.Organization = resolveSecret(profile.Organization, profile.OrganizationEnv)

	if inline.HasAny() {
		if inline.APIKey != "" || inline.APIKeyEnv != "" {
			resolved.APIKey = resolveSecret(inline.APIKey, inline.APIKeyEnv)
		}
		if inline.Organization != "" || inline.OrganizationEnv != "" {
			resolved.Organization = resolveSecret(inline.Organization, inline.OrganizationEnv)
		}
	}
	if strings.TrimSpace(resolved.APIKey) == "" {
		return config.Profile{}, fmt.Errorf("openai api key required")
	}
	return resolved, nil
}

func (w *Worker) requestTimeout(profile config.Profile) time.Duration {
	if profile.Timeout > 0 {
		return profile.Timeout
	}
	return w.cfg.RequestTimeout
}

func (w *Worker) profileCostTracking(profile config.Profile) bool {
	if profile.CostTracking != nil {
		return *profile.CostTracking
	}
	return w.cfg.CostTracking
}

func (w *Worker) profileRateLimitRetry(profile config.Profile) bool {
	if profile.RateLimitRetry != nil {
		return *profile.RateLimitRetry
	}
	return w.cfg.RateLimitRetry
}

func (w *Worker) profileMaxRetries(profile config.Profile) int {
	if profile.MaxRetries != nil {
		return *profile.MaxRetries
	}
	return w.cfg.MaxRetries
}

func (w *Worker) enforceTopic(topic string, spec actionSpec) error {
	if strings.TrimSpace(topic) == "" {
		return fmt.Errorf("job topic missing")
	}
	if topic != spec.Topic {
		return fmt.Errorf("%s actions must use %s topic", spec.Intent, spec.Topic)
	}
	return nil
}

func (w *Worker) execute(ctx context.Context, rtCtx runtime.Context, client openAIClient, profile config.Profile, action string, spec actionSpec, input JobInput) (executionResult, error) {
	switch action {
	case actionChatCompletions:
		resp, err := client.ChatCompletion(ctx, buildChatCompletionRequest(input))
		return w.finishJSONResult(profile, firstModel(resp.Body, input.Model), resp, false), err
	case actionChatCompletionsStream:
		streamResp, err := client.ChatCompletionStream(ctx, buildChatCompletionRequest(input))
		if err != nil {
			return executionResult{}, err
		}
		defer streamResp.Body.Close()
		transcript, err := openaiapi.ParseChatCompletionStream(streamResp.Body, func(event openaiapi.StreamEvent) error {
			if event.Done {
				w.publishProgress(rtCtx, 100, "stream complete")
				return nil
			}
			if strings.TrimSpace(event.ContentDelta) != "" {
				w.publishProgress(rtCtx, streamProgressPercent(event.Index), streamMessage(event.ContentDelta))
			}
			return nil
		})
		result := map[string]any{
			"content":       transcript.Content,
			"finish_reason": transcript.FinishReason,
			"events":        transcript.Events,
		}
		return executionResult{
			Model:        input.Model,
			StatusCode:   streamResp.StatusCode,
			RequestID:    streamResp.RequestID,
			RateLimit:    streamResp.RateLimit,
			Usage:        transcript.Usage,
			CostEstimate: estimateCost(profile, input.Model, transcript.Usage),
			Stream:       true,
			Result:       result,
		}, err
	case actionEmbeddings:
		resp, err := client.CreateEmbedding(ctx, openaiapi.EmbeddingRequest{
			Model:          input.Model,
			Input:          input.Input,
			Dimensions:     input.Dimensions,
			EncodingFormat: input.EncodingFormat,
		})
		return w.finishJSONResult(profile, firstModel(resp.Body, input.Model), resp, false), err
	case actionImagesGenerate:
		resp, err := client.GenerateImage(ctx, openaiapi.ImageGenerateRequest{
			Model:   input.Model,
			Prompt:  input.Prompt,
			Size:    input.Size,
			Quality: input.Quality,
			Style:   input.Style,
			N:       input.N,
		})
		return w.finishJSONResult(profile, firstModel(resp.Body, input.Model), resp, false), err
	case actionAudioTranscriptions:
		resp, err := client.TranscribeAudio(ctx, openaiapi.AudioTranscribeRequest{
			Model:          input.Model,
			FileURL:        input.FileURL,
			Language:       input.Language,
			Prompt:         input.Prompt,
			ResponseFormat: responseFormatString(input.ResponseFormat),
			Temperature:    input.Temperature,
		})
		return w.finishJSONResult(profile, firstModel(resp.Body, input.Model), resp, false), err
	case actionAudioSpeech:
		resp, err := client.TextToSpeech(ctx, openaiapi.AudioSpeechRequest{
			Model:  input.Model,
			Input:  stringifyInput(input.Input),
			Voice:  input.Voice,
			Speed:  input.Speed,
			Format: input.Format,
		})
		audioResult := map[string]any{
			"audio_base64":    base64.StdEncoding.EncodeToString(resp.Data),
			"content_type":    resp.ContentType,
			"response_format": firstNonEmpty(input.Format, "mp3"),
		}
		return executionResult{
			Model:        input.Model,
			StatusCode:   resp.StatusCode,
			RequestID:    resp.RequestID,
			RateLimit:    resp.RateLimit,
			Usage:        resp.Usage,
			CostEstimate: estimateCost(profile, input.Model, resp.Usage),
			Result:       audioResult,
		}, err
	case actionFineTuningCreate:
		resp, err := client.CreateFineTune(ctx, openaiapi.FineTuneCreateRequest{
			Model:           input.Model,
			TrainingFile:    input.TrainingFile,
			ValidationFile:  input.ValidationFile,
			Suffix:          input.Suffix,
			Hyperparameters: input.Hyperparameters,
		})
		return w.finishJSONResult(profile, firstModel(resp.Body, input.Model), resp, false), err
	case actionFineTuningList:
		resp, err := client.ListFineTunes(ctx)
		return w.finishJSONResult(profile, firstModel(resp.Body, input.Model), resp, false), err
	case actionFineTuningGet:
		resp, err := client.GetFineTune(ctx, input.FineTuneID)
		return w.finishJSONResult(profile, firstModel(resp.Body, input.Model), resp, false), err
	case actionFineTuningCancel:
		resp, err := client.CancelFineTune(ctx, input.FineTuneID)
		return w.finishJSONResult(profile, firstModel(resp.Body, input.Model), resp, false), err
	case actionModelsList:
		resp, err := client.ListModels(ctx)
		return w.finishJSONResult(profile, firstModel(resp.Body, input.Model), resp, false), err
	default:
		return executionResult{}, fmt.Errorf("unsupported action: %s", action)
	}
}

func (w *Worker) finishJSONResult(profile config.Profile, model string, resp openaiapi.JSONResponse, stream bool) executionResult {
	return executionResult{
		Model:        model,
		StatusCode:   resp.StatusCode,
		RequestID:    resp.RequestID,
		RateLimit:    resp.RateLimit,
		Usage:        resp.Usage,
		CostEstimate: estimateCost(profile, model, resp.Usage),
		Stream:       stream,
		Result:       resp.Body,
	}
}

func buildChatCompletionRequest(input JobInput) openaiapi.ChatCompletionRequest {
	return openaiapi.ChatCompletionRequest{
		Model:          input.Model,
		Messages:       input.Messages,
		Temperature:    input.Temperature,
		MaxTokens:      input.MaxTokens,
		Tools:          input.Tools,
		ToolChoice:     input.ToolChoice,
		ResponseFormat: responseFormatMap(input.ResponseFormat),
		Stream:         input.Stream,
	}
}

func validateActionInput(action string, input JobInput) error {
	switch action {
	case actionChatCompletions, actionChatCompletionsStream:
		if strings.TrimSpace(input.Model) == "" {
			return fmt.Errorf("model required")
		}
		if len(input.Messages) == 0 {
			return fmt.Errorf("messages required")
		}
	case actionEmbeddings:
		if strings.TrimSpace(input.Model) == "" {
			return fmt.Errorf("model required")
		}
		if input.Input == nil || stringifyInput(input.Input) == "" && !isStringSlice(input.Input) {
			return fmt.Errorf("input required")
		}
	case actionImagesGenerate:
		if strings.TrimSpace(input.Model) == "" {
			return fmt.Errorf("model required")
		}
		if strings.TrimSpace(input.Prompt) == "" {
			return fmt.Errorf("prompt required")
		}
	case actionAudioTranscriptions:
		if strings.TrimSpace(input.Model) == "" {
			return fmt.Errorf("model required")
		}
		if strings.TrimSpace(input.FileURL) == "" {
			return fmt.Errorf("file_url required")
		}
	case actionAudioSpeech:
		if strings.TrimSpace(input.Model) == "" {
			return fmt.Errorf("model required")
		}
		if strings.TrimSpace(stringifyInput(input.Input)) == "" {
			return fmt.Errorf("input required")
		}
		if strings.TrimSpace(input.Voice) == "" {
			return fmt.Errorf("voice required")
		}
	case actionFineTuningCreate:
		if strings.TrimSpace(input.Model) == "" {
			return fmt.Errorf("model required")
		}
		if strings.TrimSpace(input.TrainingFile) == "" {
			return fmt.Errorf("training_file required")
		}
	case actionFineTuningGet, actionFineTuningCancel:
		if strings.TrimSpace(input.FineTuneID) == "" {
			return fmt.Errorf("fine_tune_id required")
		}
	}
	return nil
}

func validateInlineAuth(inline InlineAuth, allowInlineAuth, allowInlineSecrets bool) error {
	if inline.HasAny() && !allowInlineAuth {
		return fmt.Errorf("inline auth disabled")
	}
	if inline.HasSecrets() && !allowInlineSecrets {
		return fmt.Errorf("inline secrets disabled; use *_env fields")
	}
	return nil
}

func enforceModelPolicy(profile config.Profile, model string) error {
	model = strings.TrimSpace(model)
	if model == "" {
		return fmt.Errorf("model required")
	}
	if len(profile.AllowedModels) > 0 && !matchAny(profile.AllowedModels, model) {
		return fmt.Errorf("model not allowed: %s", model)
	}
	if matchAny(profile.DeniedModels, model) {
		return fmt.Errorf("model denied: %s", model)
	}
	return nil
}

func matchAny(patterns []string, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, pattern := range patterns {
		candidate := strings.ToLower(strings.TrimSpace(pattern))
		if candidate == "" {
			continue
		}
		if candidate == value {
			return true
		}
		if ok, _ := path.Match(candidate, value); ok {
			return true
		}
	}
	return false
}

func resolveSecret(value, envKey string) string {
	if strings.TrimSpace(envKey) != "" {
		if envVal := strings.TrimSpace(os.Getenv(envKey)); envVal != "" {
			return envVal
		}
	}
	return strings.TrimSpace(value)
}

func estimateCost(profile config.Profile, model string, usage openaiapi.Usage) float64 {
	if profile.CostTracking != nil && !*profile.CostTracking {
		return 0
	}
	return openaiapi.EstimateCostUSD(model, usage)
}

func responseFormatMap(value any) map[string]any {
	if value == nil {
		return nil
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

func responseFormatString(value any) string {
	if typed, ok := value.(string); ok {
		return strings.TrimSpace(typed)
	}
	return ""
}

func stringifyInput(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return ""
	}
}

func isStringSlice(value any) bool {
	switch typed := value.(type) {
	case []string:
		return len(typed) > 0
	case []any:
		return len(typed) > 0
	default:
		return false
	}
}

func firstModel(body map[string]any, fallback string) string {
	if body != nil {
		if model, ok := body["model"].(string); ok && strings.TrimSpace(model) != "" {
			return model
		}
	}
	return strings.TrimSpace(fallback)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (w *Worker) publishProgress(ctx runtime.Context, percent int32, message string) {
	if w.natsConn == nil || ctx.Job == nil || ctx.Packet == nil {
		return
	}
	jobID := ctx.Job.GetJobId()
	if strings.TrimSpace(jobID) == "" {
		return
	}
	progress := &agentv1.JobProgress{
		JobId:   jobID,
		Percent: percent,
		Message: message,
		Status:  agentv1.JobStatus_JOB_STATUS_RUNNING,
	}
	_ = runtime.PublishProgress(w.natsConn, progress, ctx.Packet.GetTraceId(), w.workerID, nil)
}

func streamProgressPercent(index int) int32 {
	percent := 10 + (index * 5)
	if percent > 95 {
		percent = 95
	}
	return int32(percent)
}

func streamMessage(delta string) string {
	delta = strings.TrimSpace(strings.ReplaceAll(delta, "\n", " "))
	if delta == "" {
		return "stream update"
	}
	if len(delta) > 120 {
		return delta[:120] + "..."
	}
	return delta
}

func (a InlineAuth) HasAny() bool {
	return strings.TrimSpace(a.APIKey) != "" ||
		strings.TrimSpace(a.APIKeyEnv) != "" ||
		strings.TrimSpace(a.Organization) != "" ||
		strings.TrimSpace(a.OrganizationEnv) != ""
}

func (a InlineAuth) HasSecrets() bool {
	return strings.TrimSpace(a.APIKey) != ""
}
