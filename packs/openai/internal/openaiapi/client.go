package openaiapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.openai.com/v1"

type Options struct {
	Organization     string
	Headers          map[string]string
	Timeout          time.Duration
	MaxRetries       int
	RetryOnRateLimit bool
}

type Client struct {
	baseURL          string
	apiKey           string
	organization     string
	headers          map[string]string
	httpClient       *http.Client
	maxRetries       int
	retryOnRateLimit bool
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type RateLimit struct {
	LimitRequests     int    `json:"limit_requests,omitempty"`
	RemainingRequests int    `json:"remaining_requests,omitempty"`
	ResetRequests     string `json:"reset_requests,omitempty"`
	LimitTokens       int    `json:"limit_tokens,omitempty"`
	RemainingTokens   int    `json:"remaining_tokens,omitempty"`
	ResetTokens       string `json:"reset_tokens,omitempty"`
	RetryAfterMs      int64  `json:"retry_after_ms,omitempty"`
}

type JSONResponse struct {
	StatusCode int            `json:"status_code"`
	RequestID  string         `json:"request_id,omitempty"`
	RateLimit  RateLimit      `json:"rate_limit,omitempty"`
	Usage      Usage          `json:"usage"`
	Body       map[string]any `json:"body,omitempty"`
}

type BinaryResponse struct {
	StatusCode  int       `json:"status_code"`
	RequestID   string    `json:"request_id,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	RateLimit   RateLimit `json:"rate_limit,omitempty"`
	Usage       Usage     `json:"usage"`
	Data        []byte    `json:"data,omitempty"`
}

type StreamResponse struct {
	StatusCode int           `json:"status_code"`
	RequestID  string        `json:"request_id,omitempty"`
	RateLimit  RateLimit     `json:"rate_limit,omitempty"`
	Body       io.ReadCloser `json:"-"`
}

type APIError struct {
	StatusCode int
	Message    string
	Type       string
	Param      string
	Code       string
	Raw        string
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	parts := []string{fmt.Sprintf("openai api error (%d)", e.StatusCode)}
	if e.Message != "" {
		parts = append(parts, e.Message)
	}
	if e.Type != "" {
		parts = append(parts, "type="+e.Type)
	}
	if e.Code != "" {
		parts = append(parts, "code="+e.Code)
	}
	return strings.Join(parts, ": ")
}

type ChatCompletionRequest struct {
	Model          string
	Messages       []map[string]any
	Temperature    *float64
	MaxTokens      int
	Tools          []any
	ToolChoice     any
	ResponseFormat map[string]any
	Stream         bool
}

type EmbeddingRequest struct {
	Model          string
	Input          any
	Dimensions     int
	EncodingFormat string
}

type ImageGenerateRequest struct {
	Model   string
	Prompt  string
	Size    string
	Quality string
	Style   string
	N       int
}

type AudioTranscribeRequest struct {
	Model          string
	FileURL        string
	Language       string
	Prompt         string
	ResponseFormat string
	Temperature    *float64
}

type AudioSpeechRequest struct {
	Model  string
	Input  string
	Voice  string
	Speed  *float64
	Format string
}

type FineTuneCreateRequest struct {
	Model           string
	TrainingFile    string
	ValidationFile  string
	Suffix          string
	Hyperparameters map[string]any
}

type StreamEvent struct {
	Index        int            `json:"index"`
	Data         map[string]any `json:"data"`
	ContentDelta string         `json:"content_delta,omitempty"`
	Usage        Usage          `json:"usage"`
	Done         bool           `json:"done,omitempty"`
}

type StreamTranscript struct {
	Events       []map[string]any `json:"events,omitempty"`
	Content      string           `json:"content,omitempty"`
	FinishReason string           `json:"finish_reason,omitempty"`
	Usage        Usage            `json:"usage"`
}

func NewClient(baseURL, apiKey string, opts Options) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultBaseURL
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	headers := map[string]string{}
	for key, value := range opts.Headers {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		headers[key] = value
	}
	return &Client{
		baseURL:          strings.TrimRight(baseURL, "/"),
		apiKey:           strings.TrimSpace(apiKey),
		organization:     strings.TrimSpace(opts.Organization),
		headers:          headers,
		httpClient:       &http.Client{Timeout: timeout},
		maxRetries:       max(0, opts.MaxRetries),
		retryOnRateLimit: opts.RetryOnRateLimit,
	}
}

func (c *Client) ChatCompletion(ctx context.Context, req ChatCompletionRequest) (JSONResponse, error) {
	payload := map[string]any{
		"model":    req.Model,
		"messages": req.Messages,
	}
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	if req.MaxTokens > 0 {
		payload["max_tokens"] = req.MaxTokens
	}
	if len(req.Tools) > 0 {
		payload["tools"] = req.Tools
	}
	if req.ToolChoice != nil {
		payload["tool_choice"] = req.ToolChoice
	}
	if len(req.ResponseFormat) > 0 {
		payload["response_format"] = req.ResponseFormat
	}
	payload["stream"] = false
	return c.doJSON(ctx, http.MethodPost, "/chat/completions", nil, payload)
}

func (c *Client) ChatCompletionStream(ctx context.Context, req ChatCompletionRequest) (StreamResponse, error) {
	payload := map[string]any{
		"model":          req.Model,
		"messages":       req.Messages,
		"stream":         true,
		"stream_options": map[string]any{"include_usage": true},
	}
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	if req.MaxTokens > 0 {
		payload["max_tokens"] = req.MaxTokens
	}
	if len(req.Tools) > 0 {
		payload["tools"] = req.Tools
	}
	if req.ToolChoice != nil {
		payload["tool_choice"] = req.ToolChoice
	}
	if len(req.ResponseFormat) > 0 {
		payload["response_format"] = req.ResponseFormat
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return StreamResponse{}, err
	}
	resp, rateLimit, err := c.do(ctx, http.MethodPost, "/chat/completions", nil, "application/json", data, true)
	if err != nil {
		return StreamResponse{}, err
	}
	return StreamResponse{
		StatusCode: resp.StatusCode,
		RequestID:  resp.Header.Get("x-request-id"),
		RateLimit:  rateLimit,
		Body:       resp.Body,
	}, nil
}

func (c *Client) CreateEmbedding(ctx context.Context, req EmbeddingRequest) (JSONResponse, error) {
	payload := map[string]any{
		"model": req.Model,
		"input": req.Input,
	}
	if req.Dimensions > 0 {
		payload["dimensions"] = req.Dimensions
	}
	if req.EncodingFormat != "" {
		payload["encoding_format"] = req.EncodingFormat
	}
	return c.doJSON(ctx, http.MethodPost, "/embeddings", nil, payload)
}

func (c *Client) GenerateImage(ctx context.Context, req ImageGenerateRequest) (JSONResponse, error) {
	payload := map[string]any{
		"model":  req.Model,
		"prompt": req.Prompt,
	}
	if req.Size != "" {
		payload["size"] = req.Size
	}
	if req.Quality != "" {
		payload["quality"] = req.Quality
	}
	if req.Style != "" {
		payload["style"] = req.Style
	}
	if req.N > 0 {
		payload["n"] = req.N
	}
	return c.doJSON(ctx, http.MethodPost, "/images/generations", nil, payload)
}

func (c *Client) TranscribeAudio(ctx context.Context, req AudioTranscribeRequest) (JSONResponse, error) {
	fileName, fileData, err := c.downloadFile(ctx, req.FileURL)
	if err != nil {
		return JSONResponse{}, err
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	if err := writer.WriteField("model", req.Model); err != nil {
		return JSONResponse{}, err
	}
	if req.Language != "" {
		if err := writer.WriteField("language", req.Language); err != nil {
			return JSONResponse{}, err
		}
	}
	if req.Prompt != "" {
		if err := writer.WriteField("prompt", req.Prompt); err != nil {
			return JSONResponse{}, err
		}
	}
	if req.ResponseFormat != "" {
		if err := writer.WriteField("response_format", req.ResponseFormat); err != nil {
			return JSONResponse{}, err
		}
	}
	if req.Temperature != nil {
		if err := writer.WriteField("temperature", strconv.FormatFloat(*req.Temperature, 'f', -1, 64)); err != nil {
			return JSONResponse{}, err
		}
	}
	fileWriter, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		return JSONResponse{}, err
	}
	if _, err := fileWriter.Write(fileData); err != nil {
		return JSONResponse{}, err
	}
	if err := writer.Close(); err != nil {
		return JSONResponse{}, err
	}

	resp, rateLimit, err := c.do(ctx, http.MethodPost, "/audio/transcriptions", nil, writer.FormDataContentType(), body.Bytes(), false)
	if err != nil {
		return JSONResponse{}, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return JSONResponse{}, err
	}
	result := JSONResponse{
		StatusCode: resp.StatusCode,
		RequestID:  resp.Header.Get("x-request-id"),
		RateLimit:  rateLimit,
		Usage:      Usage{},
	}

	if looksLikeJSONContentType(resp.Header.Get("Content-Type")) || looksLikeJSONBody(data) {
		bodyMap := map[string]any{}
		if len(bytes.TrimSpace(data)) > 0 {
			if err := json.Unmarshal(data, &bodyMap); err != nil {
				return JSONResponse{}, err
			}
		}
		result.Body = bodyMap
		result.Usage = extractUsage(bodyMap)
		return result, nil
	}

	result.Body = map[string]any{
		"text":   string(data),
		"format": valueOr(req.ResponseFormat, "text"),
	}
	return result, nil
}

func (c *Client) TextToSpeech(ctx context.Context, req AudioSpeechRequest) (BinaryResponse, error) {
	payload := map[string]any{
		"model": req.Model,
		"input": req.Input,
		"voice": req.Voice,
	}
	if req.Speed != nil {
		payload["speed"] = *req.Speed
	}
	if req.Format != "" {
		payload["response_format"] = req.Format
	}
	return c.doBinary(ctx, http.MethodPost, "/audio/speech", nil, payload)
}

func (c *Client) CreateFineTune(ctx context.Context, req FineTuneCreateRequest) (JSONResponse, error) {
	payload := map[string]any{
		"model":         req.Model,
		"training_file": req.TrainingFile,
	}
	if req.ValidationFile != "" {
		payload["validation_file"] = req.ValidationFile
	}
	if req.Suffix != "" {
		payload["suffix"] = req.Suffix
	}
	if len(req.Hyperparameters) > 0 {
		payload["hyperparameters"] = req.Hyperparameters
	}
	return c.doJSON(ctx, http.MethodPost, "/fine_tuning/jobs", nil, payload)
}

func (c *Client) ListFineTunes(ctx context.Context) (JSONResponse, error) {
	return c.doJSON(ctx, http.MethodGet, "/fine_tuning/jobs", nil, nil)
}

func (c *Client) GetFineTune(ctx context.Context, id string) (JSONResponse, error) {
	if strings.TrimSpace(id) == "" {
		return JSONResponse{}, fmt.Errorf("fine tune id required")
	}
	return c.doJSON(ctx, http.MethodGet, "/fine_tuning/jobs/"+url.PathEscape(id), nil, nil)
}

func (c *Client) CancelFineTune(ctx context.Context, id string) (JSONResponse, error) {
	if strings.TrimSpace(id) == "" {
		return JSONResponse{}, fmt.Errorf("fine tune id required")
	}
	return c.doJSON(ctx, http.MethodPost, "/fine_tuning/jobs/"+url.PathEscape(id)+"/cancel", nil, map[string]any{})
}

func (c *Client) ListModels(ctx context.Context) (JSONResponse, error) {
	return c.doJSON(ctx, http.MethodGet, "/models", nil, nil)
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, query url.Values, payload any) (JSONResponse, error) {
	var data []byte
	var err error
	if payload != nil {
		data, err = json.Marshal(payload)
		if err != nil {
			return JSONResponse{}, err
		}
	}

	resp, rateLimit, err := c.do(ctx, method, endpoint, query, "application/json", data, false)
	if err != nil {
		return JSONResponse{}, err
	}
	defer resp.Body.Close()

	bodyData, err := io.ReadAll(resp.Body)
	if err != nil {
		return JSONResponse{}, err
	}
	bodyMap := map[string]any{}
	if len(bytes.TrimSpace(bodyData)) > 0 {
		if err := json.Unmarshal(bodyData, &bodyMap); err != nil {
			return JSONResponse{}, err
		}
	}
	return JSONResponse{
		StatusCode: resp.StatusCode,
		RequestID:  resp.Header.Get("x-request-id"),
		RateLimit:  rateLimit,
		Usage:      extractUsage(bodyMap),
		Body:       bodyMap,
	}, nil
}

func (c *Client) doBinary(ctx context.Context, method, endpoint string, query url.Values, payload any) (BinaryResponse, error) {
	var data []byte
	var err error
	if payload != nil {
		data, err = json.Marshal(payload)
		if err != nil {
			return BinaryResponse{}, err
		}
	}
	resp, rateLimit, err := c.do(ctx, method, endpoint, query, "application/json", data, false)
	if err != nil {
		return BinaryResponse{}, err
	}
	defer resp.Body.Close()

	bodyData, err := io.ReadAll(resp.Body)
	if err != nil {
		return BinaryResponse{}, err
	}
	return BinaryResponse{
		StatusCode:  resp.StatusCode,
		RequestID:   resp.Header.Get("x-request-id"),
		ContentType: resp.Header.Get("Content-Type"),
		RateLimit:   rateLimit,
		Usage:       Usage{},
		Data:        bodyData,
	}, nil
}

func (c *Client) do(ctx context.Context, method, endpoint string, query url.Values, contentType string, payload []byte, stream bool) (*http.Response, RateLimit, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		reqURL := c.baseURL + endpoint
		if len(query) > 0 {
			reqURL += "?" + query.Encode()
		}
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
		if err != nil {
			return nil, RateLimit{}, err
		}
		if contentType != "" && payload != nil {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		if c.organization != "" {
			req.Header.Set("OpenAI-Organization", c.organization)
		}
		for key, value := range c.headers {
			req.Header.Set(key, value)
		}

		resp, err := c.httpClient.Do(req) // #nosec G107 G704 -- outbound request target is controlled by pack configuration and request construction
		if err != nil {
			lastErr = err
			if attempt == c.maxRetries {
				return nil, RateLimit{}, err
			}
			if err := sleepContext(ctx, retryDelay(nil, attempt)); err != nil {
				return nil, RateLimit{}, err
			}
			continue
		}

		rateLimit := parseRateLimit(resp.Header)
		if resp.StatusCode == http.StatusTooManyRequests && c.retryOnRateLimit && attempt < c.maxRetries {
			_ = resp.Body.Close()
			if err := sleepContext(ctx, retryDelay(resp, attempt)); err != nil {
				return nil, rateLimit, err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			data, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return nil, rateLimit, parseAPIError(resp.StatusCode, data)
		}
		if stream {
			return resp, rateLimit, nil
		}
		return resp, rateLimit, nil
	}
	if lastErr != nil {
		return nil, RateLimit{}, lastErr
	}
	return nil, RateLimit{}, fmt.Errorf("request failed")
}

func (c *Client) downloadFile(ctx context.Context, rawURL string) (string, []byte, error) {
	if strings.TrimSpace(rawURL) == "" {
		return "", nil, fmt.Errorf("file url required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := c.httpClient.Do(req) // #nosec G107 G704 -- outbound request target is provided by job input and constrained by schema validation
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		message := strings.TrimSpace(string(data))
		if message == "" {
			message = resp.Status
		}
		return "", nil, fmt.Errorf("download file: %s", message)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	parsed, _ := url.Parse(rawURL)
	fileName := path.Base(parsed.Path)
	if fileName == "" || fileName == "." || fileName == "/" {
		fileName = "audio.bin"
	}
	return fileName, data, nil
}

func ParseChatCompletionStream(r io.Reader, onEvent func(StreamEvent) error) (StreamTranscript, error) {
	scanner := bufio.NewScanner(r)
	buffer := make([]byte, 0, 64*1024)
	scanner.Buffer(buffer, 1024*1024)

	var (
		dataLines    []string
		transcript   StreamTranscript
		eventIndex   int
		processEvent = func(forceDone bool) error {
			if len(dataLines) == 0 && !forceDone {
				return nil
			}
			payload := strings.TrimSpace(strings.Join(dataLines, "\n"))
			dataLines = nil
			if payload == "" && !forceDone {
				return nil
			}
			if payload == "[DONE]" || forceDone {
				if onEvent != nil {
					if err := onEvent(StreamEvent{Index: eventIndex, Done: true}); err != nil {
						return err
					}
				}
				return nil
			}
			var event map[string]any
			if err := json.Unmarshal([]byte(payload), &event); err != nil {
				return fmt.Errorf("decode stream event: %w", err)
			}
			transcript.Events = append(transcript.Events, event)
			delta := extractStreamDelta(event)
			transcript.Content += delta
			if usage := extractUsage(event); usage.TotalTokens > 0 || usage.PromptTokens > 0 || usage.CompletionTokens > 0 {
				transcript.Usage = usage
			}
			if finish := extractFinishReason(event); finish != "" {
				transcript.FinishReason = finish
			}
			if onEvent != nil {
				if err := onEvent(StreamEvent{
					Index:        eventIndex,
					Data:         event,
					ContentDelta: delta,
					Usage:        extractUsage(event),
				}); err != nil {
					return err
				}
			}
			eventIndex++
			return nil
		}
	)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			if err := processEvent(false); err != nil {
				return StreamTranscript{}, err
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if err := scanner.Err(); err != nil {
		return StreamTranscript{}, err
	}
	if err := processEvent(false); err != nil {
		return StreamTranscript{}, err
	}
	if onEvent != nil {
		if err := onEvent(StreamEvent{Index: eventIndex, Done: true}); err != nil {
			return StreamTranscript{}, err
		}
	}
	return transcript, nil
}

func EstimateCostUSD(model string, usage Usage) float64 {
	model = strings.ToLower(strings.TrimSpace(model))
	type price struct {
		inputPerMillion  float64
		outputPerMillion float64
	}

	pricing := map[string]price{
		"gpt-4o":                 {inputPerMillion: 2.50, outputPerMillion: 10.00},
		"gpt-4-turbo":            {inputPerMillion: 10.00, outputPerMillion: 30.00},
		"gpt-3.5-turbo":          {inputPerMillion: 0.50, outputPerMillion: 1.50},
		"text-embedding-3-small": {inputPerMillion: 0.02, outputPerMillion: 0},
		"text-embedding-3-large": {inputPerMillion: 0.13, outputPerMillion: 0},
	}
	rate, ok := pricing[model]
	if !ok {
		return 0
	}
	inputCost := (float64(usage.PromptTokens) / 1_000_000.0) * rate.inputPerMillion
	outputCost := (float64(usage.CompletionTokens) / 1_000_000.0) * rate.outputPerMillion
	return roundCurrency(inputCost + outputCost)
}

func extractUsage(body map[string]any) Usage {
	if body == nil {
		return Usage{}
	}
	usageMap, _ := body["usage"].(map[string]any)
	return Usage{
		PromptTokens:     intValue(usageMap["prompt_tokens"]),
		CompletionTokens: intValue(usageMap["completion_tokens"]),
		TotalTokens:      intValue(usageMap["total_tokens"]),
	}
}

func extractStreamDelta(event map[string]any) string {
	choices, _ := event["choices"].([]any)
	if len(choices) == 0 {
		return ""
	}
	choice, _ := choices[0].(map[string]any)
	delta, _ := choice["delta"].(map[string]any)
	if delta == nil {
		return ""
	}
	return contentToString(delta["content"])
}

func extractFinishReason(event map[string]any) string {
	choices, _ := event["choices"].([]any)
	if len(choices) == 0 {
		return ""
	}
	choice, _ := choices[0].(map[string]any)
	if finish, ok := choice["finish_reason"].(string); ok {
		return finish
	}
	return ""
}

func parseRateLimit(header http.Header) RateLimit {
	return RateLimit{
		LimitRequests:     intHeader(header, "x-ratelimit-limit-requests"),
		RemainingRequests: intHeader(header, "x-ratelimit-remaining-requests"),
		ResetRequests:     strings.TrimSpace(header.Get("x-ratelimit-reset-requests")),
		LimitTokens:       intHeader(header, "x-ratelimit-limit-tokens"),
		RemainingTokens:   intHeader(header, "x-ratelimit-remaining-tokens"),
		ResetTokens:       strings.TrimSpace(header.Get("x-ratelimit-reset-tokens")),
		RetryAfterMs:      retryAfterMilliseconds(header.Get("Retry-After")),
	}
}

func parseAPIError(statusCode int, body []byte) error {
	message := strings.TrimSpace(string(body))
	apiErr := &APIError{StatusCode: statusCode, Raw: message, Message: message}

	var payload struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Param   string `json:"param"`
			Code    any    `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		apiErr.Message = strings.TrimSpace(payload.Error.Message)
		apiErr.Type = strings.TrimSpace(payload.Error.Type)
		apiErr.Param = strings.TrimSpace(payload.Error.Param)
		if payload.Error.Code != nil {
			apiErr.Code = fmt.Sprint(payload.Error.Code)
		}
	}
	if apiErr.Message == "" {
		apiErr.Message = http.StatusText(statusCode)
	}
	return apiErr
}

func retryDelay(resp *http.Response, attempt int) time.Duration {
	if resp != nil {
		if retryAfter := retryAfterMilliseconds(resp.Header.Get("Retry-After")); retryAfter > 0 {
			return time.Duration(retryAfter) * time.Millisecond
		}
	}
	delay := 500 * time.Millisecond
	for i := 0; i < attempt; i++ {
		delay *= 2
		if delay >= 8*time.Second {
			return 8 * time.Second
		}
	}
	return delay
}

func retryAfterMilliseconds(raw string) int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.ParseFloat(raw, 64); err == nil && seconds >= 0 {
		return int64(seconds * 1000)
	}
	if when, err := http.ParseTime(raw); err == nil {
		if delay := time.Until(when); delay > 0 {
			return delay.Milliseconds()
		}
	}
	return 0
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func intHeader(header http.Header, key string) int {
	return intValue(header.Get(key))
}

func intValue(value any) int {
	switch typed := value.(type) {
	case nil:
		return 0
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		v, _ := typed.Int64()
		return int(v)
	case string:
		if typed == "" {
			return 0
		}
		if v, err := strconv.Atoi(typed); err == nil {
			return v
		}
		if f, err := strconv.ParseFloat(typed, 64); err == nil {
			return int(f)
		}
	}
	return 0
}

func contentToString(content any) string {
	switch typed := content.(type) {
	case string:
		return typed
	case []any:
		var builder strings.Builder
		for _, item := range typed {
			switch part := item.(type) {
			case string:
				builder.WriteString(part)
			case map[string]any:
				if text, ok := part["text"].(string); ok {
					builder.WriteString(text)
				}
			}
		}
		return builder.String()
	case map[string]any:
		if text, ok := typed["text"].(string); ok {
			return text
		}
	}
	return ""
}

func looksLikeJSONContentType(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	return strings.Contains(contentType, "application/json") || strings.Contains(contentType, "+json")
}

func looksLikeJSONBody(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func roundCurrency(value float64) float64 {
	return mathRound(value*1_000_000) / 1_000_000
}

func mathRound(value float64) float64 {
	if value < 0 {
		return float64(int64(value - 0.5))
	}
	return float64(int64(value + 0.5))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
