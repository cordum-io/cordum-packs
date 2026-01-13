package types

// IncidentInput is the workflow input schema.
type IncidentInput struct {
	IncidentID  string      `json:"incident_id"`
	Title       string      `json:"title,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Source      SourceInfo  `json:"source"`
	Raw         map[string]any `json:"raw,omitempty"`
	Destination Destination `json:"destination"`
}

type SourceInfo struct {
	System string `json:"system"`
	URL    string `json:"url,omitempty"`
}

type Destination struct {
	Mode            string `json:"mode"`
	SlackWebhookURL string `json:"slack_webhook_url,omitempty"`
}

type EvidenceItem struct {
	Kind        string `json:"kind"`
	Title       string `json:"title,omitempty"`
	ArtifactPtr string `json:"artifact_ptr,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
}

type EvidenceBundle struct {
	IncidentID        string         `json:"incident_id"`
	Evidence          []EvidenceItem `json:"evidence"`
	NormalizedContext map[string]any `json:"normalized_context,omitempty"`
	CollectedAt       string         `json:"collected_at"`
}

type Summary struct {
	IncidentID      string   `json:"incident_id"`
	SummaryMarkdown string   `json:"summary_md"`
	Highlights      []string `json:"highlights,omitempty"`
	ActionItems     []string `json:"action_items,omitempty"`
	Confidence      float64  `json:"confidence,omitempty"`
	Model           string   `json:"model,omitempty"`
	ArtifactPtr     string   `json:"artifact_ptr,omitempty"`
}

type SlackResult struct {
	OK        bool   `json:"ok"`
	Channel   string `json:"channel,omitempty"`
	Ts        string `json:"ts,omitempty"`
	Permalink string `json:"permalink,omitempty"`
	Error     string `json:"error,omitempty"`
}

type PostResult struct {
	IncidentID  string       `json:"incident_id"`
	Mode        string       `json:"mode"`
	Slack       *SlackResult `json:"slack,omitempty"`
	ArtifactPtr string       `json:"artifact_ptr,omitempty"`
	PostedAt    string       `json:"posted_at,omitempty"`
}
