package gatewayclient

import (
	"context"
	"strings"

	sdkclient "github.com/cordum/cordum/sdk/client"
)

type Client struct {
	inner *sdkclient.Client
}

func New(baseURL, apiKey, tenantID string) *Client {
	inner := sdkclient.New(baseURL, apiKey)
	if trimmed := strings.TrimSpace(tenantID); trimmed != "" {
		inner.TenantID = trimmed
	}
	return &Client{inner: inner}
}

func (c *Client) SubmitJob(ctx context.Context, req *sdkclient.JobSubmitRequest) (*sdkclient.JobSubmitResponse, error) {
	return c.inner.SubmitJob(ctx, req)
}

func (c *Client) GetJob(ctx context.Context, jobID string) (map[string]any, error) {
	return c.inner.GetJob(ctx, jobID)
}
