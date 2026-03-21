package services

import (
	"context"
	"fmt"
	"strings"
)

// MonitorService wraps Azure Monitor operations.
type MonitorService struct {
	client         *AzureClient
	subscriptionID string
	resourceGroup  string
}

// NewMonitorService creates a Monitor service.
func NewMonitorService(client *AzureClient, subscriptionID, resourceGroup string) *MonitorService {
	return &MonitorService{client: client, subscriptionID: subscriptionID, resourceGroup: resourceGroup}
}

// QueryMetrics queries Azure Monitor metrics.
func (s *MonitorService) QueryMetrics(ctx context.Context, params map[string]any) (any, error) {
	resourceID, _ := params["resource_id"].(string)
	if resourceID == "" {
		return nil, fmt.Errorf("resource_id is required")
	}

	metricNames, _ := params["metric_names"].(string)
	timespan, _ := params["timespan"].(string)
	interval, _ := params["interval"].(string)
	aggregation, _ := params["aggregation"].(string)

	queryParts := []string{"api-version=2024-02-01"}
	if metricNames != "" {
		queryParts = append(queryParts, "metricnames="+metricNames)
	}
	if timespan != "" {
		queryParts = append(queryParts, "timespan="+timespan)
	}
	if interval != "" {
		queryParts = append(queryParts, "interval="+interval)
	}
	if aggregation != "" {
		queryParts = append(queryParts, "aggregation="+aggregation)
	}

	url := fmt.Sprintf("https://management.azure.com%s/providers/Microsoft.Insights/metrics?%s",
		resourceID, strings.Join(queryParts, "&"))

	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListAlertRules lists alert rules.
func (s *MonitorService) ListAlertRules(ctx context.Context, params map[string]any) (any, error) {
	rg := s.resourceGroup
	if r, ok := params["resource_group"].(string); ok && r != "" {
		rg = r
	}

	var url string
	if rg != "" {
		url = ManagementURL(s.subscriptionID,
			fmt.Sprintf("resourceGroups/%s/providers/Microsoft.Insights/metricAlerts?api-version=2018-03-01", rg))
	} else {
		url = ManagementURL(s.subscriptionID,
			"providers/Microsoft.Insights/metricAlerts?api-version=2018-03-01")
	}

	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}
