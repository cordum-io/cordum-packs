package services

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// CloudWatchService wraps AWS CloudWatch operations.
type CloudWatchService struct {
	client *cloudwatch.Client
}

// NewCloudWatchService creates a CloudWatch service from an AWS config.
func NewCloudWatchService(cfg aws.Config) *CloudWatchService {
	return &CloudWatchService{client: cloudwatch.NewFromConfig(cfg)}
}

// GetMetricData retrieves CloudWatch metric data.
func (s *CloudWatchService) GetMetricData(ctx context.Context, params map[string]any) (any, error) {
	namespace, _ := params["namespace"].(string)
	metricName, _ := params["metric_name"].(string)
	if namespace == "" || metricName == "" {
		return nil, fmt.Errorf("namespace and metric_name are required")
	}

	period := int32(300)
	if p, ok := params["period"].(float64); ok && p > 0 {
		period = int32(p)
	}

	stat := "Average"
	if s, ok := params["stat"].(string); ok && s != "" {
		stat = s
	}

	endTime := time.Now()
	startTime := endTime.Add(-1 * time.Hour)
	if hours, ok := params["hours_back"].(float64); ok && hours > 0 {
		startTime = endTime.Add(-time.Duration(hours) * time.Hour)
	}

	input := &cloudwatch.GetMetricDataInput{
		StartTime: aws.Time(startTime),
		EndTime:   aws.Time(endTime),
		MetricDataQueries: []cwtypes.MetricDataQuery{
			{
				Id: aws.String("m1"),
				MetricStat: &cwtypes.MetricStat{
					Metric: &cwtypes.Metric{
						Namespace:  aws.String(namespace),
						MetricName: aws.String(metricName),
					},
					Period: aws.Int32(period),
					Stat:   aws.String(stat),
				},
			},
		},
	}

	// Add dimensions
	if dims, ok := params["dimensions"].(map[string]any); ok {
		dimensions := make([]cwtypes.Dimension, 0, len(dims))
		for k, v := range dims {
			if vs, ok := v.(string); ok {
				dimensions = append(dimensions, cwtypes.Dimension{
					Name:  aws.String(k),
					Value: aws.String(vs),
				})
			}
		}
		input.MetricDataQueries[0].MetricStat.Metric.Dimensions = dimensions
	}

	out, err := s.client.GetMetricData(ctx, input)
	if err != nil {
		return nil, err
	}

	results := make([]map[string]any, 0, len(out.MetricDataResults))
	for _, r := range out.MetricDataResults {
		datapoints := make([]map[string]any, 0, len(r.Timestamps))
		for i, ts := range r.Timestamps {
			dp := map[string]any{"timestamp": ts.String()}
			if i < len(r.Values) {
				dp["value"] = r.Values[i]
			}
			datapoints = append(datapoints, dp)
		}
		results = append(results, map[string]any{
			"id":         aws.ToString(r.Id),
			"label":      aws.ToString(r.Label),
			"datapoints": datapoints,
		})
	}

	return map[string]any{"metric_data_results": results}, nil
}

// ListMetrics lists available CloudWatch metrics.
func (s *CloudWatchService) ListMetrics(ctx context.Context, params map[string]any) (any, error) {
	input := &cloudwatch.ListMetricsInput{}
	if ns, ok := params["namespace"].(string); ok && ns != "" {
		input.Namespace = aws.String(ns)
	}
	if name, ok := params["metric_name"].(string); ok && name != "" {
		input.MetricName = aws.String(name)
	}

	out, err := s.client.ListMetrics(ctx, input)
	if err != nil {
		return nil, err
	}

	metrics := make([]map[string]any, 0, len(out.Metrics))
	for _, m := range out.Metrics {
		metrics = append(metrics, map[string]any{
			"namespace":   aws.ToString(m.Namespace),
			"metric_name": aws.ToString(m.MetricName),
		})
	}

	return map[string]any{"metrics": metrics, "count": len(metrics)}, nil
}

// DescribeAlarms describes CloudWatch alarms.
func (s *CloudWatchService) DescribeAlarms(ctx context.Context, params map[string]any) (any, error) {
	input := &cloudwatch.DescribeAlarmsInput{}

	if names, ok := params["alarm_names"].([]any); ok {
		for _, n := range names {
			if s, ok := n.(string); ok {
				input.AlarmNames = append(input.AlarmNames, s)
			}
		}
	}

	out, err := s.client.DescribeAlarms(ctx, input)
	if err != nil {
		return nil, err
	}

	alarms := make([]map[string]any, 0, len(out.MetricAlarms))
	for _, a := range out.MetricAlarms {
		alarms = append(alarms, map[string]any{
			"alarm_name":  aws.ToString(a.AlarmName),
			"alarm_arn":   aws.ToString(a.AlarmArn),
			"state":       string(a.StateValue),
			"metric_name": aws.ToString(a.MetricName),
			"namespace":   aws.ToString(a.Namespace),
		})
	}

	return map[string]any{"alarms": alarms, "count": len(alarms)}, nil
}
