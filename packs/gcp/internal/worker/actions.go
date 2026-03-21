package worker

import (
	"context"
	"fmt"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/gcpclient"
	"github.com/cordum-io/cordum-packs/packs/gcp/internal/services"
)

const (
	topicRead  = "job.gcp.read"
	topicWrite = "job.gcp.write"
)

type actionSpec struct {
	Intent  string
	Service string
}

var actionSpecs = map[string]actionSpec{
	// Cloud Functions
	"functions.call":           {Intent: "write", Service: "functions"},
	"functions.get_function":   {Intent: "read", Service: "functions"},
	"functions.list_functions": {Intent: "read", Service: "functions"},

	// Cloud Storage
	"storage.get_object":    {Intent: "read", Service: "storage"},
	"storage.upload_object": {Intent: "write", Service: "storage"},
	"storage.list_objects":  {Intent: "read", Service: "storage"},
	"storage.list_buckets":  {Intent: "read", Service: "storage"},
	"storage.delete_object": {Intent: "write", Service: "storage"},

	// Pub/Sub
	"pubsub.publish":            {Intent: "write", Service: "pubsub"},
	"pubsub.list_topics":        {Intent: "read", Service: "pubsub"},
	"pubsub.list_subscriptions": {Intent: "read", Service: "pubsub"},
	"pubsub.pull":               {Intent: "read", Service: "pubsub"},

	// Compute Engine
	"compute.list_instances":            {Intent: "read", Service: "compute"},
	"compute.get_instance":              {Intent: "read", Service: "compute"},
	"compute.aggregated_list_instances": {Intent: "read", Service: "compute"},

	// Monitoring
	"monitoring.list_time_series":        {Intent: "read", Service: "monitoring"},
	"monitoring.list_metric_descriptors": {Intent: "read", Service: "monitoring"},
	"monitoring.list_alert_policies":     {Intent: "read", Service: "monitoring"},

	// Secret Manager
	"secretmanager.access_secret_version": {Intent: "read", Service: "secretmanager"},
	"secretmanager.list_secrets":          {Intent: "read", Service: "secretmanager"},
	"secretmanager.get_secret":            {Intent: "read", Service: "secretmanager"},

	// IAM
	"iam.get_iam_policy":        {Intent: "read", Service: "iam"},
	"iam.list_roles":            {Intent: "read", Service: "iam"},
	"iam.list_service_accounts": {Intent: "read", Service: "iam"},
}

func dispatchAction(ctx context.Context, reqCfg gcpclient.RequestConfig, action string, spec actionSpec, params map[string]any) (any, error) {
	switch spec.Service {
	case "functions":
		svc, err := services.NewFunctionsService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()

		switch action {
		case "functions.call":
			return svc.CallFunction(ctx, params)
		case "functions.get_function":
			return svc.GetFunction(ctx, params)
		case "functions.list_functions":
			return svc.ListFunctions(ctx, params)
		}

	case "storage":
		svc, err := services.NewStorageService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()

		switch action {
		case "storage.get_object":
			return svc.GetObject(ctx, params)
		case "storage.upload_object":
			return svc.UploadObject(ctx, params)
		case "storage.list_objects":
			return svc.ListObjects(ctx, params)
		case "storage.list_buckets":
			return svc.ListBuckets(ctx, params)
		case "storage.delete_object":
			return svc.DeleteObject(ctx, params)
		}

	case "pubsub":
		svc, err := services.NewPubSubService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()

		switch action {
		case "pubsub.publish":
			return svc.Publish(ctx, params)
		case "pubsub.list_topics":
			return svc.ListTopics(ctx, params)
		case "pubsub.list_subscriptions":
			return svc.ListSubscriptions(ctx, params)
		case "pubsub.pull":
			return svc.Pull(ctx, params)
		}

	case "compute":
		svc, err := services.NewComputeService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()

		switch action {
		case "compute.list_instances":
			return svc.ListInstances(ctx, params)
		case "compute.get_instance":
			return svc.GetInstance(ctx, params)
		case "compute.aggregated_list_instances":
			return svc.AggregatedListInstances(ctx, params)
		}

	case "monitoring":
		svc, err := services.NewMonitoringService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()

		switch action {
		case "monitoring.list_time_series":
			return svc.ListTimeSeries(ctx, params)
		case "monitoring.list_metric_descriptors":
			return svc.ListMetricDescriptors(ctx, params)
		case "monitoring.list_alert_policies":
			return svc.ListAlertPolicies(ctx, params)
		}

	case "secretmanager":
		svc, err := services.NewSecretManagerService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()

		switch action {
		case "secretmanager.access_secret_version":
			return svc.AccessSecretVersion(ctx, params)
		case "secretmanager.list_secrets":
			return svc.ListSecrets(ctx, params)
		case "secretmanager.get_secret":
			return svc.GetSecret(ctx, params)
		}

	case "iam":
		svc, err := services.NewIAMService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()

		switch action {
		case "iam.get_iam_policy":
			return svc.GetIAMPolicy(ctx, params)
		case "iam.list_roles":
			return svc.ListRoles(ctx, params)
		case "iam.list_service_accounts":
			return svc.ListServiceAccounts(ctx, params)
		}
	}

	return nil, fmt.Errorf("unhandled action: %s", action)
}
