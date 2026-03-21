package services

import (
	"context"
	"fmt"
	"strings"

	pubsub "cloud.google.com/go/pubsub/apiv1"
	pubsubpb "cloud.google.com/go/pubsub/apiv1/pubsubpb"
	giterator "google.golang.org/api/iterator"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/gcpclient"
)

// PubSubService wraps Pub/Sub operations.
type PubSubService struct {
	publisher  *pubsub.PublisherClient
	subscriber *pubsub.SubscriberClient
	projectID  string
}

// NewPubSubService creates a Pub/Sub service.
func NewPubSubService(ctx context.Context, reqCfg gcpclient.RequestConfig) (*PubSubService, error) {
	publisher, err := pubsub.NewPublisherClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create pubsub publisher client: %w", err)
	}
	subscriber, err := pubsub.NewSubscriberClient(ctx, reqCfg.Options...)
	if err != nil {
		_ = publisher.Close()
		return nil, fmt.Errorf("create pubsub subscriber client: %w", err)
	}
	return &PubSubService{
		publisher:  publisher,
		subscriber: subscriber,
		projectID:  reqCfg.ProjectID,
	}, nil
}

// Close releases any client resources.
func (s *PubSubService) Close() error {
	if s.publisher != nil {
		_ = s.publisher.Close()
	}
	if s.subscriber != nil {
		return s.subscriber.Close()
	}
	return nil
}

// Publish publishes a message to a topic.
func (s *PubSubService) Publish(ctx context.Context, params map[string]any) (any, error) {
	topic := stringParam(params, "topic")
	dataValue := stringParam(params, "data")
	if topic == "" || dataValue == "" {
		return nil, fmt.Errorf("topic and data are required")
	}

	attributes, err := mapStringStringParam(params, "attributes")
	if err != nil {
		return nil, err
	}

	data, err := decodeStringData(dataValue, stringParam(params, "data_encoding"))
	if err != nil {
		return nil, err
	}

	response, err := s.publisher.Publish(ctx, &pubsubpb.PublishRequest{
		Topic: s.topicResource(topic),
		Messages: []*pubsubpb.PubsubMessage{
			{
				Data:       data,
				Attributes: attributes,
			},
		},
	})
	if err != nil {
		return nil, err
	}

	return protoToAny(response)
}

// ListTopics lists topics in the configured project.
func (s *PubSubService) ListTopics(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}

	pageToken := stringParam(params, "page_token")
	it := s.publisher.ListTopics(ctx, &pubsubpb.ListTopicsRequest{Project: s.projectResource()})
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var topics []*pubsubpb.Topic
	nextPageToken, err := pager.NextPage(&topics)
	if err != nil {
		return nil, err
	}

	mapped, err := protoSliceToMaps(topics)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"topics":          mapped,
		"next_page_token": nextPageToken,
	}, nil
}

// ListSubscriptions lists subscriptions in the configured project.
func (s *PubSubService) ListSubscriptions(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}

	pageToken := stringParam(params, "page_token")
	filterTopic := stringParam(params, "topic")
	if filterTopic != "" {
		filterTopic = s.topicResource(filterTopic)
	}

	it := s.subscriber.ListSubscriptions(ctx, &pubsubpb.ListSubscriptionsRequest{Project: s.projectResource()})
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var subscriptions []*pubsubpb.Subscription
	nextPageToken, err := pager.NextPage(&subscriptions)
	if err != nil {
		return nil, err
	}

	if filterTopic != "" {
		filtered := make([]*pubsubpb.Subscription, 0, len(subscriptions))
		for _, subscription := range subscriptions {
			if subscription.GetTopic() == filterTopic {
				filtered = append(filtered, subscription)
			}
		}
		subscriptions = filtered
	}

	mapped, err := protoSliceToMaps(subscriptions)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"subscriptions":   mapped,
		"next_page_token": nextPageToken,
	}, nil
}

// Pull synchronously pulls messages from a subscription.
func (s *PubSubService) Pull(ctx context.Context, params map[string]any) (any, error) {
	subscription := stringParam(params, "subscription")
	if subscription == "" {
		return nil, fmt.Errorf("subscription is required")
	}

	maxMessages, err := intParam(params, "max_messages", 1)
	if err != nil {
		return nil, err
	}
	if maxMessages <= 0 {
		maxMessages = 1
	}

	returnImmediately, err := boolParam(params, "return_immediately", false)
	if err != nil {
		return nil, err
	}

	response, err := s.subscriber.Pull(ctx, &pubsubpb.PullRequest{
		Subscription:      s.subscriptionResource(subscription),
		MaxMessages:       int32(maxMessages),
		ReturnImmediately: returnImmediately,
	})
	if err != nil {
		return nil, err
	}

	return protoToAny(response)
}

func (s *PubSubService) projectResource() string {
	return fmt.Sprintf("projects/%s", s.projectID)
}

func (s *PubSubService) topicResource(topic string) string {
	if isFullResource(topic) {
		return topic
	}
	return fmt.Sprintf("%s/topics/%s", s.projectResource(), strings.TrimSpace(topic))
}

func (s *PubSubService) subscriptionResource(subscription string) string {
	if isFullResource(subscription) {
		return subscription
	}
	return fmt.Sprintf("%s/subscriptions/%s", s.projectResource(), strings.TrimSpace(subscription))
}
