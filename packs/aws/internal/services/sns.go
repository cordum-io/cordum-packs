package services

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

// SNSService wraps AWS SNS operations.
type SNSService struct {
	client *sns.Client
}

// NewSNSService creates an SNS service from an AWS config.
func NewSNSService(cfg aws.Config) *SNSService {
	return &SNSService{client: sns.NewFromConfig(cfg)}
}

// Publish publishes a message to an SNS topic.
func (s *SNSService) Publish(ctx context.Context, params map[string]any) (any, error) {
	topicARN, _ := params["topic_arn"].(string)
	message, _ := params["message"].(string)
	if topicARN == "" || message == "" {
		return nil, fmt.Errorf("topic_arn and message are required")
	}

	input := &sns.PublishInput{
		TopicArn: aws.String(topicARN),
		Message:  aws.String(message),
	}
	if subject, ok := params["subject"].(string); ok && subject != "" {
		input.Subject = aws.String(subject)
	}
	if structure, ok := params["message_structure"].(string); ok && structure != "" {
		input.MessageStructure = aws.String(structure)
	}

	out, err := s.client.Publish(ctx, input)
	if err != nil {
		return nil, err
	}

	return map[string]any{"message_id": aws.ToString(out.MessageId)}, nil
}

// ListTopics lists SNS topics.
func (s *SNSService) ListTopics(ctx context.Context, _ map[string]any) (any, error) {
	out, err := s.client.ListTopics(ctx, &sns.ListTopicsInput{})
	if err != nil {
		return nil, err
	}

	topics := make([]string, 0, len(out.Topics))
	for _, t := range out.Topics {
		topics = append(topics, aws.ToString(t.TopicArn))
	}
	return map[string]any{"topics": topics, "count": len(topics)}, nil
}

// ListSubscriptions lists SNS subscriptions.
func (s *SNSService) ListSubscriptions(ctx context.Context, params map[string]any) (any, error) {
	input := &sns.ListSubscriptionsInput{}

	out, err := s.client.ListSubscriptions(ctx, input)
	if err != nil {
		return nil, err
	}

	subs := make([]map[string]any, 0, len(out.Subscriptions))
	for _, sub := range out.Subscriptions {
		subs = append(subs, map[string]any{
			"subscription_arn": aws.ToString(sub.SubscriptionArn),
			"topic_arn":        aws.ToString(sub.TopicArn),
			"protocol":         aws.ToString(sub.Protocol),
			"endpoint":         aws.ToString(sub.Endpoint),
		})
	}
	return map[string]any{"subscriptions": subs, "count": len(subs)}, nil
}
