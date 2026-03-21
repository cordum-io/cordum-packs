package services

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// SQSService wraps AWS SQS operations.
type SQSService struct {
	client *sqs.Client
}

// NewSQSService creates an SQS service from an AWS config.
func NewSQSService(cfg aws.Config) *SQSService {
	return &SQSService{client: sqs.NewFromConfig(cfg)}
}

// SendMessage sends a message to an SQS queue.
func (s *SQSService) SendMessage(ctx context.Context, params map[string]any) (any, error) {
	queueURL, _ := params["queue_url"].(string)
	messageBody, _ := params["message_body"].(string)
	if queueURL == "" || messageBody == "" {
		return nil, fmt.Errorf("queue_url and message_body are required")
	}

	input := &sqs.SendMessageInput{
		QueueUrl:    aws.String(queueURL),
		MessageBody: aws.String(messageBody),
	}

	if delay, ok := params["delay_seconds"].(float64); ok && delay > 0 {
		input.DelaySeconds = int32(delay)
	}
	if groupID, ok := params["message_group_id"].(string); ok && groupID != "" {
		input.MessageGroupId = aws.String(groupID)
	}
	if dedupID, ok := params["message_deduplication_id"].(string); ok && dedupID != "" {
		input.MessageDeduplicationId = aws.String(dedupID)
	}

	// Message attributes
	if attrs, ok := params["message_attributes"].(map[string]any); ok {
		input.MessageAttributes = make(map[string]sqstypes.MessageAttributeValue, len(attrs))
		for k, v := range attrs {
			if attrMap, ok := v.(map[string]any); ok {
				dataType, _ := attrMap["DataType"].(string)
				stringValue, _ := attrMap["StringValue"].(string)
				if dataType == "" {
					dataType = "String"
				}
				input.MessageAttributes[k] = sqstypes.MessageAttributeValue{
					DataType:    aws.String(dataType),
					StringValue: aws.String(stringValue),
				}
			}
		}
	}

	out, err := s.client.SendMessage(ctx, input)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"message_id": aws.ToString(out.MessageId),
		"md5":        aws.ToString(out.MD5OfMessageBody),
	}, nil
}

// ReceiveMessage receives messages from an SQS queue.
func (s *SQSService) ReceiveMessage(ctx context.Context, params map[string]any) (any, error) {
	queueURL, _ := params["queue_url"].(string)
	if queueURL == "" {
		return nil, fmt.Errorf("queue_url is required")
	}

	input := &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(queueURL),
		MaxNumberOfMessages: 10,
		WaitTimeSeconds:     5,
	}

	if maxMsgs, ok := params["max_messages"].(float64); ok && maxMsgs > 0 {
		input.MaxNumberOfMessages = int32(maxMsgs)
	}
	if waitTime, ok := params["wait_time_seconds"].(float64); ok {
		input.WaitTimeSeconds = int32(waitTime)
	}

	out, err := s.client.ReceiveMessage(ctx, input)
	if err != nil {
		return nil, err
	}

	messages := make([]map[string]any, 0, len(out.Messages))
	for _, msg := range out.Messages {
		messages = append(messages, map[string]any{
			"message_id":     aws.ToString(msg.MessageId),
			"receipt_handle": aws.ToString(msg.ReceiptHandle),
			"body":           aws.ToString(msg.Body),
			"md5":            aws.ToString(msg.MD5OfBody),
		})
	}
	return map[string]any{"messages": messages, "count": len(messages)}, nil
}

// GetQueueURL retrieves the URL of an SQS queue by name.
func (s *SQSService) GetQueueURL(ctx context.Context, params map[string]any) (any, error) {
	queueName, _ := params["queue_name"].(string)
	if queueName == "" {
		return nil, fmt.Errorf("queue_name is required")
	}

	out, err := s.client.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
		QueueName: aws.String(queueName),
	})
	if err != nil {
		return nil, err
	}

	return map[string]any{"queue_url": aws.ToString(out.QueueUrl)}, nil
}

// ListQueues lists SQS queues.
func (s *SQSService) ListQueues(ctx context.Context, params map[string]any) (any, error) {
	input := &sqs.ListQueuesInput{}
	if prefix, ok := params["queue_name_prefix"].(string); ok && prefix != "" {
		input.QueueNamePrefix = aws.String(prefix)
	}

	out, err := s.client.ListQueues(ctx, input)
	if err != nil {
		return nil, err
	}

	queues := make([]string, len(out.QueueUrls))
	copy(queues, out.QueueUrls)
	return map[string]any{"queue_urls": queues, "count": len(queues)}, nil
}

