package services

import (
	"bytes"
	"context"
	"fmt"
)

// ServiceBusService wraps Azure Service Bus operations.
type ServiceBusService struct {
	client *AzureClient
}

// NewServiceBusService creates a Service Bus service.
func NewServiceBusService(client *AzureClient) *ServiceBusService {
	return &ServiceBusService{client: client}
}

// SendMessage sends a message to a Service Bus queue or topic.
func (s *ServiceBusService) SendMessage(ctx context.Context, params map[string]any) (any, error) {
	namespace, _ := params["namespace"].(string)
	queueOrTopic, _ := params["queue_or_topic"].(string)
	messageBody, _ := params["message_body"].(string)
	if namespace == "" || queueOrTopic == "" || messageBody == "" {
		return nil, fmt.Errorf("namespace, queue_or_topic, and message_body are required")
	}

	url := fmt.Sprintf("https://%s.servicebus.windows.net/%s/messages", namespace, queueOrTopic)
	_, status, err := s.client.DoRequest(ctx, "POST", url, bytes.NewReader([]byte(messageBody)), "https://servicebus.azure.net/.default", nil)
	if err != nil {
		return nil, err
	}

	return map[string]any{"sent": true, "status_code": status}, nil
}

// PeekMessages peeks at messages in a queue.
func (s *ServiceBusService) PeekMessages(ctx context.Context, params map[string]any) (any, error) {
	namespace, _ := params["namespace"].(string)
	queueOrTopic, _ := params["queue_or_topic"].(string)
	if namespace == "" || queueOrTopic == "" {
		return nil, fmt.Errorf("namespace and queue_or_topic are required")
	}

	url := fmt.Sprintf("https://%s.servicebus.windows.net/%s/messages/head", namespace, queueOrTopic)
	result, status, err := s.client.DoRequest(ctx, "POST", url, nil, "https://servicebus.azure.net/.default", nil)
	if err != nil {
		return nil, err
	}

	return map[string]any{"status_code": status, "message": result}, nil
}
