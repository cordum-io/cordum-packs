package services

import (
	"context"
	"fmt"
)

// ComputeService wraps Azure Compute (VM) operations.
type ComputeService struct {
	client         *AzureClient
	subscriptionID string
	resourceGroup  string
}

// NewComputeService creates a Compute service.
func NewComputeService(client *AzureClient, subscriptionID, resourceGroup string) *ComputeService {
	return &ComputeService{client: client, subscriptionID: subscriptionID, resourceGroup: resourceGroup}
}

// ListVMs lists virtual machines.
func (s *ComputeService) ListVMs(ctx context.Context, params map[string]any) (any, error) {
	rg := s.resourceGroup
	if r, ok := params["resource_group"].(string); ok && r != "" {
		rg = r
	}
	if rg == "" {
		return nil, fmt.Errorf("resource_group is required")
	}

	url := ManagementURL(s.subscriptionID,
		fmt.Sprintf("resourceGroups/%s/providers/Microsoft.Compute/virtualMachines?api-version=2024-07-01", rg))

	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetVM gets a specific virtual machine.
func (s *ComputeService) GetVM(ctx context.Context, params map[string]any) (any, error) {
	rg := s.resourceGroup
	if r, ok := params["resource_group"].(string); ok && r != "" {
		rg = r
	}
	vmName, _ := params["vm_name"].(string)
	if rg == "" || vmName == "" {
		return nil, fmt.Errorf("resource_group and vm_name are required")
	}

	url := ManagementURL(s.subscriptionID,
		fmt.Sprintf("resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s?api-version=2024-07-01", rg, vmName))

	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetVMInstanceView gets VM instance view (running state).
func (s *ComputeService) GetVMInstanceView(ctx context.Context, params map[string]any) (any, error) {
	rg := s.resourceGroup
	if r, ok := params["resource_group"].(string); ok && r != "" {
		rg = r
	}
	vmName, _ := params["vm_name"].(string)
	if rg == "" || vmName == "" {
		return nil, fmt.Errorf("resource_group and vm_name are required")
	}

	url := ManagementURL(s.subscriptionID,
		fmt.Sprintf("resourceGroups/%s/providers/Microsoft.Compute/virtualMachines/%s/instanceView?api-version=2024-07-01", rg, vmName))

	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}
