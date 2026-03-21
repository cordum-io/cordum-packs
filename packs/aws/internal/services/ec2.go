package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// EC2Service wraps AWS EC2 describe operations (read-only).
type EC2Service struct {
	client *ec2.Client
}

// NewEC2Service creates an EC2 service from an AWS config.
func NewEC2Service(cfg aws.Config) *EC2Service {
	return &EC2Service{client: ec2.NewFromConfig(cfg)}
}

// DescribeInstances describes EC2 instances.
func (s *EC2Service) DescribeInstances(ctx context.Context, params map[string]any) (any, error) {
	input := &ec2.DescribeInstancesInput{}

	if ids, ok := params["instance_ids"].([]any); ok {
		for _, id := range ids {
			if s, ok := id.(string); ok {
				input.InstanceIds = append(input.InstanceIds, s)
			}
		}
	}

	out, err := s.client.DescribeInstances(ctx, input)
	if err != nil {
		return nil, err
	}

	instances := make([]map[string]any, 0)
	for _, reservation := range out.Reservations {
		for _, inst := range reservation.Instances {
			instance := map[string]any{
				"instance_id":    aws.ToString(inst.InstanceId),
				"instance_type":  string(inst.InstanceType),
				"state":          string(inst.State.Name),
				"private_ip":     aws.ToString(inst.PrivateIpAddress),
				"public_ip":      aws.ToString(inst.PublicIpAddress),
				"vpc_id":         aws.ToString(inst.VpcId),
				"subnet_id":      aws.ToString(inst.SubnetId),
				"launch_time":    inst.LaunchTime.String(),
				"image_id":       aws.ToString(inst.ImageId),
			}
			// Tags
			tags := make(map[string]string, len(inst.Tags))
			for _, tag := range inst.Tags {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			instance["tags"] = tags
			instances = append(instances, instance)
		}
	}

	return map[string]any{"instances": instances, "count": len(instances)}, nil
}

// DescribeSecurityGroups describes security groups.
func (s *EC2Service) DescribeSecurityGroups(ctx context.Context, params map[string]any) (any, error) {
	input := &ec2.DescribeSecurityGroupsInput{}

	if ids, ok := params["group_ids"].([]any); ok {
		for _, id := range ids {
			if s, ok := id.(string); ok {
				input.GroupIds = append(input.GroupIds, s)
			}
		}
	}

	out, err := s.client.DescribeSecurityGroups(ctx, input)
	if err != nil {
		return nil, err
	}

	groups := make([]map[string]any, 0, len(out.SecurityGroups))
	for _, sg := range out.SecurityGroups {
		groups = append(groups, map[string]any{
			"group_id":    aws.ToString(sg.GroupId),
			"group_name":  aws.ToString(sg.GroupName),
			"description": aws.ToString(sg.Description),
			"vpc_id":      aws.ToString(sg.VpcId),
		})
	}

	return map[string]any{"security_groups": groups, "count": len(groups)}, nil
}

// DescribeVPCs describes VPCs.
func (s *EC2Service) DescribeVPCs(ctx context.Context, params map[string]any) (any, error) {
	input := &ec2.DescribeVpcsInput{}

	if ids, ok := params["vpc_ids"].([]any); ok {
		for _, id := range ids {
			if s, ok := id.(string); ok {
				input.VpcIds = append(input.VpcIds, s)
			}
		}
	}

	out, err := s.client.DescribeVpcs(ctx, input)
	if err != nil {
		return nil, err
	}

	vpcs := make([]map[string]any, 0, len(out.Vpcs))
	for _, vpc := range out.Vpcs {
		vpcs = append(vpcs, map[string]any{
			"vpc_id":     aws.ToString(vpc.VpcId),
			"cidr_block": aws.ToString(vpc.CidrBlock),
			"state":      string(vpc.State),
			"is_default": aws.ToBool(vpc.IsDefault),
		})
	}

	return map[string]any{"vpcs": vpcs, "count": len(vpcs)}, nil
}
