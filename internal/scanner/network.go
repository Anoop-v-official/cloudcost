package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/storygame/cloudcost/internal/models"
)

type NetworkScanner struct {
	ec2Client  *ec2.Client
	elbClient  *elbv2.Client
	region     string
}

func NewNetworkScanner(cfg aws.Config, region string) *NetworkScanner {
	cfg.Region = region
	return &NetworkScanner{
		ec2Client: ec2.NewFromConfig(cfg),
		elbClient: elbv2.NewFromConfig(cfg),
		region:    region,
	}
}

// ScanNATGateways finds NAT Gateways and flags them for review
func (s *NetworkScanner) ScanNATGateways(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.ec2Client.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
		Filter: []ec2types.Filter{
			{
				Name:   aws.String("state"),
				Values: []string{"available"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe NAT gateways: %w", err)
	}

	for _, nat := range result.NatGateways {
		natID := *nat.NatGatewayId
		subnetID := ""
		if nat.SubnetId != nil {
			subnetID = *nat.SubnetId
		}
		name := getTagValue(nat.Tags, "Name")

		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("nat-%s", natID),
			ResourceType: models.ResourceNATGateway,
			ResourceID:   natID,
			ResourceName: name,
			Region:       s.region,
			Severity:     models.SeverityHigh,
			Title:        fmt.Sprintf("NAT Gateway: %s ($%.2f/mo base cost)", natID, models.NATGatewayPricing),
			Description:  fmt.Sprintf("NAT Gateway %s in subnet %s costs $%.2f/month base + data processing charges. Verify if instances need private-only networking or if public IPs would suffice.", natID, subnetID, models.NATGatewayPricing),
			MonthlyCost:  models.NATGatewayPricing,
			Action:       "If instances have public IPs and don't need private networking, delete the NAT Gateway",
			CLICommand:   fmt.Sprintf("aws ec2 delete-nat-gateway --nat-gateway-id %s --region %s", natID, s.region),
			ScannedAt:    time.Now(),
		})
	}

	return findings, nil
}

// ScanIdleLoadBalancers finds load balancers with no healthy targets
func (s *NetworkScanner) ScanIdleLoadBalancers(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.elbClient.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe load balancers: %w", err)
	}

	for _, lb := range result.LoadBalancers {
		lbARN := *lb.LoadBalancerArn
		lbName := *lb.LoadBalancerName
		lbType := string(lb.Type)

		// Get target groups for this LB
		tgResult, err := s.elbClient.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
			LoadBalancerArn: aws.String(lbARN),
		})
		if err != nil {
			continue
		}

		totalHealthy := 0
		totalTargets := 0

		for _, tg := range tgResult.TargetGroups {
			healthResult, err := s.elbClient.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{
				TargetGroupArn: tg.TargetGroupArn,
			})
			if err != nil {
				continue
			}

			totalTargets += len(healthResult.TargetHealthDescriptions)
			for _, th := range healthResult.TargetHealthDescriptions {
				if th.TargetHealth.State == "healthy" {
					totalHealthy++
				}
			}
		}

		// Flag if no healthy targets
		if totalHealthy > 0 {
			continue
		}

		// Estimate cost based on LB type
		var monthlyCost float64
		switch lbType {
		case "application":
			monthlyCost = 16.43 // ALB base cost
		case "network":
			monthlyCost = 16.43 // NLB base cost
		case "gateway":
			monthlyCost = 16.43
		default:
			monthlyCost = 16.43
		}

		severity := models.SeverityCritical
		if totalTargets == 0 {
			severity = models.SeverityCritical
		}

		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("elb-idle-%s", lbName),
			ResourceType: models.ResourceLoadBalancer,
			ResourceID:   lbARN,
			ResourceName: lbName,
			Region:       s.region,
			Severity:     severity,
			Title:        fmt.Sprintf("Idle %s Load Balancer: %s (0 healthy targets)", lbType, lbName),
			Description:  fmt.Sprintf("Load Balancer %s (%s) has %d targets, 0 healthy. Base cost: $%.2f/month + data charges.", lbName, lbType, totalTargets, monthlyCost),
			MonthlyCost:  monthlyCost,
			Action:       "Delete the load balancer and associated target groups if no longer needed",
			CLICommand:   fmt.Sprintf("aws elbv2 delete-load-balancer --load-balancer-arn %s --region %s", lbARN, s.region),
			ScannedAt:    time.Now(),
		})
	}

	return findings, nil
}

// ScanOrphanedTargetGroups finds target groups not associated with any load balancer
func (s *NetworkScanner) ScanOrphanedTargetGroups(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.elbClient.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe target groups: %w", err)
	}

	for _, tg := range result.TargetGroups {
		if len(tg.LoadBalancerArns) > 0 {
			continue // associated with an LB
		}

		tgName := *tg.TargetGroupName

		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("tg-orphaned-%s", tgName),
			ResourceType: models.ResourceTargetGroup,
			ResourceID:   *tg.TargetGroupArn,
			ResourceName: tgName,
			Region:       s.region,
			Severity:     models.SeverityLow,
			Title:        fmt.Sprintf("Orphaned Target Group: %s", tgName),
			Description:  fmt.Sprintf("Target Group %s is not associated with any load balancer", tgName),
			MonthlyCost:  0, // target groups don't cost, but indicate cleanup needed
			Action:       "Delete the orphaned target group",
			CLICommand:   fmt.Sprintf("aws elbv2 delete-target-group --target-group-arn %s --region %s", *tg.TargetGroupArn, s.region),
			ScannedAt:    time.Now(),
		})
	}

	return findings, nil
}
