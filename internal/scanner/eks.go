package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/storygame/cloudcost/internal/models"
)

// EKS control plane costs $0.10/hr = $73/mo in all regions
const eksControlPlaneMonthlyCost = 73.0

type EKSScanner struct {
	eksClient *eks.Client
	region    string
}

func NewEKSScanner(cfg aws.Config, region string) *EKSScanner {
	cfg.Region = region
	return &EKSScanner{
		eksClient: eks.NewFromConfig(cfg),
		region:    region,
	}
}

// ScanEKSClusters finds EKS clusters and checks for idle/unused ones
func (s *EKSScanner) ScanEKSClusters(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	listResult, err := s.eksClient.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list EKS clusters: %w", err)
	}

	for _, clusterName := range listResult.Clusters {
		// Describe the cluster
		descResult, err := s.eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: aws.String(clusterName),
		})
		if err != nil {
			continue
		}

		cluster := descResult.Cluster
		if cluster.Status != "ACTIVE" {
			continue
		}

		// List node groups
		ngResult, err := s.eksClient.ListNodegroups(ctx, &eks.ListNodegroupsInput{
			ClusterName: aws.String(clusterName),
		})
		if err != nil {
			continue
		}

		totalNodes := 0
		totalDesired := 0
		var nodeGroupDetails []string
		var totalNodeCost float64

		for _, ngName := range ngResult.Nodegroups {
			ngDesc, err := s.eksClient.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
				ClusterName:   aws.String(clusterName),
				NodegroupName: aws.String(ngName),
			})
			if err != nil {
				continue
			}

			ng := ngDesc.Nodegroup
			desired := int(*ng.ScalingConfig.DesiredSize)
			min := int(*ng.ScalingConfig.MinSize)
			max := int(*ng.ScalingConfig.MaxSize)
			totalDesired += desired
			totalNodes += desired

			instanceTypes := ""
			if len(ng.InstanceTypes) > 0 {
				instanceTypes = ng.InstanceTypes[0]
			}

			// Estimate node cost
			hourly, ok := ec2Pricing[instanceTypes]
			if !ok {
				hourly = 0.10
			}
			nodeCost := hourly * 730 * float64(desired)
			totalNodeCost += nodeCost

			detail := fmt.Sprintf("%s: %s (min:%d/desired:%d/max:%d) $%.2f/mo", ngName, instanceTypes, min, desired, max, nodeCost)
			nodeGroupDetails = append(nodeGroupDetails, detail)
		}

		totalCost := eksControlPlaneMonthlyCost + totalNodeCost

		// Check if cluster has zero running nodes
		if totalDesired == 0 {
			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("eks-idle-%s", clusterName),
				ResourceType: models.ResourceEC2Instance, // using EC2 as closest
				ResourceID:   clusterName,
				ResourceName: clusterName,
				Region:       s.region,
				Severity:     models.SeverityCritical,
				Title:        fmt.Sprintf("EKS cluster with zero nodes: %s ($%.2f/mo control plane)", clusterName, eksControlPlaneMonthlyCost),
				Description: fmt.Sprintf(
					"EKS cluster %s has %d node groups but 0 desired nodes.\n"+
						"     Control plane alone costs $%.2f/mo.\n"+
						"     If not used for scale-to-zero workloads, delete the cluster.",
					clusterName, len(ngResult.Nodegroups), eksControlPlaneMonthlyCost,
				),
				MonthlyCost: eksControlPlaneMonthlyCost,
				Action:      "Delete the cluster if no longer needed",
				CLICommand: fmt.Sprintf(
					"eksctl delete cluster --name %s --region %s --wait",
					clusterName, s.region,
				),
				ScannedAt: time.Now(),
			})
			continue
		}

		// Check if cluster has very few nodes (possible waste)
		if totalDesired <= 2 && len(ngResult.Nodegroups) > 0 {
			// Small cluster — flag for review since control plane is $73/mo overhead
			nodeDetails := ""
			for _, d := range nodeGroupDetails {
				nodeDetails += fmt.Sprintf("\n     • %s", d)
			}

			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("eks-small-%s", clusterName),
				ResourceType: models.ResourceEC2Instance,
				ResourceID:   clusterName,
				ResourceName: clusterName,
				Region:       s.region,
				Severity:     models.SeverityMedium,
				Title:        fmt.Sprintf("Small EKS cluster: %s (%d nodes, $%.2f/mo total)", clusterName, totalDesired, totalCost),
				Description: fmt.Sprintf(
					"EKS cluster %s has only %d running nodes. The $%.2f/mo control plane overhead may not be justified.\n"+
						"     Node groups:%s\n"+
						"     Total: $%.2f/mo (control plane) + $%.2f/mo (nodes) = $%.2f/mo\n"+
						"     Consider: Could these workloads run on EC2 directly or ECS?",
					clusterName, totalDesired, eksControlPlaneMonthlyCost,
					nodeDetails,
					eksControlPlaneMonthlyCost, totalNodeCost, totalCost,
				),
				MonthlyCost: eksControlPlaneMonthlyCost, // potential savings = control plane
				Action:      "Review if EKS overhead is justified for this workload size",
				CLICommand: fmt.Sprintf(
					"# Check what's running:\nkubectl --context %s get pods --all-namespaces",
					clusterName,
				),
				ScannedAt: time.Now(),
			})
		}

		// Check for node groups scaled to zero that might have forgotten resources
		for _, ngName := range ngResult.Nodegroups {
			ngDesc, err := s.eksClient.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
				ClusterName:   aws.String(clusterName),
				NodegroupName: aws.String(ngName),
			})
			if err != nil {
				continue
			}

			ng := ngDesc.Nodegroup
			if *ng.ScalingConfig.DesiredSize == 0 && *ng.ScalingConfig.MaxSize > 0 {
				instanceType := ""
				if len(ng.InstanceTypes) > 0 {
					instanceType = ng.InstanceTypes[0]
				}

				findings = append(findings, models.Finding{
					ID:           fmt.Sprintf("eks-ng-zero-%s-%s", clusterName, ngName),
					ResourceType: models.ResourceEC2Instance,
					ResourceID:   fmt.Sprintf("%s/%s", clusterName, ngName),
					ResourceName: ngName,
					Region:       s.region,
					Severity:     models.SeverityLow,
					Title:        fmt.Sprintf("Scaled-to-zero node group: %s/%s (%s, max:%d)", clusterName, ngName, instanceType, *ng.ScalingConfig.MaxSize),
					Description: fmt.Sprintf(
						"Node group %s in cluster %s is scaled to 0 but configured for max %d nodes (%s).\n"+
							"     If this is intentional (scale-to-zero with KEDA/HPA), no action needed.\n"+
							"     If not used, delete the node group.",
						ngName, clusterName, *ng.ScalingConfig.MaxSize, instanceType,
					),
					MonthlyCost: 0,
					Action:      "Delete if no longer used for scale-to-zero workloads",
					CLICommand: fmt.Sprintf(
						"aws eks delete-nodegroup --cluster-name %s --nodegroup-name %s --region %s",
						clusterName, ngName, s.region,
					),
					ScannedAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}
