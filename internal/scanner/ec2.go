package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/Anoop-v-official/cloudcost/internal/models"
)

// EC2 On-Demand pricing per hour (ap-south-1, Linux)
var ec2Pricing = map[string]float64{
	"t2.micro":   0.0116,
	"t2.small":   0.0232,
	"t2.medium":  0.0464,
	"t2.large":   0.0928,
	"t2.xlarge":  0.1856,
	"t2.2xlarge": 0.3712,
	"t3.micro":   0.0104,
	"t3.small":   0.0208,
	"t3.medium":  0.0416,
	"t3.large":   0.0832,
	"t3.xlarge":  0.1664,
	"t3.2xlarge": 0.3328,
	"m5.large":   0.096,
	"m5.xlarge":  0.192,
	"m5.2xlarge": 0.384,
	"m5.4xlarge": 0.768,
	"r5.large":   0.126,
	"r5.xlarge":  0.252,
	"c5.large":   0.085,
	"c5.xlarge":  0.170,
}

type EC2Scanner struct {
	ec2Client *ec2.Client
	cwClient  *cloudwatch.Client
	region    string
}

func NewEC2Scanner(cfg aws.Config, region string) *EC2Scanner {
	cfg.Region = region
	return &EC2Scanner{
		ec2Client: ec2.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
		region:    region,
	}
}

// ScanUnusedElasticIPs finds Elastic IPs not associated with any instance
func (s *EC2Scanner) ScanUnusedElasticIPs(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.ec2Client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe addresses: %w", err)
	}

	for _, addr := range result.Addresses {
		if addr.AssociationId != nil {
			continue // attached, skip
		}

		name := getTagValue(addr.Tags, "Name")
		ip := ""
		if addr.PublicIp != nil {
			ip = *addr.PublicIp
		}

		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("eip-unused-%s", *addr.AllocationId),
			ResourceType: models.ResourceElasticIP,
			ResourceID:   *addr.AllocationId,
			ResourceName: name,
			Region:       s.region,
			Severity:     models.SeverityHigh,
			Title:        fmt.Sprintf("Unused Elastic IP: %s", ip),
			Description:  fmt.Sprintf("Elastic IP %s (%s) is not associated with any instance. Unattached EIPs cost $%.2f/month.", ip, name, models.EIPIdlePricing),
			MonthlyCost:  models.EIPIdlePricing,
			Action:       "Release the Elastic IP if no longer needed",
			CLICommand:   fmt.Sprintf("aws ec2 release-address --allocation-id %s --region %s", *addr.AllocationId, s.region),
			ScannedAt:    time.Now(),
		})
	}

	return findings, nil
}

// ScanUnderutilizedInstances finds running instances with low CPU utilization
func (s *EC2Scanner) ScanUnderutilizedInstances(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %w", err)
	}

	for _, reservation := range result.Reservations {
		for _, inst := range reservation.Instances {
			instanceType := string(inst.InstanceType)
			name := getTagValue(inst.Tags, "Name")
			instanceID := *inst.InstanceId

			// Get average CPU over last 7 days
			avgCPU, err := s.getAverageCPU(ctx, instanceID, 7)
			if err != nil {
				continue
			}

			// Skip if CPU utilization is above 20%
			if avgCPU > 20.0 {
				continue
			}

			hourlyPrice, ok := ec2Pricing[instanceType]
			if !ok {
				hourlyPrice = 0.10 // default estimate
			}
			monthlyCost := hourlyPrice * 730

			// Suggest a smaller instance type
			suggestedType := suggestDownsize(instanceType)
			suggestedPrice, ok := ec2Pricing[suggestedType]
			if !ok {
				suggestedPrice = hourlyPrice * 0.5
			}
			savings := (hourlyPrice - suggestedPrice) * 730

			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("ec2-underutil-%s", instanceID),
				ResourceType: models.ResourceEC2Instance,
				ResourceID:   instanceID,
				ResourceName: name,
				Region:       s.region,
				Severity:     models.SeverityHigh,
				Title:        fmt.Sprintf("Underutilized instance: %s (%s, avg CPU: %.1f%%)", name, instanceType, avgCPU),
				Description:  fmt.Sprintf("Instance %s (%s, %s) has avg CPU of %.1f%% over 7 days. Current cost: $%.2f/month. Downsize to %s to save $%.2f/month.", instanceID, name, instanceType, avgCPU, monthlyCost, suggestedType, savings),
				MonthlyCost:  savings,
				Action:       fmt.Sprintf("Downsize from %s to %s", instanceType, suggestedType),
				CLICommand:   fmt.Sprintf("# Stop instance, change type, start:\naws ec2 stop-instances --instance-ids %s --region %s\naws ec2 modify-instance-attribute --instance-id %s --instance-type %s --region %s\naws ec2 start-instances --instance-ids %s --region %s", instanceID, s.region, instanceID, suggestedType, s.region, instanceID, s.region),
				ScannedAt:    time.Now(),
			})
		}
	}

	return findings, nil
}

// ScanStoppedInstancesWithVolumes finds stopped instances still incurring EBS costs
func (s *EC2Scanner) ScanStoppedInstancesWithVolumes(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"stopped"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe stopped instances: %w", err)
	}

	for _, reservation := range result.Reservations {
		for _, inst := range reservation.Instances {
			name := getTagValue(inst.Tags, "Name")
			instanceID := *inst.InstanceId

			// Calculate EBS cost for attached volumes
			var totalEBSCost float64
			var totalSize int32
			for _, bdm := range inst.BlockDeviceMappings {
				if bdm.Ebs != nil && bdm.Ebs.VolumeId != nil {
					volResult, err := s.ec2Client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
						VolumeIds: []string{*bdm.Ebs.VolumeId},
					})
					if err == nil && len(volResult.Volumes) > 0 {
						vol := volResult.Volumes[0]
						volType := string(vol.VolumeType)
						price, ok := models.EBSPricing[volType]
						if !ok {
							price = 0.10
						}
						totalEBSCost += float64(*vol.Size) * price
						totalSize += *vol.Size
					}
				}
			}

			if totalEBSCost < 1.0 {
				continue // skip trivial costs
			}

			// Check how long it's been stopped
			stoppedSince := ""
			if inst.StateTransitionReason != nil {
				stoppedSince = *inst.StateTransitionReason
			}

			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("ec2-stopped-%s", instanceID),
				ResourceType: models.ResourceEC2Instance,
				ResourceID:   instanceID,
				ResourceName: name,
				Region:       s.region,
				Severity:     models.SeverityMedium,
				Title:        fmt.Sprintf("Stopped instance with %d GB EBS ($%.2f/mo)", totalSize, totalEBSCost),
				Description:  fmt.Sprintf("Instance %s (%s) is stopped but its %d GB of EBS volumes cost $%.2f/month. %s", instanceID, name, totalSize, totalEBSCost, stoppedSince),
				MonthlyCost:  totalEBSCost,
				Action:       "If not needed, snapshot the volumes and terminate the instance",
				CLICommand:   fmt.Sprintf("# Terminate instance (EBS volumes will be deleted if DeleteOnTermination=true):\naws ec2 terminate-instances --instance-ids %s --region %s", instanceID, s.region),
				ScannedAt:    time.Now(),
			})
		}
	}

	return findings, nil
}

// ScanOldAMIs finds AMIs older than specified days
func (s *EC2Scanner) ScanOldAMIs(ctx context.Context, maxAgeDays int) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.ec2Client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe images: %w", err)
	}

	cutoff := time.Now().AddDate(0, 0, -maxAgeDays)

	for _, img := range result.Images {
		creationDate, err := time.Parse(time.RFC3339, *img.CreationDate)
		if err != nil {
			continue
		}

		if creationDate.After(cutoff) {
			continue
		}

		// Calculate associated snapshot costs
		var snapshotCost float64
		for _, bdm := range img.BlockDeviceMappings {
			if bdm.Ebs != nil && bdm.Ebs.VolumeSize != nil {
				snapshotCost += float64(*bdm.Ebs.VolumeSize) * models.SnapshotPricing
			}
		}

		ageDays := int(time.Since(creationDate).Hours() / 24)
		name := ""
		if img.Name != nil {
			name = *img.Name
		}

		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("ami-old-%s", *img.ImageId),
			ResourceType: models.ResourceEC2Instance,
			ResourceID:   *img.ImageId,
			ResourceName: name,
			Region:       s.region,
			Severity:     models.SeverityLow,
			Title:        fmt.Sprintf("Old AMI: %s (%d days old)", name, ageDays),
			Description:  fmt.Sprintf("AMI %s (%s) is %d days old with associated snapshot storage costing $%.2f/month", *img.ImageId, name, ageDays, snapshotCost),
			MonthlyCost:  snapshotCost,
			Action:       "Deregister AMI and delete associated snapshots if no longer needed",
			CLICommand:   fmt.Sprintf("aws ec2 deregister-image --image-id %s --region %s", *img.ImageId, s.region),
			ScannedAt:    time.Now(),
		})
	}

	return findings, nil
}

// getAverageCPU returns avg CPU utilization over the last N days
func (s *EC2Scanner) getAverageCPU(ctx context.Context, instanceID string, days int) (float64, error) {
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -days)

	result, err := s.cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/EC2"),
		MetricName: aws.String("CPUUtilization"),
		Dimensions: []cwtypes.Dimension{
			{
				Name:  aws.String("InstanceId"),
				Value: aws.String(instanceID),
			},
		},
		StartTime:  &startTime,
		EndTime:    &endTime,
		Period:     aws.Int32(86400), // 1 day
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	})
	if err != nil {
		return 0, err
	}

	if len(result.Datapoints) == 0 {
		return 0, fmt.Errorf("no CPU data available")
	}

	var total float64
	for _, dp := range result.Datapoints {
		total += *dp.Average
	}

	return total / float64(len(result.Datapoints)), nil
}

// suggestDownsize recommends a smaller instance type
func suggestDownsize(instanceType string) string {
	downsizeMap := map[string]string{
		"t2.2xlarge": "t3.xlarge",
		"t2.xlarge":  "t3.large",
		"t2.large":   "t3.medium",
		"t2.medium":  "t3.small",
		"t3.2xlarge": "t3.xlarge",
		"t3.xlarge":  "t3.large",
		"t3.large":   "t3.medium",
		"t3.medium":  "t3.small",
		"m5.4xlarge": "m5.2xlarge",
		"m5.2xlarge": "m5.xlarge",
		"m5.xlarge":  "m5.large",
		"r5.xlarge":  "r5.large",
		"c5.xlarge":  "c5.large",
	}

	if suggested, ok := downsizeMap[instanceType]; ok {
		return suggested
	}
	return instanceType
}
