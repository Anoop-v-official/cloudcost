package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/Anoop-v-official/cloudcost/internal/models"
)

type EBSScanner struct {
	client *ec2.Client
	region string
}

func NewEBSScanner(cfg aws.Config, region string) *EBSScanner {
	cfg.Region = region
	return &EBSScanner{
		client: ec2.NewFromConfig(cfg),
		region: region,
	}
}

// ScanUnattachedVolumes finds EBS volumes not attached to any instance
func (s *EBSScanner) ScanUnattachedVolumes(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("status"),
				Values: []string{"available"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe volumes: %w", err)
	}

	for _, vol := range result.Volumes {
		volType := string(vol.VolumeType)
		pricePerGB, ok := models.EBSPricing[volType]
		if !ok {
			pricePerGB = 0.10 // default
		}

		monthlyCost := float64(*vol.Size) * pricePerGB
		name := getTagValue(vol.Tags, "Name")

		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("ebs-unattached-%s", *vol.VolumeId),
			ResourceType: models.ResourceEBSVolume,
			ResourceID:   *vol.VolumeId,
			ResourceName: name,
			Region:       s.region,
			Severity:     models.SeverityCritical,
			Title:        fmt.Sprintf("Unattached EBS volume (%d GB, %s)", *vol.Size, volType),
			Description:  fmt.Sprintf("Volume %s (%s, %d GB) is not attached to any instance and is costing $%.2f/month", *vol.VolumeId, volType, *vol.Size, monthlyCost),
			MonthlyCost:  monthlyCost,
			Action:       "Delete the volume (snapshot first if data might be needed)",
			CLICommand:   fmt.Sprintf("aws ec2 delete-volume --volume-id %s --region %s", *vol.VolumeId, s.region),
			ScannedAt:    time.Now(),
		})
	}

	return findings, nil
}

// ScanGP2Volumes finds volumes still using gp2 that should be gp3
func (s *EBSScanner) ScanGP2Volumes(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("volume-type"),
				Values: []string{"gp2"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe gp2 volumes: %w", err)
	}

	for _, vol := range result.Volumes {
		currentCost := float64(*vol.Size) * models.EBSPricing["gp2"]
		newCost := float64(*vol.Size) * models.EBSPricing["gp3"]
		savings := currentCost - newCost
		name := getTagValue(vol.Tags, "Name")

		if savings < 0.50 {
			continue // skip tiny savings
		}

		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("ebs-gp2-%s", *vol.VolumeId),
			ResourceType: models.ResourceEBSVolume,
			ResourceID:   *vol.VolumeId,
			ResourceName: name,
			Region:       s.region,
			Severity:     models.SeverityMedium,
			Title:        fmt.Sprintf("gp2 volume should be gp3 (%d GB)", *vol.Size),
			Description:  fmt.Sprintf("Volume %s is using gp2 ($%.2f/mo). Converting to gp3 saves $%.2f/month with same or better performance", *vol.VolumeId, currentCost, savings),
			MonthlyCost:  savings,
			Action:       "Convert from gp2 to gp3",
			CLICommand:   fmt.Sprintf("aws ec2 modify-volume --volume-id %s --volume-type gp3 --region %s", *vol.VolumeId, s.region),
			ScannedAt:    time.Now(),
		})
	}

	return findings, nil
}

// ScanOldSnapshots finds snapshots older than specified days
func (s *EBSScanner) ScanOldSnapshots(ctx context.Context, maxAgeDays int) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe snapshots: %w", err)
	}

	cutoff := time.Now().AddDate(0, 0, -maxAgeDays)

	for _, snap := range result.Snapshots {
		if snap.StartTime.After(cutoff) {
			continue
		}

		sizeGB := float64(*snap.VolumeSize)
		monthlyCost := sizeGB * models.SnapshotPricing
		ageDays := int(time.Since(*snap.StartTime).Hours() / 24)
		name := getTagValue(snap.Tags, "Name")
		desc := ""
		if snap.Description != nil {
			desc = *snap.Description
		}

		severity := models.SeverityMedium
		if monthlyCost > 50 {
			severity = models.SeverityCritical
		} else if monthlyCost > 10 {
			severity = models.SeverityHigh
		}

		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("ebs-snapshot-%s", *snap.SnapshotId),
			ResourceType: models.ResourceEBSSnapshot,
			ResourceID:   *snap.SnapshotId,
			ResourceName: name,
			Region:       s.region,
			Severity:     severity,
			Title:        fmt.Sprintf("Old snapshot (%d GB, %d days old)", *snap.VolumeSize, ageDays),
			Description:  fmt.Sprintf("Snapshot %s (%d GB, created %s) costs $%.2f/month. Description: %s", *snap.SnapshotId, *snap.VolumeSize, snap.StartTime.Format("2006-01-02"), monthlyCost, desc),
			MonthlyCost:  monthlyCost,
			Action:       "Delete if no longer needed, or move to Archive tier (75% cheaper)",
			CLICommand:   fmt.Sprintf("aws ec2 delete-snapshot --snapshot-id %s --region %s", *snap.SnapshotId, s.region),
			ScannedAt:    time.Now(),
		})
	}

	return findings, nil
}

// ScanOversizedVolumes finds volumes with very low utilization
func (s *EBSScanner) ScanOversizedVolumes(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("status"),
				Values: []string{"in-use"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe volumes: %w", err)
	}

	for _, vol := range result.Volumes {
		// Flag very large volumes (> 500 GB) for review
		if *vol.Size < 500 {
			continue
		}

		volType := string(vol.VolumeType)
		pricePerGB, ok := models.EBSPricing[volType]
		if !ok {
			pricePerGB = 0.10
		}

		monthlyCost := float64(*vol.Size) * pricePerGB
		name := getTagValue(vol.Tags, "Name")
		instanceID := ""
		if len(vol.Attachments) > 0 && vol.Attachments[0].InstanceId != nil {
			instanceID = *vol.Attachments[0].InstanceId
		}

		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("ebs-oversized-%s", *vol.VolumeId),
			ResourceType: models.ResourceEBSVolume,
			ResourceID:   *vol.VolumeId,
			ResourceName: name,
			Region:       s.region,
			Severity:     models.SeverityHigh,
			Title:        fmt.Sprintf("Large volume review needed (%d GB, %s) — $%.2f/mo", *vol.Size, volType, monthlyCost),
			Description:  fmt.Sprintf("Volume %s (%d GB, %s) attached to %s costs $%.2f/month. SSH in and run 'df -h' to check actual disk usage.", *vol.VolumeId, *vol.Size, volType, instanceID, monthlyCost),
			MonthlyCost:  monthlyCost,
			Action:       "Check actual disk usage with 'df -h'. If usage is below 50%, consider migrating to a smaller volume.",
			CLICommand:   fmt.Sprintf("# SSH into the instance and check:\ndf -h\ndu -sh /* 2>/dev/null | sort -rh | head -10"),
			ScannedAt:    time.Now(),
		})
	}

	return findings, nil
}

// Helper to get tag value
func getTagValue(tags []types.Tag, key string) string {
	for _, tag := range tags {
		if *tag.Key == key {
			return *tag.Value
		}
	}
	return ""
}
