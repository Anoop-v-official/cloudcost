package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/Anoop-v-official/cloudcost/internal/models"
)

type S3Scanner struct {
	s3Client *s3.Client
	cwClient *cloudwatch.Client
	region   string
}

func NewS3Scanner(cfg aws.Config, region string) *S3Scanner {
	cfg.Region = region
	return &S3Scanner{
		s3Client: s3.NewFromConfig(cfg),
		cwClient: cloudwatch.NewFromConfig(cfg),
		region:   region,
	}
}

// ScanS3Buckets checks for empty buckets, missing lifecycle policies, and versioning costs
func (s *S3Scanner) ScanS3Buckets(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	for _, bucket := range result.Buckets {
		bucketName := *bucket.Name

		// Check bucket location to only scan buckets in current region
		locResult, err := s.s3Client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			continue
		}

		bucketRegion := string(locResult.LocationConstraint)
		if bucketRegion == "" {
			bucketRegion = "us-east-1" // default
		}
		if bucketRegion != s.region {
			continue
		}

		// Get bucket size from CloudWatch
		bucketSizeGB, objectCount := s.getBucketMetrics(ctx, bucketName)

		// Check for empty buckets
		if objectCount == 0 {
			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("s3-empty-%s", bucketName),
				ResourceType: models.ResourceS3Bucket,
				ResourceID:   bucketName,
				ResourceName: bucketName,
				Region:       s.region,
				Severity:     models.SeverityLow,
				Title:        fmt.Sprintf("Empty S3 bucket: %s", bucketName),
				Description:  fmt.Sprintf("Bucket %s has 0 objects. Empty buckets don't cost money but add clutter.", bucketName),
				MonthlyCost:  0,
				Action:       "Delete if no longer needed",
				CLICommand:   fmt.Sprintf("aws s3 rb s3://%s --region %s", bucketName, s.region),
				ScannedAt:    time.Now(),
			})
			continue
		}

		// Check versioning
		verResult, err := s.s3Client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: aws.String(bucketName),
		})
		if err == nil && verResult.Status == "Enabled" {
			// Check if lifecycle policy exists
			_, lcErr := s.s3Client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
				Bucket: aws.String(bucketName),
			})

			if lcErr != nil {
				// Versioning enabled but no lifecycle = old versions accumulate forever
				estimatedWaste := bucketSizeGB * 0.3 * 0.023 // assume 30% is old versions at S3 standard pricing
				if estimatedWaste < 1.0 {
					continue
				}

				findings = append(findings, models.Finding{
					ID:           fmt.Sprintf("s3-nolc-%s", bucketName),
					ResourceType: models.ResourceS3Bucket,
					ResourceID:   bucketName,
					ResourceName: bucketName,
					Region:       s.region,
					Severity:     models.SeverityMedium,
					Title:        fmt.Sprintf("Versioned bucket without lifecycle: %s (%.1f GB)", bucketName, bucketSizeGB),
					Description: fmt.Sprintf(
						"Bucket %s has versioning enabled (%.1f GB, %d objects) but no lifecycle policy.\n"+
							"     Old object versions accumulate forever, increasing costs.\n"+
							"     Estimated waste: $%.2f/mo from old versions",
						bucketName, bucketSizeGB, int(objectCount), estimatedWaste,
					),
					MonthlyCost: estimatedWaste,
					Action:      "Add a lifecycle policy to expire old versions after 30 days",
					CLICommand: fmt.Sprintf(
						"# Add lifecycle policy to expire old versions after 30 days:\n"+
							"aws s3api put-bucket-lifecycle-configuration --bucket %s \\\n"+
							"  --lifecycle-configuration '{\n"+
							"    \"Rules\": [{\n"+
							"      \"ID\": \"ExpireOldVersions\",\n"+
							"      \"Status\": \"Enabled\",\n"+
							"      \"NoncurrentVersionExpiration\": {\"NoncurrentDays\": 30},\n"+
							"      \"Filter\": {\"Prefix\": \"\"}\n"+
							"    }]\n"+
							"  }' --region %s",
						bucketName, s.region,
					),
					ScannedAt: time.Now(),
				})
			}
		}

		// Check for large buckets without intelligent tiering
		if bucketSizeGB > 100 {
			monthlyCost := bucketSizeGB * 0.023 // S3 standard pricing
			glacierCost := bucketSizeGB * 0.004  // Glacier pricing
			potentialSavings := monthlyCost - glacierCost

			// Check if intelligent tiering or glacier is already configured
			_, lcErr := s.s3Client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
				Bucket: aws.String(bucketName),
			})

			if lcErr != nil && potentialSavings > 5 {
				findings = append(findings, models.Finding{
					ID:           fmt.Sprintf("s3-tier-%s", bucketName),
					ResourceType: models.ResourceS3Bucket,
					ResourceID:   bucketName,
					ResourceName: bucketName,
					Region:       s.region,
					Severity:     models.SeverityHigh,
					Title:        fmt.Sprintf("Large bucket without tiering: %s (%.1f GB, $%.2f/mo)", bucketName, bucketSizeGB, monthlyCost),
					Description: fmt.Sprintf(
						"Bucket %s has %.1f GB in S3 Standard ($%.2f/mo).\n"+
							"     If data is infrequently accessed, moving to Glacier could save $%.2f/mo.\n"+
							"     Even Intelligent-Tiering auto-moves cold data for free.",
						bucketName, bucketSizeGB, monthlyCost, potentialSavings,
					),
					MonthlyCost: potentialSavings,
					Action:      "Enable S3 Intelligent-Tiering or add lifecycle transition to Glacier",
					CLICommand: fmt.Sprintf(
						"# Enable Intelligent-Tiering (auto-tiers at no extra cost):\n"+
							"aws s3api put-bucket-lifecycle-configuration --bucket %s \\\n"+
							"  --lifecycle-configuration '{\n"+
							"    \"Rules\": [{\n"+
							"      \"ID\": \"IntelligentTiering\",\n"+
							"      \"Status\": \"Enabled\",\n"+
							"      \"Transitions\": [{\"Days\": 30, \"StorageClass\": \"INTELLIGENT_TIERING\"}],\n"+
							"      \"Filter\": {\"Prefix\": \"\"}\n"+
							"    }]\n"+
							"  }' --region %s",
						bucketName, s.region,
					),
					ScannedAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// getBucketMetrics retrieves bucket size and object count from CloudWatch
func (s *S3Scanner) getBucketMetrics(ctx context.Context, bucketName string) (sizeGB float64, objectCount float64) {
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -2)

	// Bucket size
	sizeResult, err := s.cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/S3"),
		MetricName: aws.String("BucketSizeBytes"),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("BucketName"), Value: aws.String(bucketName)},
			{Name: aws.String("StorageType"), Value: aws.String("StandardStorage")},
		},
		StartTime:  &startTime,
		EndTime:    &endTime,
		Period:     aws.Int32(86400),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	})
	if err == nil && len(sizeResult.Datapoints) > 0 {
		sizeGB = *sizeResult.Datapoints[len(sizeResult.Datapoints)-1].Average / (1024 * 1024 * 1024)
	}

	// Object count
	countResult, err := s.cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/S3"),
		MetricName: aws.String("NumberOfObjects"),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("BucketName"), Value: aws.String(bucketName)},
			{Name: aws.String("StorageType"), Value: aws.String("AllStorageTypes")},
		},
		StartTime:  &startTime,
		EndTime:    &endTime,
		Period:     aws.Int32(86400),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	})
	if err == nil && len(countResult.Datapoints) > 0 {
		objectCount = *countResult.Datapoints[len(countResult.Datapoints)-1].Average
	}

	return
}
