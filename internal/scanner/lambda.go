package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/storygame/cloudcost/internal/models"
)

type LambdaScanner struct {
	lambdaClient *lambda.Client
	cwClient     *cloudwatch.Client
	region       string
}

func NewLambdaScanner(cfg aws.Config, region string) *LambdaScanner {
	cfg.Region = region
	return &LambdaScanner{
		lambdaClient: lambda.NewFromConfig(cfg),
		cwClient:     cloudwatch.NewFromConfig(cfg),
		region:       region,
	}
}

// ScanLambdaFunctions finds unused and over-provisioned Lambda functions
func (s *LambdaScanner) ScanLambdaFunctions(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	var marker *string
	for {
		result, err := s.lambdaClient.ListFunctions(ctx, &lambda.ListFunctionsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list Lambda functions: %w", err)
		}

		for _, fn := range result.Functions {
			fnName := *fn.FunctionName
			memoryMB := *fn.MemorySize
			runtime := ""
			if fn.Runtime != "" {
				runtime = string(fn.Runtime)
			}

			// Get invocation count over last 30 days
			invocations, err := s.getLambdaMetric(ctx, fnName, "Invocations", 30, cwtypes.StatisticSum)
			if err != nil {
				invocations = -1
			}

			// Get average duration
			avgDuration, _ := s.getLambdaMetric(ctx, fnName, "Duration", 30, cwtypes.StatisticAverage)

			// Check for unused functions (0 invocations in 30 days)
			if invocations == 0 {
				// Estimate cost of associated resources (CloudWatch logs, etc.)
				findings = append(findings, models.Finding{
					ID:           fmt.Sprintf("lambda-unused-%s", fnName),
					ResourceType: models.ResourceEC2Instance, // closest type
					ResourceID:   fnName,
					ResourceName: fnName,
					Region:       s.region,
					Severity:     models.SeverityMedium,
					Title:        fmt.Sprintf("Unused Lambda: %s (0 invocations in 30 days)", fnName),
					Description: fmt.Sprintf(
						"Lambda function %s (%s, %d MB) has had 0 invocations in the last 30 days.\n"+
							"     While idle Lambda functions don't cost compute, they may have associated\n"+
							"     CloudWatch log groups with retention costs.",
						fnName, runtime, memoryMB,
					),
					MonthlyCost: 0,
					Action:      "Delete if no longer needed. Check CloudWatch log groups too.",
					CLICommand: fmt.Sprintf(
						"aws lambda delete-function --function-name %s --region %s\n"+
							"aws logs delete-log-group --log-group-name /aws/lambda/%s --region %s",
						fnName, s.region, fnName, s.region,
					),
					ScannedAt: time.Now(),
				})
				continue
			}

			// Check for over-provisioned memory
			if invocations > 0 && avgDuration > 0 && memoryMB > 256 {
				// Lambda pricing: $0.0000166667 per GB-second
				currentGBSeconds := (float64(memoryMB) / 1024.0) * (avgDuration / 1000.0) * invocations
				currentCost := currentGBSeconds * 0.0000166667

				// If we halve the memory
				halfMemGBSeconds := (float64(memoryMB/2) / 1024.0) * (avgDuration / 1000.0) * invocations
				halfCost := halfMemGBSeconds * 0.0000166667
				savings := currentCost - halfCost

				// Only flag if savings are meaningful
				if savings > 1.0 {
					findings = append(findings, models.Finding{
						ID:           fmt.Sprintf("lambda-mem-%s", fnName),
						ResourceType: models.ResourceEC2Instance,
						ResourceID:   fnName,
						ResourceName: fnName,
						Region:       s.region,
						Severity:     models.SeverityMedium,
						Title:        fmt.Sprintf("Over-provisioned Lambda: %s (%d MB memory)", fnName, memoryMB),
						Description: fmt.Sprintf(
							"Lambda %s has %d MB memory with %.0f invocations/month (avg %.0fms).\n"+
								"     Current cost: $%.2f/mo\n"+
								"     Try reducing to %d MB to save $%.2f/mo\n"+
								"     Use AWS Lambda Power Tuning to find optimal memory.",
							fnName, memoryMB, invocations, avgDuration,
							currentCost,
							memoryMB/2, savings,
						),
						MonthlyCost: savings,
						Action:      fmt.Sprintf("Reduce memory from %d MB to %d MB", memoryMB, memoryMB/2),
						CLICommand: fmt.Sprintf(
							"aws lambda update-function-configuration --function-name %s \\\n"+
								"  --memory-size %d --region %s",
							fnName, memoryMB/2, s.region,
						),
						ScannedAt: time.Now(),
					})
				}
			}
		}

		if result.NextMarker == nil {
			break
		}
		marker = result.NextMarker
	}

	return findings, nil
}

func (s *LambdaScanner) getLambdaMetric(ctx context.Context, fnName, metricName string, days int, stat cwtypes.Statistic) (float64, error) {
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -days)

	result, err := s.cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/Lambda"),
		MetricName: aws.String(metricName),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("FunctionName"), Value: aws.String(fnName)},
		},
		StartTime:  &startTime,
		EndTime:    &endTime,
		Period:     aws.Int32(int32(days * 86400)), // entire period
		Statistics: []cwtypes.Statistic{stat},
	})
	if err != nil {
		return 0, err
	}

	if len(result.Datapoints) == 0 {
		return 0, nil // 0 invocations
	}

	var total float64
	for _, dp := range result.Datapoints {
		switch stat {
		case cwtypes.StatisticSum:
			total += *dp.Sum
		case cwtypes.StatisticAverage:
			total += *dp.Average
		}
	}

	if stat == cwtypes.StatisticAverage {
		return total / float64(len(result.Datapoints)), nil
	}
	return total, nil
}
