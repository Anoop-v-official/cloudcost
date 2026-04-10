package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/Anoop-v-official/cloudcost/internal/models"
)

type CloudWatchLogsScanner struct {
	logsClient *cloudwatchlogs.Client
	region     string
}

func NewCloudWatchLogsScanner(cfg aws.Config, region string) *CloudWatchLogsScanner {
	cfg.Region = region
	return &CloudWatchLogsScanner{
		logsClient: cloudwatchlogs.NewFromConfig(cfg),
		region:     region,
	}
}

// ScanLogGroups finds log groups with no retention policy (logs kept forever)
func (s *CloudWatchLogsScanner) ScanLogGroups(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding
	var noRetentionGroups []logGroupInfo
	var totalWaste float64

	var nextToken *string
	for {
		result, err := s.logsClient.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe log groups: %w", err)
		}

		for _, lg := range result.LogGroups {
			lgName := *lg.LogGroupName
			storedBytes := *lg.StoredBytes
			storedGB := float64(storedBytes) / (1024 * 1024 * 1024)

			// CloudWatch Logs storage: $0.03/GB/month
			monthlyCost := storedGB * 0.03

			// No retention policy = logs kept forever
			if lg.RetentionInDays == nil {
				noRetentionGroups = append(noRetentionGroups, logGroupInfo{
					name:    lgName,
					sizeGB:  storedGB,
					cost:    monthlyCost,
				})
				totalWaste += monthlyCost
			}

			// Flag individual large log groups (> 10 GB) with no retention
			if lg.RetentionInDays == nil && storedGB > 10 {
				findings = append(findings, models.Finding{
					ID:           fmt.Sprintf("cwlogs-large-%s", sanitizeID(lgName)),
					ResourceType: models.ResourceEC2Instance,
					ResourceID:   lgName,
					ResourceName: lgName,
					Region:       s.region,
					Severity:     models.SeverityHigh,
					Title:        fmt.Sprintf("Large log group without retention: %s (%.1f GB)", lgName, storedGB),
					Description: fmt.Sprintf(
						"Log group %s has %.1f GB of logs with no retention policy.\n"+
							"     Storage cost: $%.2f/mo and growing.\n"+
							"     Set a retention period to auto-delete old logs.",
						lgName, storedGB, monthlyCost,
					),
					MonthlyCost: monthlyCost,
					Action:      "Set retention policy to 30 or 90 days",
					CLICommand: fmt.Sprintf(
						"aws logs put-retention-policy --log-group-name \"%s\" \\\n"+
							"  --retention-in-days 30 --region %s",
						lgName, s.region,
					),
					ScannedAt: time.Now(),
				})
			}
		}

		if result.NextToken == nil {
			break
		}
		nextToken = result.NextToken
	}

	// Summary finding for all log groups without retention
	if len(noRetentionGroups) > 5 && totalWaste > 5 {
		groupList := ""
		shown := 0
		for _, g := range noRetentionGroups {
			if g.sizeGB > 0.1 {
				groupList += fmt.Sprintf("\n     • %s (%.1f GB, $%.2f/mo)", g.name, g.sizeGB, g.cost)
				shown++
				if shown >= 10 {
					groupList += fmt.Sprintf("\n     ... and %d more", len(noRetentionGroups)-shown)
					break
				}
			}
		}

		findings = append(findings, models.Finding{
			ID:           "cwlogs-noretention-summary",
			ResourceType: models.ResourceEC2Instance,
			ResourceID:   "cloudwatch-logs",
			ResourceName: "CloudWatch Logs",
			Region:       s.region,
			Severity:     models.SeverityMedium,
			Title:        fmt.Sprintf("📝 %d log groups without retention policy ($%.2f/mo)", len(noRetentionGroups), totalWaste),
			Description: fmt.Sprintf(
				"%d log groups have no retention policy — logs are kept forever.\n"+
					"     Total storage cost: $%.2f/mo\n"+
					"     Top groups:%s",
				len(noRetentionGroups), totalWaste, groupList,
			),
			MonthlyCost: totalWaste * 0.5, // assume 50% could be saved with retention
			Action:      "Set retention policy on all log groups (30-90 days recommended)",
			CLICommand: fmt.Sprintf(
				"# Set 30-day retention on ALL log groups:\n"+
					"for lg in $(aws logs describe-log-groups --region %s --query 'logGroups[?retentionInDays==null].logGroupName' --output text); do\n"+
					"  aws logs put-retention-policy --log-group-name \"$lg\" --retention-in-days 30 --region %s\n"+
					"done",
				s.region, s.region,
			),
			ScannedAt: time.Now(),
		})
	}

	return findings, nil
}

type logGroupInfo struct {
	name   string
	sizeGB float64
	cost   float64
}

func sanitizeID(s string) string {
	result := ""
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			result += string(c)
		} else {
			result += "-"
		}
	}
	return result
}
