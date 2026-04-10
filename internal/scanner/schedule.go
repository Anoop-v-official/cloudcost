package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/storygame/cloudcost/internal/models"
)

type ScheduleScanner struct {
	ec2Client *ec2.Client
	cwClient  *cloudwatch.Client
	region    string
}

func NewScheduleScanner(cfg aws.Config, region string) *ScheduleScanner {
	cfg.Region = region
	return &ScheduleScanner{
		ec2Client: ec2.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
		region:    region,
	}
}

// ScanScheduleCandidates finds instances that could benefit from auto-stop/start schedules
func (s *ScheduleScanner) ScanScheduleCandidates(ctx context.Context) ([]models.Finding, error) {
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
			instanceID := *inst.InstanceId
			instanceType := string(inst.InstanceType)
			name := getTagValue(inst.Tags, "Name")

			// Skip production-looking instances
			if isLikelyProduction(name) {
				continue
			}

			// Get hourly CPU for last 7 days
			hourlyPattern, err := s.getHourlyCPUPattern(ctx, instanceID, 7)
			if err != nil {
				continue
			}

			// Analyze the pattern
			recommendation := analyzeSchedulePattern(hourlyPattern, instanceID, instanceType, name)
			if recommendation == nil {
				continue
			}

			// Calculate savings
			hourlyPrice, ok := ec2Pricing[instanceType]
			if !ok {
				hourlyPrice = 0.10
			}

			finding := s.buildScheduleFinding(recommendation, instanceID, instanceType, name, hourlyPrice)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings, nil
}

type ScheduleRecommendation struct {
	Type         string  // "night-stop", "weekend-stop", "night-and-weekend"
	StopHourUTC  int     // hour to stop (UTC)
	StartHourUTC int     // hour to start (UTC)
	AvgNightCPU  float64
	AvgDayCPU    float64
	AvgWeekendCPU float64
	AvgWeekdayCPU float64
	IdleHoursPerDay float64
	StopWeekend  bool
}

func analyzeSchedulePattern(hourlyData map[int]float64, instanceID, instanceType, name string) *ScheduleRecommendation {
	if len(hourlyData) == 0 {
		return nil
	}

	// Calculate night average (UTC 18-23, 0-2 = IST 11:30pm - 7:30am)
	var nightTotal, dayTotal float64
	var nightCount, dayCount int

	for hour, cpu := range hourlyData {
		if hour >= 18 || hour <= 2 {
			nightTotal += cpu
			nightCount++
		} else {
			dayTotal += cpu
			dayCount++
		}
	}

	nightAvg := float64(0)
	dayAvg := float64(0)
	if nightCount > 0 {
		nightAvg = nightTotal / float64(nightCount)
	}
	if dayCount > 0 {
		dayAvg = dayTotal / float64(dayCount)
	}

	// Decision: if night CPU < 5% and day CPU > 3x night CPU
	if nightAvg < 5.0 && dayAvg > nightAvg*3 {
		idleHours := float64(0)
		for hour, cpu := range hourlyData {
			_ = hour
			if cpu < 3.0 {
				idleHours++
			}
		}

		return &ScheduleRecommendation{
			Type:            "night-stop",
			StopHourUTC:     18, // 18:30 UTC = midnight IST
			StartHourUTC:    3,  // 03:00 UTC = 8:30am IST
			AvgNightCPU:     nightAvg,
			AvgDayCPU:       dayAvg,
			IdleHoursPerDay: idleHours,
		}
	}

	return nil
}

func (s *ScheduleScanner) buildScheduleFinding(rec *ScheduleRecommendation, instanceID, instanceType, name string, hourlyPrice float64) *models.Finding {
	currentMonthlyCost := hourlyPrice * 730

	// Night stop: save ~35% (8.5 idle hours out of 24)
	var savings float64
	var scheduleDesc string
	var cliCmd string

	switch rec.Type {
	case "night-stop":
		savings = currentMonthlyCost * 0.35
		scheduleDesc = "midnight to 8:30am IST"
		cliCmd = fmt.Sprintf(
			"# Auto-stop at midnight IST (18:30 UTC)\n"+
				"aws events put-rule --name stop-%s \\\n"+
				"  --schedule-expression \"cron(30 18 * * ? *)\" \\\n"+
				"  --state ENABLED --region %s\n\n"+
				"# Create IAM role for EventBridge (one-time setup)\n"+
				"# Then add target:\n"+
				"aws events put-targets --rule stop-%s \\\n"+
				"  --targets \"Id\"=\"1\",\"Arn\"=\"arn:aws:ssm:%s::automation-definition/AWS-StopEC2Instance\",\"Input\"=\"{\\\"InstanceId\\\":[\\\"%s\\\"]}\" \\\n"+
				"  --region %s\n\n"+
				"# Auto-start at 8:30am IST (03:00 UTC)\n"+
				"aws events put-rule --name start-%s \\\n"+
				"  --schedule-expression \"cron(0 3 * * ? *)\" \\\n"+
				"  --state ENABLED --region %s\n\n"+
				"aws events put-targets --rule start-%s \\\n"+
				"  --targets \"Id\"=\"1\",\"Arn\"=\"arn:aws:ssm:%s::automation-definition/AWS-StartEC2Instance\",\"Input\"=\"{\\\"InstanceId\\\":[\\\"%s\\\"]}\" \\\n"+
				"  --region %s",
			name, s.region,
			name, s.region, instanceID, s.region,
			name, s.region,
			name, s.region, instanceID, s.region,
		)
	case "weekend-stop":
		savings = currentMonthlyCost * 0.28 // ~2 days of 7
		scheduleDesc = "Friday midnight to Monday 8:30am IST"
		cliCmd = fmt.Sprintf(
			"# Stop Friday midnight IST (18:30 UTC Friday)\n"+
				"aws events put-rule --name stop-%s-weekend \\\n"+
				"  --schedule-expression \"cron(30 18 ? * FRI *)\" \\\n"+
				"  --state ENABLED --region %s\n\n"+
				"# Start Monday 8:30am IST (03:00 UTC Monday)\n"+
				"aws events put-rule --name start-%s-weekend \\\n"+
				"  --schedule-expression \"cron(0 3 ? * MON *)\" \\\n"+
				"  --state ENABLED --region %s",
			name, s.region,
			name, s.region,
		)
	case "night-and-weekend":
		savings = currentMonthlyCost * 0.55 // nights + weekends
		scheduleDesc = "nights (midnight-8:30am) + weekends"
		cliCmd = "# Complex schedule — use AWS Instance Scheduler for combined night + weekend stops"
	}

	if savings < 3.0 {
		return nil
	}

	return &models.Finding{
		ID:           fmt.Sprintf("schedule-%s", instanceID),
		ResourceType: models.ResourceEC2Instance,
		ResourceID:   instanceID,
		ResourceName: name,
		Region:       s.region,
		Severity:     models.SeverityHigh,
		Title:        fmt.Sprintf("🕐 Schedule auto-stop: %s (%s)", name, instanceType),
		Description: fmt.Sprintf(
			"Instance %s (%s, %s) is idle during %s.\n"+
				"     Day CPU avg: %.1f%% | Night CPU avg: %.1f%%\n"+
				"     Current cost: $%.2f/mo → Save $%.2f/mo with scheduled stop/start",
			instanceID, name, instanceType, scheduleDesc,
			rec.AvgDayCPU, rec.AvgNightCPU,
			currentMonthlyCost, savings,
		),
		MonthlyCost: savings,
		Action:      fmt.Sprintf("Schedule auto-stop during %s", scheduleDesc),
		CLICommand:  cliCmd,
		ScannedAt:   time.Now(),
	}
}

// getHourlyCPUPattern returns average CPU by hour of day (UTC) over N days
func (s *ScheduleScanner) getHourlyCPUPattern(ctx context.Context, instanceID string, days int) (map[int]float64, error) {
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
		Period:     aws.Int32(3600), // 1 hour
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	})
	if err != nil {
		return nil, err
	}

	// Aggregate by hour of day
	hourlyTotal := make(map[int]float64)
	hourlyCount := make(map[int]int)

	for _, dp := range result.Datapoints {
		hour := dp.Timestamp.UTC().Hour()
		hourlyTotal[hour] += *dp.Average
		hourlyCount[hour]++
	}

	// Average per hour
	hourlyAvg := make(map[int]float64)
	for hour, total := range hourlyTotal {
		if count, ok := hourlyCount[hour]; ok && count > 0 {
			hourlyAvg[hour] = total / float64(count)
		}
	}

	return hourlyAvg, nil
}

// isLikelyProduction checks if instance name suggests it's a production server
func isLikelyProduction(name string) bool {
	name = strings.ToLower(name)
	prodIndicators := []string{
		"prod", "production", "master", "primary",
		"mongodb-server", "database", "db-",
		"api-prod", "backend-prod",
	}
	for _, indicator := range prodIndicators {
		if strings.Contains(name, indicator) {
			return true
		}
	}
	return false
}
