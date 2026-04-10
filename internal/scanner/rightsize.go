package scanner

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/Anoop-v-official/cloudcost/internal/models"
)

// Instance specs: vCPU, Memory (GB)
var instanceSpecs = map[string][2]float64{
	"t2.micro":   {1, 1},
	"t2.small":   {1, 2},
	"t2.medium":  {2, 4},
	"t2.large":   {2, 8},
	"t2.xlarge":  {4, 16},
	"t2.2xlarge": {8, 32},
	"t3.micro":   {2, 1},
	"t3.small":   {2, 2},
	"t3.medium":  {2, 4},
	"t3.large":   {2, 8},
	"t3.xlarge":  {4, 16},
	"t3.2xlarge": {8, 32},
	"m5.large":   {2, 8},
	"m5.xlarge":  {4, 16},
	"m5.2xlarge": {8, 32},
	"m5.4xlarge": {16, 64},
	"m6i.large":  {2, 8},
	"m6i.xlarge": {4, 16},
	"r5.large":   {2, 16},
	"r5.xlarge":  {4, 32},
	"r5.2xlarge": {8, 64},
	"c5.large":   {2, 4},
	"c5.xlarge":  {4, 8},
	"c5.2xlarge": {8, 16},
}

// RightSizing recommendation types
type RightSizeAction string

const (
	ActionKeep     RightSizeAction = "KEEP"
	ActionDownsize RightSizeAction = "DOWNSIZE"
	ActionStop     RightSizeAction = "SCHEDULE_STOP"
	ActionBoth     RightSizeAction = "DOWNSIZE_AND_SCHEDULE"
)

type InstanceMetrics struct {
	InstanceID   string
	InstanceType string
	Name         string
	AvgCPU       float64
	MaxCPU       float64
	MinCPU       float64
	AvgCPUNight  float64 // 12am - 8am
	AvgCPUDay    float64 // 8am - 12am
	NetworkIn    float64 // bytes
	NetworkOut   float64 // bytes
	DiskReadOps  float64
	DiskWriteOps float64
}

type RightSizeScanner struct {
	ec2Client *ec2.Client
	cwClient  *cloudwatch.Client
	region    string
}

func NewRightSizeScanner(cfg aws.Config, region string) *RightSizeScanner {
	cfg.Region = region
	return &RightSizeScanner{
		ec2Client: ec2.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
		region:    region,
	}
}

// ScanOverProvisioned finds instances that are over-provisioned based on CPU, network, and disk metrics
func (s *RightSizeScanner) ScanOverProvisioned(ctx context.Context) ([]models.Finding, error) {
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

			// Gather comprehensive metrics
			metrics, err := s.gatherMetrics(ctx, instanceID, instanceType, name)
			if err != nil {
				continue
			}

			// Analyze and generate recommendation
			finding := s.analyzeInstance(metrics)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings, nil
}

// gatherMetrics collects CPU, network, and disk metrics for an instance
func (s *RightSizeScanner) gatherMetrics(ctx context.Context, instanceID, instanceType, name string) (*InstanceMetrics, error) {
	metrics := &InstanceMetrics{
		InstanceID:   instanceID,
		InstanceType: instanceType,
		Name:         name,
	}

	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -14) // 14 days of data

	// Average CPU
	avgCPU, err := s.getMetricStat(ctx, instanceID, "CPUUtilization", startTime, endTime, 86400, cwtypes.StatisticAverage)
	if err != nil {
		return nil, err
	}
	metrics.AvgCPU = avgCPU

	// Max CPU (to catch burst patterns)
	maxCPU, err := s.getMetricStat(ctx, instanceID, "CPUUtilization", startTime, endTime, 86400, cwtypes.StatisticMaximum)
	if err == nil {
		metrics.MaxCPU = maxCPU
	}

	// Min CPU
	minCPU, err := s.getMetricStat(ctx, instanceID, "CPUUtilization", startTime, endTime, 86400, cwtypes.StatisticMinimum)
	if err == nil {
		metrics.MinCPU = minCPU
	}

	// Night CPU (12am - 8am) - last 7 days with hourly granularity
	nightCPU, err := s.getNightCPU(ctx, instanceID, 7)
	if err == nil {
		metrics.AvgCPUNight = nightCPU
	}

	// Day CPU (8am - 12am)
	dayCPU, err := s.getDayCPU(ctx, instanceID, 7)
	if err == nil {
		metrics.AvgCPUDay = dayCPU
	}

	// Network In
	netIn, err := s.getMetricStat(ctx, instanceID, "NetworkIn", startTime, endTime, 86400, cwtypes.StatisticAverage)
	if err == nil {
		metrics.NetworkIn = netIn
	}

	// Network Out
	netOut, err := s.getMetricStat(ctx, instanceID, "NetworkOut", startTime, endTime, 86400, cwtypes.StatisticAverage)
	if err == nil {
		metrics.NetworkOut = netOut
	}

	return metrics, nil
}

// analyzeInstance determines the right-sizing recommendation
func (s *RightSizeScanner) analyzeInstance(m *InstanceMetrics) *models.Finding {
	hourlyPrice, ok := ec2Pricing[m.InstanceType]
	if !ok {
		hourlyPrice = 0.10
	}
	currentMonthlyCost := hourlyPrice * 730

	specs, hasSpecs := instanceSpecs[m.InstanceType]
	cpuStr := fmt.Sprintf("%.0f vCPU", specs[0])
	memStr := fmt.Sprintf("%.0f GB RAM", specs[1])
	if !hasSpecs {
		cpuStr = "? vCPU"
		memStr = "? GB RAM"
	}

	// Decision logic
	isNightIdle := m.AvgCPUNight < 5.0 && m.AvgCPUDay > 10.0
	isOverProvisioned := m.AvgCPU < 15.0 && m.MaxCPU < 50.0
	isVeryIdle := m.AvgCPU < 5.0

	// Skip if well-utilized
	if m.AvgCPU > 30.0 {
		return nil
	}

	// Determine action and build finding
	var action RightSizeAction
	var severity models.Severity
	var title, description, actionText, cliCmd string
	var savings float64

	suggestedType := smartDownsize(m.InstanceType, m.AvgCPU, m.MaxCPU)
	suggestedPrice, _ := ec2Pricing[suggestedType]
	downsizeSavings := (hourlyPrice - suggestedPrice) * 730

	// Calculate schedule savings (stop 8.5 hrs/day = save 35% compute)
	scheduleSavings := currentMonthlyCost * 0.35

	if isVeryIdle && isNightIdle {
		// Very idle overall + idle at night → downsize AND schedule
		action = ActionBoth
		severity = models.SeverityCritical
		savings = downsizeSavings + (suggestedPrice * 730 * 0.35) // downsize savings + schedule savings on new type
		title = fmt.Sprintf("⚡ Over-provisioned + idle at night: %s (%s)", m.Name, m.InstanceType)
		description = fmt.Sprintf(
			"Instance %s (%s, %s, %s) is heavily over-provisioned.\n"+
				"     CPU: avg %.1f%% | max %.1f%% | night avg %.1f%% | day avg %.1f%%\n"+
				"     Current cost: $%.2f/mo\n"+
				"     → Downsize to %s AND schedule stop midnight-8:30am\n"+
				"     → Combined savings: $%.2f/mo",
			m.InstanceID, m.Name, cpuStr, memStr,
			m.AvgCPU, m.MaxCPU, m.AvgCPUNight, m.AvgCPUDay,
			currentMonthlyCost,
			suggestedType,
			savings,
		)
		actionText = fmt.Sprintf("Downsize to %s + schedule auto-stop midnight to 8:30am", suggestedType)
		cliCmd = fmt.Sprintf(
			"# Step 1: Downsize\n"+
				"aws ec2 stop-instances --instance-ids %s --region %s\n"+
				"aws ec2 modify-instance-attribute --instance-id %s --instance-type \"{\\\"Value\\\": \\\"%s\\\"}\" --region %s\n"+
				"aws ec2 start-instances --instance-ids %s --region %s\n\n"+
				"# Step 2: Schedule auto-stop at midnight IST (18:30 UTC)\n"+
				"aws events put-rule --name stop-%s --schedule-expression \"cron(30 18 * * ? *)\" --region %s\n\n"+
				"# Step 3: Schedule auto-start at 8:30am IST (03:00 UTC)\n"+
				"aws events put-rule --name start-%s --schedule-expression \"cron(0 3 * * ? *)\" --region %s",
			m.InstanceID, s.region,
			m.InstanceID, suggestedType, s.region,
			m.InstanceID, s.region,
			m.Name, s.region,
			m.Name, s.region,
		)
	} else if isNightIdle && !isOverProvisioned {
		// Good size but idle at night → schedule only
		action = ActionStop
		severity = models.SeverityHigh
		savings = scheduleSavings
		title = fmt.Sprintf("🌙 Idle at night: %s (%s)", m.Name, m.InstanceType)
		description = fmt.Sprintf(
			"Instance %s (%s, %s, %s) is well-sized but idle at night.\n"+
				"     CPU: avg %.1f%% | night avg %.1f%% | day avg %.1f%%\n"+
				"     Current cost: $%.2f/mo\n"+
				"     → Schedule stop midnight-8:30am to save $%.2f/mo",
			m.InstanceID, m.Name, cpuStr, memStr,
			m.AvgCPU, m.AvgCPUNight, m.AvgCPUDay,
			currentMonthlyCost,
			savings,
		)
		actionText = "Schedule auto-stop midnight to 8:30am"
		cliCmd = fmt.Sprintf(
			"# Schedule auto-stop at midnight IST (18:30 UTC)\n"+
				"aws events put-rule --name stop-%s --schedule-expression \"cron(30 18 * * ? *)\" --region %s\n\n"+
				"# Schedule auto-start at 8:30am IST (03:00 UTC)\n"+
				"aws events put-rule --name start-%s --schedule-expression \"cron(0 3 * * ? *)\" --region %s",
			m.Name, s.region,
			m.Name, s.region,
		)
	} else if isOverProvisioned {
		// Over-provisioned → downsize
		if suggestedType == m.InstanceType {
			return nil // can't downsize further
		}
		action = ActionDownsize
		severity = models.SeverityHigh
		savings = downsizeSavings
		title = fmt.Sprintf("📦 Over-provisioned: %s (%s → %s)", m.Name, m.InstanceType, suggestedType)
		description = fmt.Sprintf(
			"Instance %s (%s, %s, %s) is over-provisioned.\n"+
				"     CPU: avg %.1f%% | max %.1f%% over 14 days\n"+
				"     Current cost: $%.2f/mo → %s at $%.2f/mo\n"+
				"     → Savings: $%.2f/mo",
			m.InstanceID, m.Name, cpuStr, memStr,
			m.AvgCPU, m.MaxCPU,
			currentMonthlyCost, suggestedType, suggestedPrice*730,
			savings,
		)
		actionText = fmt.Sprintf("Downsize from %s to %s", m.InstanceType, suggestedType)
		cliCmd = fmt.Sprintf(
			"# Stop, resize, start:\n"+
				"aws ec2 stop-instances --instance-ids %s --region %s\n"+
				"aws ec2 modify-instance-attribute --instance-id %s --instance-type \"{\\\"Value\\\": \\\"%s\\\"}\" --region %s\n"+
				"aws ec2 start-instances --instance-ids %s --region %s",
			m.InstanceID, s.region,
			m.InstanceID, suggestedType, s.region,
			m.InstanceID, s.region,
		)
	} else {
		// Mild under-utilization but not enough to act
		return nil
	}

	_ = action // used for logic flow

	if savings < 2.0 {
		return nil // skip trivial savings
	}

	return &models.Finding{
		ID:           fmt.Sprintf("rightsize-%s", m.InstanceID),
		ResourceType: models.ResourceEC2Instance,
		ResourceID:   m.InstanceID,
		ResourceName: m.Name,
		Region:       s.region,
		Severity:     severity,
		Title:        title,
		Description:  description,
		MonthlyCost:  savings,
		Action:       actionText,
		CLICommand:   cliCmd,
		ScannedAt:    time.Now(),
	}
}

// smartDownsize picks the right smaller instance based on actual usage patterns
func smartDownsize(instanceType string, avgCPU, maxCPU float64) string {
	// If CPU is very low, suggest jumping down 2 sizes
	// If CPU is moderately low, suggest 1 size down
	aggressive := avgCPU < 10.0 && maxCPU < 30.0

	oneDown := map[string]string{
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
		"r5.2xlarge": "r5.xlarge",
		"r5.xlarge":  "r5.large",
		"c5.2xlarge": "c5.xlarge",
		"c5.xlarge":  "c5.large",
	}

	twoDown := map[string]string{
		"t2.2xlarge": "t3.large",
		"t2.xlarge":  "t3.medium",
		"t2.large":   "t3.small",
		"t3.2xlarge": "t3.large",
		"t3.xlarge":  "t3.medium",
		"t3.large":   "t3.small",
		"m5.4xlarge": "m5.xlarge",
		"m5.2xlarge": "m5.large",
		"r5.2xlarge": "r5.large",
		"c5.2xlarge": "c5.large",
	}

	if aggressive {
		if suggested, ok := twoDown[instanceType]; ok {
			return suggested
		}
	}

	if suggested, ok := oneDown[instanceType]; ok {
		return suggested
	}

	return instanceType
}

// getNightCPU returns average CPU during night hours (12am - 8am IST = 18:30 - 02:30 UTC)
func (s *RightSizeScanner) getNightCPU(ctx context.Context, instanceID string, days int) (float64, error) {
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
		return 0, err
	}

	var nightTotal float64
	var nightCount int

	for _, dp := range result.Datapoints {
		hour := dp.Timestamp.UTC().Hour()
		// Night in IST (UTC+5:30): 12am-8am IST = ~18:30-02:30 UTC
		// Simplified: UTC hours 18-23 and 0-2 are night in IST
		if hour >= 18 || hour <= 2 {
			nightTotal += *dp.Average
			nightCount++
		}
	}

	if nightCount == 0 {
		return 0, fmt.Errorf("no night data")
	}

	return nightTotal / float64(nightCount), nil
}

// getDayCPU returns average CPU during day hours (8am - 12am IST = 02:30 - 18:30 UTC)
func (s *RightSizeScanner) getDayCPU(ctx context.Context, instanceID string, days int) (float64, error) {
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
		return 0, err
	}

	var dayTotal float64
	var dayCount int

	for _, dp := range result.Datapoints {
		hour := dp.Timestamp.UTC().Hour()
		// Day in IST: 8am-12am IST = ~02:30-18:30 UTC
		if hour >= 3 && hour <= 17 {
			dayTotal += *dp.Average
			dayCount++
		}
	}

	if dayCount == 0 {
		return 0, fmt.Errorf("no day data")
	}

	return dayTotal / float64(dayCount), nil
}

// getMetricStat is a generic CloudWatch metric fetcher
func (s *RightSizeScanner) getMetricStat(ctx context.Context, instanceID, metricName string, startTime, endTime time.Time, period int32, stat cwtypes.Statistic) (float64, error) {
	result, err := s.cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/EC2"),
		MetricName: aws.String(metricName),
		Dimensions: []cwtypes.Dimension{
			{
				Name:  aws.String("InstanceId"),
				Value: aws.String(instanceID),
			},
		},
		StartTime:  &startTime,
		EndTime:    &endTime,
		Period:     aws.Int32(period),
		Statistics: []cwtypes.Statistic{stat},
	})
	if err != nil {
		return 0, err
	}

	if len(result.Datapoints) == 0 {
		return 0, fmt.Errorf("no data for %s", metricName)
	}

	var total float64
	for _, dp := range result.Datapoints {
		switch stat {
		case cwtypes.StatisticAverage:
			total += *dp.Average
		case cwtypes.StatisticMaximum:
			total = math.Max(total, *dp.Maximum)
			return total, nil // for max, return the highest point
		case cwtypes.StatisticMinimum:
			if total == 0 {
				total = *dp.Minimum
			}
			total = math.Min(total, *dp.Minimum)
			return total, nil
		}
	}

	return total / float64(len(result.Datapoints)), nil
}
