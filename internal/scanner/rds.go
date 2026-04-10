package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/storygame/cloudcost/internal/models"
)

// RDS/DocumentDB pricing per hour (ap-south-1)
var rdsPricing = map[string]float64{
	"db.t3.micro":   0.018,
	"db.t3.small":   0.036,
	"db.t3.medium":  0.073,
	"db.t3.large":   0.146,
	"db.t3.xlarge":  0.292,
	"db.t3.2xlarge": 0.584,
	"db.r5.large":   0.240,
	"db.r5.xlarge":  0.480,
	"db.r5.2xlarge": 0.960,
	"db.r6g.large":  0.218,
	"db.r6g.xlarge": 0.436,
	"db.m5.large":   0.185,
	"db.m5.xlarge":  0.370,
}

type RDSScanner struct {
	rdsClient *rds.Client
	cwClient  *cloudwatch.Client
	region    string
}

func NewRDSScanner(cfg aws.Config, region string) *RDSScanner {
	cfg.Region = region
	return &RDSScanner{
		rdsClient: rds.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
		region:    region,
	}
}

// ScanIdleRDSInstances finds RDS instances with very low connections and CPU
func (s *RDSScanner) ScanIdleRDSInstances(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe RDS instances: %w", err)
	}

	for _, db := range result.DBInstances {
		dbID := *db.DBInstanceIdentifier
		dbClass := *db.DBInstanceClass
		engine := *db.Engine
		status := *db.DBInstanceStatus

		if status != "available" {
			continue
		}

		// Get average connections over 7 days
		avgConnections, err := s.getRDSMetric(ctx, dbID, "DatabaseConnections", 7, cwtypes.StatisticAverage)
		if err != nil {
			avgConnections = -1 // unknown
		}

		// Get average CPU over 7 days
		avgCPU, err := s.getRDSMetric(ctx, dbID, "CPUUtilization", 7, cwtypes.StatisticAverage)
		if err != nil {
			avgCPU = -1
		}

		// Get free storage
		freeStorage, _ := s.getRDSMetric(ctx, dbID, "FreeStorageSpace", 1, cwtypes.StatisticAverage)

		// Calculate cost
		hourlyPrice, ok := rdsPricing[dbClass]
		if !ok {
			hourlyPrice = 0.15 // default estimate
		}
		monthlyCost := hourlyPrice * 730

		// Storage cost
		var storageCost float64
		if db.AllocatedStorage != nil {
			storageCost = float64(*db.AllocatedStorage) * 0.115 // gp2 RDS storage
		}
		totalCost := monthlyCost + storageCost

		// Check if idle (zero or near-zero connections)
		if avgConnections >= 0 && avgConnections < 1.0 {
			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("rds-idle-%s", dbID),
				ResourceType: models.ResourceRDS,
				ResourceID:   dbID,
				ResourceName: dbID,
				Region:       s.region,
				Severity:     models.SeverityCritical,
				Title:        fmt.Sprintf("Idle database: %s (%s, %s) — zero connections", dbID, dbClass, engine),
				Description: fmt.Sprintf(
					"RDS instance %s (%s, %s) has avg %.1f connections over 7 days.\n"+
						"     CPU: %.1f%% avg | Instance: $%.2f/mo | Storage: $%.2f/mo\n"+
						"     Total cost: $%.2f/mo for a database nobody is using",
					dbID, dbClass, engine, avgConnections,
					avgCPU, monthlyCost, storageCost,
					totalCost,
				),
				MonthlyCost: totalCost,
				Action:      "Delete the instance if no longer needed. Snapshot first for safety.",
				CLICommand: fmt.Sprintf(
					"# Create final snapshot then delete:\n"+
						"aws rds delete-db-instance --db-instance-identifier %s \\\n"+
						"  --final-db-snapshot-identifier %s-final-snapshot \\\n"+
						"  --region %s",
					dbID, dbID, s.region,
				),
				ScannedAt: time.Now(),
			})
			continue
		}

		// Check if over-provisioned (low CPU + low connections)
		if avgCPU >= 0 && avgCPU < 15.0 && avgConnections >= 0 && avgConnections < 10 {
			suggestedClass := suggestRDSDownsize(dbClass)
			if suggestedClass == dbClass {
				continue
			}

			suggestedPrice, ok := rdsPricing[suggestedClass]
			if !ok {
				continue
			}
			savings := (hourlyPrice - suggestedPrice) * 730

			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("rds-oversize-%s", dbID),
				ResourceType: models.ResourceRDS,
				ResourceID:   dbID,
				ResourceName: dbID,
				Region:       s.region,
				Severity:     models.SeverityHigh,
				Title:        fmt.Sprintf("Over-provisioned DB: %s (%s → %s)", dbID, dbClass, suggestedClass),
				Description: fmt.Sprintf(
					"RDS instance %s (%s, %s) is over-provisioned.\n"+
						"     CPU: %.1f%% avg | Connections: %.1f avg\n"+
						"     Current: $%.2f/mo → %s at $%.2f/mo\n"+
						"     Savings: $%.2f/mo",
					dbID, dbClass, engine,
					avgCPU, avgConnections,
					monthlyCost, suggestedClass, suggestedPrice*730,
					savings,
				),
				MonthlyCost: savings,
				Action:      fmt.Sprintf("Downsize from %s to %s", dbClass, suggestedClass),
				CLICommand: fmt.Sprintf(
					"aws rds modify-db-instance --db-instance-identifier %s \\\n"+
						"  --db-instance-class %s --apply-immediately \\\n"+
						"  --region %s",
					dbID, suggestedClass, s.region,
				),
				ScannedAt: time.Now(),
			})
		}

		// Check for storage over-provisioning
		if freeStorage > 0 && db.AllocatedStorage != nil {
			allocatedGB := float64(*db.AllocatedStorage)
			freeGB := freeStorage / (1024 * 1024 * 1024) // bytes to GB
			usedPercent := ((allocatedGB - freeGB) / allocatedGB) * 100

			if usedPercent < 30 && allocatedGB > 50 {
				wastedGB := freeGB - (allocatedGB * 0.3) // keep 30% free
				wastedCost := wastedGB * 0.115

				findings = append(findings, models.Finding{
					ID:           fmt.Sprintf("rds-storage-%s", dbID),
					ResourceType: models.ResourceRDS,
					ResourceID:   dbID,
					ResourceName: dbID,
					Region:       s.region,
					Severity:     models.SeverityMedium,
					Title:        fmt.Sprintf("Over-provisioned DB storage: %s (%.0f%% used of %.0f GB)", dbID, usedPercent, allocatedGB),
					Description: fmt.Sprintf(
						"RDS instance %s has %.0f GB allocated but only %.0f%% used (%.0f GB free).\n"+
							"     Wasted storage: ~%.0f GB costing $%.2f/mo",
						dbID, allocatedGB, usedPercent, freeGB, wastedGB, wastedCost,
					),
					MonthlyCost: wastedCost,
					Action:      "Note: RDS storage can only be increased, not decreased. Consider this for future instances.",
					CLICommand:  "# RDS storage cannot be shrunk. For future instances, start smaller.",
					ScannedAt:   time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// ScanDocumentDBClusters finds idle or unused DocumentDB clusters
func (s *RDSScanner) ScanDocumentDBClusters(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
	}

	for _, cluster := range result.DBClusters {
		if cluster.Engine == nil || (*cluster.Engine != "docdb" && *cluster.Engine != "aurora" && *cluster.Engine != "aurora-mysql" && *cluster.Engine != "aurora-postgresql") {
			continue
		}

		clusterID := *cluster.DBClusterIdentifier
		engine := *cluster.Engine
		status := *cluster.Status

		if status != "available" {
			continue
		}

		// Count instances in cluster
		instanceCount := len(cluster.DBClusterMembers)

		// Estimate cost based on instances
		var totalCost float64
		for _, member := range cluster.DBClusterMembers {
			if member.DBInstanceIdentifier != nil {
				// Get instance details
				instResult, err := s.rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
					DBInstanceIdentifier: member.DBInstanceIdentifier,
				})
				if err == nil && len(instResult.DBInstances) > 0 {
					inst := instResult.DBInstances[0]
					hourly, ok := rdsPricing[*inst.DBInstanceClass]
					if !ok {
						hourly = 0.15
					}
					totalCost += hourly * 730
				}
			}
		}

		// Check connections
		avgConnections, err := s.getDocDBMetric(ctx, clusterID, "DatabaseConnections", 7)
		if err != nil {
			avgConnections = -1
		}

		if avgConnections >= 0 && avgConnections < 1.0 {
			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("docdb-idle-%s", clusterID),
				ResourceType: models.ResourceRDS,
				ResourceID:   clusterID,
				ResourceName: clusterID,
				Region:       s.region,
				Severity:     models.SeverityCritical,
				Title:        fmt.Sprintf("Idle %s cluster: %s (%d instances, zero connections)", engine, clusterID, instanceCount),
				Description: fmt.Sprintf(
					"Cluster %s (%s) has %d instances with avg %.1f connections over 7 days.\n"+
						"     Total cost: $%.2f/mo for a cluster nobody is using",
					clusterID, engine, instanceCount, avgConnections, totalCost,
				),
				MonthlyCost: totalCost,
				Action:      "Delete the cluster if no longer needed. Snapshot first.",
				CLICommand: fmt.Sprintf(
					"# Delete instances first, then cluster:\n"+
						"aws rds delete-db-cluster --db-cluster-identifier %s \\\n"+
						"  --final-db-snapshot-identifier %s-final \\\n"+
						"  --region %s",
					clusterID, clusterID, s.region,
				),
				ScannedAt: time.Now(),
			})
		}
	}

	return findings, nil
}

func (s *RDSScanner) getRDSMetric(ctx context.Context, dbID, metricName string, days int, stat cwtypes.Statistic) (float64, error) {
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -days)

	result, err := s.cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/RDS"),
		MetricName: aws.String(metricName),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("DBInstanceIdentifier"), Value: aws.String(dbID)},
		},
		StartTime:  &startTime,
		EndTime:    &endTime,
		Period:     aws.Int32(86400),
		Statistics: []cwtypes.Statistic{stat},
	})
	if err != nil {
		return 0, err
	}

	if len(result.Datapoints) == 0 {
		return 0, fmt.Errorf("no data")
	}

	var total float64
	for _, dp := range result.Datapoints {
		total += *dp.Average
	}
	return total / float64(len(result.Datapoints)), nil
}

func (s *RDSScanner) getDocDBMetric(ctx context.Context, clusterID, metricName string, days int) (float64, error) {
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -days)

	result, err := s.cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/DocDB"),
		MetricName: aws.String(metricName),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("DBClusterIdentifier"), Value: aws.String(clusterID)},
		},
		StartTime:  &startTime,
		EndTime:    &endTime,
		Period:     aws.Int32(86400),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	})
	if err != nil {
		return 0, err
	}

	if len(result.Datapoints) == 0 {
		return 0, fmt.Errorf("no data")
	}

	var total float64
	for _, dp := range result.Datapoints {
		total += *dp.Average
	}
	return total / float64(len(result.Datapoints)), nil
}

func suggestRDSDownsize(dbClass string) string {
	m := map[string]string{
		"db.t3.2xlarge": "db.t3.xlarge",
		"db.t3.xlarge":  "db.t3.large",
		"db.t3.large":   "db.t3.medium",
		"db.t3.medium":  "db.t3.small",
		"db.r5.2xlarge": "db.r5.xlarge",
		"db.r5.xlarge":  "db.r5.large",
		"db.m5.xlarge":  "db.m5.large",
	}
	if s, ok := m[dbClass]; ok {
		return s
	}
	return dbClass
}
