package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/storygame/cloudcost/internal/models"
)

var elasticachePricing = map[string]float64{
	"cache.t3.micro":   0.017,
	"cache.t3.small":   0.034,
	"cache.t3.medium":  0.068,
	"cache.t4g.micro":  0.016,
	"cache.t4g.small":  0.032,
	"cache.t4g.medium": 0.065,
	"cache.r5.large":   0.228,
	"cache.r5.xlarge":  0.455,
	"cache.r6g.large":  0.205,
	"cache.r6g.xlarge": 0.410,
	"cache.m5.large":   0.155,
	"cache.m5.xlarge":  0.310,
}

type ElastiCacheScanner struct {
	ecClient *elasticache.Client
	cwClient *cloudwatch.Client
	region   string
}

func NewElastiCacheScanner(cfg aws.Config, region string) *ElastiCacheScanner {
	cfg.Region = region
	return &ElastiCacheScanner{
		ecClient: elasticache.NewFromConfig(cfg),
		cwClient: cloudwatch.NewFromConfig(cfg),
		region:   region,
	}
}

// ScanElastiCacheClusters finds idle or underutilized ElastiCache clusters
func (s *ElastiCacheScanner) ScanElastiCacheClusters(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	result, err := s.ecClient.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{
		ShowCacheNodeInfo: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ElastiCache clusters: %w", err)
	}

	for _, cluster := range result.CacheClusters {
		clusterID := *cluster.CacheClusterId
		nodeType := *cluster.CacheNodeType
		engine := *cluster.Engine
		numNodes := int(*cluster.NumCacheNodes)

		// Calculate cost
		hourlyPrice, ok := elasticachePricing[nodeType]
		if !ok {
			hourlyPrice = 0.10
		}
		monthlyCost := hourlyPrice * 730 * float64(numNodes)

		// Get CPU utilization
		avgCPU, err := s.getElastiCacheMetric(ctx, clusterID, "CPUUtilization", 7)
		if err != nil {
			avgCPU = -1
		}

		// Get current connections
		avgConnections, err := s.getElastiCacheMetric(ctx, clusterID, "CurrConnections", 7)
		if err != nil {
			avgConnections = -1
		}

		// Get cache hit rate
		hits, _ := s.getElastiCacheMetric(ctx, clusterID, "CacheHits", 7)
		misses, _ := s.getElastiCacheMetric(ctx, clusterID, "CacheMisses", 7)
		hitRate := float64(0)
		if hits+misses > 0 {
			hitRate = (hits / (hits + misses)) * 100
		}

		// Check for idle cluster (very low connections)
		if avgConnections >= 0 && avgConnections < 2 {
			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("ec-idle-%s", clusterID),
				ResourceType: models.ResourceRDS,
				ResourceID:   clusterID,
				ResourceName: clusterID,
				Region:       s.region,
				Severity:     models.SeverityCritical,
				Title:        fmt.Sprintf("Idle ElastiCache: %s (%s, %s, %d nodes)", clusterID, nodeType, engine, numNodes),
				Description: fmt.Sprintf(
					"ElastiCache cluster %s (%s, %s) has avg %.1f connections over 7 days.\n"+
						"     CPU: %.1f%% | Cost: $%.2f/mo\n"+
						"     This cluster appears unused.",
					clusterID, nodeType, engine, avgConnections,
					avgCPU, monthlyCost,
				),
				MonthlyCost: monthlyCost,
				Action:      "Delete if no longer needed",
				CLICommand: fmt.Sprintf(
					"aws elasticache delete-cache-cluster --cache-cluster-id %s \\\n"+
						"  --final-snapshot-identifier %s-final --region %s",
					clusterID, clusterID, s.region,
				),
				ScannedAt: time.Now(),
			})
			continue
		}

		// Check for over-provisioned (low CPU + low connections relative to capacity)
		if avgCPU >= 0 && avgCPU < 10 && monthlyCost > 50 {
			suggestedType := suggestElastiCacheDownsize(nodeType)
			if suggestedType == nodeType {
				continue
			}

			suggestedPrice, ok := elasticachePricing[suggestedType]
			if !ok {
				continue
			}
			savings := (hourlyPrice - suggestedPrice) * 730 * float64(numNodes)

			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("ec-oversize-%s", clusterID),
				ResourceType: models.ResourceRDS,
				ResourceID:   clusterID,
				ResourceName: clusterID,
				Region:       s.region,
				Severity:     models.SeverityHigh,
				Title:        fmt.Sprintf("Over-provisioned ElastiCache: %s (%s → %s)", clusterID, nodeType, suggestedType),
				Description: fmt.Sprintf(
					"ElastiCache %s (%s, %s, %d nodes) is over-provisioned.\n"+
						"     CPU: %.1f%% | Connections: %.1f | Hit rate: %.0f%%\n"+
						"     Current: $%.2f/mo → %s at $%.2f/mo\n"+
						"     Savings: $%.2f/mo",
					clusterID, nodeType, engine, numNodes,
					avgCPU, avgConnections, hitRate,
					monthlyCost, suggestedType, suggestedPrice*730*float64(numNodes),
					savings,
				),
				MonthlyCost: savings,
				Action:      fmt.Sprintf("Downsize from %s to %s", nodeType, suggestedType),
				CLICommand: fmt.Sprintf(
					"aws elasticache modify-cache-cluster --cache-cluster-id %s \\\n"+
						"  --cache-node-type %s --apply-immediately --region %s",
					clusterID, suggestedType, s.region,
				),
				ScannedAt: time.Now(),
			})
		}
	}

	return findings, nil
}

func (s *ElastiCacheScanner) getElastiCacheMetric(ctx context.Context, clusterID, metricName string, days int) (float64, error) {
	endTime := time.Now()
	startTime := endTime.AddDate(0, 0, -days)

	result, err := s.cwClient.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/ElastiCache"),
		MetricName: aws.String(metricName),
		Dimensions: []cwtypes.Dimension{
			{Name: aws.String("CacheClusterId"), Value: aws.String(clusterID)},
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

func suggestElastiCacheDownsize(nodeType string) string {
	m := map[string]string{
		"cache.r5.xlarge":  "cache.r5.large",
		"cache.r5.large":   "cache.t3.medium",
		"cache.r6g.xlarge": "cache.r6g.large",
		"cache.r6g.large":  "cache.t4g.medium",
		"cache.m5.xlarge":  "cache.m5.large",
		"cache.m5.large":   "cache.t3.medium",
		"cache.t3.medium":  "cache.t3.small",
		"cache.t3.small":   "cache.t3.micro",
		"cache.t4g.medium": "cache.t4g.small",
		"cache.t4g.small":  "cache.t4g.micro",
	}
	if s, ok := m[nodeType]; ok {
		return s
	}
	return nodeType
}
