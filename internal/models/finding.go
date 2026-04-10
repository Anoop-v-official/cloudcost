package models

import "time"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type ResourceType string

const (
	ResourceEBSVolume    ResourceType = "EBS Volume"
	ResourceEBSSnapshot  ResourceType = "EBS Snapshot"
	ResourceEC2Instance  ResourceType = "EC2 Instance"
	ResourceElasticIP    ResourceType = "Elastic IP"
	ResourceLoadBalancer ResourceType = "Load Balancer"
	ResourceNATGateway   ResourceType = "NAT Gateway"
	ResourceRDS          ResourceType = "RDS Instance"
	ResourceS3Bucket     ResourceType = "S3 Bucket"
	ResourceTargetGroup  ResourceType = "Target Group"
)

type Finding struct {
	ID           string       `json:"id"`
	ResourceType ResourceType `json:"resource_type"`
	ResourceID   string       `json:"resource_id"`
	ResourceName string       `json:"resource_name"`
	Region       string       `json:"region"`
	Severity     Severity     `json:"severity"`
	Title        string       `json:"title"`
	Description  string       `json:"description"`
	MonthlyCost  float64      `json:"monthly_cost"`
	Action       string       `json:"action"`
	CLICommand   string       `json:"cli_command"`
	ScannedAt    time.Time    `json:"scanned_at"`
}

type ScanReport struct {
	AccountID      string    `json:"account_id"`
	ScanDate       time.Time `json:"scan_date"`
	TotalFindings  int       `json:"total_findings"`
	TotalSavings   float64   `json:"total_savings"`
	Findings       []Finding `json:"findings"`
	CriticalCount  int       `json:"critical_count"`
	HighCount      int       `json:"high_count"`
	MediumCount    int       `json:"medium_count"`
	LowCount       int       `json:"low_count"`
}

type ScanConfig struct {
	Profile  string
	Region   string
	Regions  []string // scan multiple regions
	RoleARN  string   // for cross-account access
	Output   string   // json, text, html
	Verbose  bool
}

// Pricing constants (USD per month, ap-south-1 Mumbai)
// These are defaults, actual prices fetched per region
var EBSPricing = map[string]float64{
	"gp3":      0.096,  // per GB/month
	"gp2":      0.114,  // per GB/month
	"io1":      0.131,  // per GB/month
	"io2":      0.131,  // per GB/month
	"st1":      0.054,  // per GB/month
	"sc1":      0.018,  // per GB/month
	"standard": 0.05,   // per GB/month (magnetic)
}

var SnapshotPricing = 0.05 // per GB/month

var EIPIdlePricing = 3.60 // per unused EIP/month

var NATGatewayPricing = 32.40 // per NAT Gateway/month (hourly * 730)

// EC2 instance family categories for right-sizing
type InstanceCategory string

const (
	CategoryGeneral  InstanceCategory = "general"    // t3, m5, m6i
	CategoryCompute  InstanceCategory = "compute"    // c5, c6i
	CategoryMemory   InstanceCategory = "memory"     // r5, r6i
	CategoryStorage  InstanceCategory = "storage"    // i3, d2
	CategoryBurstable InstanceCategory = "burstable" // t2, t3
)

func GetInstanceCategory(instanceType string) InstanceCategory {
	if len(instanceType) < 2 {
		return CategoryGeneral
	}
	prefix := instanceType[:2]
	switch prefix {
	case "t2", "t3", "t4":
		return CategoryBurstable
	case "c5", "c6", "c7":
		return CategoryCompute
	case "r5", "r6", "r7":
		return CategoryMemory
	case "i3", "d2", "d3":
		return CategoryStorage
	default:
		return CategoryGeneral
	}
}
