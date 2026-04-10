package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/Anoop-v-official/cloudcost/internal/config"
	"github.com/Anoop-v-official/cloudcost/internal/models"
	"github.com/Anoop-v-official/cloudcost/internal/reporter"
	"github.com/Anoop-v-official/cloudcost/internal/scanner"
)

var (
	profile     string
	region      string
	roleARN     string
	output      string
	verbose     bool
	snapshotAge int
	amiAge      int
	allRegions  bool
	outputFile  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "cloudcost",
		Short: "☁️  CloudCost — AI-powered cloud cost optimizer",
		Long: `CloudCost scans your AWS infrastructure for cost optimization opportunities.
It finds unused resources, oversized instances, and configuration improvements
that can save you hundreds of dollars per month.`,
	}

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan AWS account for cost savings",
		Long:  "Performs a comprehensive scan of your AWS account to find unused resources, oversized instances, and cost optimization opportunities.",
		RunE:  runScan,
	}

	scanCmd.Flags().StringVarP(&profile, "profile", "p", "", "AWS CLI profile name")
	scanCmd.Flags().StringVarP(&region, "region", "r", "", "AWS region to scan (default: profile's region)")
	scanCmd.Flags().StringVar(&roleARN, "role-arn", "", "IAM Role ARN for cross-account access")
	scanCmd.Flags().StringVarP(&output, "output", "o", "text", "Output format: text, json")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed information")
	scanCmd.Flags().IntVar(&snapshotAge, "snapshot-age", 30, "Flag snapshots older than N days")
	scanCmd.Flags().IntVar(&amiAge, "ami-age", 90, "Flag AMIs older than N days")
	scanCmd.Flags().BoolVar(&allRegions, "all-regions", false, "Scan all major AWS regions")
	scanCmd.Flags().StringVar(&outputFile, "save", "", "Save report to file (JSON)")

	rootCmd.AddCommand(scanCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Banner
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println()
	cyan.Println("  ☁️  CloudCost Scanner")
	cyan.Println("  Finding money hiding in your AWS account...")
	fmt.Println()

	// Load AWS config
	cfg, err := config.LoadAWSConfig(ctx, profile, region, roleARN)
	if err != nil {
		return fmt.Errorf("❌ Failed to load AWS config: %w\n  Make sure your profile/credentials are configured correctly", err)
	}

	// Get account ID
	accountID, err := config.GetAccountID(ctx, cfg)
	if err != nil {
		return fmt.Errorf("❌ Failed to get account ID: %w", err)
	}

	fmt.Printf("  📋 Account: %s\n", accountID)
	if profile != "" {
		fmt.Printf("  👤 Profile: %s\n", profile)
	}

	// Determine regions to scan
	regions := []string{cfg.Region}
	if allRegions {
		regions = config.GetAllRegions()
	}
	fmt.Printf("  🌍 Regions: %v\n", regions)
	fmt.Println()

	var allFindings []models.Finding

	for _, r := range regions {
		if len(regions) > 1 {
			fmt.Printf("  🔍 Scanning %s...\n", r)
		}

		// --- EBS Scans ---
		fmt.Printf("    📦 Scanning EBS volumes & snapshots...")
		ebsScanner := scanner.NewEBSScanner(cfg, r)

		findings, err := ebsScanner.ScanUnattachedVolumes(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		findings, err = ebsScanner.ScanGP2Volumes(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		findings, err = ebsScanner.ScanOldSnapshots(ctx, snapshotAge)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		findings, err = ebsScanner.ScanOversizedVolumes(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		color.New(color.FgGreen).Println(" ✓")

		// --- EC2 Scans ---
		fmt.Printf("    🖥️  Scanning EC2 instances & IPs...")
		ec2Scanner := scanner.NewEC2Scanner(cfg, r)

		findings, err = ec2Scanner.ScanUnusedElasticIPs(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		findings, err = ec2Scanner.ScanUnderutilizedInstances(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		findings, err = ec2Scanner.ScanStoppedInstancesWithVolumes(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		findings, err = ec2Scanner.ScanOldAMIs(ctx, amiAge)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		color.New(color.FgGreen).Println(" ✓")

		// --- Network Scans ---
		fmt.Printf("    🌐 Scanning Load Balancers & NAT Gateways...")
		netScanner := scanner.NewNetworkScanner(cfg, r)

		findings, err = netScanner.ScanNATGateways(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		findings, err = netScanner.ScanIdleLoadBalancers(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		findings, err = netScanner.ScanOrphanedTargetGroups(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		color.New(color.FgGreen).Println(" ✓")

		// --- Right-Sizing Scans ---
		fmt.Printf("    ⚡ Analyzing instance right-sizing...")
		rightSizeScanner := scanner.NewRightSizeScanner(cfg, r)

		findings, err = rightSizeScanner.ScanOverProvisioned(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		color.New(color.FgGreen).Println(" ✓")

		// --- Schedule Scans ---
		fmt.Printf("    🕐 Detecting auto-stop/start candidates...")
		scheduleScanner := scanner.NewScheduleScanner(cfg, r)

		findings, err = scheduleScanner.ScanScheduleCandidates(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		color.New(color.FgGreen).Println(" ✓")

		// --- RDS/DocumentDB Scans ---
		fmt.Printf("    🗄️  Scanning RDS & DocumentDB...")
		rdsScanner := scanner.NewRDSScanner(cfg, r)

		findings, err = rdsScanner.ScanIdleRDSInstances(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		findings, err = rdsScanner.ScanDocumentDBClusters(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		color.New(color.FgGreen).Println(" ✓")

		// --- EKS Scans ---
		fmt.Printf("    ☸️  Scanning EKS clusters...")
		eksScanner := scanner.NewEKSScanner(cfg, r)

		findings, err = eksScanner.ScanEKSClusters(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		color.New(color.FgGreen).Println(" ✓")

		// --- S3 Scans ---
		fmt.Printf("    🪣 Scanning S3 buckets...")
		s3Scanner := scanner.NewS3Scanner(cfg, r)

		findings, err = s3Scanner.ScanS3Buckets(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		color.New(color.FgGreen).Println(" ✓")

		// --- Lambda Scans ---
		fmt.Printf("    ⚡ Scanning Lambda functions...")
		lambdaScanner := scanner.NewLambdaScanner(cfg, r)

		findings, err = lambdaScanner.ScanLambdaFunctions(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		color.New(color.FgGreen).Println(" ✓")

		// --- CloudWatch Logs Scans ---
		fmt.Printf("    📝 Scanning CloudWatch Log groups...")
		cwLogsScanner := scanner.NewCloudWatchLogsScanner(cfg, r)

		findings, err = cwLogsScanner.ScanLogGroups(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		color.New(color.FgGreen).Println(" ✓")

		// --- ElastiCache Scans ---
		fmt.Printf("    🔴 Scanning ElastiCache clusters...")
		ecScanner := scanner.NewElastiCacheScanner(cfg, r)

		findings, err = ecScanner.ScanElastiCacheClusters(ctx)
		if err == nil {
			allFindings = append(allFindings, findings...)
		}

		color.New(color.FgGreen).Println(" ✓")
	}

	// Build report
	report := buildReport(accountID, allFindings)

	// Output
	fmt.Println()
	switch output {
	case "json":
		if err := reporter.PrintJSON(report); err != nil {
			return fmt.Errorf("failed to output JSON: %w", err)
		}
	default:
		reporter.PrintReport(report)
	}

	// Save to file if requested
	if outputFile != "" {
		if err := reporter.SaveJSON(report, outputFile); err != nil {
			return fmt.Errorf("failed to save report: %w", err)
		}
		fmt.Printf("  💾 Report saved to %s\n\n", outputFile)
	}

	return nil
}

func buildReport(accountID string, findings []models.Finding) models.ScanReport {
	report := models.ScanReport{
		AccountID:     accountID,
		ScanDate:      time.Now(),
		TotalFindings: len(findings),
		Findings:      findings,
	}

	for _, f := range findings {
		report.TotalSavings += f.MonthlyCost
		switch f.Severity {
		case models.SeverityCritical:
			report.CriticalCount++
		case models.SeverityHigh:
			report.HighCount++
		case models.SeverityMedium:
			report.MediumCount++
		case models.SeverityLow:
			report.LowCount++
		}
	}

	return report
}
