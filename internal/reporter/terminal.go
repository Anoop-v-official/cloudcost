package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/storygame/cloudcost/internal/models"
)

var (
	red    = color.New(color.FgRed, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	green  = color.New(color.FgGreen, color.Bold)
	cyan   = color.New(color.FgCyan, color.Bold)
	white  = color.New(color.FgWhite, color.Bold)
	dim    = color.New(color.FgHiBlack)
)

// PrintReport outputs the scan report to terminal
func PrintReport(report models.ScanReport) {
	fmt.Println()
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	white.Printf("  ☁️  CloudCost Report — Account: %s\n", report.AccountID)
	dim.Printf("  Scanned: %s\n", report.ScanDate.Format("2006-01-02 15:04:05"))
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	if len(report.Findings) == 0 {
		green.Println("  ✅ No cost optimization findings! Your infrastructure looks clean.")
		fmt.Println()
		return
	}

	// Summary
	white.Printf("  💰 Total Potential Savings: ")
	red.Printf("$%.2f/month ($%.2f/year)\n", report.TotalSavings, report.TotalSavings*12)
	fmt.Printf("  📊 Findings: %d total", report.TotalFindings)
	if report.CriticalCount > 0 {
		red.Printf(" | %d critical", report.CriticalCount)
	}
	if report.HighCount > 0 {
		yellow.Printf(" | %d high", report.HighCount)
	}
	if report.MediumCount > 0 {
		fmt.Printf(" | %d medium", report.MediumCount)
	}
	if report.LowCount > 0 {
		dim.Printf(" | %d low", report.LowCount)
	}
	fmt.Println()
	fmt.Println()

	// Sort findings by severity then by cost
	sort.Slice(report.Findings, func(i, j int) bool {
		si := severityOrder(report.Findings[i].Severity)
		sj := severityOrder(report.Findings[j].Severity)
		if si != sj {
			return si < sj
		}
		return report.Findings[i].MonthlyCost > report.Findings[j].MonthlyCost
	})

	// Group by severity
	printSeverityGroup(report.Findings, models.SeverityCritical, "🔴 CRITICAL — Act Now", red)
	printSeverityGroup(report.Findings, models.SeverityHigh, "🟡 HIGH — Recommended", yellow)
	printSeverityGroup(report.Findings, models.SeverityMedium, "🟢 MEDIUM — Optimize", green)
	printSeverityGroup(report.Findings, models.SeverityLow, "💤 LOW — Cleanup", dim)

	// Footer
	fmt.Println()
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	dim.Println("  Run with --output json for machine-readable output")
	dim.Println("  Run with --verbose for detailed CLI commands")
	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
}

func printSeverityGroup(findings []models.Finding, severity models.Severity, header string, c *color.Color) {
	var group []models.Finding
	for _, f := range findings {
		if f.Severity == severity {
			group = append(group, f)
		}
	}

	if len(group) == 0 {
		return
	}

	var groupSavings float64
	for _, f := range group {
		groupSavings += f.MonthlyCost
	}

	c.Printf("  %s (save $%.2f/mo)\n", header, groupSavings)
	fmt.Println(strings.Repeat("  ─", 20))

	for i, f := range group {
		fmt.Printf("  %d. ", i+1)
		c.Printf("%-60s", f.Title)
		if f.MonthlyCost > 0 {
			red.Printf(" $%.2f/mo", f.MonthlyCost)
		}
		fmt.Println()
		dim.Printf("     %s [%s]\n", f.ResourceID, f.Region)
		fmt.Printf("     → %s\n", f.Action)
		fmt.Printf("     $ %s\n", f.CLICommand)
		fmt.Println()
	}
}

// PrintJSON outputs the report as JSON
func PrintJSON(report models.ScanReport) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// SaveJSON saves the report to a file
func SaveJSON(report models.ScanReport, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func severityOrder(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 0
	case models.SeverityHigh:
		return 1
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 3
	default:
		return 4
	}
}
