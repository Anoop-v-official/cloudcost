package interactive

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/Anoop-v-official/cloudcost/internal/models"
)

var (
	red    = color.New(color.FgRed, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	green  = color.New(color.FgGreen, color.Bold)
	cyan   = color.New(color.FgCyan, color.Bold)
	white  = color.New(color.FgWhite, color.Bold)
	dim    = color.New(color.FgHiBlack)
)

type FixResult struct {
	Finding models.Finding
	Action  string // "fixed", "skipped", "ignored"
	Error   error
}

// RunInteractive walks through each finding and lets the user decide what to do
func RunInteractive(report models.ScanReport, profile, region string) []FixResult {
	var results []FixResult
	reader := bufio.NewReader(os.Stdin)

	// Sort by severity then cost
	findings := report.Findings
	sort.Slice(findings, func(i, j int) bool {
		si := severityOrder(findings[i].Severity)
		sj := severityOrder(findings[j].Severity)
		if si != sj {
			return si < sj
		}
		return findings[i].MonthlyCost > findings[j].MonthlyCost
	})

	// Filter out zero-cost findings for interactive mode
	var actionable []models.Finding
	for _, f := range findings {
		if f.MonthlyCost > 0 {
			actionable = append(actionable, f)
		}
	}

	if len(actionable) == 0 {
		green.Println("\n  ✅ No actionable findings! Your infrastructure looks clean.")
		return results
	}

	// Header
	fmt.Println()
	cyan.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	white.Println("  ☁️  CloudCost Interactive Fix Mode")
	dim.Printf("  %d findings to review | Potential savings: $%.2f/mo\n", len(actionable), report.TotalSavings)
	cyan.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	dim.Println("  Walk through each finding and decide what to do.")
	dim.Println("  CloudCost will execute the fix command for you (with confirmation).")
	fmt.Println()

	var totalFixed float64
	var fixedCount, skippedCount, ignoredCount int

	for i, finding := range actionable {
		// Finding header
		fmt.Printf("  ─────────────────────────────────────────────────────\n")
		white.Printf("  [%d/%d] ", i+1, len(actionable))
		severityColor(finding.Severity).Printf("%s ", finding.Severity)
		fmt.Printf("| ")
		red.Printf("$%.2f/mo\n", finding.MonthlyCost)
		fmt.Println()

		// Finding details
		white.Printf("  %s\n", finding.Title)
		dim.Printf("  %s [%s]\n", finding.ResourceID, finding.Region)
		fmt.Println()

		// Description (indent each line)
		for _, line := range strings.Split(finding.Description, "\n") {
			dim.Printf("  %s\n", strings.TrimSpace(line))
		}
		fmt.Println()

		// Recommended action
		cyan.Printf("  → %s\n", finding.Action)
		fmt.Println()

		// Command preview
		dim.Println("  Command to execute:")
		for _, line := range strings.Split(finding.CLICommand, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				dim.Printf("    %s\n", line)
			} else {
				fmt.Printf("    %s\n", line)
			}
		}
		fmt.Println()

		// Action prompt
		action := promptAction(reader, finding, profile)

		switch action {
		case "fix":
			err := executeFix(finding, profile, reader)
			if err != nil {
				red.Printf("  ❌ Error: %s\n", err)
				results = append(results, FixResult{Finding: finding, Action: "error", Error: err})
			} else {
				green.Printf("  ✅ Fixed! Saving $%.2f/mo\n", finding.MonthlyCost)
				totalFixed += finding.MonthlyCost
				fixedCount++
				results = append(results, FixResult{Finding: finding, Action: "fixed"})
			}
		case "skip":
			dim.Println("  ⏭️  Skipped — will show again next scan")
			skippedCount++
			results = append(results, FixResult{Finding: finding, Action: "skipped"})
		case "ignore":
			dim.Println("  🔇 Ignored — won't show again")
			ignoredCount++
			results = append(results, FixResult{Finding: finding, Action: "ignored"})
		case "quit":
			fmt.Println()
			printSummary(totalFixed, fixedCount, skippedCount, ignoredCount, len(actionable)-(i))
			return results
		}
		fmt.Println()
	}

	// Final summary
	printSummary(totalFixed, fixedCount, skippedCount, ignoredCount, 0)
	return results
}

func promptAction(reader *bufio.Reader, finding models.Finding, profile string) string {
	for {
		cyan.Print("  What do you want to do?\n")
		fmt.Println()

		// Show options based on finding type
		if isDestructive(finding) {
			green.Print("    [f] Fix it")
			fmt.Println(" — execute the command above")
		} else {
			green.Print("    [f] Fix it")
			fmt.Println(" — execute the command above")
		}

		dim.Print("    [s] Skip")
		fmt.Println("   — come back to this later")

		dim.Print("    [i] Ignore")
		fmt.Println(" — don't show this again")

		dim.Print("    [c] Copy")
		fmt.Println("  — copy command to clipboard")

		red.Print("    [q] Quit")
		fmt.Println("   — exit interactive mode")

		fmt.Println()
		fmt.Print("  > ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		switch input {
		case "f", "fix":
			return "fix"
		case "s", "skip", "n", "next":
			return "skip"
		case "i", "ignore":
			return "ignore"
		case "c", "copy":
			copyToClipboard(finding.CLICommand)
			green.Println("  📋 Command copied to clipboard!")
			fmt.Println()
			continue // show prompt again
		case "q", "quit", "exit":
			return "quit"
		default:
			dim.Println("  Invalid option. Press f, s, i, c, or q.")
			fmt.Println()
		}
	}
}

func executeFix(finding models.Finding, profile string, reader *bufio.Reader) error {
	// Safety confirmation for destructive actions
	fmt.Println()
	yellow.Println("  ⚠️  Confirmation required")
	fmt.Printf("  This will execute:\n")

	// Show only the actual commands (not comments)
	commands := extractCommands(finding.CLICommand)
	for _, cmd := range commands {
		red.Printf("    $ %s\n", cmd)
	}
	fmt.Println()

	fmt.Print("  Type 'yes' to confirm: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))

	if input != "yes" {
		dim.Println("  Cancelled.")
		return nil
	}

	// Execute each command
	for _, cmdStr := range commands {
		// Add profile if not already present
		if profile != "" && !strings.Contains(cmdStr, "--profile") {
			cmdStr = cmdStr + " --profile " + profile
		}

		fmt.Printf("  Executing: %s\n", cmdStr)

		cmd := exec.Command("bash", "-c", cmdStr)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("command failed: %s — %w", cmdStr, err)
		}
	}

	return nil
}

func extractCommands(cliCommand string) []string {
	var commands []string
	for _, line := range strings.Split(cliCommand, "\n") {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Handle line continuations
		if strings.HasSuffix(line, "\\") {
			// Find the full command across continuation lines
			continue
		}
		commands = append(commands, line)
	}

	// Rejoin continuation lines
	if len(commands) == 0 {
		// Try treating the whole thing as one command
		cleaned := strings.ReplaceAll(cliCommand, "\\\n", " ")
		for _, line := range strings.Split(cleaned, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				commands = append(commands, line)
			}
		}
	}

	return commands
}

func copyToClipboard(text string) {
	// Try different clipboard commands
	cmds := []struct {
		name string
		args []string
	}{
		{"xclip", []string{"-selection", "clipboard"}},
		{"xsel", []string{"--clipboard", "--input"}},
		{"pbcopy", nil}, // macOS
		{"clip.exe", nil}, // WSL
	}

	for _, c := range cmds {
		path, err := exec.LookPath(c.name)
		if err != nil {
			continue
		}

		cmd := exec.Command(path, c.args...)
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err == nil {
			return
		}
	}

	// Fallback: print the command
	dim.Println("  (Clipboard not available — command shown above)")
}

func isDestructive(finding models.Finding) bool {
	cmd := strings.ToLower(finding.CLICommand)
	return strings.Contains(cmd, "delete") ||
		strings.Contains(cmd, "terminate") ||
		strings.Contains(cmd, "remove") ||
		strings.Contains(cmd, "release") ||
		strings.Contains(cmd, "deregister")
}

func severityColor(s models.Severity) *color.Color {
	switch s {
	case models.SeverityCritical:
		return red
	case models.SeverityHigh:
		return yellow
	case models.SeverityMedium:
		return green
	default:
		return dim
	}
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

func printSummary(totalFixed float64, fixed, skipped, ignored, remaining int) {
	fmt.Println()
	cyan.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	white.Println("  📊 Session Summary")
	cyan.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	if fixed > 0 {
		green.Printf("  ✅ Fixed:    %d findings — saving $%.2f/mo ($%.2f/yr)\n", fixed, totalFixed, totalFixed*12)
	}
	if skipped > 0 {
		dim.Printf("  ⏭️  Skipped:  %d findings\n", skipped)
	}
	if ignored > 0 {
		dim.Printf("  🔇 Ignored:  %d findings\n", ignored)
	}
	if remaining > 0 {
		dim.Printf("  📋 Remaining: %d findings (run again to review)\n", remaining)
	}

	fmt.Println()
	if totalFixed > 0 {
		green.Printf("  💰 Total savings this session: $%.2f/month ($%.2f/year)\n", totalFixed, totalFixed*12)
	}

	fmt.Println()
	dim.Println("  Run 'cloudcost scan' again to verify the fixes.")
	fmt.Println()
}
