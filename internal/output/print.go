package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"

	"god-eye/internal/config"
)

var (
	// Basic colors
	Green   = color.New(color.FgGreen).SprintFunc()
	Red     = color.New(color.FgRed).SprintFunc()
	Blue    = color.New(color.FgBlue).SprintFunc()
	Yellow  = color.New(color.FgYellow).SprintFunc()
	Cyan    = color.New(color.FgCyan).SprintFunc()
	Magenta = color.New(color.FgMagenta).SprintFunc()
	White   = color.New(color.FgWhite).SprintFunc()

	// Bold variants
	BoldGreen   = color.New(color.FgGreen, color.Bold).SprintFunc()
	BoldRed     = color.New(color.FgRed, color.Bold).SprintFunc()
	BoldCyan    = color.New(color.FgCyan, color.Bold).SprintFunc()
	BoldYellow  = color.New(color.FgYellow, color.Bold).SprintFunc()
	BoldMagenta = color.New(color.FgMagenta, color.Bold).SprintFunc()
	BoldWhite   = color.New(color.FgWhite, color.Bold).SprintFunc()

	// Dim/faint
	Dim = color.New(color.Faint).SprintFunc()

	// Background highlights
	BgRed    = color.New(color.BgRed, color.FgWhite, color.Bold).SprintFunc()
	BgGreen  = color.New(color.BgGreen, color.FgBlack, color.Bold).SprintFunc()
	BgYellow = color.New(color.BgYellow, color.FgBlack, color.Bold).SprintFunc()
)

func PrintBanner() {
	fmt.Println()
	fmt.Println(BoldCyan("    ██████╗  ██████╗ ██████╗ ") + BoldWhite("███████╗") + BoldCyan("   ███████╗██╗   ██╗███████╗"))
	fmt.Println(BoldCyan("   ██╔════╝ ██╔═══██╗██╔══██╗") + BoldWhite("██╔════╝") + BoldCyan("   ██╔════╝╚██╗ ██╔╝██╔════╝"))
	fmt.Println(BoldCyan("   ██║  ███╗██║   ██║██║  ██║") + BoldWhite("███████╗") + BoldCyan("   █████╗   ╚████╔╝ █████╗  "))
	fmt.Println(BoldCyan("   ██║   ██║██║   ██║██║  ██║") + BoldWhite("╚════██║") + BoldCyan("   ██╔══╝    ╚██╔╝  ██╔══╝  "))
	fmt.Println(BoldCyan("   ╚██████╔╝╚██████╔╝██████╔╝") + BoldWhite("███████║") + BoldCyan("   ███████╗   ██║   ███████╗"))
	fmt.Println(BoldCyan("    ╚═════╝  ╚═════╝ ╚═════╝ ") + BoldWhite("╚══════╝") + BoldCyan("   ╚══════╝   ╚═╝   ╚══════╝"))
	fmt.Println()
	fmt.Printf("              %s  %s\n", BoldWhite("⚡"), Dim("Ultra-fast subdomain enumeration & reconnaissance"))
	fmt.Printf("              %s %s  %s %s  %s %s\n",
		Dim("Version:"), BoldGreen("0.1"),
		Dim("By:"), Cyan("github.com/Vyntral"),
		Dim("For:"), Yellow("github.com/Orizon-eu"))
	fmt.Println()
}

func PrintSection(icon, title string) {
	fmt.Printf("\n%s %s %s\n", BoldCyan("┌──"), BoldWhite(icon+" "+title), BoldCyan(strings.Repeat("─", 50)))
}

func PrintSubSection(text string) {
	fmt.Printf("%s %s\n", Cyan("│"), text)
}

func PrintEndSection() {
	fmt.Printf("%s\n", BoldCyan("└"+strings.Repeat("─", 60)))
}

func PrintProgress(current, total int, label string) {
	width := 30
	filled := int(float64(current) / float64(total) * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	percent := float64(current) / float64(total) * 100
	fmt.Printf("\r%s %s %s %s %.0f%% ", Cyan("│"), label, BoldGreen(bar), Dim(fmt.Sprintf("(%d/%d)", current, total)), percent)
}

func ClearLine() {
	fmt.Print("\r\033[K")
}

func SaveOutput(path string, format string, results map[string]*config.SubdomainResult) {
	file, err := os.Create(path)
	if err != nil {
		fmt.Printf("%s Failed to create output file: %v\n", Red("[-]"), err)
		return
	}
	defer file.Close()

	// Sort subdomains for consistent output
	var sortedSubs []string
	for sub := range results {
		sortedSubs = append(sortedSubs, sub)
	}
	sort.Strings(sortedSubs)

	switch format {
	case "json":
		var resultList []*config.SubdomainResult
		for _, sub := range sortedSubs {
			resultList = append(resultList, results[sub])
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(resultList)

	case "csv":
		writer := csv.NewWriter(file)
		// Header
		writer.Write([]string{"subdomain", "ips", "status_code", "title", "server", "technologies", "ports", "takeover", "response_ms"})

		for _, sub := range sortedSubs {
			r := results[sub]
			var portStrs []string
			for _, p := range r.Ports {
				portStrs = append(portStrs, strconv.Itoa(p))
			}
			writer.Write([]string{
				r.Subdomain,
				strings.Join(r.IPs, ";"),
				strconv.Itoa(r.StatusCode),
				r.Title,
				r.Server,
				strings.Join(r.Tech, ";"),
				strings.Join(portStrs, ";"),
				r.Takeover,
				strconv.FormatInt(r.ResponseMs, 10),
			})
		}
		writer.Flush()

	default: // txt
		for _, sub := range sortedSubs {
			file.WriteString(sub + "\n")
		}
	}

	fmt.Printf("%s Results saved to %s\n", Green("[+]"), path)
}
