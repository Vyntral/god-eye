package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"god-eye/internal/ai"
	"god-eye/internal/config"
	"god-eye/internal/dns"
	gohttp "god-eye/internal/http"
	"god-eye/internal/output"
	"god-eye/internal/security"
	"god-eye/internal/sources"
)

func Run(cfg config.Config) {
	startTime := time.Now()

	// Parse custom resolvers
	var resolvers []string
	if cfg.Resolvers != "" {
		for _, r := range strings.Split(cfg.Resolvers, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				if !strings.Contains(r, ":") {
					r = r + ":53"
				}
				resolvers = append(resolvers, r)
			}
		}
	}
	if len(resolvers) == 0 {
		resolvers = config.DefaultResolvers
	}

	// Parse custom ports
	var customPorts []int
	if cfg.Ports != "" {
		for _, p := range strings.Split(cfg.Ports, ",") {
			p = strings.TrimSpace(p)
			if port, err := strconv.Atoi(p); err == nil && port > 0 && port < 65536 {
				customPorts = append(customPorts, port)
			}
		}
	}
	if len(customPorts) == 0 {
		customPorts = []int{80, 443, 8080, 8443}
	}

	if !cfg.Silent && !cfg.JsonOutput {
		output.PrintBanner()
		output.PrintSection("🎯", "TARGET CONFIGURATION")
		output.PrintSubSection(fmt.Sprintf("%s %s", output.Dim("Target:"), output.BoldCyan(cfg.Domain)))
		output.PrintSubSection(fmt.Sprintf("%s %s  %s %s  %s %s",
			output.Dim("Threads:"), output.BoldGreen(fmt.Sprintf("%d", cfg.Concurrency)),
			output.Dim("Timeout:"), output.Yellow(fmt.Sprintf("%ds", cfg.Timeout)),
			output.Dim("Resolvers:"), output.Blue(fmt.Sprintf("%d", len(resolvers)))))
		if !cfg.NoPorts {
			portStr := ""
			for i, p := range customPorts {
				if i > 0 {
					portStr += ", "
				}
				portStr += fmt.Sprintf("%d", p)
			}
			output.PrintSubSection(fmt.Sprintf("%s %s", output.Dim("Ports:"), output.Magenta(portStr)))
		}
		output.PrintEndSection()
	}

	// Load wordlist
	wordlist := config.DefaultWordlist
	if cfg.Wordlist != "" {
		if wl, err := LoadWordlist(cfg.Wordlist); err == nil {
			wordlist = wl
		} else if cfg.Verbose {
			fmt.Printf("%s Failed to load wordlist: %v\n", output.Red("[-]"), err)
		}
	}

	if !cfg.Silent && !cfg.JsonOutput {
		output.PrintSection("📚", "WORDLIST")
		output.PrintSubSection(fmt.Sprintf("%s %s words loaded", output.BoldGreen(fmt.Sprintf("%d", len(wordlist))), output.Dim("DNS brute-force")))
		output.PrintEndSection()
	}

	// Results storage
	results := make(map[string]*config.SubdomainResult)
	var resultsMu sync.Mutex
	seen := make(map[string]bool)
	var seenMu sync.Mutex

	// Channel for subdomains
	subdomainChan := make(chan string, 10000)

	// Passive sources
	if !cfg.Silent && !cfg.JsonOutput {
		output.PrintSection("🔍", "PASSIVE ENUMERATION")
		output.PrintSubSection(fmt.Sprintf("%s passive sources launching...", output.BoldYellow("20")))
	}

	var sourcesWg sync.WaitGroup
	sourceResults := make(chan config.SourceResult, 100)

	sourceList := []struct {
		name string
		fn   func(string) ([]string, error)
	}{
		// Free sources (no API key required)
		{"crt.sh", sources.FetchCrtsh},
		{"Certspotter", sources.FetchCertspotter},
		{"AlienVault", sources.FetchAlienVault},
		{"HackerTarget", sources.FetchHackerTarget},
		{"URLScan", sources.FetchURLScan},
		{"RapidDNS", sources.FetchRapidDNS},
		{"Anubis", sources.FetchAnubis},
		{"ThreatMiner", sources.FetchThreatMiner},
		{"DNSRepo", sources.FetchDNSRepo},
		{"SubdomainCenter", sources.FetchSubdomainCenter},
		{"Wayback", sources.FetchWayback},
		{"CommonCrawl", sources.FetchCommonCrawl},
		{"Sitedossier", sources.FetchSitedossier},
		{"Riddler", sources.FetchRiddler},
		{"Robtex", sources.FetchRobtex},
		{"DNSHistory", sources.FetchDNSHistory},
		{"ArchiveToday", sources.FetchArchiveToday},
		{"JLDC", sources.FetchJLDC},
		{"SynapsInt", sources.FetchSynapsInt},
		{"CensysFree", sources.FetchCensysFree},
	}

	for _, src := range sourceList {
		sourcesWg.Add(1)
		go func(name string, fn func(string) ([]string, error)) {
			defer sourcesWg.Done()
			subs, err := fn(cfg.Domain)
			sourceResults <- config.SourceResult{Name: name, Subs: subs, Err: err}
		}(src.name, src.fn)
	}

	// Collect source results
	go func() {
		sourcesWg.Wait()
		close(sourceResults)
	}()

	// Process source results
	var processWg sync.WaitGroup
	processWg.Add(1)
	go func() {
		defer processWg.Done()
		for result := range sourceResults {
			if result.Err != nil {
				if cfg.Verbose {
					fmt.Printf("%s %s: %v\n", output.Red("[-]"), result.Name, result.Err)
				}
				continue
			}

			count := 0
			seenMu.Lock()
			for _, sub := range result.Subs {
				sub = strings.ToLower(strings.TrimSpace(sub))
				if sub != "" && !seen[sub] && strings.HasSuffix(sub, cfg.Domain) {
					seen[sub] = true
					subdomainChan <- sub
					count++
				}
			}
			seenMu.Unlock()

			if !cfg.Silent && !cfg.JsonOutput && count > 0 {
				output.PrintSubSection(fmt.Sprintf("%s %s: %s new", output.Green("✓"), output.BoldWhite(result.Name), output.BoldGreen(fmt.Sprintf("%d", count))))
			} else if cfg.Verbose && !cfg.JsonOutput && count == 0 {
				output.PrintSubSection(fmt.Sprintf("%s %s: %s", output.Dim("○"), output.Dim(result.Name), output.Dim("0 results")))
			}
		}
	}()

	// DNS Brute-force
	var bruteWg sync.WaitGroup
	if !cfg.NoBrute {
		// Check wildcard
		wildcardIPs := dns.CheckWildcard(cfg.Domain, resolvers)
		if !cfg.Silent && !cfg.JsonOutput {
			if len(wildcardIPs) > 0 {
				output.PrintSubSection(fmt.Sprintf("%s Wildcard DNS: %s", output.Yellow("⚠"), output.BoldYellow("DETECTED")))
			} else {
				output.PrintSubSection(fmt.Sprintf("%s Wildcard DNS: %s", output.Green("✓"), output.Green("not detected")))
			}
		}

		// Brute-force
		semaphore := make(chan struct{}, cfg.Concurrency)
		for _, word := range wordlist {
			bruteWg.Add(1)
			go func(word string) {
				defer bruteWg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				subdomain := fmt.Sprintf("%s.%s", word, cfg.Domain)
				ips := dns.ResolveSubdomain(subdomain, resolvers, cfg.Timeout)

				if len(ips) > 0 {
					// Check if wildcard
					isWildcard := false
					if len(wildcardIPs) > 0 {
						for _, ip := range ips {
							for _, wip := range wildcardIPs {
								if ip == wip {
									isWildcard = true
									break
								}
							}
							if isWildcard {
								break
							}
						}
					}

					if !isWildcard {
						seenMu.Lock()
						if !seen[subdomain] {
							seen[subdomain] = true
							subdomainChan <- subdomain
						}
						seenMu.Unlock()
					}
				}
			}(word)
		}
	}

	// Collect all subdomains in a separate goroutine
	var subdomains []string
	var subdomainsMu sync.Mutex
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for sub := range subdomainChan {
			subdomainsMu.Lock()
			subdomains = append(subdomains, sub)
			subdomainsMu.Unlock()
		}
	}()

	// Wait for sources and brute-force to complete
	processWg.Wait()
	bruteWg.Wait()
	close(subdomainChan)

	// Wait for collection to complete
	collectWg.Wait()

	// Resolve all subdomains
	if !cfg.Silent && !cfg.JsonOutput {
		output.PrintEndSection()
		output.PrintSection("🌐", "DNS RESOLUTION")
		output.PrintSubSection(fmt.Sprintf("Resolving %s subdomains...", output.BoldCyan(fmt.Sprintf("%d", len(subdomains)))))
	}

	var resolveWg sync.WaitGroup
	semaphore := make(chan struct{}, cfg.Concurrency)

	for _, subdomain := range subdomains {
		resolveWg.Add(1)
		go func(sub string) {
			defer resolveWg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			ips := dns.ResolveSubdomain(sub, resolvers, cfg.Timeout)
			if len(ips) > 0 {
				cname := dns.ResolveCNAME(sub, resolvers, cfg.Timeout)
				ptr := dns.ResolvePTR(ips[0], resolvers, cfg.Timeout)

				// Get IP info (ASN, Org, Country, City)
				var asn, org, country, city string
				if ipInfo, err := dns.GetIPInfo(ips[0]); err == nil && ipInfo != nil {
					asn = ipInfo.ASN
					org = ipInfo.Org
					country = ipInfo.Country
					city = ipInfo.City
				}

				// Get MX/TXT/NS records for the subdomain
				mx := dns.ResolveMX(sub, resolvers, cfg.Timeout)
				txt := dns.ResolveTXT(sub, resolvers, cfg.Timeout)
				ns := dns.ResolveNS(sub, resolvers, cfg.Timeout)

				// Detect cloud provider
				cloudProvider := DetectCloudProvider(ips, cname, asn)

				// Check email security (only once, for the target domain)
				// SPF/DMARC records are always on the root domain, so we check cfg.Domain
				var spfRecord, dmarcRecord, emailSecurity string
				if sub == cfg.Domain {
					spfRecord, dmarcRecord, emailSecurity = CheckEmailSecurity(cfg.Domain, resolvers, cfg.Timeout)
				}

				resultsMu.Lock()
				results[sub] = &config.SubdomainResult{
					Subdomain:     sub,
					IPs:           ips,
					CNAME:         cname,
					PTR:           ptr,
					ASN:           asn,
					Org:           org,
					Country:       country,
					City:          city,
					MXRecords:     mx,
					TXTRecords:    txt,
					NSRecords:     ns,
					CloudProvider: cloudProvider,
					SPFRecord:     spfRecord,
					DMARCRecord:   dmarcRecord,
					EmailSecurity: emailSecurity,
				}
				resultsMu.Unlock()
			}
		}(subdomain)
	}
	resolveWg.Wait()

	// HTTP Probing
	if !cfg.NoProbe && len(results) > 0 {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("🌍", "HTTP PROBING & SECURITY CHECKS")
			output.PrintSubSection(fmt.Sprintf("Probing %s subdomains with %s parallel checks...", output.BoldCyan(fmt.Sprintf("%d", len(results))), output.BoldGreen("13")))
		}

		var probeWg sync.WaitGroup
		for sub := range results {
			probeWg.Add(1)
			go func(subdomain string) {
				defer probeWg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				// Use shared client for connection pooling
				client := gohttp.GetSharedClient(cfg.Timeout)

				// Primary HTTP probe
				result := gohttp.ProbeHTTP(subdomain, cfg.Timeout)

				// Run all HTTP checks in parallel using goroutines
				var checkWg sync.WaitGroup
				var checkMu sync.Mutex

				var robotsTxt, sitemapXml bool
				var faviconHash string
				var openRedirect bool
				var corsMisconfig string
				var allowedMethods, dangerousMethods []string
				var adminPanels, backupFiles, apiEndpoints []string
				var gitExposed, svnExposed bool
				var s3Buckets, tlsAltNames []string
				var jsFiles, jsSecrets []string

				// Check robots.txt
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					r := CheckRobotsTxtWithClient(subdomain, client)
					checkMu.Lock()
					robotsTxt = r
					checkMu.Unlock()
				}()

				// Check sitemap.xml
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					s := CheckSitemapXmlWithClient(subdomain, client)
					checkMu.Lock()
					sitemapXml = s
					checkMu.Unlock()
				}()

				// Check favicon
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					f := GetFaviconHashWithClient(subdomain, client)
					checkMu.Lock()
					faviconHash = f
					checkMu.Unlock()
				}()

				// Check open redirect
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					o := security.CheckOpenRedirectWithClient(subdomain, client)
					checkMu.Lock()
					openRedirect = o
					checkMu.Unlock()
				}()

				// Check CORS
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					c := security.CheckCORSWithClient(subdomain, client)
					checkMu.Lock()
					corsMisconfig = c
					checkMu.Unlock()
				}()

				// Check HTTP methods
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					a, d := security.CheckHTTPMethodsWithClient(subdomain, client)
					checkMu.Lock()
					allowedMethods = a
					dangerousMethods = d
					checkMu.Unlock()
				}()

				// Check admin panels
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					p := security.CheckAdminPanelsWithClient(subdomain, client)
					checkMu.Lock()
					adminPanels = p
					checkMu.Unlock()
				}()

				// Check Git/SVN exposure
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					g, s := security.CheckGitSvnExposureWithClient(subdomain, client)
					checkMu.Lock()
					gitExposed = g
					svnExposed = s
					checkMu.Unlock()
				}()

				// Check backup files
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					b := security.CheckBackupFilesWithClient(subdomain, client)
					checkMu.Lock()
					backupFiles = b
					checkMu.Unlock()
				}()

				// Check API endpoints
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					e := security.CheckAPIEndpointsWithClient(subdomain, client)
					checkMu.Lock()
					apiEndpoints = e
					checkMu.Unlock()
				}()

				// Check S3 buckets
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					b := CheckS3BucketsWithClient(subdomain, client)
					checkMu.Lock()
					s3Buckets = b
					checkMu.Unlock()
				}()

				// Get TLS alt names
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					t := GetTLSAltNames(subdomain, cfg.Timeout)
					checkMu.Lock()
					tlsAltNames = t
					checkMu.Unlock()
				}()

				// Analyze JavaScript files
				checkWg.Add(1)
				go func() {
					defer checkWg.Done()
					f, s := AnalyzeJSFiles(subdomain, client)
					checkMu.Lock()
					jsFiles = f
					jsSecrets = s
					checkMu.Unlock()
				}()

				// Wait for all checks to complete
				checkWg.Wait()

				resultsMu.Lock()
				if r, ok := results[subdomain]; ok {
					r.StatusCode = result.StatusCode
					r.ContentLength = result.ContentLength
					r.RedirectURL = result.RedirectURL
					r.Title = result.Title
					r.Server = result.Server
					r.Tech = result.Tech
					r.Headers = result.Headers
					r.WAF = result.WAF
					r.TLSVersion = result.TLSVersion
					r.TLSIssuer = result.TLSIssuer
					r.TLSExpiry = result.TLSExpiry
					r.ResponseMs = result.ResponseMs
					r.RobotsTxt = robotsTxt
					r.SitemapXml = sitemapXml
					r.FaviconHash = faviconHash
					r.SecurityHeaders = result.SecurityHeaders
					r.MissingHeaders = result.MissingHeaders
					r.OpenRedirect = openRedirect
					r.CORSMisconfig = corsMisconfig
					r.AllowedMethods = allowedMethods
					r.DangerousMethods = dangerousMethods
					r.AdminPanels = adminPanels
					r.GitExposed = gitExposed
					r.S3Buckets = s3Buckets
					r.TLSAltNames = tlsAltNames
					r.SvnExposed = svnExposed
					r.BackupFiles = backupFiles
					r.APIEndpoints = apiEndpoints
					r.JSFiles = jsFiles
					r.JSSecrets = jsSecrets
				}
				resultsMu.Unlock()
			}(sub)
		}
		probeWg.Wait()
	}

	// Port Scanning
	if !cfg.NoPorts && len(results) > 0 {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("🔌", "PORT SCANNING")
			output.PrintSubSection(fmt.Sprintf("Scanning %s ports on %s hosts...", output.BoldMagenta(fmt.Sprintf("%d", len(customPorts))), output.BoldCyan(fmt.Sprintf("%d", len(results)))))
		}

		var portWg sync.WaitGroup

		for sub, result := range results {
			if len(result.IPs) == 0 {
				continue
			}
			portWg.Add(1)
			go func(subdomain string, ip string) {
				defer portWg.Done()
				openPorts := ScanPorts(ip, customPorts, cfg.Timeout)
				resultsMu.Lock()
				if r, ok := results[subdomain]; ok {
					r.Ports = openPorts
				}
				resultsMu.Unlock()
			}(sub, result.IPs[0])
		}
		portWg.Wait()
	}

	// Subdomain Takeover Check
	var takeoverCount int32
	if !cfg.NoTakeover && len(results) > 0 {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("🎯", "SUBDOMAIN TAKEOVER")
			output.PrintSubSection(fmt.Sprintf("Checking %s fingerprints against %s subdomains...", output.BoldRed("110+"), output.BoldCyan(fmt.Sprintf("%d", len(results)))))
		}

		var takeoverWg sync.WaitGroup
		for sub := range results {
			takeoverWg.Add(1)
			go func(subdomain string) {
				defer takeoverWg.Done()
				if takeover := CheckTakeover(subdomain, cfg.Timeout); takeover != "" {
					resultsMu.Lock()
					if r, ok := results[subdomain]; ok {
						r.Takeover = takeover
					}
					resultsMu.Unlock()
					atomic.AddInt32(&takeoverCount, 1)
					if !cfg.JsonOutput {
						output.PrintSubSection(fmt.Sprintf("%s %s → %s", output.BgRed(" TAKEOVER "), output.BoldWhite(subdomain), output.BoldRed(takeover)))
					}
				}
			}(sub)
		}
		takeoverWg.Wait()

		if takeoverCount > 0 && !cfg.JsonOutput {
			output.PrintSubSection(fmt.Sprintf("%s Found %s potential takeover(s)!", output.Red("⚠"), output.BoldRed(fmt.Sprintf("%d", takeoverCount))))
		}
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
		}
	}

	// AI-Powered Analysis
	var aiClient *ai.OllamaClient
	var aiFindings int32
	if cfg.EnableAI && len(results) > 0 {
		aiClient = ai.NewOllamaClient(cfg.AIUrl, cfg.AIFastModel, cfg.AIDeepModel, cfg.AICascade)

		// Check if Ollama is available
		if !aiClient.IsAvailable() {
			if cfg.Verbose && !cfg.JsonOutput {
				fmt.Printf("%s Ollama is not available at %s. Skipping AI analysis.\n", output.Yellow("⚠"), cfg.AIUrl)
				fmt.Printf("%s Run: ollama serve\n", output.Dim("→"))
			}
		} else {
			if !cfg.Silent && !cfg.JsonOutput {
				output.PrintEndSection()
				output.PrintSection("🧠", "AI-POWERED ANALYSIS")
				cascadeStr := ""
				if cfg.AICascade {
					cascadeStr = fmt.Sprintf(" (cascade: %s + %s)", cfg.AIFastModel, cfg.AIDeepModel)
				} else {
					cascadeStr = fmt.Sprintf(" (model: %s)", cfg.AIDeepModel)
				}
				output.PrintSubSection(fmt.Sprintf("Analyzing findings with local LLM%s", output.Dim(cascadeStr)))
			}

			var aiWg sync.WaitGroup
			aiSemaphore := make(chan struct{}, 5) // Limit concurrent AI requests

			for sub, result := range results {
				// Only analyze interesting findings
				shouldAnalyze := false

				// Analyze JS files if found
				if len(result.JSFiles) > 0 || len(result.JSSecrets) > 0 {
					shouldAnalyze = true
				}

				// Analyze if vulnerabilities detected
				if result.OpenRedirect || result.CORSMisconfig != "" ||
				   len(result.DangerousMethods) > 0 || result.GitExposed ||
				   result.SvnExposed || len(result.BackupFiles) > 0 {
					shouldAnalyze = true
				}

				// Analyze takeovers
				if result.Takeover != "" {
					shouldAnalyze = true
				}

				// Deep analysis mode: analyze everything
				if cfg.AIDeepAnalysis {
					shouldAnalyze = true
				}

				if !shouldAnalyze {
					continue
				}

				aiWg.Add(1)
				go func(subdomain string, r *config.SubdomainResult) {
					defer aiWg.Done()
					aiSemaphore <- struct{}{}
					defer func() { <-aiSemaphore }()

					var aiResults []*ai.AnalysisResult

					// Analyze JavaScript if present
					if len(r.JSFiles) > 0 && len(r.JSSecrets) > 0 {
						// Build context from secrets
						jsContext := strings.Join(r.JSSecrets, "\n")
						if analysis, err := aiClient.AnalyzeJavaScript(jsContext); err == nil {
							aiResults = append(aiResults, analysis)
						}
					}

					// Analyze HTTP response for misconfigurations
					if r.StatusCode > 0 && (len(r.MissingHeaders) > 3 || r.GitExposed || r.SvnExposed) {
						bodyContext := r.Title
						if analysis, err := aiClient.AnalyzeHTTPResponse(subdomain, r.StatusCode, r.Headers, bodyContext); err == nil {
							aiResults = append(aiResults, analysis)
						}
					}

					// CVE matching for detected technologies
					if len(r.Tech) > 0 {
						for _, tech := range r.Tech {
							if cve, err := aiClient.CVEMatch(tech, ""); err == nil && cve != "" {
								resultsMu.Lock()
								r.CVEFindings = append(r.CVEFindings, fmt.Sprintf("%s: %s", tech, cve))
								resultsMu.Unlock()
							}
						}
					}

					// Aggregate findings
					resultsMu.Lock()
					defer resultsMu.Unlock()

					highestSeverity := "info"
					for _, analysis := range aiResults {
						for _, finding := range analysis.Findings {
							finding = strings.TrimSpace(finding)
							if finding != "" && !strings.HasPrefix(finding, "Skipped") && !strings.HasPrefix(finding, "Normal") {
								r.AIFindings = append(r.AIFindings, finding)
								atomic.AddInt32(&aiFindings, 1)
							}
						}

						// Track highest severity
						severities := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
						if severities[analysis.Severity] > severities[highestSeverity] {
							highestSeverity = analysis.Severity
						}
					}

					if len(r.AIFindings) > 0 {
						r.AISeverity = highestSeverity
						if cfg.AICascade {
							r.AIModel = fmt.Sprintf("%s→%s", cfg.AIFastModel, cfg.AIDeepModel)
						} else {
							r.AIModel = cfg.AIDeepModel
						}

						if !cfg.JsonOutput && !cfg.Silent {
							severityColor := output.Blue
							if highestSeverity == "critical" {
								severityColor = output.BgRed
							} else if highestSeverity == "high" {
								severityColor = output.Red
							} else if highestSeverity == "medium" {
								severityColor = output.Yellow
							}

							output.PrintSubSection(fmt.Sprintf("%s %s → %s",
								severityColor(fmt.Sprintf(" AI:%s ", strings.ToUpper(highestSeverity[:1]))),
								output.BoldWhite(subdomain),
								output.Dim(fmt.Sprintf("%d findings", len(r.AIFindings)))))
						}
					}
				}(sub, result)
			}

			aiWg.Wait()

			// Generate summary report
			if aiFindings > 0 && !cfg.JsonOutput {
				output.PrintSubSection(fmt.Sprintf("%s AI analysis complete: %s findings across %s subdomains",
					output.Green("✓"),
					output.BoldGreen(fmt.Sprintf("%d", aiFindings)),
					output.BoldCyan(fmt.Sprintf("%d", countSubdomainsWithAI(results)))))

				// Generate executive report
				summary := buildAISummary(results)
				stats := map[string]int{
					"total":     len(results),
					"active":    countActive(results),
					"vulns":     countVulns(results),
					"takeovers": int(takeoverCount),
				}

				if report, err := aiClient.GenerateReport(summary, stats); err == nil {
					if !cfg.Silent {
						output.PrintEndSection()
						output.PrintSection("📋", "AI SECURITY REPORT")
						fmt.Println(report)
					}
				}
			}

			if !cfg.Silent && !cfg.JsonOutput {
				output.PrintEndSection()
			}
		}
	}

	// Filter active only if requested
	if cfg.OnlyActive {
		filtered := make(map[string]*config.SubdomainResult)
		for sub, r := range results {
			if r.StatusCode >= 200 && r.StatusCode < 400 {
				filtered[sub] = r
			}
		}
		results = filtered
	}

	// Sort subdomains
	var sortedSubs []string
	for sub := range results {
		sortedSubs = append(sortedSubs, sub)
	}
	sort.Strings(sortedSubs)

	// JSON output to stdout
	if cfg.JsonOutput {
		var resultList []*config.SubdomainResult
		for _, sub := range sortedSubs {
			resultList = append(resultList, results[sub])
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		encoder.Encode(resultList)
		return
	}

	// Print results
	elapsed := time.Since(startTime)

	// Count statistics
	var activeCount, vulnCount, cloudCount int
	for _, r := range results {
		if r.StatusCode >= 200 && r.StatusCode < 400 {
			activeCount++
		}
		if r.OpenRedirect || r.CORSMisconfig != "" || len(r.DangerousMethods) > 0 || r.GitExposed || r.SvnExposed || len(r.BackupFiles) > 0 {
			vulnCount++
		}
		if r.CloudProvider != "" {
			cloudCount++
		}
	}

	// Summary box
	fmt.Println()
	fmt.Println(output.BoldCyan("╔══════════════════════════════════════════════════════════════════════════════╗"))
	fmt.Println(output.BoldCyan("║") + "                              " + output.BoldWhite("📊 SCAN SUMMARY") + "                              " + output.BoldCyan("║"))
	fmt.Println(output.BoldCyan("╠══════════════════════════════════════════════════════════════════════════════╣"))
	fmt.Printf("%s  %-20s %s  %-20s %s  %-20s %s\n",
		output.BoldCyan("║"),
		fmt.Sprintf("🌐 Total: %s", output.BoldCyan(fmt.Sprintf("%d", len(results)))),
		output.Dim("|"),
		fmt.Sprintf("✅ Active: %s", output.BoldGreen(fmt.Sprintf("%d", activeCount))),
		output.Dim("|"),
		fmt.Sprintf("⏱️  Time: %s", output.BoldYellow(fmt.Sprintf("%.1fs", elapsed.Seconds()))),
		output.BoldCyan("║"))
	fmt.Printf("%s  %-20s %s  %-20s %s  %-20s %s\n",
		output.BoldCyan("║"),
		fmt.Sprintf("⚠️  Vulns: %s", output.BoldRed(fmt.Sprintf("%d", vulnCount))),
		output.Dim("|"),
		fmt.Sprintf("☁️  Cloud: %s", output.Blue(fmt.Sprintf("%d", cloudCount))),
		output.Dim("|"),
		fmt.Sprintf("🎯 Takeover: %s", output.BoldRed(fmt.Sprintf("%d", takeoverCount))),
		output.BoldCyan("║"))
	fmt.Println(output.BoldCyan("╚══════════════════════════════════════════════════════════════════════════════╝"))
	fmt.Println()
	fmt.Println(output.BoldCyan("═══════════════════════════════════════════════════════════════════════════════"))

	for _, sub := range sortedSubs {
		r := results[sub]

		// Color code by status
		var statusColor func(a ...interface{}) string
		var statusIcon string
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			statusColor = output.Green
			statusIcon = "●"
		} else if r.StatusCode >= 300 && r.StatusCode < 400 {
			statusColor = output.Yellow
			statusIcon = "◐"
		} else if r.StatusCode >= 400 {
			statusColor = output.Red
			statusIcon = "○"
		} else {
			statusColor = output.Blue
			statusIcon = "◌"
		}

		// Line 1: Subdomain name with status (modern box style)
		statusBadge := ""
		if r.StatusCode > 0 {
			statusBadge = fmt.Sprintf(" %s", statusColor(fmt.Sprintf("[%d]", r.StatusCode)))
		}

		// Response time badge
		timeBadge := ""
		if r.ResponseMs > 0 {
			if r.ResponseMs < 200 {
				timeBadge = fmt.Sprintf(" %s", output.Green(fmt.Sprintf("⚡%dms", r.ResponseMs)))
			} else if r.ResponseMs < 500 {
				timeBadge = fmt.Sprintf(" %s", output.Yellow(fmt.Sprintf("⏱️%dms", r.ResponseMs)))
			} else {
				timeBadge = fmt.Sprintf(" %s", output.Red(fmt.Sprintf("🐢%dms", r.ResponseMs)))
			}
		}

		fmt.Printf("\n%s %s%s%s\n", statusColor(statusIcon), output.BoldCyan(sub), statusBadge, timeBadge)

		// Line 2: IPs
		if len(r.IPs) > 0 {
			ips := r.IPs
			if len(ips) > 3 {
				ips = ips[:3]
			}
			fmt.Printf("    %s %s\n", output.Dim("IP:"), output.White(strings.Join(ips, ", ")))
		}

		// Line 3: CNAME
		if r.CNAME != "" {
			fmt.Printf("    %s %s\n", output.Dim("CNAME:"), output.Blue(r.CNAME))
		}

		// Line 4: Location + ASN
		if r.Country != "" || r.City != "" || r.ASN != "" {
			loc := ""
			if r.City != "" && r.Country != "" {
				loc = r.City + ", " + r.Country
			} else if r.Country != "" {
				loc = r.Country
			} else if r.City != "" {
				loc = r.City
			}

			asnStr := ""
			if r.ASN != "" {
				asnStr = r.ASN
				if len(asnStr) > 40 {
					asnStr = asnStr[:37] + "..."
				}
			}

			if loc != "" && asnStr != "" {
				fmt.Printf("    Location: %s | %s\n", output.Cyan(loc), output.Blue(asnStr))
			} else if loc != "" {
				fmt.Printf("    Location: %s\n", output.Cyan(loc))
			} else if asnStr != "" {
				fmt.Printf("    ASN: %s\n", output.Blue(asnStr))
			}
		}

		// Line 5: PTR
		if r.PTR != "" {
			fmt.Printf("    PTR: %s\n", output.Magenta(r.PTR))
		}

		// Line 6: HTTP Info (Title, Size)
		if r.Title != "" || r.ContentLength > 0 {
			httpInfo := "    HTTP: "
			if r.Title != "" {
				title := r.Title
				if len(title) > 50 {
					title = title[:47] + "..."
				}
				httpInfo += fmt.Sprintf("\"%s\"", title)
			}
			if r.ContentLength > 0 {
				sizeStr := ""
				if r.ContentLength > 1024*1024 {
					sizeStr = fmt.Sprintf("%.1fMB", float64(r.ContentLength)/(1024*1024))
				} else if r.ContentLength > 1024 {
					sizeStr = fmt.Sprintf("%.1fKB", float64(r.ContentLength)/1024)
				} else {
					sizeStr = fmt.Sprintf("%dB", r.ContentLength)
				}
				if r.Title != "" {
					httpInfo += fmt.Sprintf(" (%s)", sizeStr)
				} else {
					httpInfo += sizeStr
				}
			}
			fmt.Println(httpInfo)
		}

		// Line 7: Redirect
		if r.RedirectURL != "" {
			redirectURL := r.RedirectURL
			if len(redirectURL) > 60 {
				redirectURL = redirectURL[:57] + "..."
			}
			fmt.Printf("    Redirect: %s\n", output.Yellow(redirectURL))
		}

		// Line 8: Tech + Server
		if len(r.Tech) > 0 || r.Server != "" {
			techMap := make(map[string]bool)
			var uniqueTech []string
			for _, t := range r.Tech {
				if !techMap[t] {
					techMap[t] = true
					uniqueTech = append(uniqueTech, t)
				}
			}
			if len(uniqueTech) > 5 {
				uniqueTech = uniqueTech[:5]
			}
			if len(uniqueTech) > 0 {
				fmt.Printf("    Tech: %s\n", output.Yellow(strings.Join(uniqueTech, ", ")))
			}
		}

		// Line 9: Security (WAF, TLS)
		var securityInfo []string
		if r.WAF != "" {
			securityInfo = append(securityInfo, fmt.Sprintf("WAF: %s", output.Red(r.WAF)))
		}
		if r.TLSVersion != "" {
			securityInfo = append(securityInfo, fmt.Sprintf("TLS: %s", output.Cyan(r.TLSVersion)))
		}
		if len(securityInfo) > 0 {
			fmt.Printf("    Security: %s\n", strings.Join(securityInfo, " | "))
		}

		// Line 10: Ports
		if len(r.Ports) > 0 {
			var portStrs []string
			for _, p := range r.Ports {
				portStrs = append(portStrs, fmt.Sprintf("%d", p))
			}
			fmt.Printf("    Ports: %s\n", output.Magenta(strings.Join(portStrs, ", ")))
		}

		// Line 11: Extra files
		var extras []string
		if r.RobotsTxt {
			extras = append(extras, "robots.txt")
		}
		if r.SitemapXml {
			extras = append(extras, "sitemap.xml")
		}
		if r.FaviconHash != "" {
			extras = append(extras, fmt.Sprintf("favicon:%s", r.FaviconHash[:8]))
		}
		if len(extras) > 0 {
			fmt.Printf("    Files: %s\n", output.Green(strings.Join(extras, ", ")))
		}

		// Line 12: DNS Records
		if len(r.MXRecords) > 0 {
			mx := r.MXRecords
			if len(mx) > 2 {
				mx = mx[:2]
			}
			fmt.Printf("    MX: %s\n", strings.Join(mx, ", "))
		}

		// Line 13: Security Headers
		if len(r.MissingHeaders) > 0 && len(r.MissingHeaders) < 7 {
			// Only show if some headers are present (not all missing)
			if len(r.SecurityHeaders) > 0 {
				fmt.Printf("    Headers: %s | Missing: %s\n",
					output.Green(strings.Join(r.SecurityHeaders, ", ")),
					output.Yellow(strings.Join(r.MissingHeaders, ", ")))
			}
		} else if len(r.SecurityHeaders) > 0 {
			fmt.Printf("    Headers: %s\n", output.Green(strings.Join(r.SecurityHeaders, ", ")))
		}

		// Line 14: Cloud Provider
		if r.CloudProvider != "" {
			fmt.Printf("    Cloud: %s\n", output.Cyan(r.CloudProvider))
		}

		// Line 15: Email Security (only for root domain)
		if r.EmailSecurity != "" {
			emailColor := output.Green
			if r.EmailSecurity == "Weak" {
				emailColor = output.Yellow
			} else if r.EmailSecurity == "None" {
				emailColor = output.Red
			}
			fmt.Printf("    Email: %s\n", emailColor(r.EmailSecurity))
		}

		// Line 16: TLS Alt Names
		if len(r.TLSAltNames) > 0 {
			altNames := r.TLSAltNames
			if len(altNames) > 5 {
				altNames = altNames[:5]
			}
			fmt.Printf("    TLS Alt: %s\n", output.Blue(strings.Join(altNames, ", ")))
		}

		// Line 17: S3 Buckets
		if len(r.S3Buckets) > 0 {
			for _, bucket := range r.S3Buckets {
				if strings.Contains(bucket, "PUBLIC") {
					fmt.Printf("    %s %s\n", output.Red("S3:"), output.Red(bucket))
				} else {
					fmt.Printf("    S3: %s\n", output.Yellow(bucket))
				}
			}
		}

		// Line 18: Security Issues (vulnerabilities found)
		var vulns []string
		if r.OpenRedirect {
			vulns = append(vulns, "Open Redirect")
		}
		if r.CORSMisconfig != "" {
			vulns = append(vulns, fmt.Sprintf("CORS: %s", r.CORSMisconfig))
		}
		if len(r.DangerousMethods) > 0 {
			vulns = append(vulns, fmt.Sprintf("Methods: %s", strings.Join(r.DangerousMethods, ", ")))
		}
		if r.GitExposed {
			vulns = append(vulns, ".git Exposed")
		}
		if r.SvnExposed {
			vulns = append(vulns, ".svn Exposed")
		}
		if len(r.BackupFiles) > 0 {
			files := r.BackupFiles
			if len(files) > 3 {
				files = files[:3]
			}
			vulns = append(vulns, fmt.Sprintf("Backup: %s", strings.Join(files, ", ")))
		}
		if len(vulns) > 0 {
			fmt.Printf("    %s %s\n", output.Red("VULNS:"), output.Red(strings.Join(vulns, " | ")))
		}

		// Line 19: Discovery (admin panels, API endpoints)
		var discoveries []string
		if len(r.AdminPanels) > 0 {
			panels := r.AdminPanels
			if len(panels) > 5 {
				panels = panels[:5]
			}
			discoveries = append(discoveries, fmt.Sprintf("Admin: %s", strings.Join(panels, ", ")))
		}
		if len(r.APIEndpoints) > 0 {
			endpoints := r.APIEndpoints
			if len(endpoints) > 5 {
				endpoints = endpoints[:5]
			}
			discoveries = append(discoveries, fmt.Sprintf("API: %s", strings.Join(endpoints, ", ")))
		}
		if len(discoveries) > 0 {
			fmt.Printf("    %s %s\n", output.Magenta("FOUND:"), output.Magenta(strings.Join(discoveries, " | ")))
		}

		// Line 20: JavaScript Analysis
		if len(r.JSFiles) > 0 {
			files := r.JSFiles
			if len(files) > 3 {
				files = files[:3]
			}
			fmt.Printf("    JS Files: %s\n", output.Blue(strings.Join(files, ", ")))
		}
		if len(r.JSSecrets) > 0 {
			for _, secret := range r.JSSecrets {
				fmt.Printf("    %s %s\n", output.Red("JS SECRET:"), output.Red(secret))
			}
		}

		// Line 21: Takeover
		if r.Takeover != "" {
			fmt.Printf("    %s %s\n", output.BgRed(" TAKEOVER "), output.BoldRed(r.Takeover))
		}

		// Line 22: AI Findings
		if len(r.AIFindings) > 0 {
			severityColor := output.Cyan
			severityLabel := "AI"
			if r.AISeverity == "critical" {
				severityColor = output.BoldRed
				severityLabel = "AI:CRITICAL"
			} else if r.AISeverity == "high" {
				severityColor = output.Red
				severityLabel = "AI:HIGH"
			} else if r.AISeverity == "medium" {
				severityColor = output.Yellow
				severityLabel = "AI:MEDIUM"
			}

			for i, finding := range r.AIFindings {
				if i == 0 {
					fmt.Printf("    %s %s\n", severityColor(severityLabel+":"), finding)
				} else {
					fmt.Printf("    %s %s\n", output.Dim("     "), finding)
				}
				if i >= 4 { // Limit displayed findings
					remaining := len(r.AIFindings) - 5
					if remaining > 0 {
						fmt.Printf("    %s (%d more findings...)\n", output.Dim("     "), remaining)
					}
					break
				}
			}

			// Show model used
			if r.AIModel != "" {
				fmt.Printf("    %s model: %s\n", output.Dim("     "), output.Dim(r.AIModel))
			}
		}

		// Line 23: CVE Findings
		if len(r.CVEFindings) > 0 {
			for _, cve := range r.CVEFindings {
				fmt.Printf("    %s %s\n", output.BoldRed("CVE:"), output.Red(cve))
			}
		}
	}

	fmt.Println()
	fmt.Println(output.BoldCyan("═══════════════════════════════════════════════════════════════════════════════"))

	// Save output
	if cfg.Output != "" {
		output.SaveOutput(cfg.Output, cfg.Format, results)
	}
}

// LoadWordlist loads words from a file
func LoadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	return words, scanner.Err()
}

// ScanPorts scans ports on an IP address
func ScanPorts(ip string, ports []int, timeout int) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	sort.Ints(openPorts)
	return openPorts
}

// Helper functions for AI analysis

func countSubdomainsWithAI(results map[string]*config.SubdomainResult) int {
	count := 0
	for _, r := range results {
		if len(r.AIFindings) > 0 {
			count++
		}
	}
	return count
}

func countActive(results map[string]*config.SubdomainResult) int {
	count := 0
	for _, r := range results {
		if r.StatusCode >= 200 && r.StatusCode < 400 {
			count++
		}
	}
	return count
}

func countVulns(results map[string]*config.SubdomainResult) int {
	count := 0
	for _, r := range results {
		if r.OpenRedirect || r.CORSMisconfig != "" || len(r.DangerousMethods) > 0 ||
			r.GitExposed || r.SvnExposed || len(r.BackupFiles) > 0 {
			count++
		}
	}
	return count
}

func buildAISummary(results map[string]*config.SubdomainResult) string {
	var summary strings.Builder

	criticalCount := 0
	highCount := 0
	mediumCount := 0

	for sub, r := range results {
		if len(r.AIFindings) == 0 {
			continue
		}

		switch r.AISeverity {
		case "critical":
			criticalCount++
			summary.WriteString(fmt.Sprintf("\n[CRITICAL] %s:\n", sub))
		case "high":
			highCount++
			summary.WriteString(fmt.Sprintf("\n[HIGH] %s:\n", sub))
		case "medium":
			mediumCount++
			summary.WriteString(fmt.Sprintf("\n[MEDIUM] %s:\n", sub))
		default:
			continue // Skip low/info for summary
		}

		// Add first 3 findings
		for i, finding := range r.AIFindings {
			if i >= 3 {
				break
			}
			summary.WriteString(fmt.Sprintf("  - %s\n", finding))
		}

		// Add CVE findings
		if len(r.CVEFindings) > 0 {
			summary.WriteString("  CVEs:\n")
			for _, cve := range r.CVEFindings {
				summary.WriteString(fmt.Sprintf("    - %s\n", cve))
			}
		}
	}

	header := fmt.Sprintf("Summary: %d critical, %d high, %d medium findings\n", criticalCount, highCount, mediumCount)
	return header + summary.String()
}
