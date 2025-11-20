package ai

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CVEInfo represents CVE vulnerability information
type CVEInfo struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
	Published   string  `json:"published"`
	References  []string `json:"references"`
}

// NVDResponse represents the response from NVD API
type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Published   string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore      float64 `json:"baseScore"`
						BaseSeverity   string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31,omitempty"`
				CVSSMetricV2 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2,omitempty"`
			} `json:"metrics,omitempty"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

var (
	nvdClient = &http.Client{
		Timeout: 10 * time.Second,
	}
	nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// Rate limiting: max 5 requests per 30 seconds (NVD allows 10 req/60s without API key)
	lastNVDRequest time.Time
	nvdRateLimit   = 6 * time.Second // Wait 6 seconds between requests
)

// SearchCVE searches for CVE vulnerabilities using NVD API
func SearchCVE(technology string, version string) (string, error) {
	// Normalize technology name
	tech := normalizeTechnology(technology)

	// Build search query
	query := tech
	if version != "" && version != "unknown" {
		query = fmt.Sprintf("%s %s", tech, version)
	}

	// Query NVD API
	cves, err := queryNVD(query)
	if err != nil {
		return fmt.Sprintf("Unable to search CVE database for %s: %v", technology, err), nil
	}

	if len(cves) == 0 {
		return fmt.Sprintf("No known CVE vulnerabilities found for %s %s in the NVD database. This doesn't guarantee the software is secure - always keep software updated.", technology, version), nil
	}

	// Format results
	result := fmt.Sprintf("CVE Vulnerabilities for %s %s:\n\n", technology, version)
	result += fmt.Sprintf("Found %d CVE(s):\n\n", len(cves))

	// Show top 5 most recent/critical CVEs
	maxShow := 5
	if len(cves) < maxShow {
		maxShow = len(cves)
	}

	for i := 0; i < maxShow; i++ {
		cve := cves[i]
		result += fmt.Sprintf("🔴 %s (%s - Score: %.1f)\n", cve.ID, cve.Severity, cve.Score)
		result += fmt.Sprintf("   Published: %s\n", cve.Published)

		// Truncate description if too long
		desc := cve.Description
		if len(desc) > 200 {
			desc = desc[:200] + "..."
		}
		result += fmt.Sprintf("   %s\n", desc)

		if len(cve.References) > 0 {
			result += fmt.Sprintf("   Reference: %s\n", cve.References[0])
		}
		result += "\n"
	}

	if len(cves) > maxShow {
		result += fmt.Sprintf("... and %d more CVEs. Check https://nvd.nist.gov for complete details.\n", len(cves)-maxShow)
	}

	result += "\n⚠️  Recommendation: Update to the latest version to mitigate known vulnerabilities."

	return result, nil
}

// queryNVD queries the NVD API for CVE information
func queryNVD(keyword string) ([]CVEInfo, error) {
	// Rate limiting: wait if necessary
	if !lastNVDRequest.IsZero() {
		elapsed := time.Since(lastNVDRequest)
		if elapsed < nvdRateLimit {
			time.Sleep(nvdRateLimit - elapsed)
		}
	}
	lastNVDRequest = time.Now()

	// Build URL with query parameters
	params := url.Values{}
	params.Add("keywordSearch", keyword)
	params.Add("resultsPerPage", "10") // Limit results

	reqURL := fmt.Sprintf("%s?%s", nvdBaseURL, params.Encode())

	// Create request
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// NVD recommends including a user agent
	req.Header.Set("User-Agent", "GodEye-Security-Scanner/0.1")

	// Execute request
	resp, err := nvdClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query NVD: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %w", err)
	}

	// Convert to CVEInfo
	var cves []CVEInfo
	for _, vuln := range nvdResp.Vulnerabilities {
		cve := CVEInfo{
			ID:        vuln.CVE.ID,
			Published: formatDate(vuln.CVE.Published),
		}

		// Get description
		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}

		// Get severity and score (prefer CVSS v3.1)
		if len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
			metric := vuln.CVE.Metrics.CVSSMetricV31[0]
			cve.Score = metric.CVSSData.BaseScore
			cve.Severity = metric.CVSSData.BaseSeverity
		} else if len(vuln.CVE.Metrics.CVSSMetricV2) > 0 {
			metric := vuln.CVE.Metrics.CVSSMetricV2[0]
			cve.Score = metric.CVSSData.BaseScore
			cve.Severity = metric.BaseSeverity
		}

		// Get references
		for _, ref := range vuln.CVE.References {
			cve.References = append(cve.References, ref.URL)
		}

		cves = append(cves, cve)
	}

	return cves, nil
}

// normalizeTechnology normalizes technology names for better CVE search results
func normalizeTechnology(tech string) string {
	tech = strings.ToLower(tech)

	// Common normalizations
	replacements := map[string]string{
		"microsoft-iis": "iis",
		"apache httpd": "apache",
		"apache http server": "apache",
		"nginx/": "nginx",
		"wordpress": "wordpress",
		"asp.net": "asp.net",
		"next.js": "nextjs",
		"react": "react",
		"angular": "angular",
		"vue": "vue",
		"express": "express",
		"django": "django",
		"flask": "flask",
		"spring": "spring",
		"tomcat": "tomcat",
		"jetty": "jetty",
		"php": "php",
		"mysql": "mysql",
		"postgresql": "postgresql",
		"mongodb": "mongodb",
		"redis": "redis",
		"elasticsearch": "elasticsearch",
		"docker": "docker",
		"kubernetes": "kubernetes",
		"jenkins": "jenkins",
		"gitlab": "gitlab",
		"grafana": "grafana",
	}

	for old, new := range replacements {
		if strings.Contains(tech, old) {
			return new
		}
	}

	// Remove version numbers and extra info
	parts := strings.Fields(tech)
	if len(parts) > 0 {
		return parts[0]
	}

	return tech
}

// formatDate formats ISO 8601 date to a more readable format
func formatDate(isoDate string) string {
	t, err := time.Parse(time.RFC3339, isoDate)
	if err != nil {
		return isoDate
	}
	return t.Format("2006-01-02")
}
