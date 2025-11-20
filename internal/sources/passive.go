package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func FetchCrtsh(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read body first to handle empty responses
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Handle empty response
	if len(body) == 0 {
		return []string{}, nil
	}

	// Check if response is HTML (error page) instead of JSON
	if len(body) > 0 && body[0] == '<' {
		return []string{}, nil
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.Unmarshal(body, &entries); err != nil {
		// If JSON parsing fails, return empty instead of error
		return []string{}, nil
	}

	seen := make(map[string]bool)
	var subs []string
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimPrefix(name, "*.")
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" && !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchCertspotter(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read body first to handle different response types
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Handle empty response
	if len(body) == 0 {
		return []string{}, nil
	}

	// Check if response is an error object instead of array
	if len(body) > 0 && body[0] == '{' {
		// API returned an error object, return empty
		return []string{}, nil
	}

	var entries []struct {
		DNSNames []string `json:"dns_names"`
	}

	if err := json.Unmarshal(body, &entries); err != nil {
		// If parsing fails, return empty instead of error
		return []string{}, nil
	}

	seen := make(map[string]bool)
	var subs []string
	for _, entry := range entries {
		for _, name := range entry.DNSNames {
			name = strings.TrimPrefix(name, "*.")
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" && !seen[name] && strings.HasSuffix(name, domain) {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchAlienVault(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var subs []string
	for _, entry := range result.PassiveDNS {
		name := strings.ToLower(strings.TrimSpace(entry.Hostname))
		if name != "" && !seen[name] && strings.HasSuffix(name, domain) {
			seen[name] = true
			subs = append(subs, name)
		}
	}

	return subs, nil
}

func FetchHackerTarget(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")

	var subs []string
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			if name != "" && strings.HasSuffix(name, domain) {
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchURLScan(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var subs []string
	for _, entry := range result.Results {
		name := strings.ToLower(strings.TrimSpace(entry.Page.Domain))
		if name != "" && !seen[name] && strings.HasSuffix(name, domain) {
			seen[name] = true
			subs = append(subs, name)
		}
	}

	return subs, nil
}

func FetchRapidDNS(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchAnubis(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var subs []string
	if err := json.NewDecoder(resp.Body).Decode(&subs); err != nil {
		return nil, err
	}

	return subs, nil
}

func FetchThreatMiner(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read body first to handle empty/EOF responses
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Handle empty response
	if len(body) == 0 {
		return []string{}, nil
	}

	var result struct {
		StatusCode string   `json:"status_code"`
		Results    []string `json:"results"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		// If JSON parsing fails, return empty results instead of error
		return []string{}, nil
	}

	// ThreatMiner returns status_code "404" when no results
	if result.StatusCode == "404" || result.Results == nil {
		return []string{}, nil
	}

	return result.Results, nil
}

func FetchDNSRepo(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://dnsrepo.noc.org/?domain=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchSubdomainCenter(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.subdomain.center/?domain=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var subs []string
	if err := json.NewDecoder(resp.Body).Decode(&subs); err != nil {
		return nil, err
	}

	return subs, nil
}

func FetchWayback(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Return empty instead of error on timeout - Wayback is often slow
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] && !strings.HasPrefix(name, ".") {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchBinaryEdge(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.binaryedge.io/v2/query/domains/subdomain/%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Events []string `json:"events"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return []string{}, nil
	}

	var subs []string
	for _, sub := range result.Events {
		if strings.HasSuffix(sub, domain) {
			subs = append(subs, sub)
		}
	}

	return subs, nil
}

func FetchCensys(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://search.censys.io/api/v1/search/certificates?q=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchFacebook(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://developers.facebook.com/tools/ct/search/?query=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchFullHunt(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://fullhunt.io/api/v1/domain/%s/subdomains", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Hosts []string `json:"hosts"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return []string{}, nil
	}

	return result.Hosts, nil
}

func FetchChaos(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://chaos-data.projectdiscovery.io/index.json")
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchNetlas(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://app.netlas.io/api/domains/?q=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchSitedossier(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchWebArchive(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://web.archive.org/__wb/search/host?q=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Hosts []string `json:"hosts"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return []string{}, nil
	}

	var subs []string
	for _, host := range result.Hosts {
		if strings.HasSuffix(host, domain) {
			subs = append(subs, host)
		}
	}

	return subs, nil
}

func FetchSecurityTrails(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://securitytrails.com/list/apex_domain/%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchHackerOne(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := "https://hackerone.com/graphql"
	payload := fmt.Sprintf(`{"query":"query {team(handle:\"%s\"){structured_scopes{edges{node{asset_identifier}}}}}"}`, domain)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchDNSDumpster(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 15 * time.Second}

	pageReq, _ := http.NewRequestWithContext(ctx, "GET", "https://dnsdumpster.com/", nil)
	pageReq.Header.Set("User-Agent", "Mozilla/5.0")
	pageResp, err := client.Do(pageReq)
	if err != nil {
		return []string{}, nil
	}
	defer pageResp.Body.Close()

	pageBody, _ := io.ReadAll(pageResp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(pageBody), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchShodan(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return []string{}, nil
	}

	var subs []string
	for _, sub := range result.Subdomains {
		subs = append(subs, fmt.Sprintf("%s.%s", sub, domain))
	}

	return subs, nil
}

func FetchBufferOver(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		FDNS_A []string `json:"FDNS_A"`
		RDNS   []string `json:"RDNS"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return []string{}, nil
	}

	seen := make(map[string]bool)
	var subs []string

	for _, record := range result.FDNS_A {
		parts := strings.Split(record, ",")
		if len(parts) >= 2 {
			name := strings.ToLower(strings.TrimSpace(parts[1]))
			if name != "" && !seen[name] && strings.HasSuffix(name, domain) {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	for _, record := range result.RDNS {
		parts := strings.Split(record, ",")
		if len(parts) >= 2 {
			name := strings.ToLower(strings.TrimSpace(parts[1]))
			if name != "" && !seen[name] && strings.HasSuffix(name, domain) {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchCommonCrawl(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.%s&output=json", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] && !strings.HasPrefix(name, ".") {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchVirusTotal(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://www.virustotal.com/ui/domains/%s/subdomains?limit=40", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return []string{}, nil
	}

	var subs []string
	for _, item := range result.Data {
		if item.ID != "" && strings.HasSuffix(item.ID, domain) {
			subs = append(subs, item.ID)
		}
	}

	return subs, nil
}

// Additional free sources

func FetchRiddler(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://riddler.io/search/exportcsv?q=pld:%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchRobtex(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://freeapi.robtex.com/pdns/forward/%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchDNSHistory(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://dnshistory.org/dns-records/%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchArchiveToday(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://archive.ph/*.%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchJLDC(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var subs []string
	if err := json.Unmarshal(body, &subs); err != nil {
		return []string{}, nil
	}

	var result []string
	for _, sub := range subs {
		if strings.HasSuffix(sub, domain) {
			result = append(result, sub)
		}
	}

	return result, nil
}

func FetchCrtshPostgres(domain string) ([]string, error) {
	// Alternative crt.sh endpoint that scrapes the HTML page
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://crt.sh/?q=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)>([a-z0-9*][a-z0-9._-]*\.%s)<`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.TrimPrefix(strings.ToLower(match[1]), "*.")
			if !seen[name] && name != "" {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchSynapsInt(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://synapsint.com/report.php?name=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}

func FetchCensysFree(domain string) ([]string, error) {
	// Uses the free web search interface
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://search.censys.io/search?resource=hosts&q=%s", domain)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	re := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain)))
	matches := re.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			if !seen[name] {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs, nil
}
