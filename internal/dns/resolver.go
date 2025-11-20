package dns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"god-eye/internal/config"
)

func ResolveSubdomain(subdomain string, resolvers []string, timeout int) []string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(subdomain), dns.TypeA)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		var ips []string
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}

		if len(ips) > 0 {
			return ips
		}
	}

	return nil
}

func CheckWildcard(domain string, resolvers []string) []string {
	// Test multiple random patterns for better wildcard detection
	patterns := []string{
		fmt.Sprintf("random%d.%s", time.Now().UnixNano(), domain),
		fmt.Sprintf("xyz%d.%s", time.Now().UnixNano()%1000000, domain),
		fmt.Sprintf("nonexistent-%s.%s", "abc123xyz", domain),
	}

	allIPs := make(map[string]int)
	for _, pattern := range patterns {
		ips := ResolveSubdomain(pattern, resolvers, 3)
		for _, ip := range ips {
			allIPs[ip]++
		}
	}

	// If same IP(s) appear in multiple patterns, it's a wildcard
	var wildcardIPs []string
	for ip, count := range allIPs {
		if count >= 2 {
			wildcardIPs = append(wildcardIPs, ip)
		}
	}

	return wildcardIPs
}

func ResolveCNAME(subdomain string, resolvers []string, timeout int) string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(subdomain), dns.TypeCNAME)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		for _, ans := range r.Answer {
			if cname, ok := ans.(*dns.CNAME); ok {
				return strings.TrimSuffix(cname.Target, ".")
			}
		}
	}

	return ""
}

func ResolvePTR(ip string, resolvers []string, timeout int) string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Convert IP to reverse DNS format
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	reverseIP := fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa.", parts[3], parts[2], parts[1], parts[0])

	m := dns.Msg{}
	m.SetQuestion(reverseIP, dns.TypePTR)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		for _, ans := range r.Answer {
			if ptr, ok := ans.(*dns.PTR); ok {
				return strings.TrimSuffix(ptr.Ptr, ".")
			}
		}
	}

	return ""
}

func ResolveMX(domain string, resolvers []string, timeout int) []string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		var records []string
		for _, ans := range r.Answer {
			if mx, ok := ans.(*dns.MX); ok {
				records = append(records, strings.TrimSuffix(mx.Mx, "."))
			}
		}
		if len(records) > 0 {
			return records
		}
	}

	return nil
}

func ResolveTXT(domain string, resolvers []string, timeout int) []string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		var records []string
		for _, ans := range r.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				for _, t := range txt.Txt {
					// Limit length for display
					if len(t) > 100 {
						t = t[:97] + "..."
					}
					records = append(records, t)
				}
			}
		}
		if len(records) > 0 {
			return records
		}
	}

	return nil
}

func ResolveNS(domain string, resolvers []string, timeout int) []string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		var records []string
		for _, ans := range r.Answer {
			if ns, ok := ans.(*dns.NS); ok {
				records = append(records, strings.TrimSuffix(ns.Ns, "."))
			}
		}
		if len(records) > 0 {
			return records
		}
	}

	return nil
}

func GetIPInfo(ip string) (*config.IPInfo, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=as,org,country,city", ip)

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info config.IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}
