package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DetectCloudProvider detects cloud provider based on IP/CNAME
func DetectCloudProvider(ips []string, cname string, asn string) string {
	// Check CNAME patterns
	cnamePatterns := map[string]string{
		"amazonaws.com":          "AWS",
		"aws.com":                "AWS",
		"cloudfront.net":         "AWS CloudFront",
		"elasticbeanstalk.com":   "AWS Elastic Beanstalk",
		"elb.amazonaws.com":      "AWS ELB",
		"s3.amazonaws.com":       "AWS S3",
		"azure.com":              "Azure",
		"azurewebsites.net":      "Azure App Service",
		"cloudapp.net":           "Azure",
		"azurefd.net":            "Azure Front Door",
		"blob.core.windows.net":  "Azure Blob",
		"googleapis.com":         "Google Cloud",
		"appspot.com":            "Google App Engine",
		"storage.googleapis.com": "Google Cloud Storage",
		"digitaloceanspaces.com": "DigitalOcean Spaces",
		"ondigitalocean.app":     "DigitalOcean App Platform",
		"cloudflare.com":         "Cloudflare",
		"fastly.net":             "Fastly",
		"akamai.net":             "Akamai",
		"netlify.app":            "Netlify",
		"vercel.app":             "Vercel",
		"herokuapp.com":          "Heroku",
	}

	for pattern, provider := range cnamePatterns {
		if strings.Contains(cname, pattern) {
			return provider
		}
	}

	// Check ASN patterns
	asnPatterns := map[string]string{
		"AS14618": "AWS",
		"AS16509": "AWS",
		"AS8075":  "Azure",
		"AS15169": "Google Cloud",
		"AS14061": "DigitalOcean",
		"AS13335": "Cloudflare",
		"AS54113": "Fastly",
		"AS20940": "Akamai",
	}

	for pattern, provider := range asnPatterns {
		if strings.Contains(asn, pattern) {
			return provider
		}
	}

	return ""
}

// CheckS3Buckets checks for exposed S3 buckets
func CheckS3Buckets(subdomain string, timeout int) []string {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Common S3 bucket URL patterns
	parts := strings.Split(subdomain, ".")
	bucketName := parts[0]

	patterns := []string{
		fmt.Sprintf("https://%s.s3.amazonaws.com", bucketName),
		fmt.Sprintf("https://s3.amazonaws.com/%s", bucketName),
		fmt.Sprintf("https://%s.s3.us-east-1.amazonaws.com", bucketName),
		fmt.Sprintf("https://%s.s3.us-west-2.amazonaws.com", bucketName),
		fmt.Sprintf("https://%s.s3.eu-west-1.amazonaws.com", bucketName),
	}

	var found []string
	for _, url := range patterns {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Public bucket if 200 or 403 (exists but forbidden)
		if resp.StatusCode == 200 {
			found = append(found, url+" (PUBLIC)")
		} else if resp.StatusCode == 403 {
			found = append(found, url+" (exists)")
		}
	}

	return found
}

// CheckEmailSecurity checks SPF/DKIM/DMARC records
func CheckEmailSecurity(domain string, resolvers []string, timeout int) (spf string, dmarc string, security string) {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Check SPF record
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		for _, ans := range r.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				for _, t := range txt.Txt {
					if strings.HasPrefix(t, "v=spf1") {
						spf = t
						if len(spf) > 80 {
							spf = spf[:77] + "..."
						}
						break
					}
				}
			}
		}
		if spf != "" {
			break
		}
	}

	// Check DMARC record
	m2 := dns.Msg{}
	m2.SetQuestion(dns.Fqdn("_dmarc."+domain), dns.TypeTXT)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m2, resolver)
		if err != nil || r == nil {
			continue
		}

		for _, ans := range r.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				for _, t := range txt.Txt {
					if strings.HasPrefix(t, "v=DMARC1") {
						dmarc = t
						if len(dmarc) > 80 {
							dmarc = dmarc[:77] + "..."
						}
						break
					}
				}
			}
		}
		if dmarc != "" {
			break
		}
	}

	// Determine email security level
	if spf != "" && dmarc != "" {
		if strings.Contains(dmarc, "p=reject") || strings.Contains(dmarc, "p=quarantine") {
			security = "Strong"
		} else {
			security = "Moderate"
		}
	} else if spf != "" || dmarc != "" {
		security = "Weak"
	} else {
		security = "None"
	}

	return spf, dmarc, security
}

// GetTLSAltNames extracts Subject Alternative Names from TLS certificate
func GetTLSAltNames(subdomain string, timeout int) []string {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: time.Duration(timeout) * time.Second},
		"tcp",
		subdomain+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	var altNames []string
	seen := make(map[string]bool)

	for _, cert := range certs {
		for _, name := range cert.DNSNames {
			if !seen[name] && name != subdomain {
				seen[name] = true
				altNames = append(altNames, name)
			}
		}
	}

	// Limit to first 10
	if len(altNames) > 10 {
		altNames = altNames[:10]
	}

	return altNames
}

// CheckS3BucketsWithClient checks for exposed S3 buckets with shared client
func CheckS3BucketsWithClient(subdomain string, client *http.Client) []string {
	parts := strings.Split(subdomain, ".")
	if len(parts) < 2 {
		return nil
	}

	subPrefix := parts[0]
	// Get domain name (e.g., "finnat" from "ftp.finnat.it")
	var domainName string
	if len(parts) >= 2 {
		domainName = parts[len(parts)-2]
	}

	// Skip generic subdomain names that cause false positives
	genericNames := map[string]bool{
		"www": true, "ftp": true, "mail": true, "smtp": true, "imap": true,
		"pop": true, "webmail": true, "autodiscover": true, "test": true,
		"dev": true, "staging": true, "api": true, "admin": true, "pop3": true,
	}

	var patterns []string
	if genericNames[subPrefix] {
		// For generic subdomains, use domain-specific bucket names
		patterns = []string{
			fmt.Sprintf("https://%s-%s.s3.amazonaws.com", domainName, subPrefix),
			fmt.Sprintf("https://%s.s3.amazonaws.com", domainName),
		}
	} else {
		// For specific subdomains, use combination
		patterns = []string{
			fmt.Sprintf("https://%s-%s.s3.amazonaws.com", domainName, subPrefix),
			fmt.Sprintf("https://%s.s3.amazonaws.com", domainName),
		}
	}

	var found []string
	for _, url := range patterns {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Only report PUBLIC buckets (200), not just existing (403)
		if resp.StatusCode == 200 {
			found = append(found, url+" (PUBLIC)")
		}
	}

	return found
}
