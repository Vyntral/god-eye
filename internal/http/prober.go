package http

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"god-eye/internal/config"
)

func ProbeHTTP(subdomain string, timeout int) *config.SubdomainResult {
	result := &config.SubdomainResult{}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, url := range urls {
		start := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		result.StatusCode = resp.StatusCode
		result.ResponseMs = time.Since(start).Milliseconds()

		// Content-Length
		if cl := resp.ContentLength; cl > 0 {
			result.ContentLength = cl
		}

		// Redirect location
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			if loc := resp.Header.Get("Location"); loc != "" {
				result.RedirectURL = loc
			}
		}

		// Server header
		if server := resp.Header.Get("Server"); server != "" {
			result.Server = server
			result.Tech = append(result.Tech, server)
		}

		// TLS/SSL info
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			result.TLSIssuer = cert.Issuer.CommonName
			result.TLSExpiry = cert.NotAfter.Format("2006-01-02")

			// TLS version
			switch resp.TLS.Version {
			case tls.VersionTLS13:
				result.TLSVersion = "TLS 1.3"
			case tls.VersionTLS12:
				result.TLSVersion = "TLS 1.2"
			case tls.VersionTLS11:
				result.TLSVersion = "TLS 1.1"
			case tls.VersionTLS10:
				result.TLSVersion = "TLS 1.0"
			}
		}

		// Interesting headers
		interestingHeaders := []string{
			"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
			"X-Generator", "X-Drupal-Cache", "X-Varnish",
			"X-Cache", "X-Backend-Server", "X-Server",
		}
		for _, h := range interestingHeaders {
			if val := resp.Header.Get(h); val != "" {
				result.Headers = append(result.Headers, fmt.Sprintf("%s: %s", h, val))
				if h == "X-Powered-By" {
					result.Tech = append(result.Tech, val)
				}
			}
		}

		// WAF detection
		result.WAF = DetectWAF(resp)

		// Security headers check
		result.SecurityHeaders, result.MissingHeaders = CheckSecurityHeaders(resp)

		// Read body for title and tech detection
		body, err := io.ReadAll(io.LimitReader(resp.Body, 100000))
		if err == nil {
			// Content-Length from body if not set
			if result.ContentLength == 0 {
				result.ContentLength = int64(len(body))
			}

			// Extract title
			titleRe := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
			if matches := titleRe.FindSubmatch(body); len(matches) > 1 {
				result.Title = strings.TrimSpace(string(matches[1]))
			}

			// Detect technologies
			bodyStr := string(body)
			if strings.Contains(bodyStr, "wp-content") || strings.Contains(bodyStr, "wordpress") {
				result.Tech = append(result.Tech, "WordPress")
			}
			if strings.Contains(bodyStr, "_next") || strings.Contains(bodyStr, "Next.js") {
				result.Tech = append(result.Tech, "Next.js")
			}
			if strings.Contains(bodyStr, "react") || strings.Contains(bodyStr, "React") {
				result.Tech = append(result.Tech, "React")
			}
			if strings.Contains(bodyStr, "laravel") || strings.Contains(bodyStr, "Laravel") {
				result.Tech = append(result.Tech, "Laravel")
			}
			if strings.Contains(bodyStr, "django") || strings.Contains(bodyStr, "Django") {
				result.Tech = append(result.Tech, "Django")
			}
			if strings.Contains(bodyStr, "angular") || strings.Contains(bodyStr, "ng-") {
				result.Tech = append(result.Tech, "Angular")
			}
			if strings.Contains(bodyStr, "vue") || strings.Contains(bodyStr, "Vue.js") {
				result.Tech = append(result.Tech, "Vue.js")
			}
		}

		break
	}

	return result
}

func DetectWAF(resp *http.Response) string {
	// Check headers for WAF signatures
	serverHeader := strings.ToLower(resp.Header.Get("Server"))

	// Cloudflare
	if resp.Header.Get("CF-RAY") != "" || strings.Contains(serverHeader, "cloudflare") {
		return "Cloudflare"
	}

	// AWS WAF/CloudFront
	if resp.Header.Get("X-Amz-Cf-Id") != "" || resp.Header.Get("X-Amz-Cf-Pop") != "" {
		return "AWS CloudFront"
	}

	// Akamai
	if resp.Header.Get("X-Akamai-Transformed") != "" || strings.Contains(serverHeader, "akamai") {
		return "Akamai"
	}

	// Sucuri
	if resp.Header.Get("X-Sucuri-ID") != "" || strings.Contains(serverHeader, "sucuri") {
		return "Sucuri"
	}

	// Imperva/Incapsula
	if resp.Header.Get("X-Iinfo") != "" || resp.Header.Get("X-CDN") == "Incapsula" {
		return "Imperva"
	}

	// F5 BIG-IP
	if strings.Contains(serverHeader, "big-ip") || resp.Header.Get("X-WA-Info") != "" {
		return "F5 BIG-IP"
	}

	// Barracuda
	if strings.Contains(serverHeader, "barracuda") {
		return "Barracuda"
	}

	// Fastly
	if resp.Header.Get("X-Fastly-Request-ID") != "" || resp.Header.Get("Fastly-Debug-Digest") != "" {
		return "Fastly"
	}

	// Varnish
	if resp.Header.Get("X-Varnish") != "" {
		return "Varnish"
	}

	return ""
}

func CheckSecurityHeaders(resp *http.Response) (present []string, missing []string) {
	securityHeaders := map[string]string{
		"Content-Security-Policy":   "CSP",
		"X-Frame-Options":           "X-Frame",
		"X-Content-Type-Options":    "X-Content-Type",
		"Strict-Transport-Security": "HSTS",
		"X-XSS-Protection":          "X-XSS",
		"Referrer-Policy":           "Referrer",
		"Permissions-Policy":        "Permissions",
	}

	for header, shortName := range securityHeaders {
		if val := resp.Header.Get(header); val != "" {
			present = append(present, shortName)
		} else {
			missing = append(missing, shortName)
		}
	}

	return present, missing
}
