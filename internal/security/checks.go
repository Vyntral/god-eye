package security

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CheckOpenRedirect tests for open redirect vulnerabilities
func CheckOpenRedirect(subdomain string, timeout int) bool {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Common open redirect parameters
	testPayloads := []string{
		"?url=https://evil.com",
		"?redirect=https://evil.com",
		"?next=https://evil.com",
		"?return=https://evil.com",
		"?dest=https://evil.com",
		"?destination=https://evil.com",
		"?rurl=https://evil.com",
		"?target=https://evil.com",
	}

	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		for _, payload := range testPayloads {
			testURL := baseURL + payload
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Check if redirects to evil.com
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if strings.Contains(location, "evil.com") {
					return true
				}
			}
		}
	}

	return false
}

// CheckCORS tests for CORS misconfiguration
func CheckCORS(subdomain string, timeout int) string {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, url := range urls {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		// Test with evil origin
		req.Header.Set("Origin", "https://evil.com")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		// Check for dangerous CORS configs
		if acao == "*" {
			if acac == "true" {
				return "Wildcard + Credentials"
			}
			return "Wildcard Origin"
		}

		if acao == "https://evil.com" {
			if acac == "true" {
				return "Origin Reflection + Credentials"
			}
			return "Origin Reflection"
		}

		if strings.Contains(acao, "null") {
			return "Null Origin Allowed"
		}
	}

	return ""
}

// CheckHTTPMethods tests which HTTP methods are allowed
func CheckHTTPMethods(subdomain string, timeout int) (allowed []string, dangerous []string) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"}
	dangerousMethods := map[string]bool{
		"PUT":    true,
		"DELETE": true,
		"TRACE":  true,
		"PATCH":  true,
	}

	for _, url := range urls {
		// First try OPTIONS to get Allow header
		req, err := http.NewRequest("OPTIONS", url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check Allow header
		allowHeader := resp.Header.Get("Allow")
		if allowHeader != "" {
			for _, method := range strings.Split(allowHeader, ",") {
				method = strings.TrimSpace(method)
				allowed = append(allowed, method)
				if dangerousMethods[method] {
					dangerous = append(dangerous, method)
				}
			}
			return allowed, dangerous
		}

		// If no Allow header, test each method
		for _, method := range methods {
			req, err := http.NewRequest(method, url, nil)
			if err != nil {
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Method is allowed if not 405 Method Not Allowed
			if resp.StatusCode != 405 {
				allowed = append(allowed, method)
				if dangerousMethods[method] {
					dangerous = append(dangerous, method)
				}
			}
		}

		if len(allowed) > 0 {
			return allowed, dangerous
		}
	}

	return allowed, dangerous
}

// WithClient versions for parallel execution with shared client

func CheckOpenRedirectWithClient(subdomain string, client *http.Client) bool {
	testPayloads := []string{
		"?url=https://evil.com",
		"?redirect=https://evil.com",
		"?next=https://evil.com",
		"?return=https://evil.com",
	}

	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		for _, payload := range testPayloads {
			testURL := baseURL + payload
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				// Check if redirect actually goes to evil.com, not just contains it as parameter
				if strings.HasPrefix(location, "https://evil.com") ||
					strings.HasPrefix(location, "http://evil.com") ||
					strings.HasPrefix(location, "//evil.com") {
					return true
				}
			}
		}
	}

	return false
}

func CheckCORSWithClient(subdomain string, client *http.Client) string {
	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, url := range urls {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Origin", "https://evil.com")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if acao == "*" {
			if acac == "true" {
				return "Wildcard + Credentials"
			}
			return "Wildcard Origin"
		}

		if acao == "https://evil.com" {
			if acac == "true" {
				return "Origin Reflection + Credentials"
			}
			return "Origin Reflection"
		}

		if strings.Contains(acao, "null") {
			return "Null Origin Allowed"
		}
	}

	return ""
}

func CheckHTTPMethodsWithClient(subdomain string, client *http.Client) (allowed []string, dangerous []string) {
	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	dangerousMethods := map[string]bool{
		"PUT":    true,
		"DELETE": true,
		"TRACE":  true,
		"PATCH":  true,
	}

	for _, url := range urls {
		req, err := http.NewRequest("OPTIONS", url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Only trust the Allow header from OPTIONS response
		// Don't probe individual methods as this causes too many false positives
		allowHeader := resp.Header.Get("Allow")
		if allowHeader != "" {
			for _, method := range strings.Split(allowHeader, ",") {
				method = strings.TrimSpace(method)
				allowed = append(allowed, method)
				if dangerousMethods[method] {
					dangerous = append(dangerous, method)
				}
			}
			return allowed, dangerous
		}
	}

	// If no Allow header found, don't report anything to avoid false positives
	return allowed, dangerous
}
