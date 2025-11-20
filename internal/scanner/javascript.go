package scanner

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// AnalyzeJSFiles finds JavaScript files and extracts potential secrets
func AnalyzeJSFiles(subdomain string, client *http.Client) ([]string, []string) {
	var jsFiles []string
	var secrets []string

	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	// Common JS file paths
	jsPaths := []string{
		"/main.js", "/app.js", "/bundle.js", "/vendor.js",
		"/static/js/main.js", "/static/js/app.js",
		"/assets/js/app.js", "/js/main.js", "/js/app.js",
		"/dist/main.js", "/dist/bundle.js",
		"/_next/static/chunks/main.js",
		"/build/static/js/main.js",
	}

	// Secret patterns to search for
	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)['"]?api[_-]?key['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`),
		regexp.MustCompile(`(?i)['"]?aws[_-]?access[_-]?key[_-]?id['"]?\s*[:=]\s*['"]([A-Z0-9]{20})['"]`),
		regexp.MustCompile(`(?i)['"]?aws[_-]?secret[_-]?access[_-]?key['"]?\s*[:=]\s*['"]([a-zA-Z0-9/+=]{40})['"]`),
		regexp.MustCompile(`(?i)['"]?google[_-]?api[_-]?key['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{39})['"]`),
		regexp.MustCompile(`(?i)['"]?firebase[_-]?api[_-]?key['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{39})['"]`),
		regexp.MustCompile(`(?i)['"]?stripe[_-]?(publishable|secret)[_-]?key['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`),
		regexp.MustCompile(`(?i)['"]?github[_-]?token['"]?\s*[:=]\s*['"]([a-zA-Z0-9_]{36,})['"]`),
		regexp.MustCompile(`(?i)['"]?slack[_-]?token['"]?\s*[:=]\s*['"]([a-zA-Z0-9\-]{30,})['"]`),
		regexp.MustCompile(`(?i)['"]?private[_-]?key['"]?\s*[:=]\s*['"]([a-zA-Z0-9/+=]{50,})['"]`),
		regexp.MustCompile(`(?i)['"]?secret['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`),
		regexp.MustCompile(`(?i)['"]?password['"]?\s*[:=]\s*['"]([^'"]{8,})['"]`),
		regexp.MustCompile(`(?i)['"]?authorization['"]?\s*[:=]\s*['"]Bearer\s+([a-zA-Z0-9_\-\.]+)['"]`),
	}

	// Also search for API endpoints in JS
	endpointPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)['"]https?://[a-zA-Z0-9\-\.]+/api/[a-zA-Z0-9/\-_]+['"]`),
		regexp.MustCompile(`(?i)['"]https?://api\.[a-zA-Z0-9\-\.]+[a-zA-Z0-9/\-_]*['"]`),
	}

	for _, baseURL := range urls {
		// First, get the main page and extract JS file references
		resp, err := client.Get(baseURL)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 500000))
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Find JS files referenced in HTML
		jsRe := regexp.MustCompile(`src=["']([^"']*\.js[^"']*)["']`)
		matches := jsRe.FindAllStringSubmatch(string(body), -1)
		for _, match := range matches {
			if len(match) > 1 {
				jsURL := match[1]
				if !strings.HasPrefix(jsURL, "http") {
					if strings.HasPrefix(jsURL, "/") {
						jsURL = baseURL + jsURL
					} else {
						jsURL = baseURL + "/" + jsURL
					}
				}
				jsFiles = append(jsFiles, jsURL)
			}
		}

		// Also check common JS paths
		for _, path := range jsPaths {
			testURL := baseURL + path
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				jsFiles = append(jsFiles, path)

				// Read JS content and search for secrets
				jsBody, err := io.ReadAll(io.LimitReader(resp.Body, 500000))
				resp.Body.Close()
				if err != nil {
					continue
				}

				jsContent := string(jsBody)

				// Search for secrets
				for _, pattern := range secretPatterns {
					if matches := pattern.FindAllStringSubmatch(jsContent, 3); len(matches) > 0 {
						for _, m := range matches {
							if len(m) > 1 {
								secret := m[0]
								if len(secret) > 60 {
									secret = secret[:57] + "..."
								}
								secrets = append(secrets, secret)
							}
						}
					}
				}

				// Search for API endpoints
				for _, pattern := range endpointPatterns {
					if matches := pattern.FindAllString(jsContent, 5); len(matches) > 0 {
						for _, m := range matches {
							if len(m) > 60 {
								m = m[:57] + "..."
							}
							secrets = append(secrets, "endpoint: "+m)
						}
					}
				}
			} else {
				resp.Body.Close()
			}
		}

		if len(jsFiles) > 0 || len(secrets) > 0 {
			break
		}
	}

	// Deduplicate and limit
	jsFiles = UniqueStrings(jsFiles)
	secrets = UniqueStrings(secrets)

	if len(jsFiles) > 10 {
		jsFiles = jsFiles[:10]
	}
	if len(secrets) > 10 {
		secrets = secrets[:10]
	}

	return jsFiles, secrets
}

// UniqueStrings returns unique strings from a slice
func UniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
