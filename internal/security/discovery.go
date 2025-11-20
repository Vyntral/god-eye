package security

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func CheckAdminPanels(subdomain string, timeout int) []string {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Common admin panel paths
	paths := []string{
		"/admin", "/administrator", "/admin.php", "/admin.html",
		"/login", "/login.php", "/signin", "/auth",
		"/wp-admin", "/wp-login.php",
		"/phpmyadmin", "/pma", "/mysql",
		"/cpanel", "/webmail",
		"/manager", "/console", "/dashboard",
		"/admin/login", "/user/login",
	}

	var found []string
	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		for _, path := range paths {
			testURL := baseURL + path
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Found if 200, 301, 302, 401, 403 (not 404)
			if resp.StatusCode != 404 && resp.StatusCode != 0 {
				found = append(found, path)
			}
		}
		if len(found) > 0 {
			break
		}
	}

	return found
}

// CheckGitSvnExposure checks for exposed .git or .svn directories
func CheckGitSvnExposure(subdomain string, timeout int) (gitExposed bool, svnExposed bool) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		// Check .git
		resp, err := client.Get(baseURL + "/.git/config")
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
			resp.Body.Close()
			if resp.StatusCode == 200 && strings.Contains(string(body), "[core]") {
				gitExposed = true
			}
		}

		// Check .svn
		resp, err = client.Get(baseURL + "/.svn/entries")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				svnExposed = true
			}
		}

		if gitExposed || svnExposed {
			break
		}
	}

	return gitExposed, svnExposed
}

// CheckBackupFiles checks for common backup files
func CheckBackupFiles(subdomain string, timeout int) []string {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Common backup file patterns
	paths := []string{
		"/backup.zip", "/backup.tar.gz", "/backup.sql",
		"/db.sql", "/database.sql", "/dump.sql",
		"/site.zip", "/www.zip", "/public.zip",
		"/config.bak", "/config.old", "/.env.bak",
		"/index.php.bak", "/index.php.old", "/index.html.bak",
		"/web.config.bak", "/.htaccess.bak",
	}

	var found []string
	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		for _, path := range paths {
			resp, err := client.Head(baseURL + path)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == 200 {
				found = append(found, path)
			}
		}
		if len(found) > 0 {
			break
		}
	}

	return found
}

// CheckAPIEndpoints checks for common API endpoints
func CheckAPIEndpoints(subdomain string, timeout int) []string {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Common API endpoint patterns
	paths := []string{
		"/api", "/api/v1", "/api/v2", "/api/v3",
		"/graphql", "/graphiql",
		"/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
		"/openapi.json", "/openapi.yaml",
		"/docs", "/api-docs", "/redoc",
		"/health", "/healthz", "/status",
		"/metrics", "/actuator", "/actuator/health",
		"/v1", "/v2", "/rest",
	}

	var found []string
	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		for _, path := range paths {
			resp, err := client.Get(baseURL + path)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Found if not 404
			if resp.StatusCode != 404 && resp.StatusCode != 0 {
				found = append(found, path)
			}
		}
		if len(found) > 0 {
			break
		}
	}

	return found
}

// WithClient versions for parallel execution

func CheckAdminPanelsWithClient(subdomain string, client *http.Client) []string {
	paths := []string{
		"/admin", "/administrator", "/admin.php", "/admin.html",
		"/login", "/login.php", "/signin", "/auth",
		"/wp-admin", "/wp-login.php",
		"/phpmyadmin", "/pma", "/mysql",
		"/cpanel", "/webmail",
		"/manager", "/console", "/dashboard",
		"/admin/login", "/user/login",
	}

	var found []string
	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		// First, get the root page to detect SPA catch-all behavior
		rootResp, err := client.Get(baseURL + "/")
		var rootContentLength string
		var rootContentType string
		if err == nil {
			rootContentLength = rootResp.Header.Get("Content-Length")
			rootContentType = rootResp.Header.Get("Content-Type")
			rootResp.Body.Close()
		}

		for _, path := range paths {
			testURL := baseURL + path
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Report 200 OK (found), 401/403 (protected but exists)
			if resp.StatusCode == 200 {
				// Check for SPA catch-all: same content-length and content-type as root
				contentLength := resp.Header.Get("Content-Length")
				contentType := resp.Header.Get("Content-Type")

				// If response matches root page exactly, it's likely SPA catch-all
				isSPACatchAll := rootContentLength != "" && contentLength == rootContentLength &&
					strings.Contains(contentType, "text/html") && strings.Contains(rootContentType, "text/html")

				if !isSPACatchAll {
					found = append(found, path)
				}
			} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
				// Protected endpoint exists
				found = append(found, path+" (protected)")
			}
		}

		if len(found) > 0 {
			break // Found results, no need to try HTTP
		}
	}

	return found
}

func CheckGitSvnExposureWithClient(subdomain string, client *http.Client) (gitExposed bool, svnExposed bool) {
	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		resp, err := client.Get(baseURL + "/.git/config")
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
			resp.Body.Close()
			if resp.StatusCode == 200 && strings.Contains(string(body), "[core]") {
				gitExposed = true
			}
		}

		resp, err = client.Get(baseURL + "/.svn/entries")
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
			resp.Body.Close()
			// SVN entries file starts with version number or contains specific format
			// Must not be HTML (SPA catch-all returns HTML for all routes)
			bodyStr := string(body)
			if resp.StatusCode == 200 && !strings.Contains(bodyStr, "<html") && !strings.Contains(bodyStr, "<!DOCTYPE") {
				// Old SVN format starts with version number, new format is XML
				if len(bodyStr) > 0 && (bodyStr[0] >= '0' && bodyStr[0] <= '9' || strings.Contains(bodyStr, "<?xml")) {
					svnExposed = true
				}
			}
		}

		if gitExposed || svnExposed {
			break
		}
	}

	return gitExposed, svnExposed
}

func CheckBackupFilesWithClient(subdomain string, client *http.Client) []string {
	paths := []string{
		"/backup.zip", "/backup.tar.gz", "/backup.sql",
		"/db.sql", "/database.sql", "/dump.sql",
		"/site.zip", "/www.zip", "/public.zip",
		"/config.bak", "/config.old", "/.env.bak",
		"/index.php.bak", "/index.php.old", "/index.html.bak",
		"/web.config.bak", "/.htaccess.bak",
	}

	var found []string
	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		for _, path := range paths {
			resp, err := client.Head(baseURL + path)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == 200 {
				// Check content-type to avoid SPA catch-all false positives
				contentType := resp.Header.Get("Content-Type")
				// Backup files should NOT be text/html - that indicates SPA catch-all
				if !strings.Contains(contentType, "text/html") {
					found = append(found, path)
				}
			}
		}

		if len(found) > 0 {
			break // Found results, no need to try HTTP
		}
	}

	return found
}

func CheckAPIEndpointsWithClient(subdomain string, client *http.Client) []string {
	paths := []string{
		"/api", "/api/v1", "/api/v2", "/api/v3",
		"/graphql", "/graphiql",
		"/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
		"/openapi.json", "/openapi.yaml",
		"/docs", "/api-docs", "/redoc",
		"/health", "/healthz", "/status",
		"/metrics", "/actuator", "/actuator/health",
		"/v1", "/v2", "/rest",
	}

	var found []string
	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		// First, get the root page to detect SPA catch-all behavior
		rootResp, err := client.Get(baseURL + "/")
		var rootContentLength string
		var rootContentType string
		if err == nil {
			rootContentLength = rootResp.Header.Get("Content-Length")
			rootContentType = rootResp.Header.Get("Content-Type")
			rootResp.Body.Close()
		}

		for _, path := range paths {
			resp, err := client.Get(baseURL + path)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Report 200 OK (found), 401/403 (protected but exists)
			if resp.StatusCode == 200 {
				// Check for SPA catch-all: same content-length and content-type as root
				contentLength := resp.Header.Get("Content-Length")
				contentType := resp.Header.Get("Content-Type")

				// If response matches root page exactly, it's likely SPA catch-all
				isSPACatchAll := rootContentLength != "" && contentLength == rootContentLength &&
					strings.Contains(contentType, "text/html") && strings.Contains(rootContentType, "text/html")

				if !isSPACatchAll {
					found = append(found, path)
				}
			} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
				// Protected endpoint exists
				found = append(found, path+" (protected)")
			}
		}

		if len(found) > 0 {
			break // Found results, no need to try HTTP
		}
	}

	return found
}
