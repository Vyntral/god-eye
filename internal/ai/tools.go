package ai

import (
	"encoding/json"
	"fmt"
)

// Tool represents a function that can be called by the AI
type Tool struct {
	Type     string                 `json:"type"`
	Function ToolFunction           `json:"function"`
}

// ToolFunction describes a callable function
type ToolFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// ToolCall represents an AI request to call a function
type ToolCall struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Function ToolCallFunction       `json:"function"`
}

// ToolCallFunction contains the function name and arguments
type ToolCallFunction struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// GetAvailableTools returns the list of tools available for AI function calling
func GetAvailableTools() []Tool {
	return []Tool{
		{
			Type: "function",
			Function: ToolFunction{
				Name:        "search_cve",
				Description: "Search for CVE vulnerabilities for a specific software/technology and version. Returns a list of known CVEs with descriptions and severity.",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"technology": map[string]interface{}{
							"type":        "string",
							"description": "The software or technology name (e.g., 'nginx', 'Apache', 'WordPress', 'IIS')",
						},
						"version": map[string]interface{}{
							"type":        "string",
							"description": "The version number if known (e.g., '2.4.49', '10.0'). Use 'unknown' if version is not specified.",
						},
					},
					"required": []string{"technology"},
				},
			},
		},
		{
			Type: "function",
			Function: ToolFunction{
				Name:        "check_security_headers",
				Description: "Analyzes HTTP security headers and returns recommendations for missing or misconfigured headers.",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"headers": map[string]interface{}{
							"type":        "object",
							"description": "HTTP response headers as key-value pairs",
						},
					},
					"required": []string{"headers"},
				},
			},
		},
		{
			Type: "function",
			Function: ToolFunction{
				Name:        "analyze_javascript",
				Description: "Analyzes JavaScript code for potential security issues like hardcoded secrets, eval usage, or suspicious patterns.",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"code": map[string]interface{}{
							"type":        "string",
							"description": "JavaScript code snippet to analyze",
						},
						"url": map[string]interface{}{
							"type":        "string",
							"description": "The URL where the JavaScript was found",
						},
					},
					"required": []string{"code"},
				},
			},
		},
	}
}

// ExecuteTool executes a tool call and returns the result
func ExecuteTool(toolCall ToolCall) (string, error) {
	switch toolCall.Function.Name {
	case "search_cve":
		var args struct {
			Technology string `json:"technology"`
			Version    string `json:"version"`
		}
		if err := json.Unmarshal(toolCall.Function.Arguments, &args); err != nil {
			return "", fmt.Errorf("failed to parse arguments: %w", err)
		}
		return SearchCVE(args.Technology, args.Version)

	case "check_security_headers":
		var args struct {
			Headers map[string]string `json:"headers"`
		}
		if err := json.Unmarshal(toolCall.Function.Arguments, &args); err != nil {
			return "", fmt.Errorf("failed to parse arguments: %w", err)
		}
		return CheckSecurityHeaders(args.Headers)

	case "analyze_javascript":
		var args struct {
			Code string `json:"code"`
			URL  string `json:"url"`
		}
		if err := json.Unmarshal(toolCall.Function.Arguments, &args); err != nil {
			return "", fmt.Errorf("failed to parse arguments: %w", err)
		}
		return AnalyzeJavaScript(args.Code, args.URL)

	default:
		return "", fmt.Errorf("unknown tool: %s", toolCall.Function.Name)
	}
}

// CheckSecurityHeaders analyzes HTTP headers for security issues
func CheckSecurityHeaders(headers map[string]string) (string, error) {
	var issues []string
	var recommendations []string

	// Check for important security headers
	if _, ok := headers["Strict-Transport-Security"]; !ok {
		issues = append(issues, "Missing HSTS header")
		recommendations = append(recommendations, "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'")
	}

	if _, ok := headers["X-Content-Type-Options"]; !ok {
		issues = append(issues, "Missing X-Content-Type-Options header")
		recommendations = append(recommendations, "Add 'X-Content-Type-Options: nosniff'")
	}

	if _, ok := headers["X-Frame-Options"]; !ok {
		issues = append(issues, "Missing X-Frame-Options header")
		recommendations = append(recommendations, "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'")
	}

	if csp, ok := headers["Content-Security-Policy"]; !ok {
		issues = append(issues, "Missing Content-Security-Policy header")
		recommendations = append(recommendations, "Add CSP header to prevent XSS attacks")
	} else if csp == "" {
		issues = append(issues, "Empty Content-Security-Policy header")
	}

	if xss, ok := headers["X-XSS-Protection"]; ok && xss == "0" {
		issues = append(issues, "X-XSS-Protection is disabled")
		recommendations = append(recommendations, "Enable XSS protection: '1; mode=block'")
	}

	// Check for information disclosure
	if server, ok := headers["Server"]; ok {
		issues = append(issues, fmt.Sprintf("Server header exposes technology: %s", server))
		recommendations = append(recommendations, "Remove or obfuscate Server header")
	}

	if xPowered, ok := headers["X-Powered-By"]; ok {
		issues = append(issues, fmt.Sprintf("X-Powered-By header exposes technology: %s", xPowered))
		recommendations = append(recommendations, "Remove X-Powered-By header")
	}

	result := fmt.Sprintf("Security Headers Analysis:\n\nIssues Found (%d):\n", len(issues))
	for i, issue := range issues {
		result += fmt.Sprintf("%d. %s\n", i+1, issue)
	}

	if len(recommendations) > 0 {
		result += fmt.Sprintf("\nRecommendations (%d):\n", len(recommendations))
		for i, rec := range recommendations {
			result += fmt.Sprintf("%d. %s\n", i+1, rec)
		}
	}

	if len(issues) == 0 {
		result = "Security headers look good! No major issues found."
	}

	return result, nil
}

// AnalyzeJavaScript performs basic security analysis on JavaScript code
func AnalyzeJavaScript(code string, url string) (string, error) {
	var findings []string

	// Simple pattern matching for security issues
	patterns := map[string]string{
		"eval(":                        "Usage of eval() - can lead to code injection",
		"innerHTML":                    "Usage of innerHTML - potential XSS vulnerability",
		"document.write":               "Usage of document.write - can be dangerous",
		"api_key":                      "Potential hardcoded API key",
		"apikey":                       "Potential hardcoded API key",
		"password":                     "Potential hardcoded password",
		"secret":                       "Potential hardcoded secret",
		"token":                        "Potential hardcoded token",
		"access_token":                 "Potential hardcoded access token",
		"AKIA":                         "Potential AWS access key",
		"Bearer ":                      "Potential hardcoded bearer token",
		"crypto.createCipheriv":        "Cryptographic operations - review implementation",
		"Math.random()":                "Math.random() is not cryptographically secure",
		"localStorage.setItem":         "Data stored in localStorage - ensure no sensitive data",
		"sessionStorage.setItem":       "Data stored in sessionStorage - ensure no sensitive data",
		"XMLHttpRequest":               "Legacy XMLHttpRequest - consider using fetch API",
		"dangerouslySetInnerHTML":      "React dangerouslySetInnerHTML - XSS risk",
	}

	for pattern, description := range patterns {
		if contains(code, pattern) {
			findings = append(findings, fmt.Sprintf("⚠️  %s", description))
		}
	}

	result := fmt.Sprintf("JavaScript Security Analysis for %s:\n\n", url)

	if len(findings) == 0 {
		result += "No obvious security issues detected in this code snippet."
	} else {
		result += fmt.Sprintf("Found %d potential security issues:\n", len(findings))
		for i, finding := range findings {
			result += fmt.Sprintf("%d. %s\n", i+1, finding)
		}
		result += "\nNote: These are automated findings. Manual review is recommended."
	}

	return result, nil
}

// contains checks if a string contains a substring (case-insensitive for simplicity)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
