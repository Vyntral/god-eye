package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// OllamaClient handles communication with local Ollama instance
type OllamaClient struct {
	BaseURL     string
	FastModel   string // deepseek-r1:1.5b for quick triage
	DeepModel   string // qwen2.5-coder:7b for deep analysis
	Timeout     time.Duration
	EnableCascade bool
}

// OllamaRequest represents the request payload for Ollama API
type OllamaRequest struct {
	Model   string                 `json:"model"`
	Prompt  string                 `json:"prompt,omitempty"`
	Stream  bool                   `json:"stream"`
	Tools   []Tool                 `json:"tools,omitempty"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// OllamaResponse represents the response from Ollama API
type OllamaResponse struct {
	Model      string     `json:"model"`
	CreatedAt  time.Time  `json:"created_at"`
	Response   string     `json:"response"`
	Done       bool       `json:"done"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

// AnalysisResult contains AI analysis findings
type AnalysisResult struct {
	Type     string   // "javascript", "http", "anomaly", "report"
	Severity string   // "critical", "high", "medium", "low", "info"
	Findings []string
	Model    string
	Duration time.Duration
}

// NewOllamaClient creates a new Ollama client
func NewOllamaClient(baseURL, fastModel, deepModel string, enableCascade bool) *OllamaClient {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if fastModel == "" {
		fastModel = "deepseek-r1:1.5b"
	}
	if deepModel == "" {
		deepModel = "qwen2.5-coder:7b"
	}

	return &OllamaClient{
		BaseURL:       baseURL,
		FastModel:     fastModel,
		DeepModel:     deepModel,
		Timeout:       60 * time.Second,
		EnableCascade: enableCascade,
	}
}

// IsAvailable checks if Ollama is running and models are available
func (c *OllamaClient) IsAvailable() bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(c.BaseURL + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// QuickTriage performs fast classification using lightweight model
func (c *OllamaClient) QuickTriage(content, contextType string) (bool, string, error) {
	prompt := fmt.Sprintf(`You are a security triage expert. Quickly classify if this %s contains security-relevant information.

Content:
%s

Respond with ONLY:
- "RELEVANT: <brief reason>" if it contains security issues, secrets, vulnerabilities, or suspicious patterns
- "SKIP: <brief reason>" if it's normal/benign

Be concise. One line response only.`, contextType, truncate(content, 2000))

	start := time.Now()
	response, err := c.query(c.FastModel, prompt, 10*time.Second)
	if err != nil {
		return false, "", err
	}

	duration := time.Since(start)
	response = strings.TrimSpace(response)

	// Parse response
	isRelevant := strings.HasPrefix(strings.ToUpper(response), "RELEVANT:")
	reason := strings.TrimPrefix(response, "RELEVANT:")
	reason = strings.TrimPrefix(reason, "SKIP:")
	reason = strings.TrimSpace(reason)

	if duration > 5*time.Second {
		// If fast model is too slow, disable it
		c.EnableCascade = false
	}

	return isRelevant, reason, nil
}

// AnalyzeJavaScript performs deep analysis of JavaScript code
func (c *OllamaClient) AnalyzeJavaScript(code string) (*AnalysisResult, error) {
	// Fast triage first if cascade enabled
	if c.EnableCascade {
		relevant, reason, err := c.QuickTriage(code, "JavaScript code")
		if err == nil && !relevant {
			return &AnalysisResult{
				Type:     "javascript",
				Severity: "info",
				Findings: []string{fmt.Sprintf("Skipped (triage: %s)", reason)},
				Model:    c.FastModel,
			}, nil
		}
	}

	prompt := fmt.Sprintf(`You are a security expert analyzing JavaScript code. Identify:

1. **Hardcoded Secrets**: API keys, tokens, passwords, private keys
2. **Vulnerabilities**: XSS, injection points, insecure functions
3. **Suspicious Patterns**: Obfuscation, backdoors, malicious logic
4. **Hidden Endpoints**: Undocumented APIs, internal URLs

JavaScript Code:
%s

Format your response as:
CRITICAL: <finding>
HIGH: <finding>
MEDIUM: <finding>
LOW: <finding>
INFO: <finding>

Only list actual findings. Be concise and specific.`, truncate(code, 3000))

	start := time.Now()
	response, err := c.query(c.DeepModel, prompt, 30*time.Second)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}

	return parseFindings(response, "javascript", c.DeepModel, duration), nil
}

// AnalyzeHTTPResponse analyzes HTTP response for security issues
func (c *OllamaClient) AnalyzeHTTPResponse(subdomain string, statusCode int, headers []string, body string) (*AnalysisResult, error) {
	// Fast triage
	if c.EnableCascade {
		content := fmt.Sprintf("Status: %d\nHeaders: %s\nBody: %s", statusCode, strings.Join(headers, ", "), truncate(body, 500))
		relevant, reason, err := c.QuickTriage(content, "HTTP response")
		if err == nil && !relevant {
			return &AnalysisResult{
				Type:     "http",
				Severity: "info",
				Findings: []string{fmt.Sprintf("Normal response (triage: %s)", reason)},
				Model:    c.FastModel,
			}, nil
		}
	}

	prompt := fmt.Sprintf(`Analyze this HTTP response for security issues:

URL: %s
Status: %d
Headers: %s
Body (first 1000 chars): %s

Identify:
- Information disclosure
- Misconfigurations
- Debug/error information exposure
- Unusual behavior patterns

Format as: SEVERITY: finding`, subdomain, statusCode, strings.Join(headers, "\n"), truncate(body, 1000))

	start := time.Now()
	response, err := c.query(c.DeepModel, prompt, 20*time.Second)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}

	return parseFindings(response, "http", c.DeepModel, duration), nil
}

// DetectAnomalies identifies unusual patterns across scan results
func (c *OllamaClient) DetectAnomalies(summary string) (*AnalysisResult, error) {
	prompt := fmt.Sprintf(`You are analyzing subdomain enumeration results. Find anomalies and prioritize findings:

%s

Identify:
- Subdomains with unusual behavior vs others
- Potential high-value targets (admin, api, internal)
- Misconfigurations or exposed services
- Patterns suggesting vulnerabilities

Format: SEVERITY: finding`, truncate(summary, 4000))

	start := time.Now()
	response, err := c.query(c.DeepModel, prompt, 30*time.Second)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}

	return parseFindings(response, "anomaly", c.DeepModel, duration), nil
}

// GenerateReport creates executive summary and recommendations
func (c *OllamaClient) GenerateReport(findings string, stats map[string]int) (string, error) {
	prompt := fmt.Sprintf(`You are a security analyst. Create a brief security report from the scan data below.

STATISTICS: %d subdomains scanned, %d active, %d vulnerabilities, %d takeovers

SCAN FINDINGS:
%s

RULES:
- Use ONLY the subdomain names shown in SCAN FINDINGS above
- Do NOT invent or make up any subdomain names
- If no vulnerabilities found, say "No critical issues identified"

FORMAT:
## Summary
(2 sentences about what was found)

## Issues
(List each real subdomain with its actual issues, or "None" if clean)

## Actions
(1-3 specific recommendations)`,
		stats["total"], stats["active"], stats["vulns"], stats["takeovers"], truncate(findings, 3000))

	response, err := c.query(c.DeepModel, prompt, 45*time.Second)
	if err != nil {
		return "", err
	}

	return response, nil
}

// CVEMatch checks for known vulnerabilities in detected technologies
// Returns concise format directly: "CVE-ID (SEVERITY/SCORE), ..."
func (c *OllamaClient) CVEMatch(technology, version string) (string, error) {
	// Call SearchCVE directly - it now returns concise format with caching
	cveData, err := SearchCVE(technology, version)
	if err != nil {
		return "", err
	}

	// Return directly without AI processing - the format is already clean
	return cveData, nil
}

// FilterSecrets uses AI to filter false positives from potential secrets
// Returns only real secrets, filtering out UI text, placeholders, and example values
func (c *OllamaClient) FilterSecrets(potentialSecrets []string) ([]string, error) {
	if len(potentialSecrets) == 0 {
		return nil, nil
	}

	// Build the list of secrets for AI analysis
	secretsList := strings.Join(potentialSecrets, "\n")

	prompt := fmt.Sprintf(`Task: Filter JavaScript findings. Output only REAL secrets.

Examples of FAKE (do NOT output):
- Change Password (UI button text)
- Update Password (UI button text)
- Password (just a word)
- Enter your API key (placeholder)
- YOUR_API_KEY (placeholder)
- Login, Token, Secret (single words)

Examples of REAL (DO output):
- pk_test_TYooMQauvdEDq54NiTphI7jx (Stripe key - has random chars)
- AKIAIOSFODNN7EXAMPLE (AWS key - 20 char pattern)
- mongodb://admin:secret123@db.example.com (connection string)
- eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (JWT token)

Input findings:
%s

Output only the REAL secrets in their original [Type] format, one per line. If none are real, output: NONE`, secretsList)

	response, err := c.query(c.FastModel, prompt, 15*time.Second)
	if err != nil {
		// On error, return original list (fail open for security)
		return potentialSecrets, nil
	}

	// Parse response
	response = strings.TrimSpace(response)
	if strings.ToUpper(response) == "NONE" || response == "" {
		return nil, nil
	}

	var realSecrets []string

	// First, try to find secrets in [Type] format in the response
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.ToUpper(line) == "NONE" {
			continue
		}
		// Accept any line that contains our format [Type] value
		if strings.Contains(line, "[") && strings.Contains(line, "]") {
			// Extract the [Type] value part
			startIdx := strings.Index(line, "[")
			if startIdx >= 0 {
				// Find the actual secret value after ]
				endBracket := strings.Index(line[startIdx:], "]")
				if endBracket > 0 {
					// Get everything from [ to end of meaningful content
					secretPart := line[startIdx:]
					// Remove trailing explanations (after " –" or " -")
					if dashIdx := strings.Index(secretPart, " –"); dashIdx > 0 {
						secretPart = secretPart[:dashIdx]
					}
					if dashIdx := strings.Index(secretPart, " -"); dashIdx > 0 {
						secretPart = secretPart[:dashIdx]
					}
					secretPart = strings.TrimSpace(secretPart)
					if secretPart != "" && strings.HasPrefix(secretPart, "[") {
						realSecrets = append(realSecrets, secretPart)
					}
				}
			}
		}
	}

	// If AI returned nothing valid but we had input, something went wrong
	// Return original secrets (fail-safe: better false positives than miss real ones)
	if len(realSecrets) == 0 && len(potentialSecrets) > 0 {
		// Check if response contains "NONE" anywhere - that's a valid empty result
		if !strings.Contains(strings.ToUpper(response), "NONE") {
			return potentialSecrets, nil
		}
	}

	return realSecrets, nil
}

// query sends a request to Ollama API
func (c *OllamaClient) query(model, prompt string, timeout time.Duration) (string, error) {
	reqBody := OllamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
		Options: map[string]interface{}{
			"temperature": 0.3, // Low temperature for more focused responses
			"top_p":       0.9,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(
		c.BaseURL+"/api/generate",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	return strings.TrimSpace(ollamaResp.Response), nil
}

// parseFindings extracts findings by severity from AI response
func parseFindings(response, findingType, model string, duration time.Duration) *AnalysisResult {
	result := &AnalysisResult{
		Type:     findingType,
		Severity: "info",
		Findings: []string{},
		Model:    model,
		Duration: duration,
	}

	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse severity-prefixed findings
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "CRITICAL:") {
			result.Severity = "critical"
			result.Findings = append(result.Findings, strings.TrimPrefix(line, "CRITICAL:"))
		} else if strings.HasPrefix(upper, "HIGH:") {
			if result.Severity != "critical" {
				result.Severity = "high"
			}
			result.Findings = append(result.Findings, strings.TrimPrefix(line, "HIGH:"))
		} else if strings.HasPrefix(upper, "MEDIUM:") {
			if result.Severity != "critical" && result.Severity != "high" {
				result.Severity = "medium"
			}
			result.Findings = append(result.Findings, strings.TrimPrefix(line, "MEDIUM:"))
		} else if strings.HasPrefix(upper, "LOW:") {
			if result.Severity == "info" {
				result.Severity = "low"
			}
			result.Findings = append(result.Findings, strings.TrimPrefix(line, "LOW:"))
		} else if strings.HasPrefix(upper, "INFO:") {
			result.Findings = append(result.Findings, strings.TrimPrefix(line, "INFO:"))
		} else if len(line) > 0 && !strings.HasPrefix(line, "#") {
			// Non-prefixed findings
			result.Findings = append(result.Findings, line)
		}
	}

	// Clean up findings
	for i := range result.Findings {
		result.Findings[i] = strings.TrimSpace(result.Findings[i])
	}

	return result
}

// queryWithTools sends a request to Ollama API with function calling support
func (c *OllamaClient) queryWithTools(model, prompt string, timeout time.Duration) (string, error) {
	tools := GetAvailableTools()

	reqBody := OllamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
		Tools:  tools,
		Options: map[string]interface{}{
			"temperature": 0.3,
			"top_p":       0.9,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(
		c.BaseURL+"/api/generate",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	// Check if AI requested tool calls
	if len(ollamaResp.ToolCalls) > 0 {
		// Execute tool calls and get results
		toolResults := make(map[string]string)
		for _, toolCall := range ollamaResp.ToolCalls {
			result, err := ExecuteTool(toolCall)
			if err != nil {
				toolResults[toolCall.Function.Name] = fmt.Sprintf("Error: %v", err)
			} else {
				toolResults[toolCall.Function.Name] = result
			}
		}

		// Build a clear follow-up prompt with context
		followUpPrompt := fmt.Sprintf(`You previously asked to use tools to answer this question:
"%s"

Here are the results from the tools you requested:

%s

Now, based on these SPECIFIC results above, provide a detailed security analysis. Use the actual CVE data provided, including CVE IDs, severity scores, and descriptions. Do NOT say you don't have information - the data is RIGHT ABOVE.`, prompt, formatToolResults(toolResults))

		return c.query(model, followUpPrompt, timeout)
	}

	return strings.TrimSpace(ollamaResp.Response), nil
}

// formatToolResults formats tool execution results for the AI
func formatToolResults(results map[string]string) string {
	var formatted strings.Builder
	for tool, result := range results {
		formatted.WriteString(fmt.Sprintf("\n=== %s ===\n%s\n", tool, result))
	}
	return formatted.String()
}

// truncate limits string length for prompts
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n...(truncated)"
}
