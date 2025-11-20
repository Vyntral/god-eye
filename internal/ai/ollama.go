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
	FastModel   string // phi3.5:3.8b for quick triage
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
		fastModel = "phi3.5:3.8b"
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
	prompt := fmt.Sprintf(`Create a concise security assessment report:

SCAN STATISTICS:
- Total subdomains: %d
- Active: %d
- Vulnerabilities: %d
- Takeovers: %d

KEY FINDINGS:
%s

Generate report with:
## Executive Summary (2-3 sentences)
## Critical Findings (prioritized list)
## Recommendations (actionable items)

Be concise and professional.`,
		stats["total"], stats["active"], stats["vulns"], stats["takeovers"], truncate(findings, 3000))

	response, err := c.query(c.DeepModel, prompt, 45*time.Second)
	if err != nil {
		return "", err
	}

	return response, nil
}

// CVEMatch checks for known vulnerabilities in detected technologies using function calling
func (c *OllamaClient) CVEMatch(technology, version string) (string, error) {
	prompt := fmt.Sprintf(`Check if %s version %s has known CVE vulnerabilities. Use the search_cve tool to look up real CVE data from the NVD database.

After getting CVE results, analyze them and provide:
1. Summary of findings
2. Severity assessment
3. Specific recommendations

If version is unknown, still search using just the technology name.`, technology, version)

	// Use function calling with tools
	response, err := c.queryWithTools(c.DeepModel, prompt, 30*time.Second)
	if err != nil {
		return "", err
	}

	if strings.Contains(strings.ToLower(response), "no known cve") {
		return "", nil
	}

	return response, nil
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

		// Send tool results back to AI for final analysis
		followUpPrompt := fmt.Sprintf(`%s

Tool Results:
%s

Based on these results, provide your analysis.`, prompt, formatToolResults(toolResults))

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
