# God's Eye - AI Integration Examples

## 🎯 Real-World Usage Examples

### Example 1: Bug Bounty Recon

```bash
# Initial reconnaissance with AI analysis
./god-eye -d target.com --enable-ai -o recon.json -f json

# Filter high-severity AI findings
cat recon.json | jq '.[] | select(.ai_severity == "critical" or .ai_severity == "high")'

# Extract subdomains with CVEs
cat recon.json | jq '.[] | select(.cve_findings | length > 0)'

# Get AI-detected admin panels
cat recon.json | jq '.[] | select(.admin_panels | length > 0)'
```

### Example 2: Pentesting Workflow

```bash
# Fast scan for initial scope
./god-eye -d client.com --enable-ai --no-brute --active

# Deep analysis on interesting findings
./god-eye -d client.com --enable-ai --ai-deep -c 500

# Generate report for client
./god-eye -d client.com --enable-ai -o client_report.txt
```

### Example 3: Security Audit

```bash
# Comprehensive audit with all checks
./god-eye -d company.com --enable-ai

# Focus on specific issues
./god-eye -d company.com --enable-ai --active | grep -E "AI:CRITICAL|CVE"

# Export for further analysis
./god-eye -d company.com --enable-ai -o audit.csv -f csv
```

### Example 4: Quick Triage

```bash
# Super fast scan (no brute-force, cascade enabled)
time ./god-eye -d target.com --enable-ai --no-brute

# Should complete in ~30-60 seconds for small targets
```

### Example 5: Development Environment Check

```bash
# Find exposed dev/staging environments
./god-eye -d company.com --enable-ai | grep -E "dev|staging|test"

# AI will identify debug mode, error messages, etc.
```

---

## 📊 Expected Output Examples

### Without AI

```
═══════════════════════════════════════════════════
● api.example.com [200] ⚡156ms
    IP: 93.184.216.34
    Tech: nginx, React
    FOUND: Admin: /admin [200]
    JS SECRET: api_key: "sk_test_123..."
═══════════════════════════════════════════════════
```

### With AI Enabled

```
═══════════════════════════════════════════════════
● api.example.com [200] ⚡156ms
    IP: 93.184.216.34
    Tech: nginx, React
    FOUND: Admin: /admin [200]
    JS SECRET: api_key: "sk_test_123..."
    AI:CRITICAL: Hardcoded Stripe test API key exposed in main.js
                 Authentication bypass possible via admin parameter
                 React version 16.8.0 has known XSS vulnerability
                 Missing rate limiting on /api/v1/users endpoint
                 (1 more findings...)
                 model: phi3.5:3.8b→qwen2.5-coder:7b
    CVE: React: CVE-2020-15168 - XSS vulnerability in development mode
═══════════════════════════════════════════════════
```

### AI Report Section

```
🧠 AI-POWERED ANALYSIS (cascade: phi3.5:3.8b + qwen2.5-coder:7b)
   Analyzing findings with local LLM

   AI:C  api.example.com → 4 findings
   AI:H  admin.example.com → 2 findings
   AI:H  dev.example.com → 3 findings
   AI:M  staging.example.com → 5 findings

   ✓ AI analysis complete: 14 findings across 4 subdomains

📋 AI SECURITY REPORT

## Executive Summary
Analysis identified 14 security findings across 4 subdomains, with 1 critical
and 2 high-severity issues requiring immediate attention. Key concerns include
hardcoded credentials and exposed development environments.

## Critical Findings

[CRITICAL] api.example.com:
  - Hardcoded Stripe API key in main.js (test key exposed)
  - Authentication bypass via admin parameter
  - React XSS vulnerability (CVE-2020-15168)
  CVEs:
    - React: CVE-2020-15168

[HIGH] admin.example.com:
  - Basic auth with default credentials detected
  - Directory listing enabled on /uploads/

[HIGH] dev.example.com:
  - Django debug mode enabled with stack traces
  - Source code exposure via .git directory
  - Database connection string in error messages

## Recommendations
1. IMMEDIATE: Remove hardcoded API keys and rotate credentials
2. IMMEDIATE: Disable debug mode in production environments
3. IMMEDIATE: Remove exposed .git directory
4. HIGH: Update React to latest stable version
5. HIGH: Implement proper authentication on admin panel
6. MEDIUM: Disable directory listing on sensitive paths
7. MEDIUM: Configure proper error handling to prevent information disclosure
```

---

## 🎭 Scenario-Based Examples

### Scenario 1: Found a Suspicious Subdomain

```bash
# Initial scan found dev.target.com
# Let AI analyze it in detail

./god-eye -d target.com --enable-ai --ai-deep

# AI might find:
# - Debug mode enabled
# - Test credentials in source
# - Exposed API documentation
# - Missing security headers
```

### Scenario 2: JavaScript Heavy Application

```bash
# SPA with lots of JavaScript
./god-eye -d webapp.com --enable-ai

# AI excels at:
# ✓ Analyzing minified/obfuscated code
# ✓ Finding hidden API endpoints
# ✓ Detecting auth bypass logic
# ✓ Identifying client-side security issues
```

### Scenario 3: API-First Platform

```bash
# Multiple API subdomains
./god-eye -d api-platform.com --enable-ai --ai-deep

# AI will identify:
# ✓ API version mismatches
# ✓ Unprotected endpoints
# ✓ CORS issues
# ✓ Rate limiting problems
```

### Scenario 4: Legacy Application

```bash
# Old PHP/WordPress site
./god-eye -d old-site.com --enable-ai

# AI checks for:
# ✓ Known CVEs in detected versions
# ✓ Common WordPress vulns
# ✓ Outdated library versions
# ✓ Exposed backup files
```

---

## 💡 Pro Tips

### Tip 1: Combine with Other Tools

```bash
# God's Eye → Nuclei pipeline
./god-eye -d target.com --enable-ai --active -s | nuclei -t cves/

# God's Eye → httpx pipeline
./god-eye -d target.com --enable-ai -s | httpx -tech-detect

# God's Eye → Custom script
./god-eye -d target.com --enable-ai -o scan.json -f json
python analyze.py scan.json
```

### Tip 2: Incremental Scans

```bash
# Day 1: Initial recon
./god-eye -d target.com --enable-ai -o day1.json -f json

# Day 2: Update scan
./god-eye -d target.com --enable-ai -o day2.json -f json

# Compare findings
diff <(jq '.[] | .subdomain' day1.json) <(jq '.[] | .subdomain' day2.json)
```

### Tip 3: Filter by AI Severity

```bash
# Only show critical findings
./god-eye -d target.com --enable-ai -o scan.json -f json
cat scan.json | jq '.[] | select(.ai_severity == "critical")'

# Count findings by severity
cat scan.json | jq -r '.[] | .ai_severity' | sort | uniq -c
```

### Tip 4: Custom Wordlist with AI

```bash
# AI can help identify naming patterns
# First run to learn patterns
./god-eye -d target.com --enable-ai --no-brute

# AI identifies pattern: api-v1, api-v2, api-v3
# Create custom wordlist:
echo -e "api-v4\napi-v5\napi-staging\napi-prod" > custom.txt

# Second run with custom wordlist
./god-eye -d target.com --enable-ai -w custom.txt
```

### Tip 5: Monitoring Setup

```bash
#!/bin/bash
# monitor-target.sh - Daily AI-powered monitoring

TARGET="target.com"
DATE=$(date +%Y%m%d)
OUTPUT="scans/${TARGET}_${DATE}.json"

./god-eye -d $TARGET --enable-ai --active -o $OUTPUT -f json

# Alert on new critical findings
CRITICAL=$(cat $OUTPUT | jq '.[] | select(.ai_severity == "critical")' | wc -l)
if [ $CRITICAL -gt 0 ]; then
    echo "ALERT: $CRITICAL critical findings for $TARGET"
    cat $OUTPUT | jq '.[] | select(.ai_severity == "critical")'
fi
```

---

## 🧪 Testing AI Features

### Test 1: Verify AI is Working

```bash
# Should show AI analysis section
./god-eye -d example.com --enable-ai --no-brute -v

# Look for:
# ✓ "🧠 AI-POWERED ANALYSIS"
# ✓ Model names in output
# ✓ AI findings if vulnerabilities detected
```

### Test 2: Compare AI vs No-AI

```bash
# Without AI
time ./god-eye -d target.com --no-brute -o noai.json -f json

# With AI
time ./god-eye -d target.com --no-brute --enable-ai -o ai.json -f json

# Compare
echo "Findings without AI: $(cat noai.json | jq length)"
echo "Findings with AI: $(cat ai.json | jq length)"
echo "New AI findings: $(cat ai.json | jq '[.[] | select(.ai_findings != null)] | length')"
```

### Test 3: Benchmark Different Modes

```bash
# Cascade (default)
time ./god-eye -d target.com --enable-ai --no-brute

# No cascade
time ./god-eye -d target.com --enable-ai --ai-cascade=false --no-brute

# Deep mode
time ./god-eye -d target.com --enable-ai --ai-deep --no-brute
```

---

## 📈 Performance Optimization

### For Large Targets (>100 subdomains)

```bash
# Reduce concurrency to avoid overwhelming Ollama
./god-eye -d large-target.com --enable-ai -c 500

# Use fast model only (skip deep analysis)
./god-eye -d large-target.com --enable-ai --ai-cascade=false \
  --ai-deep-model phi3.5:3.8b

# Disable AI for initial enumeration, enable for interesting findings
./god-eye -d large-target.com --no-brute -s > subdomains.txt
cat subdomains.txt | head -20 | while read sub; do
    ./god-eye -d $sub --enable-ai --no-brute
done
```

### For GPU Acceleration

```bash
# Ollama automatically uses GPU if available
# Check GPU usage:
nvidia-smi  # Linux/Windows with NVIDIA
ollama ps   # Should show GPU model

# With GPU, you can use larger models:
./god-eye -d target.com --enable-ai \
  --ai-deep-model deepseek-coder-v2:16b
```

---

## 🎓 Learning from AI Output

### Example: Understanding AI Findings

**Input:** JavaScript code with potential issue
```javascript
const API_KEY = "sk_live_51H...";
fetch(`/api/user/${userId}`);
```

**AI Output:**
```
AI:CRITICAL: Hardcoded production API key detected
             Unsanitized user input in URL parameter
             Missing authentication on API endpoint
```

**What to Do:**
1. Verify the API key is active
2. Test the userId parameter for injection
3. Check if /api/user requires authentication
4. Report to bug bounty program or client

---

**Happy Hunting with AI! 🎯🧠**
