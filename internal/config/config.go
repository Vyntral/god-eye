package config

import (
	"time"
)

// Config holds the scan configuration
type Config struct {
	Domain      string
	Wordlist    string
	Concurrency int
	Timeout     int
	Output      string
	Format      string
	Silent      bool
	Verbose     bool
	NoBrute    bool
	NoProbe    bool
	NoPorts    bool
	NoTakeover bool
	Resolvers   string
	Ports       string
	OnlyActive  bool
	JsonOutput  bool
	// AI Configuration
	EnableAI      bool
	AIUrl         string
	AIFastModel   string
	AIDeepModel   string
	AICascade     bool
	AIDeepAnalysis bool
}

// Stats holds scan statistics
type Stats struct {
	TotalFound    int32
	TotalResolved int32
	TotalActive   int32
	TakeoverFound int32
	StartTime     time.Time
}

// SubdomainResult holds all information about a subdomain
type SubdomainResult struct {
	Subdomain     string   `json:"subdomain"`
	IPs           []string `json:"ips,omitempty"`
	CNAME         string   `json:"cname,omitempty"`
	PTR           string   `json:"ptr,omitempty"`
	ASN           string   `json:"asn,omitempty"`
	Org           string   `json:"org,omitempty"`
	Country       string   `json:"country,omitempty"`
	City          string   `json:"city,omitempty"`
	StatusCode    int      `json:"status_code,omitempty"`
	ContentLength int64    `json:"content_length,omitempty"`
	RedirectURL   string   `json:"redirect_url,omitempty"`
	Title         string   `json:"title,omitempty"`
	Server        string   `json:"server,omitempty"`
	Tech          []string `json:"technologies,omitempty"`
	Headers       []string `json:"headers,omitempty"`
	WAF           string   `json:"waf,omitempty"`
	TLSVersion    string   `json:"tls_version,omitempty"`
	TLSIssuer     string   `json:"tls_issuer,omitempty"`
	TLSExpiry     string   `json:"tls_expiry,omitempty"`
	Ports         []int    `json:"ports,omitempty"`
	Takeover      string   `json:"takeover,omitempty"`
	ResponseMs    int64    `json:"response_ms,omitempty"`
	FaviconHash   string   `json:"favicon_hash,omitempty"`
	RobotsTxt     bool     `json:"robots_txt,omitempty"`
	SitemapXml    bool     `json:"sitemap_xml,omitempty"`
	MXRecords     []string `json:"mx_records,omitempty"`
	TXTRecords    []string `json:"txt_records,omitempty"`
	NSRecords     []string `json:"ns_records,omitempty"`
	// Security checks
	SecurityHeaders  []string `json:"security_headers,omitempty"`
	MissingHeaders   []string `json:"missing_headers,omitempty"`
	OpenRedirect     bool     `json:"open_redirect,omitempty"`
	CORSMisconfig    string   `json:"cors_misconfig,omitempty"`
	AllowedMethods   []string `json:"allowed_methods,omitempty"`
	DangerousMethods []string `json:"dangerous_methods,omitempty"`
	// Discovery checks
	AdminPanels  []string `json:"admin_panels,omitempty"`
	GitExposed   bool     `json:"git_exposed,omitempty"`
	SvnExposed   bool     `json:"svn_exposed,omitempty"`
	BackupFiles  []string `json:"backup_files,omitempty"`
	APIEndpoints []string `json:"api_endpoints,omitempty"`
	// Cloud and Email Security
	CloudProvider string   `json:"cloud_provider,omitempty"`
	S3Buckets     []string `json:"s3_buckets,omitempty"`
	SPFRecord     string   `json:"spf_record,omitempty"`
	DMARCRecord   string   `json:"dmarc_record,omitempty"`
	EmailSecurity string   `json:"email_security,omitempty"`
	TLSAltNames   []string `json:"tls_alt_names,omitempty"`
	// JavaScript Analysis
	JSFiles   []string `json:"js_files,omitempty"`
	JSSecrets []string `json:"js_secrets,omitempty"`
	// AI Analysis
	AIFindings     []string `json:"ai_findings,omitempty"`
	AISeverity     string   `json:"ai_severity,omitempty"`
	AIModel        string   `json:"ai_model,omitempty"`
	CVEFindings    []string `json:"cve_findings,omitempty"`
}

// IPInfo holds IP geolocation data
type IPInfo struct {
	ASN     string `json:"as"`
	Org     string `json:"org"`
	Country string `json:"country"`
	City    string `json:"city"`
}

// SourceResult holds passive source results
type SourceResult struct {
	Name string
	Subs []string
	Err  error
}

// Default values
var DefaultResolvers = []string{
	"8.8.8.8:53",
	"8.8.4.4:53",
	"1.1.1.1:53",
	"1.0.0.1:53",
	"9.9.9.9:53",
}

var DefaultWordlist = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
	"ns3", "ns4", "dns", "dns1", "dns2", "api", "dev", "staging", "prod",
	"admin", "administrator", "app", "apps", "auth", "beta", "blog", "cdn",
	"chat", "cloud", "cms", "cpanel", "dashboard", "db", "demo", "docs",
	"email", "forum", "git", "gitlab", "help", "home", "host", "img",
	"images", "imap", "internal", "intranet", "jenkins", "jira", "lab",
	"legacy", "login", "m", "mobile", "monitor", "mx", "mysql", "new",
	"news", "old", "panel", "portal", "preview", "private", "proxy", "remote",
	"server", "shop", "smtp", "sql", "ssh", "ssl", "stage", "staging",
	"static", "status", "store", "support", "test", "testing", "tools",
	"vpn", "web", "webmail", "wiki", "www1", "www2", "www3",
}
