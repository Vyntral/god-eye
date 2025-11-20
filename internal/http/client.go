package http

import (
	"crypto/tls"
	"net/http"
	"time"
)

// SharedTransport is a global shared HTTP transport for connection pooling
var SharedTransport = &http.Transport{
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 10,
	IdleConnTimeout:     30 * time.Second,
	DisableCompression:  true, // Keep Content-Length header for SPA detection
}

// GetSharedClient returns an HTTP client with connection pooling
func GetSharedClient(timeout int) *http.Client {
	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: SharedTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
