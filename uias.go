package uias

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	defaultTimeout         = 10 * time.Second
	defaultCheckActionPath = "/v1/uias/action/check"
	xRequestIdKey          = "X-Request-Id"
	xAuthTokenKey          = "X-Auth-Token"
	contentTypeJSON        = "application/json; charset=utf-8"
)

// 定义错误类型
var (
	ErrInvalidEndpoint  = errors.New("endpoint is required and must be a valid URL")
	ErrRequestFailed    = errors.New("request failed")
	ErrInvalidResponse  = errors.New("invalid response from server")
	ErrPermissionDenied = errors.New("permission denied")
	ErrInvalidCACert    = errors.New("invalid CA certificate")
	ErrRequestTimeout   = errors.New("request timeout")
)

// RespData contains the returned data after successful token verification
type RespData struct {
	Metadata struct {
		Message string `json:"message"`
		Time    int64  `json:"time"`
		Ecode   string `json:"ecode"`
	} `json:"metadata"`
	Payload struct {
		Authentication int    `json:"authentication"`
		Error          string `json:"error"`
		Msg            struct {
			Action    string `json:"action"`
			Statement struct {
				Action string `json:"Action"`
				Effect string `json:"Effect"`
			} `json:"Statement"`
		} `json:"msg"`
		User struct {
			Domain struct {
				Id   string `json:"id"`
				Name string `json:"name"`
			} `json:"domain"`
			Id   string `json:"id"`
			Name struct {
				Account string `json:"account"`
			} `json:"name"`
		} `json:"user"`
	} `json:"payload"`
}

// Config contains client configuration parameters
type Config struct {
	Endpoint        string        // Service endpoint (e.g., "https://api.example.com")
	UrlPath         string        // API path to use for requests
	SkipTlsVerify   bool          // Whether to skip TLS verification (default: false)
	CACertPath      string        // Path to CA certificate file
	Timeout         time.Duration // Request timeout duration (default: 5 seconds)
	MaxIdleConns    int           // Maximum number of idle connections
	IdleConnTimeout time.Duration // Timeout for idle connections
}

// Client represents a UIAS service client
type Client struct {
	config     Config
	httpClient *http.Client
}

// ClientBuilder helps construct a Client with specific configurations
type ClientBuilder struct {
	config Config
}

// Response encapsulates the results of an HTTP request
type Response struct {
	StatusCode int         // e.g. 200
	Body       []byte      // Response body content
	Header     http.Header // Response headers
}

// NewClientBuilder creates a new client builder with default configuration
func NewClientBuilder() *ClientBuilder {
	return &ClientBuilder{
		config: Config{
			Timeout:         defaultTimeout,
			SkipTlsVerify:   false,
			UrlPath:         defaultCheckActionPath,
			MaxIdleConns:    100,
			IdleConnTimeout: 90 * time.Second,
		},
	}
}

// WithEndpoint sets the service endpoint
func (b *ClientBuilder) WithEndpoint(endpoint string) *ClientBuilder {
	b.config.Endpoint = endpoint
	return b
}

// WithUrlPath sets the request path
func (b *ClientBuilder) WithUrlPath(path string) *ClientBuilder {
	b.config.UrlPath = path
	return b
}

// WithSkipTlsVerify sets whether to skip TLS verification
func (b *ClientBuilder) WithSkipTlsVerify(skip bool) *ClientBuilder {
	b.config.SkipTlsVerify = skip
	return b
}

// WithCACertPath sets the CA certificate path
func (b *ClientBuilder) WithCACertPath(path string) *ClientBuilder {
	b.config.CACertPath = path
	return b
}

// WithTimeout sets the request timeout duration
func (b *ClientBuilder) WithTimeout(timeout time.Duration) *ClientBuilder {
	b.config.Timeout = timeout
	return b
}

// WithConnectionPool sets connection pool parameters
func (b *ClientBuilder) WithConnectionPool(maxIdleConns int, idleTimeout time.Duration) *ClientBuilder {
	b.config.MaxIdleConns = maxIdleConns
	b.config.IdleConnTimeout = idleTimeout
	return b
}

// Build constructs the client instance
func (b *ClientBuilder) Build() (*Client, error) {
	// Validate required configurations
	if b.config.Endpoint == "" {
		return nil, ErrInvalidEndpoint
	}

	// Create HTTP client with proper configuration
	httpClient, err := createHttpClient(
		b.config.SkipTlsVerify,
		b.config.CACertPath,
		b.config.MaxIdleConns,
		b.config.IdleConnTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create http client: %w", err)
	}

	// Set timeout
	httpClient.Timeout = b.config.Timeout

	return &Client{
		config:     b.config,
		httpClient: httpClient,
	}, nil
}

// createHttpClient initializes an HTTP client with connection pooling and TLS configuration
func createHttpClient(skipTlsVerify bool, caCertPath string, maxIdleConns int, idleConnTimeout time.Duration) (*http.Client, error) {
	// Create transport with connection pooling
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          maxIdleConns,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	// Configure TLS
	var tlsConfig *tls.Config
	switch {
	case caCertPath != "":
		// Load custom CA certificate
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read CA certificate: %v", ErrInvalidCACert, err)
		}

		// Create certificate pool
		caCertPool, _ := x509.SystemCertPool()
		if caCertPool == nil {
			caCertPool = x509.NewCertPool()
		}

		// Add custom CA certificate to the pool
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("%w: failed to parse CA certificate", ErrInvalidCACert)
		}

		tlsConfig = &tls.Config{
			RootCAs: caCertPool,
		}

		if skipTlsVerify {
			log.Printf("warning: skipTlsVerify=true is ignored when using custom CA: %s", caCertPath)
		}

	case skipTlsVerify:
		// Skip TLS verification (INSECURE - for testing only)
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{Transport: transport}, nil
}

// sendHttpRequest sends an HTTP request and handles the response safely
func sendHttpRequest(
	ctx context.Context,
	client *http.Client,
	method, url string,
	body []byte,
	headers map[string]string,
) (*Response, error) {
	// Create request with context
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Apply headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		// Check if it's a timeout error
		if os.IsTimeout(err) {
			return nil, ErrRequestTimeout
		}
		return nil, fmt.Errorf("%w: %v", ErrRequestFailed, err)
	}
	defer resp.Body.Close()

	// Read response body with limit to prevent excessive memory usage
	maxBodySize := int64(10 * 1024 * 1024) // 10MB limit
	limitedReader := &io.LimitedReader{R: resp.Body, N: maxBodySize}
	responseBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response body: %v", ErrInvalidResponse, err)
	}

	// Check if we hit the size limit
	if limitedReader.N <= 0 {
		return nil, fmt.Errorf("%w: response body exceeds size limit", ErrInvalidResponse)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       responseBody,
		Header:     resp.Header,
	}, nil
}

// VerifyAction verifies the action permission with enhanced error handling
func (c *Client) VerifyAction(ctx context.Context, requestId, token string, rawBody []byte) (*RespData, error) {
	// Build request headers
	headers := map[string]string{
		"Content-Type": contentTypeJSON,
		xRequestIdKey:  requestId,
		xAuthTokenKey:  token,
	}

	// Build request URL
	url := c.config.Endpoint + c.config.UrlPath

	// Send request with context
	response, err := sendHttpRequest(ctx, c.httpClient, "POST", url, rawBody, headers)
	if err != nil {
		return nil, fmt.Errorf("request to UIAS failed: %w", err)
	}

	// Check response status code first
	if response.StatusCode != http.StatusOK {
		// Try to parse error response as JSON
		var errorResp RespData
		if jsonErr := json.Unmarshal(response.Body, &errorResp); jsonErr == nil {
			return &errorResp, fmt.Errorf("UIAS returned error status: %d, message: %s",
				response.StatusCode, errorResp.Metadata.Message)
		}

		// If not JSON, return the raw response body for debugging
		bodyStr := string(response.Body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return nil, fmt.Errorf("UIAS returned error status: %d, response: %s",
			response.StatusCode, bodyStr)
	}

	// Parse response body
	var respData RespData
	if err := json.Unmarshal(response.Body, &respData); err != nil {
		// Log the invalid response for debugging
		bodyStr := string(response.Body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		log.Printf("Invalid JSON response from UIAS: %s", bodyStr)
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrInvalidResponse, err)
	}

	return &respData, nil
}

// Close releases any resources held by the client
func (c *Client) Close() {
	// Close idle connections if transport supports it
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}
