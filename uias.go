// uias.go
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

// 常量定义
const (
	defaultTimeout         = 10 * time.Second
	defaultCheckActionPath = "/v1/uias/action/check"
	defaultVerifyTokenPath = "/v1/uias/verify/token"
	defaultTokenPath       = "/v1/uias/auth/token"
	maxBodySize            = 10 << 20 // 10MB
	maxBodyLogSize         = 500
	xRequestIdKey          = "X-Request-Id"
	xAuthTokenKey          = "X-Auth-Token"
	xSubjectTokenKey       = "X-Subject-Token"
	contentTypeJSON        = "application/json; charset=utf-8"
)

// 成功状态码
var successStatusCodes = map[int]bool{
	http.StatusOK:      true, // 200
	http.StatusCreated: true, // 201
}

// 错误类型定义
var (
	ErrInvalidEndpoint    = errors.New("endpoint is required and must be a valid URL")
	ErrRequestFailed      = errors.New("request failed")
	ErrInvalidResponse    = errors.New("invalid response from server")
	ErrPermissionDenied   = errors.New("permission denied")
	ErrInvalidCACert      = errors.New("invalid CA certificate")
	ErrRequestTimeout     = errors.New("request timeout")
	ErrAuthNotConfigured  = errors.New("authentication not configured")
	ErrResponseTooLarge   = errors.New("response body exceeds size limit")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// UIASError 自定义错误类型
type UIASError struct {
	Code     string
	Message  string
	Original error
}

func (e *UIASError) Error() string {
	if e.Original != nil {
		return fmt.Sprintf("UIAS error [%s]: %s (caused by: %v)", e.Code, e.Message, e.Original)
	}
	return fmt.Sprintf("UIAS error [%s]: %s", e.Code, e.Message)
}

func (e *UIASError) Unwrap() error {
	return e.Original
}

// RespCheckActionData 包含令牌验证成功后返回的数据
type RespCheckActionData struct {
	Metadata struct {
		Message string `json:"message"`
		Time    int64  `json:"time"`
		Ecode   string `json:"ecode"`
	} `json:"metadata"`
	Payload struct {
		Authentication int    `json:"authentication"` // 1:有效;0:无效
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

// RespVerifyTokenData 包含令牌验证成功后返回的数据
type RespVerifyTokenData struct {
	Metadata struct {
		Message string `json:"message"`
		Time    int64  `json:"time"`
		Ecode   string `json:"ecode"`
	} `json:"metadata"`
	Payload struct {
		Token struct {
			Valid     int    `json:"valid"` // 1:有效;0:无效
			IssuedAt  string `json:"issued_at"`
			ExpiresAt string `json:"expires_at"`
		} `json:"token"`
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

// RespDataToken 包含令牌创建成功后返回的数据
type RespDataToken struct {
	Metadata struct {
		Message string `json:"message"`
		Time    int64  `json:"time"`
		Ecode   string `json:"ecode"`
	} `json:"metadata"`
	Payload struct {
		Token struct {
			IssuedAt  string `json:"issued_at"`
			ExpiresAt string `json:"expires_at"`
			User      struct {
				Domain struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"domain"`
				ID   string `json:"id"`
				Name struct {
					Account string `json:"account"`
				} `json:"name"`
			} `json:"user"`
			Roles []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"roles"`
		} `json:"token"`
	} `json:"payload"`
}

// RespToken 令牌响应
type RespToken struct {
	Token string
	Body  RespDataToken
}

// Config 包含客户端配置参数
type Config struct {
	Endpoint        string        // 服务端点 (例如: "https://api.example.com")
	UrlPath         string        // 用于请求的API路径
	SkipTlsVerify   bool          // 是否跳过TLS验证 (默认: false)
	CACertPath      string        // CA证书文件路径
	Timeout         time.Duration // 请求超时时间 (默认: 10秒)
	MaxIdleConns    int           // 最大空闲连接数
	IdleConnTimeout time.Duration // 空闲连接超时时间
}

// AuthConfig 认证配置
type AuthConfig struct {
	Ak string
	Sk string
}

// Auth 认证信息
type Auth struct {
	config AuthConfig
}

// Response 封装HTTP请求的结果
type Response struct {
	StatusCode int         // 例如 200
	Body       []byte      // 响应体内容
	Header     http.Header // 响应头
}

// Logger 日志接口
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// DefaultLogger 默认日志实现
type DefaultLogger struct{}

func (l *DefaultLogger) Debugf(format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format, args...)
}

func (l *DefaultLogger) Infof(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func (l *DefaultLogger) Warnf(format string, args ...interface{}) {
	log.Printf("[WARN] "+format, args...)
}

func (l *DefaultLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

// Metrics 指标接口
type Metrics interface {
	IncRequestCounter(method, path string, statusCode int)
	ObserveRequestDuration(method, path string, duration time.Duration)
}

// NoopMetrics 空指标实现
type NoopMetrics struct{}

func (m *NoopMetrics) IncRequestCounter(method, path string, statusCode int)              {}
func (m *NoopMetrics) ObserveRequestDuration(method, path string, duration time.Duration) {}

// UIASClient UIAS客户端接口
type UIASClient interface {
	VerifyAction(ctx context.Context, requestId, token string, rawBody []byte) (*RespCheckActionData, error)
	CreateToken(ctx context.Context, requestId string) (*RespToken, error)
	VerifyToken(ctx context.Context, requestId, token string) (*RespCheckActionData, error)
	Close()
}

// Client 表示UIAS服务客户端
type Client struct {
	auth       *Auth
	config     Config
	httpClient *http.Client
	logger     Logger
	metrics    Metrics
}

// ClientOption 客户端选项函数
type ClientOption func(*Client)

// CredentialBuilder 凭证构建器
type CredentialBuilder struct {
	config AuthConfig
}

// ClientBuilder 客户端构建器
type ClientBuilder struct {
	config Config
	auth   *Auth
}

// 包装错误信息
func wrapError(err error, message string) error {
	if err == nil {
		return errors.New(message)
	}
	return fmt.Errorf("%s: %w", message, err)
}

// 过滤敏感字段
func filterSensitiveFields(data map[string]interface{}) {
	sensitiveFields := []string{"password", "secret", "token", "key", "sk", "ak"}
	for _, field := range sensitiveFields {
		if _, exists := data[field]; exists {
			data[field] = "***REDACTED***"
		}
	}
}

// 清理日志中的敏感信息
func sanitizeBodyForLog(body []byte) string {
	if len(body) > maxBodyLogSize {
		body = body[:maxBodyLogSize]
	}

	// 尝试解析JSON并过滤敏感字段
	var jsonData map[string]interface{}
	if err := json.Unmarshal(body, &jsonData); err == nil {
		filterSensitiveFields(jsonData)
		sanitized, _ := json.Marshal(jsonData)
		return string(sanitized)
	}

	// 非JSON数据，直接返回截断内容
	return string(body) + "..."
}

// NewCredentialBuilder 创建新的凭证构建器
func NewCredentialBuilder() *CredentialBuilder {
	return &CredentialBuilder{
		config: AuthConfig{},
	}
}

// WithAk 设置AK
func (b *CredentialBuilder) WithAk(ak string) *CredentialBuilder {
	b.config.Ak = ak
	return b
}

// WithSk 设置SK
func (b *CredentialBuilder) WithSk(sk string) *CredentialBuilder {
	b.config.Sk = sk
	return b
}

// Build 构建认证信息
func (b *CredentialBuilder) Build() *Auth {
	if b.config.Ak == "" || b.config.Sk == "" {
		panic("ak or sk cannot be empty")
	}

	return &Auth{config: b.config}
}

// NewClientBuilder 创建新的客户端构建器
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

// WithEndpoint 设置服务端点
func (b *ClientBuilder) WithEndpoint(endpoint string) *ClientBuilder {
	b.config.Endpoint = endpoint
	return b
}

// WithUrlPath 设置请求路径
func (b *ClientBuilder) WithUrlPath(path string) *ClientBuilder {
	b.config.UrlPath = path
	return b
}

// WithCredential 设置认证信息
func (b *ClientBuilder) WithCredential(auth *Auth) *ClientBuilder {
	if auth != nil {
		b.auth = auth
	}
	return b
}

// WithSkipTlsVerify 设置是否跳过TLS验证
func (b *ClientBuilder) WithSkipTlsVerify(skip bool) *ClientBuilder {
	b.config.SkipTlsVerify = skip
	return b
}

// WithCACertPath 设置CA证书路径
func (b *ClientBuilder) WithCACertPath(path string) *ClientBuilder {
	b.config.CACertPath = path
	return b
}

// WithTimeout 设置请求超时时间
func (b *ClientBuilder) WithTimeout(timeout time.Duration) *ClientBuilder {
	b.config.Timeout = timeout
	return b
}

// WithConnectionPool 设置连接池参数
func (b *ClientBuilder) WithConnectionPool(maxIdleConns int, idleTimeout time.Duration) *ClientBuilder {
	b.config.MaxIdleConns = maxIdleConns
	b.config.IdleConnTimeout = idleTimeout
	return b
}

// Build 构建客户端实例
func (b *ClientBuilder) Build() *Client {
	client, err := SafeBuild(b.config, b.auth)
	if err != nil {
		panic(err)
	}
	return client
}

// SafeBuild 创建新的客户端
func SafeBuild(config Config, auth *Auth, opts ...ClientOption) (*Client, error) {
	if config.Endpoint == "" {
		return nil, ErrInvalidEndpoint
	}

	httpClient, err := createHttpClient(config.SkipTlsVerify, config.CACertPath, config.MaxIdleConns, config.IdleConnTimeout)
	if err != nil {
		return nil, wrapError(err, "failed to create http client")
	}

	httpClient.Timeout = config.Timeout

	client := &Client{
		auth:       auth,
		config:     config,
		httpClient: httpClient,
		logger:     &DefaultLogger{},
		metrics:    &NoopMetrics{},
	}

	// 应用选项
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// WithLogger 设置日志器
func WithLogger(logger Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithMetrics 设置指标收集器
func WithMetrics(metrics Metrics) ClientOption {
	return func(c *Client) {
		c.metrics = metrics
	}
}

// 创建TLS配置
func createTLSConfig(skipTlsVerify bool, caCertPath string) (*tls.Config, error) {
	if skipTlsVerify {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	if caCertPath != "" {
		// 加载CA证书
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, wrapError(err, "failed to read CA certificate")
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, ErrInvalidCACert
		}
		config.RootCAs = caCertPool
	}

	return config, nil
}

// 创建HTTP客户端
func createHttpClient(skipTlsVerify bool, caCertPath string, maxIdleConns int, idleConnTimeout time.Duration) (*http.Client, error) {
	// 创建TLS配置
	tlsConfig, err := createTLSConfig(skipTlsVerify, caCertPath)
	if err != nil {
		return nil, err
	}

	// 创建传输层配置
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
		TLSClientConfig:       tlsConfig,
	}

	return &http.Client{Transport: transport}, nil
}

// 发送HTTP请求
func sendHttpRequest(
	ctx context.Context,
	client *http.Client,
	method, url string,
	body []byte,
	headers map[string]string,
) (*Response, error) {
	// 创建请求
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, wrapError(err, "failed to create request")
	}

	// 设置请求头
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// 执行请求
	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	// 记录指标
	if metrics, ok := client.Transport.(interface {
		ObserveRequestDuration(method, url string, duration time.Duration)
	}); ok {
		metrics.ObserveRequestDuration(method, url, duration)
	}

	if err != nil {
		// 检查是否为超时错误
		if os.IsTimeout(err) {
			return nil, ErrRequestTimeout
		}
		return nil, wrapError(ErrRequestFailed, err.Error())
	}
	defer resp.Body.Close()

	// 记录请求状态指标
	if metrics, ok := client.Transport.(interface {
		IncRequestCounter(method, url string, statusCode int)
	}); ok {
		metrics.IncRequestCounter(method, url, resp.StatusCode)
	}

	// 读取响应体
	limitedReader := &io.LimitedReader{R: resp.Body, N: maxBodySize}
	responseBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, wrapError(ErrInvalidResponse, "failed to read response body")
	}

	// 检查是否超过大小限制
	if limitedReader.N <= 0 {
		return nil, ErrResponseTooLarge
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       responseBody,
		Header:     resp.Header,
	}, nil
}

// 执行请求
func (c *Client) doRequest(ctx context.Context, method, path string, body []byte, headers map[string]string) (*Response, error) {
	url := c.config.Endpoint + path
	c.logger.Debugf("Making request: %s %s", method, url)

	response, err := sendHttpRequest(ctx, c.httpClient, method, url, body, headers)
	if err != nil {
		c.logger.Errorf("Request failed: %s %s: %v", method, url, err)
		return nil, err
	}

	c.logger.Debugf("Response status: %d %s", response.StatusCode, http.StatusText(response.StatusCode))
	return response, nil
}

// 检查状态码是否为成功状态码
func isSuccessStatusCode(statusCode int) bool {
	return successStatusCodes[statusCode]
}

// 处理错误响应
func (c *Client) handleErrorResponse(response *Response) error {
	// 尝试解析错误响应为JSON
	var errorResp struct {
		Metadata struct {
			Message string `json:"message"`
			Ecode   string `json:"ecode"`
		} `json:"metadata"`
	}

	if jsonErr := json.Unmarshal(response.Body, &errorResp); jsonErr == nil {
		return &UIASError{
			Code:     errorResp.Metadata.Ecode,
			Message:  errorResp.Metadata.Message,
			Original: fmt.Errorf("UIAS returned error status: %d", response.StatusCode),
		}
	}

	// 如果不是JSON，返回原始响应体进行调试
	bodyStr := sanitizeBodyForLog(response.Body)
	return &UIASError{
		Code:     "UNKNOWN",
		Message:  fmt.Sprintf("UIAS returned error status: %d, response: %s", response.StatusCode, bodyStr),
		Original: ErrRequestFailed,
	}
}

// 解析响应
func (c *Client) parseResponse(response *Response, result interface{}) error {
	if !isSuccessStatusCode(response.StatusCode) {
		return c.handleErrorResponse(response)
	}

	if err := json.Unmarshal(response.Body, result); err != nil {
		c.logger.Errorf("Invalid JSON response: %s", sanitizeBodyForLog(response.Body))
		return wrapError(ErrInvalidResponse, "failed to parse response")
	}

	return nil
}

// VerifyAction 验证操作权限
func (c *Client) VerifyAction(ctx context.Context, requestId, token string, rawBody []byte) (*RespCheckActionData, error) {
	// 构建请求头
	headers := map[string]string{
		"Content-Type": contentTypeJSON,
		xRequestIdKey:  requestId,
		xAuthTokenKey:  token,
	}

	// 发送请求
	response, err := c.doRequest(ctx, "POST", c.config.UrlPath, rawBody, headers)
	if err != nil {
		return nil, err
	}

	// 解析响应
	var respData RespCheckActionData
	if err := c.parseResponse(response, &respData); err != nil {
		return nil, err
	}

	return &respData, nil
}

// 构建令牌请求
func (c *Client) buildTokenRequest() ([]byte, error) {
	type rawReq struct {
		Auth struct {
			Credential struct {
				ID     string `json:"id"`
				Secret string `json:"secret"`
			} `json:"credential"`
		} `json:"auth"`
	}

	var raw rawReq
	raw.Auth.Credential.ID = c.auth.config.Ak
	raw.Auth.Credential.Secret = c.auth.config.Sk

	rawBody, err := json.Marshal(raw)
	if err != nil {
		return nil, wrapError(err, "failed to marshal token request")
	}

	return rawBody, nil
}

// CreateToken 创建令牌
func (c *Client) CreateToken(ctx context.Context, requestId string) (*RespToken, error) {
	if c.auth == nil {
		return nil, ErrAuthNotConfigured
	}

	// 构建请求头
	headers := map[string]string{
		"Content-Type": contentTypeJSON,
		xRequestIdKey:  requestId,
	}

	// 构建请求体
	requestBody, err := c.buildTokenRequest()
	if err != nil {
		return nil, err
	}

	// 发送请求
	response, err := c.doRequest(ctx, "POST", defaultTokenPath, requestBody, headers)
	if err != nil {
		return nil, err
	}

	// 解析响应 - 注意：CreateToken 期望 201 状态码
	if !isSuccessStatusCode(response.StatusCode) {
		return nil, c.handleErrorResponse(response)
	}

	var respData RespDataToken
	if err := json.Unmarshal(response.Body, &respData); err != nil {
		c.logger.Errorf("Invalid JSON response: %s", sanitizeBodyForLog(response.Body))
		return nil, wrapError(ErrInvalidResponse, "failed to parse response")
	}

	token := response.Header.Get(xSubjectTokenKey)
	return &RespToken{Token: token, Body: respData}, nil
}

// VerifyToken 验证令牌
func (c *Client) VerifyToken(ctx context.Context, requestId, token string) (*RespVerifyTokenData, error) {
	// 构建请求头
	headers := map[string]string{
		"Content-Type": contentTypeJSON,
		xRequestIdKey:  requestId,
		xAuthTokenKey:  token,
	}

	// 发送请求
	response, err := c.doRequest(ctx, "POST", defaultVerifyTokenPath, nil, headers)
	if err != nil {
		return nil, err
	}

	// 解析响应
	var respData RespVerifyTokenData
	if err := c.parseResponse(response, &respData); err != nil {
		return nil, err
	}

	return &respData, nil
}

// Close 释放客户端持有的资源
func (c *Client) Close() {
	// 关闭空闲连接
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}
