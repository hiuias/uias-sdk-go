package uias

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	xRequestIdKey   = "X-Request-Id"
	xAuthTokenKey   = "X-Auth-Token"
	checkActionPath = "/v1/uias/action/check" // 权限校验路径
)

// NewClientBuilder 创建一个新的客户端构建器
func NewClientBuilder() *ClientBuilder {
	// 设置默认配置
	return &ClientBuilder{
		config: Config{
			Timeout:       5 * time.Second,
			SkipTlsVerify: false,
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

// WithSkipTlsVerify 设置是否忽略TLS验证
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

// Build 构建客户端实例
func (b *ClientBuilder) Build() (*Client, error) {
	// 验证必要配置
	if b.config.Endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	if b.config.UrlPath == "" {
		b.config.UrlPath = checkActionPath
	}

	// 创建HTTP客户端
	httpClient, err := createHttpClient(b.config.SkipTlsVerify, b.config.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create http client: %w", err)
	}

	// 设置超时
	httpClient.Timeout = b.config.Timeout
	return &Client{config: b.config, httpClient: httpClient}, nil
}

// VerifyToken 验证token并返回用户信息
func (c *Client) VerifyToken(ctx context.Context, requestId, token string, rawBody []byte) (*RespData, error) {
	// 构建请求头
	headers := map[string]string{
		"Content-Type": "application/json; charset=utf-8",
		xRequestIdKey:  requestId,
		xAuthTokenKey:  token,
	}

	// 构建请求URL
	url := c.config.Endpoint + c.config.UrlPath

	// 发送请求
	response, err := sendHttpRequest(ctx, c.httpClient, "POST", url, rawBody, headers, c.config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// 解析响应体
	var resp *RespData
	err = json.Unmarshal(response.Body, &resp)
	if err != nil {
		panic(err)
	}

	// 检查响应状态码
	if response.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	return resp, nil
}
