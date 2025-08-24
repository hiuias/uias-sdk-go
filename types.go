package uias

import (
	"net/http"
	"time"
)

// RespData 包含token验证成功后的返回数据
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

// Config 客户端配置参数
type Config struct {
	Endpoint      string        // 服务端点
	UrlPath       string        // api path
	SkipTlsVerify bool          // 是否忽略TLS验证，默认false
	CACertPath    string        // CA证书路径
	Timeout       time.Duration // 请求超时时间，默认5秒
}

// Client UIAS服务客户端
type Client struct {
	config     Config
	httpClient *http.Client
}

// ClientBuilder 客户端构建器
type ClientBuilder struct {
	config Config
}
