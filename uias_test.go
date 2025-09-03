package uias_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hiuias/uias-sdk-go"
)

var (
	endpoint  = ""
	ak        = ""
	sk        = ""
	token     = ""
	requestId = "request-12345"
)

func TestA(t *testing.T) {
	client := uias.NewClientBuilder().
		WithEndpoint(endpoint).
		WithTimeout(10 * time.Second).
		WithSkipTlsVerify(false).
		Build()

	// 验证Token
	ctx := context.Background()
	body := []byte(`{"uias":{"action":"ledger:transaction:create"}}`)
	resp, err := client.VerifyAction(ctx, requestId, token, body)
	if err != nil {
		fmt.Printf("========>Verification failed: %v\n", err)
	}

	// 将结构体转换为JSON
	jsonData, err := json.Marshal(resp)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 输出JSON字符串
	fmt.Printf("----->%s\n", string(jsonData))

}

// 创建token
func TestB(t *testing.T) {
	auth := uias.NewCredentialBuilder().
		WithAk(ak).
		WithSk(sk).
		Build()

	client := uias.NewClientBuilder().
		WithEndpoint(endpoint).
		WithTimeout(10 * time.Second).
		WithSkipTlsVerify(false).
		WithCredential(auth).
		Build()

	ctx := context.Background()
	res, err := client.CreateToken(ctx, requestId)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("token: ", res.Token)
}

