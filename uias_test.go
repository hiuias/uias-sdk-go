package uias_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hiuias/uias-sdk-go"
)

func TestA(t *testing.T) {
	client, err := uias.NewClientBuilder().
		WithEndpoint("https://uias.apilocalvm.outsrkem.top:30078").
		WithTimeout(10 * time.Second).
		WithSkipTlsVerify(false).
		Build()

	if err != nil {
		fmt.Printf("Failed to create client: %v\n", err)
		return
	}

	// 验证Token
	ctx := context.Background()
	resp, err := client.VerifyAction(
		ctx,
		"request-12345",
		"",
		[]byte(`{"uias":{"action":"ledger:transaction:create"}}`),
	)
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
