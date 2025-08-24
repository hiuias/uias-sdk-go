package uias_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hiuias/uias-sdk-go"
)

func TestA(t *testing.T) {
	client, err := uias.NewClientBuilder().
		WithEndpoint("https://uias.apilocalvm.outsrkem.top:30078").
		WithTimeout(10 * time.Second).WithUrlPath("/asd").
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
		[]byte(`{"uias":{"action":"snms:report:print"}}`),
	)

	fmt.Printf("----->%+v\n", resp)
	if err != nil {
		fmt.Printf("========>Verification failed: %v\n", err)
		return
	}

}
