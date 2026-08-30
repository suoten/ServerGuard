package devops

import (
	"context"
	"net/http"
)

// newHTTPRequest 创建 HTTP 请求
func newHTTPRequest(ctx context.Context, method, url string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, method, url, nil)
}

// doHTTPRequest 执行 HTTP 请求
func doHTTPRequest(req *http.Request) error {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return &apiError{StatusCode: resp.StatusCode, Message: "server error"}
	}
	return nil
}

type apiError struct {
	StatusCode int
	Message   string
}

func (e *apiError) Error() string {
	return e.Message
}
