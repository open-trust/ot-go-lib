package otgo

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Version ...
const Version = "v0.8.0"

const headerAuthorization = "Authorization"
const authPrefix = "Bearer "

// DefaultHTTPClient ...
var DefaultHTTPClient = NewHTTPClient(nil)

// ExtractTokenFromHeader ...
func ExtractTokenFromHeader(h http.Header) string {
	token := h.Get(headerAuthorization)
	if strings.HasPrefix(token, authPrefix) {
		return token[7:]
	}
	return ""
}

// AddTokenToHeader ...
func AddTokenToHeader(h http.Header, token string) {
	if token != "" {
		h.Set(headerAuthorization, authPrefix+token)
	}
}

// SelectEndpoints ...
func SelectEndpoints(ctx context.Context, cli *HTTPClient, serviceEndpoints []string) (string, error) {
	if len(serviceEndpoints) == 0 {
		return "", errors.New("no service endpoints")
	}
	if cli == nil {
		cli = DefaultHTTPClient
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ch := make(chan string)
	i := int32(len(serviceEndpoints))
	for _, serviceEndpoint := range serviceEndpoints {
		go func(url string) {
			if err := cli.Get(ctx, url, nil); err == nil {
				ch <- url
			}
			if atomic.AddInt32(&i, -1) == 0 {
				cancel()
			}
		}(serviceEndpoint)
	}
	select {
	case url := <-ch:
		return url, nil
	case <-ctx.Done():
		return "", errors.New("no valid service endpoints")
	}
}
