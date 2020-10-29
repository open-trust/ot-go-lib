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
const Version = "v0.9.0"

const headerAuthorization = "Authorization"
const authPrefix = "Bearer "

// DefaultHTTPClient ...
var DefaultHTTPClient = NewClient(nil)

// ExtractTokenFromHeader ...
func ExtractTokenFromHeader(h http.Header) string {
	token := h.Get(headerAuthorization)
	if strings.HasPrefix(token, authPrefix) {
		return token[7:]
	}
	return ""
}

// AddTokenToHeader ...
func AddTokenToHeader(h http.Header, token string) http.Header {
	if token != "" {
		h.Set(headerAuthorization, authPrefix+token)
	}
	return h
}

// SelectEndpoints ...
func SelectEndpoints(ctx context.Context, serviceEndpoints []string, cli HTTPClient) (string, error) {
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
			if strings.HasPrefix(url, "http") {
				if err := cli.Do(ctx, "GET", url, nil, nil, nil); err == nil {
					ch <- url
				}
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
