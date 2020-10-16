package otgo

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

// Version ...
const Version = "v0.7.0"

const headerAuthorization = "Authorization"
const authPrefix = "Bearer "

// Debugger ...
type Debugger interface {
	Debug(v interface{})
	Debugf(format string, args ...interface{})
}

// Debugging ...
var Debugging Debugger

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

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	DialContext: (&net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   20,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   3 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// HTTPClient ...
type HTTPClient struct {
	client *http.Client
	header http.Header
}

// NewHTTPClient ...
func NewHTTPClient(client *http.Client) *HTTPClient {
	if client == nil {
		client = &http.Client{
			Transport: tr,
			Timeout:   time.Second * 5,
		}
	}
	return &HTTPClient{client: client, header: http.Header{}}
}

// WithHeader ...
func (c *HTTPClient) WithHeader(header http.Header) *HTTPClient {
	hc := *c
	copyHeader(hc.header, header)
	return &hc
}

// WithToken ...
func (c *HTTPClient) WithToken(token string) *HTTPClient {
	h := http.Header{}
	AddTokenToHeader(h, token)
	return c.WithHeader(h)
}

// Get ...
func (c *HTTPClient) Get(ctx context.Context, url string, output interface{}) error {
	return c.Do(ctx, "GET", url, nil, nil, output)
}

// Post ...
func (c *HTTPClient) Post(ctx context.Context, url string, input, output interface{}) error {
	return c.Do(ctx, "POST", url, nil, input, output)
}

// Do ...
func (c *HTTPClient) Do(ctx context.Context, method, url string, header http.Header, input, output interface{}) error {
	err := ctx.Err()
	if err != nil {
		return fmt.Errorf("context.Context error: %v", err)
	}

	var b *bytes.Buffer
	if input != nil {
		b = new(bytes.Buffer)
		if err = json.NewEncoder(b).Encode(input); err != nil {
			return fmt.Errorf("encode input data error: %v", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, b)
	if err != nil {
		return fmt.Errorf("create http request error: %v", err)
	}

	copyHeader(req.Header, header)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("do http request error: %v", err)
	}

	defer resp.Body.Close()
	body := resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		body, err = gzip.NewReader(body)
		if err != nil {
			return fmt.Errorf("gzip reader error: %v", err)
		}
		defer body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		data, _ := ioutil.ReadAll(body)
		return fmt.Errorf("server returned a non-200 status code: %v, with response: %s",
			resp.StatusCode, string(data))
	}
	if err := json.NewDecoder(body).Decode(output); err != nil {
		return fmt.Errorf("decoding json error: %s", err.Error())
	}
	return nil
}

func copyHeader(dst http.Header, hs ...http.Header) {
	for _, h := range hs {
		for k, vv := range h {
			for _, v := range vv {
				dst.Add(k, v)
			}
		}
	}
}
