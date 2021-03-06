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
	"net/url"
	"strings"
	"time"
)

type ctxKey int

const (
	// CtxHeaderKey ...
	CtxHeaderKey ctxKey = 0
)

var tr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	DialContext: (&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 25 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   100,
	IdleConnTimeout:       59 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 4 * time.Second,
	ResponseHeaderTimeout: 10 * time.Second,
}

// Client ...
type Client struct {
	*http.Client
	Header             http.Header
	ConstraintEndpoint string // set it for testing purposes only
}

// HTTPClient ...
type HTTPClient interface {
	Do(ctx context.Context, method, api string, h http.Header, input, output interface{}) error
}

// NewClient ...
func NewClient(client *http.Client) *Client {
	if client == nil {
		client = &http.Client{
			Transport: tr,
			Timeout:   time.Second * 5,
		}
	}
	return &Client{Client: client, Header: http.Header{}}
}

// Do ...
func (c *Client) Do(ctx context.Context, method, api string, h http.Header, input, output interface{}) error {
	err := ctx.Err()
	if err != nil {
		return fmt.Errorf("context.Context error: %v", err)
	}

	var b bytes.Buffer
	if input != nil {
		if err = json.NewEncoder(&b).Encode(input); err != nil {
			return fmt.Errorf("encode input data error: %v", err)
		}
	}

	if c.ConstraintEndpoint != "" {
		if strings.HasPrefix(api, "http") {
			u, err := url.Parse(api)
			if err != nil {
				return err
			}
			api = c.ConstraintEndpoint + u.RequestURI() // override URL endpoint
		} else {
			api = c.ConstraintEndpoint + api
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, api, &b)
	if err != nil {
		return fmt.Errorf("create http request error: %v", err)
	}

	copyHeader(req.Header, c.Header)
	if val := ctx.Value(CtxHeaderKey); val != nil {
		copyHeader(req.Header, val.(http.Header))
	}
	if h != nil {
		copyHeader(req.Header, h)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := c.Client.Do(req)
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
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return fmt.Errorf("read response error: %s, status code: %v", err.Error(), resp.StatusCode)
	}

	if output != nil {
		if err := json.Unmarshal(data, output); err != nil {
			return fmt.Errorf("decoding json error: %s, status code: %v, response: %s", err.Error(), resp.StatusCode, string(data))
		}
	}

	if resp.StatusCode >= 300 {
		return fmt.Errorf("non-success response, status code: %v, response: %s",
			resp.StatusCode, string(data))
	}
	return nil
}

func copyHeader(dst http.Header, src http.Header) {
	for k, vv := range src {
		switch len(vv) {
		case 1:
			dst.Set(k, vv[0])
		default:
			dst.Del(k)
			for _, v := range vv {
				dst.Add(k, v)
			}
		}
	}
}
