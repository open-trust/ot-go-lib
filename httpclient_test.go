package otgo_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	otgo "github.com/open-trust/ot-go-lib"
	"github.com/stretchr/testify/assert"
)

func TestHTTPClient(t *testing.T) {
	t.Run("DefaultHTTPClient", func(t *testing.T) {
		assert := assert.New(t)

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(200)
			if r.Method == "POST" {
				_, err := io.Copy(w, r.Body)
				if err != nil {
					panic(err)
				}
			} else {
				w.Write([]byte(`{"result": "ok"}`))
			}
		}))
		defer ts.Close()

		res := map[string]string{}
		err := otgo.DefaultHTTPClient.Do(context.Background(), "GET", ts.URL, nil, nil, &res)
		assert.Nil(err)
		assert.Equal("ok", res["result"])

		res = map[string]string{}
		err = otgo.DefaultHTTPClient.Do(context.Background(), "POST", ts.URL, nil, map[string]string{"result": "OK"}, &res)
		assert.Nil(err)
		assert.Equal("OK", res["result"])
	})

	t.Run("WithUA & WithToken", func(t *testing.T) {
		assert := assert.New(t)

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(200)
			m := map[string]string{}
			for k, v := range r.Header {
				m[k] = v[0]
			}
			b, err := json.Marshal(m)
			if err != nil {
				panic(err)
			}
			w.Write(b)
		}))
		defer ts.Close()

		cli := otgo.DefaultHTTPClient

		res := map[string]string{}
		cli.Header.Set("User-Agent", "UA123")
		err := cli.Do(context.Background(), "GET", ts.URL, nil, nil, &res)
		assert.Nil(err)
		assert.Equal("UA123", res["User-Agent"])

		res = map[string]string{}
		err = cli.Do(context.Background(), "GET", ts.URL, otgo.AddTokenToHeader(http.Header{}, "token456"), nil, &res)
		assert.Nil(err)
		assert.Equal("UA123", res["User-Agent"])
		assert.Equal("Bearer token456", res["Authorization"])
	})
}
