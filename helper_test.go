package otgo_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	otgo "github.com/open-trust/ot-go-lib"
	"github.com/stretchr/testify/assert"
)

func TestHelper(t *testing.T) {
	t.Run("ExtractTokenFromHeader & AddTokenToHeader func", func(t *testing.T) {
		assert := assert.New(t)

		h := http.Header{}
		otgo.AddTokenToHeader(h, "")
		assert.Equal("", otgo.ExtractTokenFromHeader(h))

		h.Set("Authorization", "token")
		assert.Equal("", otgo.ExtractTokenFromHeader(h))

		h.Set("Authorization", "Bearer 123")
		assert.Equal("123", otgo.ExtractTokenFromHeader(h))

		otgo.AddTokenToHeader(h, "456")
		assert.Equal("456", otgo.ExtractTokenFromHeader(h))
	})

	t.Run("SelectEndpoints func", func(t *testing.T) {
		assert := assert.New(t)

		ts0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(200)
			w.Write([]byte(`{"result": "ok"}`))
		}))
		defer ts0.Close()

		ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(50 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(200)
			w.Write([]byte(`{"result": "ok"}`))
		}))
		defer ts1.Close()

		ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(500)
			w.Write([]byte(`{"result": "error"}`))
		}))
		defer ts2.Close()

		ts3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(50 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(500)
			w.Write([]byte(`{"result": "error"}`))
		}))
		defer ts3.Close()

		url, err := otgo.SelectEndpoints(context.Background(), nil, []string{ts0.URL, ts1.URL, ts2.URL})
		assert.Nil(err)
		assert.Equal(ts1.URL, url)

		url, err = otgo.SelectEndpoints(context.Background(), nil, []string{ts2.URL, ts3.URL})
		assert.NotNil(err)
		assert.Equal("", url)
	})
}
