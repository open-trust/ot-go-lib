package otgo_test

import (
	"net/http"
	"testing"

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

	t.Run("Debugging", func(t *testing.T) {
		assert := assert.New(t)
		assert.True(otgo.Debugging == nil)
	})
}
