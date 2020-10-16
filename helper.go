package otgo

import (
	"net/http"
	"strings"
)

// Version ...
const Version = "v0.7.1"

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
