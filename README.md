# otgo

This library is a convenient Go library for working with Open Trust.

[![License](https://img.shields.io/badge/license-Apache%202-blue)](https://raw.githubusercontent.com/open-trust/ot-go-lib/master/LICENSE)

## Package

### Import
```go
import (
	otgo "github.com/open-trust/ot-go-lib"
)
```

### Example
```go
package main

import (
	"encoding/json"
	"fmt"
	"time"

	otgo "github.com/open-trust/ot-go-lib"
)

func mustMarshal(v interface{}) string {
	s, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return string(s)
}

func main() {
	// generate a private key
	key := otgo.MustPrivateKey("ES256")
	fmt.Println("New private key:", string(mustMarshal(key)))
	// New private key: {"kty":"EC","alg":"ES256","crv":"P-256","d":"FPlpnaNqsov7WqtmwN5HrBL2vIY3kOFfuxEIkIiCDkA","kid":"xKvnlC2IZETCavHK37dCSbKOpoqxh0GRfGJY5qhXhIQ","x":"NyvBdfJFhV7xiE1fRgMeMLKmwC9eDl8TUKZlX53fiHU","y":"d_dCI9FRrWyXvvpCiYypQNmwAJwkgHIWQ5jGMXALGNs"}

	// sign a OTVID(Open Trust Verifiable Identity Document)
	vid := &otgo.OTVID{}
	td := otgo.TrustDomain("ot.example.com")
	vid.ID = td.NewOTID("user", "tom")
	vid.Issuer = td.OTID()
	vid.Audience = otgo.OTIDs{td.NewOTID("svc", "someservice")}
	vid.Expiry = time.Now().Add(time.Minute)
	token, err := vid.Sign(key)
	fmt.Println("New OTVID:", string(token))
	// New OTVID: eyJhbGciOiJFUzI1NiIsImtpZCI6InhLdm5sQzJJWkVUQ2F2SEszN2RDU2JLT3BvcXhoMEdSZkdKWTVxaFhoSVEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsib3RpZDpvdC5leGFtcGxlLmNvbTpzdmM6c29tZXNlcnZpY2UiXSwiZXhwIjoxNjAwMzI1OTA0LCJpYXQiOjE2MDAzMjU4NDQsImlzcyI6Im90aWQ6b3QuZXhhbXBsZS5jb20iLCJzdWIiOiJvdGlkOm90LmV4YW1wbGUuY29tOnVzZXI6dG9tIn0.0vaVSOiQ1Vrr88peGBiNByDLW_VkGIC7l8zm2LGqloGtNTMP2woj--s0aRWyTm8UYRluuv3VbDtpDaEM-v15lQ

	// Get public keys
	ks := otgo.LookupPublicKeys(otgo.MustKeys(key))

	// Parse OTVID
	vid2, err := otgo.ParseOTVID(token, ks, td.OTID(), td.NewOTID("svc", "someservice"))
	if err != nil {
		panic(err)
	}
	fmt.Println("Parsed OTVID Claims:", string(mustMarshal(vid2.Claims)))
	// Parsed OTVID Claims: {"aud":["otid:ot.example.com:svc:someservice"],"ext":"2020-09-17T06:58:24Z","iat":"2020-09-17T06:57:24Z","iss":"otid:ot.example.com","sub":"otid:ot.example.com:user:tom"}

	// Parse OTVID insecure
	vid3, err := otgo.ParseOTVIDInsecure(token)
	if err != nil {
		panic(err)
	}
	err = vid3.Verify(ks, td.OTID(), td.NewOTID("svc", "someservice"))
	if err != nil {
		panic(err)
	}
}
```

## CLI Tool

### Install
```sh
go get github.com/open-trust/ot-go-lib/cmd/otgo
```

```sh
otgo help
```

### Usage

Generate a new private key:
```sh
otgo key -alg ES256 -out key.jwk
cat key.jwk
# {"kty":"EC","alg":"ES256","crv":"P-256","d":"ODLkw-aml5zhOCsm0wM0j8ZhiOEEimir-7-rLvp6BfI","kid":"qKSF2H_0rOrOqy8FZRySntVhOyAqNAxesETiHtZo3SU","x":"keuJQ_zprQr5ewGltlGjcgHsMmzkZ880miaNdj5aFn4","y":"tp-6vhkvqsfLQUeyfi20cxb248khaEA5PYmeB9Z4YBY"}
```

Generate a public key from a private key:
```sh
otgo key -jwk key.jwk -out pub.jwk
cat pub.jwk
# {"kty":"EC","alg":"ES256","crv":"P-256","kid":"qKSF2H_0rOrOqy8FZRySntVhOyAqNAxesETiHtZo3SU","x":"keuJQ_zprQr5ewGltlGjcgHsMmzkZ880miaNdj5aFn4","y":"tp-6vhkvqsfLQUeyfi20cxb248khaEA5PYmeB9Z4YBY"}
```

Or:
```sh
otgo key -jwk '{"kty":"EC","alg":"ES256","crv":"P-256", ...i20cxb248khaEA5PYmeB9Z4YBY"}'
# {"kty":"EC","alg":"ES256","crv":"P-256","kid":"qKSF2H_0rOrOqy8FZRySntVhOyAqNAxesETiHtZo3SU","x":"keuJQ_zprQr5ewGltlGjcgHsMmzkZ880miaNdj5aFn4","y":"tp-6vhkvqsfLQUeyfi20cxb248khaEA5PYmeB9Z4YBY"}
```

Sign a OTVID with the given private key and payload:
```sh
otgo sign -jwk key.jwk -sub otid:localhost:test:123 -iss otid:localhost -aud otid:localhost:svc:auth
# eyJhbGciOiJFUzI1NiIsImtpZCI6InFLU0YySF8wck9yT3F5OEZaUnlTbnRWaE95QXFOQXhlc0VUaUh0Wm8zU1UiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsib3RpZDpsb2NhbGhvc3Q6c3ZjOmF1dGgiXSwiZXhwIjoxNjAwMzI0MTcwLCJpYXQiOjE2MDAzMjM1NzAsImlzcyI6Im90aWQ6bG9jYWxob3N0Iiwic3ViIjoib3RpZDpsb2NhbGhvc3Q6dGVzdDoxMjMifQ.6vq1OYorsYm3oZH1DHam0qZHumuEeFRu0v1J65W-YgzY7xcp0xfcpU3cz8Nn244awnEBl_3Pwjy62nEywLDQ_g
```

Parse and verify a OTVID:
```sh
otgo verify -jwk pub.jwk eyJhbGciOiJFUzI1NiIsImtpZCI6InFLU0YyS...7xcp0xfcpU3cz8Nn244awnEBl_3Pwjy62nEywLDQ_g
# {"aud":["otid:localhost:svc:auth"],"ext":"2020-09-17T06:29:30Z","iat":"2020-09-17T06:19:30Z","iss":"otid:localhost","sub":"otid:localhost:test:123"}
# Verify success!
```

Parse and verify a OTVID with remote public keys:
```sh
otgo verify -jwk https://my-trust-domain/.well-known/open-trust-configuration eyJhbGciOiJFUzI1NiIsImtpZCI6InFLU0YyS...7xcp0xfcpU3cz8Nn244awnEBl_3Pwjy62nEywLDQ_g
# {"aud":["otid:localhost:svc:auth"],"ext":"2020-09-17T06:29:30Z","iat":"2020-09-17T06:19:30Z","iss":"otid:localhost","sub":"otid:localhost:test:123"}
# Verify success!
```

## Documentation

https://pkg.go.dev/github.com/open-trust/ot-go-lib
