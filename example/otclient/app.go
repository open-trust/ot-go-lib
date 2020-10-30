package main

import (
	"context"
	"encoding/json"
	"fmt"

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
	td := otgo.TrustDomain("ot.example.com")
	subject := td.NewOTID("agent", "admin")
	key, err := otgo.ParseKey(`{"kty":"EC","alg":"ES256","crv":"P-256","d":"oPMtH9jXcUv14YMeKZobee4f3oqS9CSGBwHzvzlJGW8","kid":"RJEq_LyfqYxf0M6NNPz-RnLirou3fvVbF-rMsbly3oQ","x":"cleqDz1kCXSI9QVU2HdPu97qLt5QTlvLKIttwzswe2E","y":"IQ0IqixMzPHWSEAT9_3Ojot1V6ql5uGfTy7hCpYl_jg"}`)
	if err != nil {
		panic(err)
	}

	cli := otgo.NewOTClient(context.Background(), subject)
	httpClient := otgo.NewClient(nil)
	httpClient.ConstraintEndpoint = "http://localhost:8080"
	httpClient.Header.Set("User-Agent", "ot-go-lib-example")
	cli.HTTPClient = httpClient
	cli.SetPrivateKeys(*otgo.MustKeys(key))

	output, err := cli.Sign(context.Background(), otgo.SignInput{
		Subject:  subject,
		Audience: td.OTID(),
	})
	fmt.Printf("cli.Sign: %v, %#v\n\n", err, output)

	vid, err := cli.ParseOTVID(context.Background(), output.OTVID, td.OTID())
	fmt.Printf("cli.ParseOTVID: %v, %#v\n\n", err, vid)

	vid, err = cli.Verify(context.Background(), output.OTVID, td.OTID())
	fmt.Printf("cli.Verify: %v, %#v\n\n", err, vid)
}
