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
	agent := td.NewOTID("agent", "admin")
	key, err := otgo.ParseKey(`{"kty":"EC","alg":"ES256","crv":"P-256","d":"oPMtH9jXcUv14YMeKZobee4f3oqS9CSGBwHzvzlJGW8","kid":"RJEq_LyfqYxf0M6NNPz-RnLirou3fvVbF-rMsbly3oQ","x":"cleqDz1kCXSI9QVU2HdPu97qLt5QTlvLKIttwzswe2E","y":"IQ0IqixMzPHWSEAT9_3Ojot1V6ql5uGfTy7hCpYl_jg"}`)
	if err != nil {
		panic(err)
	}

	cli := otgo.NewOTClient(context.Background(), agent)
	cli.HTTPClient.(*otgo.Client).Endpoint = "http://localhost:8080"
	cli.HTTPClient.(*otgo.Client).Header.Set("User-Agent", "ot-go-lib")
	cli.SetPrivateKeys(*otgo.MustKeys(key))
	err = cli.LoadConfig()
	if err != nil {
		panic(err)
	}

	output, err := cli.Sign(context.Background(), otgo.SignInput{
		Subject:  agent,
		Audience: td.NewOTID("svc", "testing"),
	})
	fmt.Printf("cli.Sign: %v, %#v\n\n", err, output)

	vid, err := cli.ParseOTVID(context.Background(), output.OTVID, td.NewOTID("svc", "testing"))
	fmt.Printf("cli.ParseOTVID: %v, %#v\n\n", err, vid)

	vid, err = cli.Verify(context.Background(), output.OTVID, td.NewOTID("svc", "testing"))
	fmt.Printf("cli.Verify: %v, %#v\n\n", err, vid)
}
