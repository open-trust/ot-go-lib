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

	cli, err := otgo.NewOTClient(context.Background(), agent)
	if err != nil {
		panic(err)
	}
	cli.SetHTTPClient(otgo.NewTestClient("http://localhost:8081").WithUA("ot-go-lib"))
	cli.SetPrivateKeys(*otgo.MustKeys(key))
	err = cli.LoadConfig()
	if err != nil {
		panic(err)
	}

	token, err := cli.Sign(context.Background(), otgo.SignInput{
		Subject:  agent,
		Audience: td.NewOTID("svc", "testing"),
	})
	fmt.Printf("cli.Sign: %#v\n\n", token)

	vid, err := cli.ParseOTVID(context.Background(), token, td.NewOTID("svc", "testing"))
	fmt.Printf("cli.ParseOTVID: %#v\n\n", vid)

	vid, err = cli.Verify(context.Background(), token, td.NewOTID("svc", "testing"))
	fmt.Printf("cli.Verify: %#v\n\n", vid)
}
