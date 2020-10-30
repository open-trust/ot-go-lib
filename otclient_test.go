package otgo_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	otgo "github.com/open-trust/ot-go-lib"
	"github.com/stretchr/testify/assert"
)

func TestOTClient(t *testing.T) {
	t.Run("NewOTClient func", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("localhost")
		assert.Panics(func() { otgo.NewOTClient(context.Background(), td.NewOTID("app", "")) })
	})

	t.Run("OTClient.AddAudience & ServiceClient.Resolve method", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("localhost")
		cli := otgo.NewOTClient(context.Background(), td.NewOTID("app", "123"))

		var aud otgo.OTID
		assert.Panics(func() { cli.Service(aud) })

		aud = otgo.OTID{}
		assert.Panics(func() { cli.Service(aud) })

		aud = td.NewOTID("svc", "tester")
		scli := cli.Service(aud)
		_, err := scli.Resolve(context.Background())
		assert.NotNil(err)

		pk := otgo.MustPrivateKey("ES256")
		vid := &otgo.OTVID{}
		vid.ID = td.NewOTID("app", "123")
		vid.Issuer = td.OTID()
		vid.Audience = aud
		vid.Expiry = time.Now().Add(time.Hour)
		token, err := vid.Sign(pk)
		assert.Nil(err)

		serviceEndpoint := "http://localhost:1234"
		err = cli.AddAudience(token, serviceEndpoint)
		assert.Nil(err)

		cfg, err := scli.Resolve(context.Background())
		assert.Nil(err)
		assert.Equal(token, cfg.OTVID.Token())
		assert.Equal(serviceEndpoint, cfg.Endpoint)

		vid = &otgo.OTVID{}
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = td.OTID()
		vid.Audience = aud
		vid.Expiry = time.Now().Add(time.Hour)
		token, _ = vid.Sign(pk)
		err = cli.AddAudience(token, serviceEndpoint)
		assert.NotNil(err)

		vid = &otgo.OTVID{}
		vid.ID = td.NewOTID("app", "123")
		vid.Issuer = td.OTID()
		vid.Audience = aud
		vid.Expiry = time.Now().Add(time.Second)
		token, _ = vid.Sign(pk)
		err = cli.AddAudience(token, serviceEndpoint)
		assert.NotNil(err)
	})

	t.Run("OTClient.SignSelf method", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("localhost")
		sub := td.NewOTID("app", "123")
		pk := otgo.MustPrivateKey("ES256")
		cli := otgo.NewOTClient(context.Background(), sub)

		token, err := cli.SignSelf()
		assert.NotNil(err)

		cli.SetPrivateKeys(*otgo.MustKeys(pk))
		token, err = cli.SignSelf()
		assert.Nil(err)
		assert.True(token != "")

		key, err := otgo.ToPublicKey(pk)
		assert.Nil(err)

		vid, err := otgo.ParseOTVID(token, otgo.MustKeys(key), sub, td.OTID())
		assert.Nil(err)
		assert.True(vid.ID.Equal(sub))
	})

	t.Run("DomainResolver", func(t *testing.T) {
		assert := assert.New(t)

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(200)
			w.Write([]byte(`
{
	"keys": [{
		"kty": "EC",
		"alg": "ES512",
		"crv": "P-521",
		"kid": "ySQYnCsV4cOZBxbHCv4E410k0gjTbi8WfJJwVkV6QqI",
		"x": "AdtXGowadABABWC0FVolCYnRhiBEYdO6-bpyldNh1RrLVIDJJRJelA_O2UB9DyssCN8gLfJio3OdV8YH6uyfvOwb",
		"y": "AX1Waed_878v_Y1JE2U3dLvAOIScuu_UVGUFZpQyB-hRTXMIQHTqEQw9os_Jcb491-0ZUANJZs_gne7srQ2yOCN6"
	}],
	"keysRefreshHint": 3600,
	"otid": "otid:localhost",
	"serviceEndpoints": ["https://localhost/v1"],
	"serviceTypes": ["agent", "app", "svc"],
	"userTypes": ["user", "dev"]
}
			`))
		}))
		defer ts.Close()

		td := otgo.TrustDomain("localhost")
		sub := td.NewOTID("app", "123")
		cli := otgo.NewOTClient(context.Background(), sub)
		cli.HTTPClient.(*otgo.Client).ConstraintEndpoint = ts.URL

		df := cli.Domain(td)
		cfg, err := df.Resolve(context.Background())
		assert.Nil(err)
		assert.Equal("https://localhost/v1", cfg.Endpoint)
		assert.Equal(1, len(cfg.JWKSet.Keys))
		assert.Equal("ySQYnCsV4cOZBxbHCv4E410k0gjTbi8WfJJwVkV6QqI", cfg.JWKSet.Keys[0].KeyID())

		ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(200)
			w.Write([]byte(`
{
	"keys": [{
		"kty": "EC",
		"alg": "ES512",
		"crv": "P-521",
		"kid": "",
		"x": "AdtXGowadABABWC0FVolCYnRhiBEYdO6-bpyldNh1RrLVIDJJRJelA_O2UB9DyssCN8gLfJio3OdV8YH6uyfvOwb",
		"y": "AX1Waed_878v_Y1JE2U3dLvAOIScuu_UVGUFZpQyB-hRTXMIQHTqEQw9os_Jcb491-0ZUANJZs_gne7srQ2yOCN6"
	}],
	"keysRefreshHint": 3600,
	"otid": "otid:localhost",
	"serviceEndpoints": ["https://localhost/v1"],
	"serviceTypes": ["agent", "app", "svc"],
	"userTypes": ["user", "dev"]
}
			`))
		}))
		defer ts.Close()
		cli = otgo.NewOTClient(context.Background(), sub)
		cli.HTTPClient.(*otgo.Client).ConstraintEndpoint = ts.URL
		df = cli.Domain(td)
		_, err = df.Resolve(context.Background())
		assert.NotNil(err)
	})

	t.Run("OTClient.Verify method", func(t *testing.T) {
		assert := assert.New(t)

		vid := &otgo.OTVID{Claims: make(map[string]interface{})}
		td := otgo.TrustDomain("localhost")
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = td.OTID()
		vid.Audience = td.NewOTID("app", "123")
		vid.Expiry = time.Now().UTC().Truncate(time.Second).Add(time.Hour)
		vid.ReleaseID = "123456789"

		domainKeys := otgo.MustKeys(otgo.MustPrivateKey("ES256"))
		key, err := otgo.LookupSigningKey(domainKeys)
		assert.Nil(err)
		token, err := vid.Sign(key)
		assert.Nil(err)

		appVid := &otgo.OTVID{}
		appVid.ID = td.NewOTID("app", "123")
		appVid.Issuer = td.OTID()
		appVid.Audience = td.OTID()
		appVid.Expiry = time.Now().Add(time.Hour)
		appToken, err := appVid.Sign(key)
		assert.Nil(err)

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := vid.ToJWT()
			if err != nil {
				panic(err)
			}
			b, err := json.Marshal(map[string]interface{}{"result": token})
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(200)
			w.Write(b)
		}))
		defer ts.Close()

		cli := otgo.NewOTClient(context.Background(), vid.Audience)
		cli.HTTPClient.(*otgo.Client).ConstraintEndpoint = ts.URL
		assert.Nil(cli.AddAudience(appToken, ts.URL))
		cli.SetPrivateKeys(*otgo.MustKeys(otgo.MustPrivateKey("ES256")))

		parsedVid, err := cli.Verify(context.Background(), token)
		assert.Nil(err)
		assert.True(vid.ID.Equal(parsedVid.ID))
		assert.True(vid.Issuer.Equal(parsedVid.Issuer))
		assert.True(vid.Audience.Equal(parsedVid.Audience))
		assert.True(vid.Expiry.Equal(parsedVid.Expiry))
		assert.Equal(vid.ReleaseID, parsedVid.ReleaseID)
	})

	t.Run("OTClient.ParseOTVID method", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("localhost")
		pk := otgo.MustPrivateKey("ES256")
		cli := otgo.NewOTClient(context.Background(), td.NewOTID("app", "123"))

		vid := &otgo.OTVID{}
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = td.OTID()
		vid.Audience = td.NewOTID("app", "123")
		vid.Expiry = time.Now().Add(time.Hour)
		token, err := vid.Sign(pk)
		assert.Nil(err)

		vid1, err := cli.ParseOTVID(context.Background(), token)
		assert.NotNil(err)

		cli.SetDomainKeys(*otgo.LookupPublicKeys(otgo.MustKeys(pk)))
		vid1, err = cli.ParseOTVID(context.Background(), token)
		assert.Nil(err)
		assert.True(vid.ID.Equal(vid1.ID))

		vid = &otgo.OTVID{}
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = otgo.TrustDomain("localhost1").OTID()
		vid.Audience = td.NewOTID("app", "123")
		vid.Expiry = time.Now().Add(time.Hour)
		token, err = vid.Sign(pk)
		assert.Nil(err)
		_, err = cli.ParseOTVID(context.Background(), token)
		assert.NotNil(err)

		vid = &otgo.OTVID{}
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = td.OTID()
		vid.Audience = td.NewOTID("app", "456")
		vid.Expiry = time.Now().Add(time.Hour)
		token, err = vid.Sign(pk)
		assert.Nil(err)
		_, err = cli.ParseOTVID(context.Background(), token)
		assert.NotNil(err)
	})
}
