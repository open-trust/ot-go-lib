package otgo_test

import (
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/stretchr/testify/assert"
)

func TestOTVID(t *testing.T) {
	t.Run("OTVID.Validate method", func(t *testing.T) {
		assert := assert.New(t)

		vid := &otgo.OTVID{}
		assert.NotNil(vid.Validate())

		td := otgo.TrustDomain("localhost")
		vid.ID = td.NewOTID("user", "abc")
		assert.NotNil(vid.Validate())

		vid.Issuer = td.OTID()
		assert.NotNil(vid.Validate())

		vid.Audience = td.NewOTID("app", "123")
		assert.Nil(vid.Validate())
	})

	t.Run("OTVID.MaybeRevoked method", func(t *testing.T) {
		assert := assert.New(t)

		vid := &otgo.OTVID{}
		assert.False(vid.MaybeRevoked())

		vid.ReleaseID = "1234567"
		assert.True(vid.MaybeRevoked())
	})

	t.Run("OTVID.ShouldRenew method", func(t *testing.T) {
		assert := assert.New(t)

		vid := &otgo.OTVID{}
		assert.True(vid.ShouldRenew())
		vid.Expiry = time.Now()
		assert.True(vid.ShouldRenew())
		vid.Expiry = time.Now().Add(time.Second * 61)
		assert.False(vid.ShouldRenew())
	})

	t.Run("OTVID.ToJSON method", func(t *testing.T) {
		assert := assert.New(t)

		vid := &otgo.OTVID{}
		td := otgo.TrustDomain("localhost")
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = td.OTID()
		vid.Audience = td.NewOTID("app", "123")
		vid.Claims = map[string]interface{}{"name": "test"}
		vid.Expiry = time.Now().Add(time.Second * 61)

		json := vid.ToJSON()
		assert.Equal(map[string]interface{}{
			"sub":  "otid:localhost:user:abc",
			"iss":  "otid:localhost",
			"aud":  []string{"otid:localhost:app:123"},
			"name": "test",
			"exp":  vid.Expiry.Unix()}, json)
	})

	t.Run("OTVID.Sign & OTVID.Verify method", func(t *testing.T) {
		assert := assert.New(t)

		vid := &otgo.OTVID{}
		td := otgo.TrustDomain("localhost")
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = td.OTID()
		vid.Audience = td.NewOTID("app", "123")
		vid.Expiry = time.Now().Add(time.Hour)

		keys := otgo.MustKeys(otgo.MustPrivateKey("ES256"))
		pubKeys := otgo.LookupPublicKeys(keys)

		keys2 := otgo.MustKeys(otgo.MustPrivateKey("ES256"))
		pubKeys2 := otgo.LookupPublicKeys(keys2)
		assert.NotNil(vid.Verify(pubKeys, td.OTID(), td.NewOTID("app", "123")))

		key, err := otgo.LookupSigningKey(keys)
		assert.Nil(err)
		_, err = vid.Sign(key)
		assert.Nil(err)

		assert.NotNil(vid.Verify(pubKeys, td.OTID(), otgo.OTID{}))
		assert.Nil(vid.Verify(pubKeys, td.OTID(), td.NewOTID("app", "123")))
		pubKeys.Keys = append(pubKeys.Keys, pubKeys2.Keys...)
		assert.Nil(vid.Verify(pubKeys, td.OTID(), td.NewOTID("app", "123")))

		assert.NotNil(vid.Verify(pubKeys2, td.OTID(), td.NewOTID("app", "123")))
		assert.NotNil(vid.Verify(pubKeys, td.OTID(), td.NewOTID("app", "456")))
		assert.NotNil(vid.Verify(pubKeys, otgo.TrustDomain("localhost1").OTID(), td.NewOTID("app", "123")))

		algs := []jwa.SignatureAlgorithm{jwa.RS256, jwa.RS384, jwa.RS512, jwa.ES256, jwa.ES384, jwa.ES512, jwa.PS256, jwa.PS384, jwa.PS512}
		pubKeys = &otgo.Keys{}
		for _, alg := range algs {
			vid := &otgo.OTVID{}
			vid.ID = td.NewOTID("user", "abc")
			vid.Issuer = td.OTID()
			vid.Audience = td.NewOTID("app", "123")
			vid.Expiry = time.Now().Add(time.Hour)

			key := otgo.MustPrivateKey(string(alg))
			pk, _ := otgo.ToPublicKey(key)
			pubKeys.Keys = append(pubKeys.Keys, pk)
			_, err := vid.Sign(key)
			assert.Nil(err)
			assert.Nil(vid.Verify(pubKeys, td.OTID(), td.NewOTID("app", "123")))
		}
	})

	t.Run("ParseOTVID func", func(t *testing.T) {
		assert := assert.New(t)

		vid := &otgo.OTVID{Claims: make(map[string]interface{})}
		td := otgo.TrustDomain("localhost")
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = td.OTID()
		vid.Audience = td.NewOTID("app", "123")
		vid.Expiry = time.Now().Add(time.Hour)
		vid.ReleaseID = "123456789"
		vid.Claims["name"] = "test"

		keys := otgo.MustKeys(otgo.MustPrivateKey("ES256"))
		pubKeys := otgo.LookupPublicKeys(keys)

		keys2 := otgo.MustKeys(otgo.MustPrivateKey("ES256"))
		pubKeys2 := otgo.LookupPublicKeys(keys2)

		key, err := otgo.LookupSigningKey(keys)
		assert.Nil(err)
		token, err := vid.Sign(key)
		assert.Nil(err)

		vid2, err := otgo.ParseOTVID(token, pubKeys, vid.Issuer, vid.Audience)
		assert.Nil(err)
		assert.True(vid2.ID.Equal(vid.ID))
		assert.True(vid2.IssuedAt.Equal(vid.IssuedAt))
		assert.Equal("123456789", vid2.ReleaseID)
		assert.Equal("123456789", vid2.Claims["rid"].(string))
		assert.Equal("test", vid2.Claims["name"].(string))

		_, err = otgo.ParseOTVID(token, pubKeys2, vid.Issuer, vid.Audience)
		assert.NotNil(err)

		_, err = otgo.ParseOTVID(token[:len(token)-2], pubKeys, vid.Issuer, vid.Audience)
		assert.NotNil(err)

		_, err = otgo.ParseOTVID(token, pubKeys, vid.Issuer, vid.Issuer)
		assert.NotNil(err)

		_, err = otgo.ParseOTVID(token, pubKeys2, vid.ID, vid.Audience)
		assert.NotNil(err)
	})

	t.Run("ParseOTVIDInsecure func", func(t *testing.T) {
		assert := assert.New(t)

		vid := &otgo.OTVID{}
		td := otgo.TrustDomain("localhost")
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = td.OTID()
		vid.Audience = td.NewOTID("app", "123")
		vid.Expiry = time.Now().Add(time.Hour)
		vid.Claims = map[string]interface{}{"rid": 12345, "sub": "123"}

		keys := otgo.MustKeys(otgo.MustPrivateKey("ES256"))
		pubKeys := otgo.LookupPublicKeys(keys)

		keys2 := otgo.MustKeys(otgo.MustPrivateKey("ES256"))
		pubKeys2 := otgo.LookupPublicKeys(keys2)

		key, err := otgo.LookupSigningKey(keys)
		assert.Nil(err)
		token, err := vid.Sign(key)
		assert.Nil(err)

		vid2, err := otgo.ParseOTVIDInsecure(token)
		assert.NotNil(err)
		assert.Contains(err.Error(), "invalid 'rid' field")

		vid.Claims = map[string]interface{}{"name": strings.Repeat("a", 2000)}
		token, err = vid.Sign(key)
		assert.NotNil(err)
		assert.Contains(err.Error(), "is too large")

		vid.Claims = map[string]interface{}{"rid": "12345", "sub": "123"}
		token, err = vid.Sign(key)
		assert.Nil(err)
		vid2, err = otgo.ParseOTVIDInsecure(token)
		assert.Nil(err)
		assert.True(vid2.ID.Equal(vid.ID))
		assert.True(vid2.IssuedAt.Equal(vid.IssuedAt))
		assert.Equal("12345", vid2.Claims["rid"])
		assert.Nil(vid2.Verify(pubKeys, vid.Issuer, vid.Audience))
		assert.NotNil(vid2.Verify(pubKeys2, vid.Issuer, vid.Audience))
		assert.NotNil(vid2.Verify(pubKeys2, vid.ID, vid.Audience))
		assert.NotNil(vid2.Verify(pubKeys2, vid.Issuer, vid.ID))
	})
}
