package otgo_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	otgo "github.com/open-trust/ot-go-lib"
	"github.com/stretchr/testify/assert"
)

func mustMarshal(v interface{}) string {
	s, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return string(s)
}

func TestJWX(t *testing.T) {
	t.Run("ParseKey func", func(t *testing.T) {
		assert := assert.New(t)

		priKey := otgo.MustPrivateKey("PS256")
		priS := mustMarshal(priKey)

		pubKey, err := otgo.ToPublicKey(priKey)
		assert.Nil(err)
		pubS := mustMarshal(pubKey)

		key, err := otgo.ParseKey(priS)
		assert.Nil(err)
		assert.Equal(priKey.KeyID(), key.KeyID())

		key, err = otgo.ParseKey(pubS)
		assert.Nil(err)
		assert.Equal(priKey.KeyID(), key.KeyID())

		_, err = otgo.ParseKey("")
		assert.NotNil(err)
		_, err = otgo.ParseKey(pubS + "abc")
		assert.NotNil(err)

		priKey.Set("kid", "")
		priS = mustMarshal(priKey)
		_, err = otgo.ParseKey(priS)
		assert.NotNil(err)

		pubKey.Set("alg", "abc")
		pubS = mustMarshal(pubKey)
		_, err = otgo.ParseKey(pubS)
		assert.NotNil(err)
	})

	t.Run("ParseKeys func", func(t *testing.T) {
		assert := assert.New(t)

		priKeys := otgo.MustKeys(otgo.MustPrivateKey("RS256"), otgo.MustPrivateKey("PS256"), otgo.MustPrivateKey("ES256"))
		priS := mustMarshal(priKeys)

		pubKeys := otgo.LookupPublicKeys(priKeys)
		pubS := mustMarshal(pubKeys)

		keys, err := otgo.ParseKeys(priS)
		assert.Nil(err)
		assert.Equal(len(priKeys.Keys), len(keys.Keys))

		for i, key := range keys.Keys {
			assert.Equal(priKeys.Keys[i].KeyID(), key.KeyID())
			assert.Equal(pubKeys.Keys[i].KeyID(), key.KeyID())
		}

		keys, err = otgo.ParseKeys(pubS)
		assert.Nil(err)
		assert.Equal(len(pubKeys.Keys), len(keys.Keys))

		for i, key := range keys.Keys {
			assert.Equal(pubKeys.Keys[i].KeyID(), key.KeyID())
		}

		priKey1 := otgo.MustPrivateKey("PS256")
		priKey2 := otgo.MustPrivateKey("ES256")
		keys, err = otgo.ParseKeys(mustMarshal(priKey1), mustMarshal(priKey2))
		assert.Nil(err)
		assert.Equal(2, len(keys.Keys))
		assert.Equal(keys.Keys[0].KeyID(), priKey1.KeyID())
		assert.Equal(keys.Keys[1].KeyID(), priKey2.KeyID())
	})

	t.Run("LookupPublicKeys func", func(t *testing.T) {
		assert := assert.New(t)

		priKey := otgo.MustPrivateKey("PS256")
		pubKey, err := otgo.ToPublicKey(priKey)
		assert.Nil(err)

		k, err := jwk.New([]byte("111111"))
		assert.Nil(err)

		ks := otgo.MustKeys(otgo.MustPrivateKey("RS256"), pubKey, otgo.MustPrivateKey("ES256"))
		ks.Keys = append(ks.Keys, k)

		pks := otgo.LookupPublicKeys(ks)
		assert.Equal(3, len(pks.Keys))
		assert.NotEqual(ks.Keys[0], pks.Keys[0])
		assert.Equal(ks.Keys[0].KeyID(), pks.Keys[0].KeyID())
		assert.Equal(ks.Keys[1], pks.Keys[1])
		assert.NotEqual(ks.Keys[2], pks.Keys[2])
		assert.Equal(ks.Keys[2].KeyID(), pks.Keys[2].KeyID())
	})

	t.Run("LookupSigningKey func", func(t *testing.T) {
		assert := assert.New(t)

		ks := otgo.MustKeys(otgo.MustPrivateKey("RS256"))
		k, err := otgo.LookupSigningKey(ks)
		assert.Nil(err)
		assert.Equal(ks.Keys[0], k)

		ks.Keys = append(ks.Keys, otgo.MustPrivateKey("PS256"))
		k, err = otgo.LookupSigningKey(ks)
		assert.Nil(err)
		assert.Equal(ks.Keys[1], k)

		ks.Keys = append(ks.Keys, otgo.MustPrivateKey("ES256"))
		k, err = otgo.LookupSigningKey(ks)
		assert.Nil(err)
		assert.Equal(ks.Keys[1], k)

		_, err = otgo.LookupSigningKey(nil)
		assert.NotNil(err)
		_, err = otgo.LookupSigningKey(otgo.MustKeys())
		assert.NotNil(err)

		pubKey, err := otgo.ToPublicKey(otgo.MustPrivateKey("RS256"))
		assert.Nil(err)
		_, err = otgo.LookupSigningKey(otgo.MustKeys(pubKey))
		assert.NotNil(err)
	})
}
