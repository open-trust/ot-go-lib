package otgo_test

import (
	"context"
	"testing"
	"time"

	otgo "github.com/open-trust/ot-go-lib"
	"github.com/stretchr/testify/assert"
)

func TestHolder(t *testing.T) {
	t.Run("NewHolder func", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("localhost")
		pk := otgo.MustPrivateKey("ES256")
		hd, err := otgo.NewHolder(context.Background(), td.NewOTID("app", ""), mustMarshal(pk))
		assert.NotNil(err)
		assert.Nil(hd)

		hd0, err := otgo.NewHolder(context.Background(), td.NewOTID("app", "123"))
		assert.Nil(err)
		assert.NotNil(hd0)

		hd1, err := otgo.NewHolder(context.Background(), td.NewOTID("app", "123"), mustMarshal(pk))
		assert.Nil(err)
		assert.NotNil(hd1)
	})

	t.Run("Holder.GetOTVIDToken & Holder.AddOTVIDTokens method", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("localhost")
		pk := otgo.MustPrivateKey("ES256")
		issPk := otgo.MustPrivateKey("ES256")
		hd, err := otgo.NewHolder(context.Background(), td.NewOTID("app", "123"), mustMarshal(pk))
		assert.Nil(err)

		var aud otgo.OTID
		_, err = hd.GetOTVIDToken(aud)
		assert.NotNil(err)
		assert.Contains(err.Error(), "invalid audience OTVID")

		aud = otgo.OTID{}
		_, err = hd.GetOTVIDToken(aud)
		assert.NotNil(err)
		assert.Contains(err.Error(), "invalid audience OTVID")

		aud = td.NewOTID("svc", "tester")
		_, err = hd.GetOTVIDToken(aud)
		assert.NotNil(err)

		vid := &otgo.OTVID{}
		vid.ID = td.NewOTID("app", "123")
		vid.Issuer = td.OTID()
		vid.Audience = otgo.OTIDs{aud}
		vid.Expiry = time.Now().Add(time.Hour)
		token, err := vid.Sign(issPk)
		assert.Nil(err)

		err = hd.AddOTVIDTokens(token)
		assert.Nil(err)

		token2, err := hd.GetOTVIDToken(aud)
		assert.Nil(err)
		assert.Equal(token, token2)

		vid = &otgo.OTVID{}
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = td.OTID()
		vid.Audience = otgo.OTIDs{aud}
		vid.Expiry = time.Now().Add(time.Hour)
		token, _ = vid.Sign(issPk)
		err = hd.AddOTVIDTokens(token)
		assert.NotNil(err)

		vid = &otgo.OTVID{}
		vid.ID = td.NewOTID("app", "123")
		vid.Issuer = td.OTID()
		vid.Audience = otgo.OTIDs{aud}
		vid.Expiry = time.Now().Add(time.Second)
		token, _ = vid.Sign(issPk)
		err = hd.AddOTVIDTokens(token)
		assert.NotNil(err)
	})

	t.Run("Holder.SignSelf method", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("localhost")
		sub := td.NewOTID("app", "123")
		pk := otgo.MustPrivateKey("ES256")
		hd0, err := otgo.NewHolder(context.Background(), sub)
		assert.Nil(err)

		hd1, err := otgo.NewHolder(context.Background(), sub, mustMarshal(pk))
		assert.Nil(err)

		token, err := hd0.SignSelf()
		assert.NotNil(err)

		token, err = hd1.SignSelf()
		assert.Nil(err)
		assert.True(token != "")

		key, err := otgo.ToPublicKey(pk)
		assert.Nil(err)

		vid, err := otgo.ParseOTVID(token, otgo.MustKeys(key), sub, td.OTID())
		assert.Nil(err)
		assert.True(vid.ID.Equal(sub))
	})
}
