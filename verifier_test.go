package otgo_test

import (
	"context"
	"testing"
	"time"

	otgo "github.com/open-trust/ot-go-lib"
	"github.com/stretchr/testify/assert"
)

func TestVerifier(t *testing.T) {
	t.Run("NewVerifier func", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("localhost")
		pk := otgo.MustPrivateKey("ES256")
		vf, err := otgo.NewVerifier(context.Background(), td.NewOTID("app", ""), false, mustMarshal(pk))
		assert.NotNil(err)
		assert.Nil(vf)

		vf, err = otgo.NewVerifier(context.Background(), td.NewOTID("app", "123"), false, mustMarshal(pk))
		assert.Nil(err)

		vid := &otgo.OTVID{}
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = td.OTID()
		vid.Audience = otgo.OTIDs{td.NewOTID("app", "123")}
		vid.Expiry = time.Now().Add(time.Hour)
		token, err := vid.Sign(pk)
		assert.Nil(err)

		vid1, err := vf.ParseOTVID(token)
		assert.Nil(err)
		assert.True(vid.ID.Equal(vid1.ID))

		vid = &otgo.OTVID{}
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = otgo.TrustDomain("localhost1").OTID()
		vid.Audience = otgo.OTIDs{td.NewOTID("app", "123")}
		vid.Expiry = time.Now().Add(time.Hour)
		token, err = vid.Sign(pk)
		assert.Nil(err)
		_, err = vf.ParseOTVID(token)
		assert.NotNil(err)

		vid = &otgo.OTVID{}
		vid.ID = td.NewOTID("user", "abc")
		vid.Issuer = td.OTID()
		vid.Audience = otgo.OTIDs{td.NewOTID("app", "456")}
		vid.Expiry = time.Now().Add(time.Hour)
		token, err = vid.Sign(pk)
		assert.Nil(err)
		_, err = vf.ParseOTVID(token)
		assert.NotNil(err)
	})
}
