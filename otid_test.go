package otgo_test

import (
	"encoding/json"
	"strings"
	"testing"

	otgo "github.com/open-trust/ot-go-lib"
	"github.com/stretchr/testify/assert"
)

func TestTrustDomain(t *testing.T) {
	t.Run("TrustDomain.Validate method", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("localhost")
		err := td.Validate()
		assert.Nil(err)
		assert.True(td == otgo.TrustDomain("localhost"))

		td = otgo.TrustDomain("ot.example.com")
		err = td.Validate()
		assert.Nil(err)

		td = otgo.TrustDomain("o-t.example.com")
		err = td.Validate()
		assert.Nil(err)

		td = otgo.TrustDomain("o_t.example.com")
		err = td.Validate()
		assert.Nil(err)

		td = otgo.TrustDomain("")
		err = td.Validate()
		assert.NotNil(err)
		assert.Contains(err.Error(), "trust domain required")

		td = otgo.TrustDomain("localHost")
		err = td.Validate()
		assert.NotNil(err)
		assert.Contains(err.Error(), "invalid trust domain rune 'H'")

		td = otgo.TrustDomain(" ")
		err = td.Validate()
		assert.NotNil(err)
		assert.Contains(err.Error(), "invalid trust domain rune ' '")

		td = otgo.TrustDomain("*.example.com")
		err = td.Validate()
		assert.NotNil(err)
		assert.Contains(err.Error(), "invalid trust domain rune '*'")

		td = otgo.TrustDomain("ot.example.co m")
		err = td.Validate()
		assert.NotNil(err)
		assert.Contains(err.Error(), "invalid trust domain rune ' '")

		td = otgo.TrustDomain("ww☺.example.com ")
		err = td.Validate()
		assert.NotNil(err)
		assert.Contains(err.Error(), "invalid trust domain rune '☺'")
	})

	t.Run("TrustDomain.String method", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("ot.example.com")
		assert.Equal("ot.example.com", td.String())
	})

	t.Run("TrustDomain.OTID method", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("ot.example.com")
		assert.Equal("otid:ot.example.com", td.OTID().String())
	})

	t.Run("TrustDomain.NewOTID method", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("ot.example.com")
		assert.Equal("otid:ot.example.com:user:joe", td.NewOTID("user", "joe").String())
	})
}

func TestOTID(t *testing.T) {
	t.Run("NewOTID func", func(t *testing.T) {
		assert := assert.New(t)

		id, err := otgo.NewOTID("localhost")
		assert.Nil(err)
		assert.Equal("otid:localhost", id.String())

		id, err = otgo.NewOTID("localhost", "app", "auth")
		assert.Nil(err)
		assert.Equal("otid:localhost:app:auth", id.String())

		id, err = otgo.NewOTID("localhost", "user", "123")
		assert.Nil(err)
		assert.Equal("otid:localhost:user:123", id.String())

		_, err = otgo.NewOTID("")
		assert.NotNil(err)

		_, err = otgo.NewOTID("T")
		assert.NotNil(err)

		_, err = otgo.NewOTID("localhost", "")
		assert.NotNil(err)

		_, err = otgo.NewOTID("localhost", "", "")
		assert.NotNil(err)

		_, err = otgo.NewOTID("localhost", "app", "")
		assert.NotNil(err)

		_, err = otgo.NewOTID("localhost", "app")
		assert.NotNil(err)
		assert.Contains(err.Error(), "invalid subject params")

		_, err = otgo.NewOTID("localhost", "app", "auth", "123")
		assert.NotNil(err)
		assert.Contains(err.Error(), "invalid subject params")
	})

	t.Run("ParseOTID func", func(t *testing.T) {
		assert := assert.New(t)

		id, err := otgo.ParseOTID("otid:localhost")
		assert.Nil(err)
		assert.Equal("otid:localhost", id.String())

		id, err = otgo.ParseOTID("otid:localhost:app:auth")
		assert.Nil(err)
		assert.Equal("otid:localhost:app:auth", id.String())

		_, err = otgo.ParseOTID("")
		assert.NotNil(err)

		_, err = otgo.ParseOTID("L")
		assert.NotNil(err)

		_, err = otgo.ParseOTID("otid")
		assert.NotNil(err)

		_, err = otgo.ParseOTID("otid:")
		assert.NotNil(err)

		_, err = otgo.ParseOTID("oti:localhost")
		assert.NotNil(err)

		_, err = otgo.ParseOTID("otiD:localhost")
		assert.NotNil(err)

		_, err = otgo.ParseOTID("otid:localhost:")
		assert.NotNil(err)

		_, err = otgo.ParseOTID("otid:localhost::")
		assert.NotNil(err)

		_, err = otgo.ParseOTID("otid:localhost:app:auth:")
		assert.NotNil(err)
	})

	t.Run("OTID.Validate method", func(t *testing.T) {
		assert := assert.New(t)

		td := otgo.TrustDomain("localhost")
		id := td.OTID()
		assert.Nil(id.Validate())

		td = otgo.TrustDomain("localhost")
		id = td.NewOTID("user", "123")
		assert.Nil(id.Validate())

		td = otgo.TrustDomain("")
		id = td.OTID()
		assert.NotNil(id.Validate())

		td = otgo.TrustDomain("L")
		id = td.OTID()
		assert.NotNil(id.Validate())

		td = otgo.TrustDomain("localhost")
		id = td.NewOTID("user", "")
		assert.NotNil(id.Validate())

		id = td.NewOTID("", "")
		assert.Nil(id.Validate())
		assert.Equal("otid:localhost", id.String())

		id = td.NewOTID(" ", "")
		assert.NotNil(id.Validate())

		id = td.NewOTID("user", " ")
		assert.NotNil(id.Validate())

		id = td.NewOTID("user ", "123")
		assert.NotNil(id.Validate())

		id = td.NewOTID("user☺", "123")
		assert.NotNil(id.Validate())

		id = td.NewOTID("user", "123☺")
		assert.NotNil(id.Validate())

		id = td.NewOTID("user", strings.Repeat("a", 1000))
		assert.Nil(id.Validate())

		id = td.NewOTID("user", strings.Repeat("a", 1024))
		assert.NotNil(id.Validate())
	})

	t.Run("OTID.MemberOf method", func(t *testing.T) {
		assert := assert.New(t)

		id, err := otgo.ParseOTID("otid:localhost")
		assert.Nil(err)
		assert.True(id.MemberOf(otgo.TrustDomain("localhost")))
		assert.False(id.MemberOf(otgo.TrustDomain("localhos")))

		id, err = otgo.ParseOTID("otid:localhost:app:abc")
		assert.Nil(err)
		assert.True(id.MemberOf(otgo.TrustDomain("localhost")))
		assert.False(id.MemberOf(otgo.TrustDomain("localhost1")))
	})

	t.Run("OTID.Equal method", func(t *testing.T) {
		assert := assert.New(t)

		id, err := otgo.ParseOTID("otid:localhost")
		assert.Nil(err)
		assert.True(id.Equal(otgo.TrustDomain("localhost").OTID()))
		assert.False(id.Equal(otgo.TrustDomain("localhos").OTID()))
		assert.False(id.Equal(otgo.TrustDomain("localhost").NewOTID("user", "abc")))
	})

	t.Run("OTID.MarshalJSON & OTID.UnmarshalJSON method", func(t *testing.T) {
		assert := assert.New(t)

		id := otgo.TrustDomain("localhost").NewOTID("user", "abc")
		b, err := json.Marshal(id)
		assert.Nil(err)
		assert.Equal(`"otid:localhost:user:abc"`, string(b))

		id2 := otgo.OTID{}
		err = json.Unmarshal(b, &id2)
		assert.Nil(err)
		assert.True(id.Equal(id2))

		obj := map[string]interface{}{
			"id": id,
		}
		b, err = json.Marshal(obj)
		assert.Nil(err)
		assert.Equal(`{"id":"otid:localhost:user:abc"}`, string(b))

		obj2 := map[string]otgo.OTID{}
		err = json.Unmarshal(b, &obj2)
		assert.Nil(err)
		assert.True(id.Equal(obj2["id"]))

		type testOTID struct {
			ID  otgo.OTID  `json:"id"`
			ID1 otgo.OTID  `json:"id1"`
			ID2 otgo.OTID  `json:"id2"`
			ID3 *otgo.OTID `json:"id3"`
			ID4 *otgo.OTID `json:"id4"`
			ID5 *otgo.OTID `json:"id5"`
		}

		obj3 := testOTID{}
		err = json.Unmarshal([]byte(`{"id":"otid:localhost","id2":null,"id1":"","id3":null,"id4":""}`), &obj3)
		assert.Nil(err)
		assert.True(obj3.ID.Equal(otgo.TrustDomain("localhost").OTID()))

		assert.NotNil(obj3.ID1.Validate())
		assert.NotNil(obj3.ID2.Validate())
		assert.Nil(obj3.ID3)
		assert.NotNil(obj3.ID4)
		assert.NotNil(obj3.ID4.Validate())
		assert.Nil(obj3.ID5)

		id = otgo.TrustDomain("localhost").NewOTID("user", "")
		_, err = json.Marshal(id)
		assert.NotNil(err)

		id = otgo.TrustDomain("localhost").NewOTID("user", "abc☺")
		_, err = json.Marshal(id)
		assert.NotNil(err)

		obj2 = map[string]otgo.OTID{}
		err = json.Unmarshal([]byte(`{"id":"otid:localhost:user:abc:"}`), &obj2)
		assert.NotNil(err)
		err = json.Unmarshal([]byte(`{"id":"otId:localhost:user:abc"}`), &obj2)
		assert.NotNil(err)
		err = json.Unmarshal([]byte(`{"id":"otid:localhost:user:"}`), &obj2)
		assert.NotNil(err)
		err = json.Unmarshal([]byte(`{"id":"otid:localhost::"}`), &obj2)
		assert.NotNil(err)
		err = json.Unmarshal([]byte(`{"id":"otid:localhost:"}`), &obj2)
		assert.NotNil(err)

		err = json.Unmarshal([]byte(`{"id":"otid:localhost"}`), &obj2)
		assert.Nil(err)
		assert.True(otgo.TrustDomain("localhost").OTID().Equal(obj2["id"]))
	})

	t.Run("OTID.MarshalText & OTID.UnmarshalText method", func(t *testing.T) {
		assert := assert.New(t)

		id := otgo.TrustDomain("localhost").NewOTID("user", "abc")
		b, err := id.MarshalText()
		assert.Nil(err)
		assert.Equal("otid:localhost:user:abc", string(b))

		id2 := otgo.OTID{}
		err = id2.UnmarshalText(b)
		assert.Nil(err)
		assert.True(id.Equal(id2))

		id = otgo.TrustDomain("localhost").NewOTID("user", "")
		_, err = id.MarshalText()
		assert.NotNil(err)
		id2 = otgo.OTID{}
		err = id2.UnmarshalText([]byte("otid:localhost:user:abc:"))
		assert.NotNil(err)
	})
}

func TestOTIDs(t *testing.T) {
	t.Run("ParseOTIDs func", func(t *testing.T) {
		assert := assert.New(t)

		ids, err := otgo.ParseOTIDs()
		assert.Nil(err)
		assert.Equal(0, len(ids))

		ids, err = otgo.ParseOTIDs("otid:localhost", "otid:localhost:user:abc")
		assert.Nil(err)
		assert.Equal(2, len(ids))
		assert.True(ids[0].Equal(otgo.TrustDomain("localhost").OTID()))
		assert.True(ids[1].Equal(otgo.TrustDomain("localhost").NewOTID("user", "abc")))

		_, err = otgo.ParseOTIDs("otid:localhost", "")
		assert.NotNil(err)
		_, err = otgo.ParseOTIDs("otid:localhost", "otid:localhost:user:abc:")
		assert.NotNil(err)
	})

	t.Run("OTIDs.Has method", func(t *testing.T) {
		assert := assert.New(t)

		ids, err := otgo.ParseOTIDs("otid:localhost", "otid:localhost:user:abc")
		assert.Nil(err)
		assert.True(ids.Has(otgo.TrustDomain("localhost").OTID()))
		assert.True(ids.Has(otgo.TrustDomain("localhost").NewOTID("user", "abc")))
		assert.False(ids.Has(otgo.TrustDomain("localhost").NewOTID("app", "abc")))
	})

	t.Run("OTIDs.Strings method", func(t *testing.T) {
		assert := assert.New(t)

		ids, err := otgo.ParseOTIDs("otid:localhost", "otid:localhost:user:abc")
		assert.Nil(err)
		assert.Equal([]string{"otid:localhost", "otid:localhost:user:abc"}, ids.Strings())
	})

	t.Run("OTIDs.Validate method", func(t *testing.T) {
		assert := assert.New(t)

		ids, err := otgo.ParseOTIDs("otid:localhost", "otid:localhost:user:abc")
		assert.Nil(err)
		assert.Nil(ids.Validate())

		ids = append(ids, otgo.OTID{})
		assert.NotNil(ids.Validate())
	})
}
