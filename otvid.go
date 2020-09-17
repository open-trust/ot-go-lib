package otgo

import (
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

// OTVID represents a Open Trust Verifiable Identity Document.
type OTVID struct {
	// ID is the Open Trust ID of the OTVID as present in the 'sub' claim
	ID OTID
	// Issuer is the principal that issued OTVID as present in 'iss' claim
	Issuer OTID
	// Audience is the intended recipients of OTVID as present in the 'aud' claim
	Audience OTIDs
	// Expiry is the expiration time of OTVID as present in 'exp' claim
	Expiry time.Time
	// IssuedAt is the the time at which the OTVID was issued as present in 'iat' claim
	IssuedAt time.Time
	// Claims is the parsed claims from token
	Claims map[string]interface{}
	// token is the serialized JWT token
	token string
}

func (o *OTVID) from(t jwt.Token) error {
	var err error
	o.ID, err = ParseOTID(t.Subject())
	if err != nil {
		return err
	}
	o.Issuer, err = ParseOTID(t.Issuer())
	if err != nil {
		return err
	}
	o.Audience, err = ParseOTIDs(t.Audience()...)
	if err != nil {
		return err
	}

	o.Expiry = t.Expiration()
	o.IssuedAt = t.IssuedAt()
	o.Claims = t.PrivateClaims()
	o.Claims["sub"] = t.Subject()
	o.Claims["iss"] = t.Issuer()
	o.Claims["aud"] = t.Audience()
	o.Claims["ext"] = t.Expiration()
	o.Claims["iat"] = t.IssuedAt()
	return nil
}

// Validate ...
func (o *OTVID) Validate() error {
	if err := o.ID.Validate(); err != nil {
		return err
	}
	if err := o.Issuer.Validate(); err != nil {
		return err
	}
	if err := o.Audience.Validate(); err != nil {
		return err
	}
	if len(o.Audience) == 0 {
		return errors.New(`otgo.OTVID.Validate: audience not exists`)
	}
	return nil
}

// Verify ...
func (o *OTVID) Verify(keys *Keys, issuer, audience OTID) error {
	err := o.Validate()
	if err != nil {
		return err
	}
	if err = o.verifyClaims(issuer, audience); err != nil {
		return err
	}
	_, err = jwt.ParseString(o.token, jwt.WithKeySet(keys))
	return err
}

func (o *OTVID) verifyClaims(issuer, audience OTID) error {
	if !o.Issuer.Equal(issuer) {
		return errors.New(`otgo.OTVID.Verify: issuer not satisfied`)
	}
	if !o.Audience.Has(audience) {
		return errors.New(`otgo.OTVID.Verify: audience not satisfied`)
	}
	if !time.Now().Truncate(time.Second).Before(o.Expiry) {
		return errors.New(`otgo.OTVID.Validate: expiration time not satisfied`)
	}
	return nil
}

// Token ...
func (o *OTVID) Token() string {
	return o.token
}

// MaybeRevoked ...
func (o *OTVID) MaybeRevoked() bool {
	_, ok := o.Claims["rts"] // Release Timestamp Claim
	return ok
}

// Sign ...
func (o *OTVID) Sign(key Key) (string, error) {
	var err error
	if err = validateKeys(key); err != nil {
		return "", err
	}

	t := jwt.New()
	hdrs := jws.NewHeaders()
	alg := key.Algorithm()
	if err = hdrs.Set("alg", alg); err != nil {
		return "", err
	}
	if err = hdrs.Set("kid", key.KeyID()); err != nil {
		return "", err
	}

	for key, val := range o.Claims {
		if err = t.Set(key, val); err != nil {
			return "", err
		}
	}
	if err = t.Set("sub", o.ID.String()); err != nil {
		return "", err
	}
	if err = t.Set("iss", o.Issuer.String()); err != nil {
		return "", err
	}
	if err = t.Set("aud", o.Audience.Strings()); err != nil {
		return "", err
	}

	o.IssuedAt = time.Now().UTC().Truncate(time.Second)
	if err = t.Set("iat", o.IssuedAt); err != nil {
		return "", err
	}
	if o.Expiry.IsZero() {
		o.Expiry = o.IssuedAt.Add(time.Minute * 10)
	}
	if err = t.Set("exp", o.Expiry); err != nil {
		return "", err
	}

	s, err := jwt.Sign(t, jwa.SignatureAlgorithm(alg), key, jwt.WithHeaders(hdrs))
	if err != nil {
		return "", err
	}
	o.token = string(s)
	return o.token, nil
}

// ParseOTVID parses a OTVID from a serialized JWT token.
// The OTVID signature is verified using the JWK set.
func ParseOTVID(token string, keys *Keys, issuer, audience OTID) (*OTVID, error) {
	t, err := jwt.ParseString(token, jwt.WithKeySet(keys))
	if err != nil {
		return nil, err
	}
	vid := &OTVID{token: token}
	if err = vid.from(t); err != nil {
		return nil, err
	}
	if err = vid.Validate(); err != nil {
		return nil, err
	}
	if err = vid.verifyClaims(issuer, audience); err != nil {
		return nil, err
	}
	return vid, nil
}

// ParseOTVIDInsecure parses a OTVID from a serialized JWT token.
// The OTVID signature is not verified.
func ParseOTVIDInsecure(token string) (*OTVID, error) {
	t, err := jwt.ParseString(token)
	if err != nil {
		return nil, err
	}
	vid := &OTVID{token: token}
	if err = vid.from(t); err != nil {
		return nil, err
	}
	if err = vid.Validate(); err != nil {
		return nil, err
	}
	return vid, nil
}
