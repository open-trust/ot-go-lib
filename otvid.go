package otgo

import (
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

const otvidMaxSize = 2048

// OTVID represents a Open Trust Verifiable Identity Document.
type OTVID struct {
	// ID is the Open Trust ID of the OTVID as present in the 'sub' claim
	ID OTID
	// Issuer is the principal that issued OTVID as present in 'iss' claim
	Issuer OTID
	// Audience is the intended recipient of OTVID as present in the 'aud' claim
	Audience OTID
	// Expiry is the expiration time of OTVID as present in 'exp' claim
	Expiry time.Time
	// IssuedAt is the the time at which the OTVID was issued as present in 'iat' claim
	IssuedAt time.Time
	// Release ID
	ReleaseID string
	// Claims is the parsed claims from token
	Claims map[string]interface{}
	// token is the serialized JWT token
	token string
}

// ToJSON returns a map[string]interface{} value represented as JWT.
func (o *OTVID) ToJSON() map[string]interface{} {
	j := make(map[string]interface{})
	for k, v := range o.Claims {
		j[k] = v
	}
	j["sub"] = o.ID.String()
	j["iss"] = o.Issuer.String()
	j["aud"] = []string{o.Audience.String()}
	if !o.IssuedAt.IsZero() {
		j["iat"] = o.IssuedAt.Unix()
	}
	if !o.Expiry.IsZero() {
		j["exp"] = o.Expiry.Unix()
	}
	if o.ReleaseID != "" {
		j["rid"] = o.ReleaseID
	}
	return j
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
	o.Audience, err = ParseOTID(t.Audience()[0]) // TODO
	if err != nil {
		return err
	}

	if rid, ok := t.Get("rid"); ok {
		if o.ReleaseID, ok = rid.(string); !ok {
			return fmt.Errorf("invalid 'rid' field, must be a string")
		}
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
		return fmt.Errorf("sub OTID invalid: %s", err.Error())
	}
	if err := o.Issuer.Validate(); err != nil {
		return fmt.Errorf("iss OTID invalid: %s", err.Error())
	}
	if err := o.Audience.Validate(); err != nil {
		return fmt.Errorf("aud OTID invalid: %s", err.Error())
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
	if keys == nil {
		return fmt.Errorf("otgo.OTVID.Verify: public keys required")
	}
	_, err = jwt.ParseString(o.token, jwt.WithKeySet(keys))
	return err
}

func (o *OTVID) verifyClaims(issuer, audience OTID) error {
	if !o.Issuer.Equal(issuer) {
		return errors.New(`otgo.OTVID.Verify: issuer not satisfied`)
	}
	if !o.Audience.Equal(audience) {
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
	return o.ReleaseID != ""
}

// ShouldRenew ...
func (o *OTVID) ShouldRenew() bool {
	return time.Now().Add(time.Second * 60).After(o.Expiry)
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
	if err = t.Set("aud", []string{o.Audience.String()}); err != nil {
		return "", err
	}
	if o.ReleaseID != "" {
		if err = t.Set("rid", o.ReleaseID); err != nil {
			return "", err
		}
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
	if l := len(s); l > otvidMaxSize {
		return "", fmt.Errorf("invalid OTVID, it' length %d is too large", l)
	}
	return o.token, nil
}

// ParseOTVID parses a OTVID from a serialized JWT token.
// The OTVID signature is verified using the JWK set.
func ParseOTVID(token string, keys *Keys, issuer, audience OTID) (*OTVID, error) {
	if l := len(token); l < 64 || l > 2048 {
		return nil, fmt.Errorf("invalid OTVID token with length %d", l)
	}
	if keys == nil {
		return nil, fmt.Errorf("otgo.ParseOTVID: public keys required")
	}
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
	if l := len(token); l < 64 || l > 2048 {
		return nil, fmt.Errorf("invalid OTVID token with length %d", l)
	}
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
