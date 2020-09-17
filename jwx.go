package otgo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

// Keys ...
type Keys = jwk.Set

// Key ...
type Key = jwk.Key

// ParseKey ...
func ParseKey(s string) (Key, error) {
	k, err := jwk.ParseKey([]byte(s))
	if err == nil {
		err = validateKeys(k)
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// ParseKeys ...
func ParseKeys(s string) (*Keys, error) {
	if !strings.Contains(s, `"keys"`) {
		key, err := ParseKey(s)
		if err != nil {
			return nil, err
		}
		return &jwk.Set{Keys: []jwk.Key{key}}, nil
	}
	ks, err := jwk.ParseString(s)
	if err == nil {
		err = validateKeys(ks.Keys...)
	}
	if err != nil {
		return nil, err
	}
	return ks, nil
}

// FetchKeys ...
func FetchKeys(ctx context.Context, jwkurl string, cl *http.Client) (*Keys, error) {
	opts := make([]jwk.Option, 0)
	if cl != nil {
		opts = append(opts, jwk.WithHTTPClient(cl))
	}
	ks, err := jwk.FetchHTTPWithContext(ctx, jwkurl, opts...)
	if err == nil {
		err = validateKeys(ks.Keys...)
	}
	if err != nil {
		return nil, err
	}
	return ks, nil
}

// NewKeys ...
func NewKeys(keys ...Key) (*Keys, error) {
	if err := validateKeys(keys...); err != nil {
		return nil, err
	}
	return &jwk.Set{Keys: keys}, nil
}

// MustKeys ...
func MustKeys(keys ...Key) *Keys {
	ks, err := NewKeys(keys...)
	if err != nil {
		panic(err)
	}
	return ks
}

// ToPublicKey ...
func ToPublicKey(k Key) (Key, error) {
	switch key := k.(type) {
	case jwk.RSAPrivateKey:
		pub, err := key.PublicKey()
		if err == nil {
			err = copyParams(key, pub, "alg", "kid", "use", "key_ops")
		}
		if err != nil {
			return nil, err
		}
		return pub, nil
	case jwk.ECDSAPrivateKey:
		pub, err := key.PublicKey()
		if err == nil {
			err = copyParams(key, pub, "alg", "kid", "use", "key_ops")
		}
		if err != nil {
			return nil, err
		}
		return pub, nil
	case jwk.RSAPublicKey, jwk.ECDSAPublicKey:
		return key, nil
	default:
		return nil, fmt.Errorf("otgo.ToPublicKey: invalid key type %T", key)
	}
}

// LookupPublicKeys ...
func LookupPublicKeys(ks *Keys) *Keys {
	rs := &jwk.Set{Keys: make([]Key, 0)}
	for _, k := range ks.Keys {
		if pub, err := ToPublicKey(k); err == nil {
			rs.Keys = append(rs.Keys, pub)
		}
	}
	return rs
}

// LookupSigningKey ...
func LookupSigningKey(ks *Keys) (Key, error) {
	if ks == nil || len(ks.Keys) == 0 {
		return nil, errors.New("otgo.LookupSigningKey: no keys exists")
	}
	key := ks.Keys[0]
	if len(ks.Keys) > 1 {
		key = ks.Keys[1]
	}
	switch key.(type) {
	case jwk.RSAPrivateKey, jwk.ECDSAPrivateKey:
		return key, nil
	}
	return nil, fmt.Errorf(`otgo.LookupSigningKey: invalid key type '%T'`, key)
}

// MustPrivateKey ...
func MustPrivateKey(alg string) Key {
	key, err := NewPrivateKey(alg)
	if err != nil {
		panic(err)
	}
	return key
}

// NewPrivateKey ...
func NewPrivateKey(alg string) (Key, error) {
	var key Key
	var err error
	switch jwa.SignatureAlgorithm(alg) {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		key, err = newRSAPrivateKey()
	case jwa.ES256:
		key, err = newECDSAPrivateKey(elliptic.P256())
	case jwa.ES384:
		key, err = newECDSAPrivateKey(elliptic.P384())
	case jwa.ES512:
		key, err = newECDSAPrivateKey(elliptic.P521())
	default:
		err = fmt.Errorf("otgo.NewPrivateKey: invalid algorithm '%s'", alg)
	}

	if err != nil {
		return nil, err
	}
	if err = key.Set("alg", alg); err != nil {
		return nil, err
	}
	if err = jwk.AssignKeyID(key); err != nil {
		return nil, err
	}
	return key, nil
}

// ValidateAlgorithm ...
func ValidateAlgorithm(alg string) bool {
	switch jwa.SignatureAlgorithm(alg) {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.ES256, jwa.ES384, jwa.ES512, jwa.PS256, jwa.PS384, jwa.PS512:
		return true
	}
	return false
}

func validateKeys(keys ...Key) error {
	for _, k := range keys {
		if alg := k.Algorithm(); !ValidateAlgorithm(alg) {
			return fmt.Errorf("otgo.validateKeys: invalid algorithm '%s'", alg)
		}
		if kid := k.KeyID(); kid == "" {
			return errors.New("otgo.validateKeys: kid required")
		}
	}
	return nil
}

// The recommended RSA key-length is 2048 bits.
func newRSAPrivateKey() (Key, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	key := jwk.NewRSAPrivateKey()
	if err = key.FromRaw(pk); err != nil {
		return nil, err
	}
	return key, nil
}

// newECDSAPrivateKey ...
func newECDSAPrivateKey(c elliptic.Curve) (Key, error) {
	pk, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}
	key := jwk.NewECDSAPrivateKey()
	if err = key.FromRaw(pk); err != nil {
		return nil, err
	}
	return key, nil
}

func copyParams(src, dst Key, params ...string) error {
	var err error
	for _, k := range params {
		if v, ok := src.Get(k); ok {
			if err = dst.Set(k, v); err != nil {
				return nil
			}
		}
	}
	return nil
}
