package otgo

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// renewer ...
type renewer interface {
	RLock()
	RUnlock()
	Lock()
	Unlock()
	value() interface{}
	shouldRenew() bool
	renew(context.Context, *OTClient) error
}

type cache struct {
	mu  sync.RWMutex
	kv  map[string]renewer
	new func(OTID) renewer
}

func newCache(fn func(OTID) renewer) *cache {
	return &cache{
		kv:  make(map[string]renewer),
		new: fn,
	}
}

// Get ...
func (r *cache) Get(id OTID) renewer {
	key := id.String()
	r.mu.RLock()
	val, ok := r.kv[key]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		defer r.mu.Unlock()
		val, ok = r.kv[key]
		if !ok {
			val = r.new(id)
			r.kv[key] = val
		}
	}
	return val
}

func resolve(ctx context.Context, obj renewer, oc *OTClient) (interface{}, error) {
	obj.RLock()
	v := obj.value()
	if !obj.shouldRenew() {
		obj.RUnlock()
		return v, nil
	}

	obj.RUnlock()
	obj.Lock()
	defer obj.Unlock()
	v = obj.value()
	if !obj.shouldRenew() {
		return v, nil
	}
	if err := obj.renew(ctx, oc); err != nil {
		return nil, err
	}
	return obj.value(), nil
}

type domainRenewer struct {
	sync.RWMutex
	td        TrustDomain
	ks        *JWKSet
	expiresAt time.Time
	endpoint  string
}

// DomainConfig ...
type DomainConfig struct {
	OTID     OTID
	JWKSet   *JWKSet
	Endpoint string
}

// Resolve ...
func (r *domainRenewer) Resolve(ctx context.Context, oc *OTClient) (*DomainConfig, error) {
	obj, err := resolve(ctx, r, oc)
	if err != nil {
		return nil, err
	}
	return obj.(*DomainConfig), nil
}

func (r *domainRenewer) value() interface{} {
	return &DomainConfig{
		OTID:     r.td.OTID(),
		JWKSet:   r.ks,
		Endpoint: r.endpoint,
	}
}

func (r *domainRenewer) shouldRenew() bool {
	return r.endpoint == "" || r.ks == nil || time.Now().After(r.expiresAt)
}

type domainConfigProxy struct {
	OTID             OTID              `json:"otid"`
	Keys             []json.RawMessage `json:"keys"`
	KeysRefreshHint  int64             `json:"keysRefreshHint"`
	ServiceEndpoints []string          `json:"serviceEndpoints"`
	ks               JWKSet
}

func (r *domainRenewer) renew(ctx context.Context, oc *OTClient) error {
	res := &domainConfigProxy{}
	err := oc.HTTPClient.Do(ctx, "GET", r.td.ConfigURL(), nil, nil, res)
	if err != nil {
		return err
	}
	if !res.OTID.Equal(r.td.OTID()) {
		return fmt.Errorf("invalid OT-Auth config with %s, need %s", res.OTID.String(), r.td.OTID().String())
	}
	bs := make([][]byte, 0, len(res.Keys))
	for _, b := range res.Keys {
		bs = append(bs, []byte(b))
	}

	res.ks.Keys, err = ParseKeys(bs...)
	if err != nil {
		return err
	}
	if r.endpoint == "" || !stringsHas(res.ServiceEndpoints, r.endpoint) {
		endpoint, err := SelectEndpoints(ctx, res.ServiceEndpoints, oc.HTTPClient)
		if err != nil {
			return err
		}
		r.endpoint = endpoint
	}
	r.ks = &res.ks
	if res.KeysRefreshHint > 1 {
		r.expiresAt = time.Now().Add(time.Duration(res.KeysRefreshHint) * time.Second)
	} else {
		r.expiresAt = time.Now().Add(time.Hour)
	}
	return nil
}

type serviceRenewer struct {
	sync.RWMutex
	otid     OTID
	vid      *OTVID
	endpoint string
}

// ServiceConfig ...
type ServiceConfig struct {
	OTVID    *OTVID // subject' OTVID to access the service
	Endpoint string // service's endpoint
}

// Resolve ...
func (r *serviceRenewer) Resolve(ctx context.Context, oc *OTClient) (*ServiceConfig, error) {
	obj, err := resolve(ctx, r, oc)
	if err != nil {
		return nil, err
	}

	return obj.(*ServiceConfig), nil
}

func (r *serviceRenewer) value() interface{} {
	return &ServiceConfig{
		OTVID:    r.vid,
		Endpoint: r.endpoint,
	}
}

func (r *serviceRenewer) shouldRenew() bool {
	return r.endpoint == "" || r.vid == nil || r.vid.ShouldRenew()
}

func (r *serviceRenewer) renew(ctx context.Context, oc *OTClient) error {
	output, err := oc.Sign(ctx, SignInput{
		Subject:  oc.sub,
		Audience: r.otid,
	})
	if err != nil {
		return err
	}
	r.vid, err = ParseOTVIDInsecure(output.OTVID)
	if err != nil {
		return err
	}
	if r.endpoint == "" || !stringsHas(output.ServiceEndpoints, r.endpoint) {
		r.endpoint, err = SelectEndpoints(ctx, output.ServiceEndpoints, oc.HTTPClient)
		if err != nil {
			return err
		}
	}
	return nil
}

func stringsHas(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
