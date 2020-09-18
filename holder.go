package otgo

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Holder ...
type Holder struct {
	ctx         context.Context
	mu          sync.RWMutex
	sf          *singleflight.Group
	td          TrustDomain
	sub         OTID
	ks          *Keys
	timeout     time.Duration
	otvidsCache map[string]*OTVID
}

// NewHolder ...
func NewHolder(ctx context.Context, sub OTID, privateKeys ...string) (*Holder, error) {
	if err := sub.Validate(); err != nil {
		return nil, err
	}

	vf := &Holder{ctx: ctx, sub: sub,
		sf:          &singleflight.Group{},
		td:          sub.TrustDomain(),
		timeout:     time.Second * 5,
		otvidsCache: make(map[string]*OTVID),
	}
	if len(privateKeys) > 0 {
		ks, err := ParseKeys(privateKeys...)
		if err != nil {
			return nil, err
		}
		vf.ks = ks
	}
	return vf, nil
}

// GetOTVIDToken ...
func (vf *Holder) GetOTVIDToken(aud OTID) (string, error) {
	if aud.String() == "" {
		return "", fmt.Errorf("invalid audience OTVID %s", aud)
	}
	vf.mu.RLock()
	vid, ok := vf.otvidsCache[aud.String()]
	vf.mu.RUnlock()
	if ok && !vid.ShouldRenew() {
		return vid.Token(), nil
	}
	return vf.fetchOTVIDTokenAndCache(aud)
}

// AddOTVIDTokens ...
func (vf *Holder) AddOTVIDTokens(tokens ...string) error {
	vids := make([]*OTVID, 0, len(tokens))
	for _, token := range tokens {
		vid, err := ParseOTVIDInsecure(token)
		if err == nil {
			if !vid.ID.Equal(vf.sub) {
				err = fmt.Errorf("the OTVID sub(%s) is not belong to holder %s", vid.ID.String(), vf.sub.String())
			} else if vid.ShouldRenew() {
				err = fmt.Errorf("the OTVID token(%s) should renew", token)
			}
		}
		if err != nil {
			return err
		}
		vids = append(vids, vid)
	}
	vf.cacheOTVIDTokens(vids...)
	return nil
}

// SignSelf ...
func (vf *Holder) SignSelf(exp ...time.Duration) (string, error) {
	key, err := LookupSigningKey(vf.ks)
	if err != nil {
		return "", err
	}

	vid := &OTVID{}
	vid.ID = vf.sub
	vid.Issuer = vf.sub
	vid.Audience = OTIDs{vf.sub.TrustDomain().OTID()}
	e := time.Minute * 10
	if len(exp) > 0 {
		e = exp[0]
	}
	vid.Expiry = time.Now().Add(e)
	return vid.Sign(key)
}

func (vf *Holder) cacheOTVIDTokens(vids ...*OTVID) {
	vf.mu.Lock()
	for _, vid := range vids {
		for _, aud := range vid.Audience {
			vf.otvidsCache[aud.String()] = vid
		}
	}
	vf.mu.Unlock()
}

func (vf *Holder) fetchOTVIDTokenAndCache(aud OTID) (string, error) {
	v, err, _ := vf.sf.Do(aud.String(), func() (interface{}, error) {
		return "", errors.New("not implemented")
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}
