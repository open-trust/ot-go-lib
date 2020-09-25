package otgo

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Verifier ...
type Verifier struct {
	ctx     context.Context
	mu      sync.RWMutex
	du      time.Duration
	timeout time.Duration
	aud     OTID
	iss     OTID
	td      TrustDomain
	ks      *Keys
}

// NewVerifier ...
func NewVerifier(ctx context.Context, aud OTID, refreshKeys bool, publicKeys ...string) (*Verifier, error) {
	if err := aud.Validate(); err != nil {
		return nil, err
	}

	vf := &Verifier{ctx: ctx, aud: aud,
		td:      aud.TrustDomain(),
		iss:     aud.TrustDomain().OTID(),
		du:      time.Second * 3600,
		timeout: time.Second * 5,
	}
	if len(publicKeys) > 0 {
		ks, err := ParseKeys(publicKeys...)
		if err != nil {
			return nil, err
		}
		vf.ks = LookupPublicKeys(ks)
	}

	if refreshKeys {
		ctx, cancel := context.WithTimeout(ctx, vf.timeout)
		defer cancel()
		if err := vf.fetchKeys(ctx); err != nil {
			return nil, fmt.Errorf("otgo.NewVerifier: fetch keys failed: %s", err.Error())
		}
		vf.refreshKeys(ctx)
	}
	return vf, nil
}

// SetKeys ...
func (vf *Verifier) SetKeys(publicKeys Keys) {
	vf.mu.Lock()
	vf.ks = &publicKeys
	vf.mu.Unlock()
}

// ParseOTVID ...
func (vf *Verifier) ParseOTVID(token string) (*OTVID, error) {
	vf.mu.RLock()
	ks := vf.ks
	vf.mu.RUnlock()
	return ParseOTVID(token, ks, vf.iss, vf.aud)
}

func (vf *Verifier) refreshKeys(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(vf.du)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				nCtx, cancel := context.WithTimeout(ctx, vf.timeout)
				if err := vf.fetchKeys(nCtx); err != nil {
					if Debugging != nil {
						Debugging.Debugf("otgo.Verifier: refresh keys failed: %v", err)
					}
				}
				cancel()
			}
		}
	}()
}

func (vf *Verifier) fetchKeys(ctx context.Context) error {
	ks, err := FetchKeys(ctx, vf.td.VerifyURL(), HTTPClient)
	if err == nil && len(ks.Keys) > 0 {
		vf.SetKeys(*ks)
	}
	return err
}
