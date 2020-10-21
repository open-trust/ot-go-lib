package otgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// OTClient ...
type OTClient struct {
	ctx             context.Context
	mu              sync.RWMutex
	td              TrustDomain
	sub             OTID
	ks              *JWKSet
	domainKs        *JWKSet
	serviceEndpoint string
	refresh         time.Duration
	timeout         time.Duration
	cli             *HTTPClient
	sf              *singleflight.Group
	otvidsCache     map[string]*OTVID // 简单缓存，Audience 为 key，数据量不大
	onError         func(err error)
}

// Config ...
type Config struct {
	JWKSet          *JWKSet
	ServiceEndpoint string
}

// NewOTClient ...
func NewOTClient(ctx context.Context, sub OTID) (*OTClient, error) {
	if err := sub.Validate(); err != nil {
		return nil, err
	}
	return &OTClient{
		ctx:         ctx,
		sub:         sub,
		td:          sub.TrustDomain(),
		refresh:     time.Second * 3600,
		timeout:     time.Second * 5,
		cli:         DefaultHTTPClient,
		sf:          &singleflight.Group{},
		otvidsCache: make(map[string]*OTVID),
	}, nil
}

// SetDomainKeys ...
func (ot *OTClient) SetDomainKeys(publicKeys JWKSet) {
	ot.domainKs = &publicKeys
}

// SetTestHost ...
func (ot *OTClient) SetTestHost(host string) {
	ot.serviceEndpoint = host
	ot.cli.testHost = host
}

// SetPrivateKeys ...
func (ot *OTClient) SetPrivateKeys(privateKeys JWKSet) {
	ot.ks = &privateKeys
}

// SetOnError ...
func (ot *OTClient) SetOnError(cb func(err error)) {
	ot.onError = cb
}

// SetHTTPClient ...
func (ot *OTClient) SetHTTPClient(cli *HTTPClient) {
	ot.cli = cli
}

// GetToken ...
func (ot *OTClient) GetToken(ctx context.Context, aud OTID) (string, error) {
	if err := aud.Validate(); err != nil {
		return "", fmt.Errorf("invalid audience OTVID: %s", err.Error())
	}
	ot.mu.RLock()
	vid, ok := ot.otvidsCache[aud.String()]
	ot.mu.RUnlock()
	if ok && !vid.ShouldRenew() {
		return vid.Token(), nil
	}
	return ot.fetchOTVIDTokenAndCache(ctx, aud)
}

// AddTokens ...
func (ot *OTClient) AddTokens(tokens ...string) error {
	vids := make([]OTVID, 0, len(tokens))
	for _, token := range tokens {
		vid, err := ParseOTVIDInsecure(token)
		if err == nil {
			if !vid.ID.Equal(ot.sub) {
				err = fmt.Errorf("the OTVID %s is not belong to subject %s", vid.ID.String(), ot.sub.String())
			} else if vid.ShouldRenew() {
				err = fmt.Errorf("the OTVID token(%s) should renew", token)
			}
		}
		if err != nil {
			return err
		}
		vids = append(vids, *vid)
	}
	ot.cacheOTVIDTokens(vids...)
	return nil
}

// SignSelf ...
func (ot *OTClient) SignSelf(exp ...time.Duration) (string, error) {
	key, err := LookupSigningKey(ot.ks)
	if err != nil {
		return "", err
	}

	vid := &OTVID{}
	vid.ID = ot.sub
	vid.Issuer = ot.sub
	vid.Audience = ot.td.OTID()
	e := time.Minute * 10
	if len(exp) > 0 {
		e = exp[0]
	}
	vid.Expiry = time.Now().Add(e)
	return vid.Sign(key)
}

// SignInput ...
type SignInput struct {
	Subject        OTID                   `json:"sub"` // 申请签发 OTVID 的 sub，可以是联盟信任域的 sub
	Audience       OTID                   `json:"aud"` // 申请签发 OTVID 的 aud，可以是联盟信任域的 aud
	Expiry         int64                  `json:"exp"`
	Claims         map[string]interface{} `json:"claims"`         // 需要包含的其它签发数据
	ForwardedOTVID string                 `json:"forwardedOtvid"` // 请求主体与 sub 不一致则是代理申请，且请求主体不是联盟域，需要 sub 的自签发 OTVID
}

type signOutput struct {
	Issuer OTID   `json:"iss"`
	OTVID  string `json:"otvid"`
	Expiry int64  `json:"exp"`
}

// Get ...
func (ot *OTClient) Get(ctx context.Context, path string, output interface{}) error {
	if ot.serviceEndpoint == "" {
		return errors.New("no service endpoint, run LoadConfigs() first")
	}
	token, err := ot.GetToken(ctx, ot.td.OTID())
	if err != nil {
		return err
	}
	return ot.cli.WithToken(token).Get(ctx, ot.serviceEndpoint+path, output)
}

// Post ...
func (ot *OTClient) Post(ctx context.Context, path string, input, output interface{}) error {
	if ot.serviceEndpoint == "" {
		return errors.New("no service endpoint, run LoadConfigs() first")
	}
	token, err := ot.GetToken(ctx, ot.td.OTID())
	if err != nil {
		return err
	}
	return ot.cli.WithToken(token).Post(ctx, ot.serviceEndpoint+path, input, output)
}

// Sign ...
func (ot *OTClient) Sign(ctx context.Context, input SignInput) (string, error) {
	if ot.serviceEndpoint == "" {
		return "", errors.New("no service endpoint, run LoadConfig() firstly")
	}
	selfToken, err := ot.SignSelf()
	if err != nil {
		return "", err
	}
	output := &signOutput{}
	err = ot.cli.WithToken(selfToken).Post(ctx, ot.serviceEndpoint+"/sign", input, &Response{Result: output})
	if err != nil {
		return "", err
	}

	return output.OTVID, nil
}

// Verify ...
func (ot *OTClient) Verify(ctx context.Context, token string, auds ...OTID) (*OTVID, error) {
	aud := ot.sub
	if len(auds) > 0 {
		aud = auds[0]
	}
	input := map[string]interface{}{
		"aud":   aud.String(),
		"otvid": token,
	}
	jwt := NewToken()
	err := ot.Post(ctx, "/verify", input, &Response{Result: jwt})
	vid, err := FromJWT(token, jwt)
	if err != nil {
		return nil, err
	}
	return vid, nil
}

// ParseOTVID ...
func (ot *OTClient) ParseOTVID(ctx context.Context, token string, auds ...OTID) (*OTVID, error) {
	cfg := ot.Config()
	aud := ot.sub
	if len(auds) > 0 {
		aud = auds[0]
	}
	vid, err := ParseOTVID(token, cfg.JWKSet, ot.td.OTID(), aud)
	if err != nil {
		return nil, err
	}
	if vid.MaybeRevoked() && cfg.ServiceEndpoint != "" {
		vid, err = ot.Verify(ctx, token, aud)
	}
	if err != nil {
		return nil, err
	}
	return vid, nil
}

func (ot *OTClient) cacheOTVIDTokens(vids ...OTVID) {
	ot.mu.Lock()
	for _, vid := range vids {
		ot.otvidsCache[vid.Audience.String()] = &vid
	}
	ot.mu.Unlock()
}

func (ot *OTClient) fetchOTVIDTokenAndCache(ctx context.Context, aud OTID) (string, error) {
	v, err, _ := ot.sf.Do(aud.String(), func() (interface{}, error) {
		return ot.Sign(ctx, SignInput{
			Subject:  ot.sub,
			Audience: aud,
		})
	})
	if err != nil {
		return "", err
	}
	vid, err := ParseOTVIDInsecure(v.(string))
	if err != nil {
		return "", err
	}
	ot.cacheOTVIDTokens(*vid)
	return vid.Token(), nil
}

// Config ...
func (ot *OTClient) Config() Config {
	ot.mu.RLock()
	defer ot.mu.RUnlock()
	return Config{
		JWKSet:          ot.domainKs,
		ServiceEndpoint: ot.serviceEndpoint,
	}
}

type jsonOTConfigProxy struct {
	OTID             OTID              `json:"otid"`
	Keys             []json.RawMessage `json:"keys"`
	KeysRefreshHint  int64             `json:"keysRefreshHint"`
	ServiceEndpoints []string          `json:"serviceEndpoints"`
	ks               JWKSet
}

// LoadConfig ...
func (ot *OTClient) LoadConfig() error {
	nCtx, cancel := context.WithTimeout(ot.ctx, ot.timeout)
	defer cancel()

	res := &jsonOTConfigProxy{}
	err := ot.cli.Get(nCtx, ot.td.ConfigURL(), res)
	if err == nil {
		if !res.OTID.Equal(ot.td.OTID()) {
			return fmt.Errorf("invalid OT-Auth config with %s, need %s", res.OTID.String(), ot.td.OTID().String())
		}
		bs := make([][]byte, 0, len(res.Keys))
		for _, b := range res.Keys {
			bs = append(bs, []byte(b))
		}

		res.ks.Keys, err = ParseKeys(bs...)
		if err == nil {
			var sp string
			sp, err = ot.SelectEndpoints(nCtx, res.ServiceEndpoints)
			if err == nil {
				ot.mu.Lock()
				ot.serviceEndpoint = sp
				if len(res.ks.Keys) > 0 {
					ot.domainKs = &res.ks
				}
				if res.KeysRefreshHint > 0 {
					ot.refresh = time.Duration(res.KeysRefreshHint) * time.Second
				}
				ot.mu.Unlock()
			}
		}
	}
	return err
}

// RefreshConfig ...
func (ot *OTClient) RefreshConfig() error {
	if err := ot.LoadConfig(); err != nil {
		return err
	}
	go ot.waitAndLoadConfig()
	return nil
}

// SelectEndpoints ...
func (ot *OTClient) SelectEndpoints(ctx context.Context, serviceEndpoints []string) (string, error) {
	return SelectEndpoints(ctx, ot.cli, serviceEndpoints)
}

func (ot *OTClient) waitAndLoadConfig() {
	for {
		ticker := time.NewTicker(ot.refresh)
		select {
		case <-ot.ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			ticker.Stop()
			if err := ot.LoadConfig(); err != nil {
				if ot.onError != nil {
					ot.onError(err)
				}
			}
		}
	}
}
