package otgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// OTClient ...
type OTClient struct {
	HTTPClient      HTTPClient
	ctx             context.Context
	mu              sync.RWMutex
	td              TrustDomain
	sub             OTID
	aud             OTID
	ks              *JWKSet
	domainKs        *JWKSet
	serviceEndpoint string
	refresh         time.Duration
	timeout         time.Duration
	audsCache       map[string]*audInfo // 简单缓存，Audience 为 key，数据量不大
	onError         func(err error)
	serviceClient   *ServiceClient
}

type audInfo struct {
	vid      *OTVID
	endpoint string
}

// Config ...
type Config struct {
	JWKSet          *JWKSet
	ServiceEndpoint string
}

// NewOTClient ...
func NewOTClient(ctx context.Context, sub OTID) *OTClient {
	if err := sub.Validate(); err != nil {
		panic(fmt.Errorf("invalid subject OTID: %s", err.Error()))
	}

	cli := &OTClient{
		HTTPClient: NewClient(nil),
		ctx:        ctx,
		sub:        sub,
		aud:        sub.TrustDomain().OTID(),
		td:         sub.TrustDomain(),
		refresh:    time.Second * 3600,
		timeout:    time.Second * 5,
		audsCache:  make(map[string]*audInfo),
	}
	cli.serviceClient = cli.ServiceClient(cli.aud)
	return cli
}

// SetDomainKeys ...
func (oc *OTClient) SetDomainKeys(publicKeys JWKSet) {
	oc.domainKs = &publicKeys
}

// SetPrivateKeys ...
func (oc *OTClient) SetPrivateKeys(privateKeys JWKSet) {
	oc.ks = &privateKeys
}

// SetOnError ...
func (oc *OTClient) SetOnError(cb func(err error)) {
	oc.onError = cb
}

// WithAud ...
func (oc *OTClient) mustGetAudInfo(aud OTID) *audInfo {
	oc.mu.RLock()
	info, ok := oc.audsCache[aud.String()]
	oc.mu.RUnlock()
	if !ok {
		oc.mu.Lock()
		info, ok = oc.audsCache[aud.String()]
		if !ok {
			info = &audInfo{}
			oc.audsCache[aud.String()] = info
		}
		oc.mu.Unlock()
	}
	return info
}

// AddAudience ...
func (oc *OTClient) AddAudience(token, serviceEndpoint string) error {
	vid, err := ParseOTVIDInsecure(token)
	if err == nil {
		if !vid.ID.Equal(oc.sub) {
			err = fmt.Errorf("the OTVID %s is not belong to subject %s", vid.ID.String(), oc.sub.String())
		} else if vid.ShouldRenew() {
			err = fmt.Errorf("the OTVID token(%s) should renew", token)
		}
	}
	if err != nil {
		return err
	}

	audInfo := oc.mustGetAudInfo(vid.Audience)
	audInfo.vid = vid
	audInfo.endpoint = serviceEndpoint
	return nil
}

// SignSelf ...
func (oc *OTClient) SignSelf(exp ...time.Duration) (string, error) {
	key, err := LookupSigningKey(oc.ks)
	if err != nil {
		return "", err
	}

	vid := &OTVID{}
	vid.ID = oc.sub
	vid.Issuer = oc.sub
	vid.Audience = oc.td.OTID()
	e := time.Minute * 10
	if len(exp) > 0 {
		e = exp[0]
	}
	vid.Expiry = time.Now().Add(e)
	return vid.Sign(key)
}

// Response ...
type Response struct {
	Error  interface{} `json:"error"`
	Result interface{} `json:"result"`
}

// SignInput ...
type SignInput struct {
	Subject        OTID                   `json:"sub"` // 申请签发 OTVID 的 sub，可以是联盟信任域的 sub
	Audience       OTID                   `json:"aud"` // 申请签发 OTVID 的 aud，可以是联盟信任域的 aud
	Expiry         int64                  `json:"exp"`
	Claims         map[string]interface{} `json:"claims"`         // 需要包含的其它签发数据
	ForwardedOTVID string                 `json:"forwardedOtvid"` // 请求主体与 sub 不一致则是代理申请，且请求主体不是联盟域，需要 sub 的自签发 OTVID
}

// SignOutput ...
type SignOutput struct {
	Issuer           OTID     `json:"iss"`
	Audience         OTID     `json:"aud"`
	Expiry           int64    `json:"exp"`
	OTVID            string   `json:"otvid"`
	ServiceEndpoints []string `json:"serviceEndpoints"`
}

// Sign ...
func (oc *OTClient) Sign(ctx context.Context, input SignInput) (*SignOutput, error) {
	cfg := oc.Config()
	if cfg.ServiceEndpoint == "" {
		return nil, errors.New("no auth service endpoint, run LoadConfig() firstly")
	}
	selfToken, err := oc.SignSelf()
	if err != nil {
		return nil, err
	}
	output := &SignOutput{}
	h := AddTokenToHeader(make(http.Header), selfToken)
	err = oc.HTTPClient.Do(ctx, "POST", cfg.ServiceEndpoint+"/sign", h, input, &Response{Result: output})
	if err != nil {
		return nil, err
	}

	return output, nil
}

// Verify ...
func (oc *OTClient) Verify(ctx context.Context, token string, auds ...OTID) (*OTVID, error) {
	aud := oc.sub
	if len(auds) > 0 {
		aud = auds[0]
	}
	input := map[string]interface{}{
		"aud":   aud.String(),
		"otvid": token,
	}
	jwt := NewToken()

	err := oc.serviceClient.Do(ctx, "POST", "/verify", nil, input, &Response{Result: jwt})
	if err != nil {
		return nil, err
	}
	vid, err := FromJWT(token, jwt)
	if err != nil {
		return nil, err
	}
	return vid, nil
}

// ParseOTVID ...
func (oc *OTClient) ParseOTVID(ctx context.Context, token string, auds ...OTID) (*OTVID, error) {
	cfg := oc.Config()
	aud := oc.sub
	if len(auds) > 0 {
		aud = auds[0]
	}
	vid, err := ParseOTVID(token, cfg.JWKSet, oc.td.OTID(), aud)
	if err != nil {
		return nil, err
	}
	if vid.MaybeRevoked() && cfg.ServiceEndpoint != "" {
		vid, err = oc.Verify(ctx, token, aud)
	}
	if err != nil {
		return nil, err
	}
	return vid, nil
}

// Config ...
func (oc *OTClient) Config() Config {
	oc.mu.RLock()
	defer oc.mu.RUnlock()
	return Config{
		JWKSet:          oc.domainKs,
		ServiceEndpoint: oc.serviceEndpoint,
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
func (oc *OTClient) LoadConfig() error {
	nCtx, cancel := context.WithTimeout(oc.ctx, oc.timeout)
	defer cancel()

	res := &jsonOTConfigProxy{}
	err := oc.HTTPClient.Do(nCtx, "GET", oc.td.ConfigURL(), nil, nil, res)
	if err == nil {
		if !res.OTID.Equal(oc.td.OTID()) {
			return fmt.Errorf("invalid OT-Auth config with %s, need %s", res.OTID.String(), oc.td.OTID().String())
		}
		bs := make([][]byte, 0, len(res.Keys))
		for _, b := range res.Keys {
			bs = append(bs, []byte(b))
		}

		res.ks.Keys, err = ParseKeys(bs...)
		if err == nil {
			var sp string
			sp, err = SelectEndpoints(nCtx, res.ServiceEndpoints, oc.HTTPClient)
			if err == nil {
				oc.mu.Lock()
				oc.serviceEndpoint = sp
				if len(res.ks.Keys) > 0 {
					oc.domainKs = &res.ks
				}
				if res.KeysRefreshHint > 1 {
					oc.refresh = time.Duration(res.KeysRefreshHint) * time.Second
				}
				oc.mu.Unlock()
			}
		}
	}
	return err
}

// RefreshConfig ...
func (oc *OTClient) RefreshConfig() error {
	if err := oc.LoadConfig(); err != nil {
		return err
	}
	go oc.waitAndLoadConfig()
	return nil
}

func (oc *OTClient) waitAndLoadConfig() {
	for {
		ticker := time.NewTicker(oc.refresh)
		select {
		case <-oc.ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			ticker.Stop()
			if err := oc.LoadConfig(); err != nil {
				if oc.onError != nil {
					oc.onError(err)
				}
			}
		}
	}
}

// ServiceClient ...
type ServiceClient struct {
	otid OTID
	mu   sync.RWMutex
	oc   *OTClient
	info *audInfo
}

// ServiceClient ...
func (oc *OTClient) ServiceClient(aud OTID) *ServiceClient {
	if err := aud.Validate(); err != nil {
		panic(fmt.Errorf("invalid audience OTID: %s", err.Error()))
	}
	info := oc.mustGetAudInfo(aud)
	return &ServiceClient{oc: oc, otid: aud, info: info}
}

// Resolve ...
func (sc *ServiceClient) Resolve(ctx context.Context) (token string, endpoint string, err error) {
	sc.mu.RLock()
	vid := sc.info.vid
	endpoint = sc.info.endpoint
	sc.mu.RUnlock()

	if endpoint == "" || vid == nil || vid.ShouldRenew() {
		sc.mu.Lock()
		defer sc.mu.Unlock()

		if sc.info.endpoint == "" || sc.info.vid == nil || sc.info.vid.ShouldRenew() {
			output, err := sc.oc.Sign(ctx, SignInput{
				Subject:  sc.oc.sub,
				Audience: sc.otid,
			})
			if err != nil {
				return "", "", err
			}
			sc.info.vid, err = ParseOTVIDInsecure(output.OTVID)
			if err != nil {
				return "", "", err
			}
			if sc.info.endpoint == "" || !stringsHas(output.ServiceEndpoints, sc.info.endpoint) {
				sc.info.endpoint, err = SelectEndpoints(ctx, output.ServiceEndpoints, sc.oc.HTTPClient)
				if err != nil {
					return "", "", err
				}
			}
		}

		vid = sc.info.vid
		endpoint = sc.info.endpoint
	}
	return vid.Token(), endpoint, nil
}

// Do ...
func (sc *ServiceClient) Do(ctx context.Context, method, path string, h http.Header, input, output interface{}) error {
	token, endpoint, err := sc.Resolve(ctx)
	if err != nil {
		return err
	}
	if h == nil {
		h = make(http.Header)
	}
	AddTokenToHeader(h, token)
	return sc.oc.HTTPClient.Do(ctx, method, endpoint+path, h, input, output)
}

func stringsHas(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
