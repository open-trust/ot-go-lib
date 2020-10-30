package otgo

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

const nullhost = "nullhost"

// OTClient ...
type OTClient struct {
	sub          OTID
	ks           *JWKSet
	td           TrustDomain
	otDomain     *DomainResolver
	otClient     *ServiceClient
	domainCache  *cache
	serviceCache *cache
	HTTPClient   HTTPClient
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
		sub:        sub,
		td:         sub.TrustDomain(),
		domainCache: newCache(func(otid OTID) renewer {
			return &domainRenewer{td: otid.TrustDomain()}
		}),
		serviceCache: newCache(func(otid OTID) renewer {
			return &serviceRenewer{otid: otid}
		}),
	}
	cli.otDomain = cli.Domain(cli.td)
	cli.otClient = cli.Service(cli.td.OTID())
	return cli
}

// SetPrivateKeys ...
func (oc *OTClient) SetPrivateKeys(privateKeys JWKSet) {
	oc.ks = &privateKeys
}

// SetDomainKeys set trust domain's public keys persistently
// do not call this method if trust domain's OT-Auth service is online.
func (oc *OTClient) SetDomainKeys(publicKeys JWKSet) {
	oc.otDomain.ks = &publicKeys
	oc.otDomain.endpoint = nullhost
	oc.otDomain.expiresAt = time.Now().Add(time.Hour * 24 * 365 * 99)
}

// AddAudience add audience service' config to the OTClient.
// do not call this method if trust domain's OT-Auth service is online.
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

	renewer := oc.serviceCache.Get(vid.Audience).(*serviceRenewer)
	renewer.vid = vid
	renewer.endpoint = serviceEndpoint
	return nil
}

// SignSelf ...
func (oc *OTClient) SignSelf() (string, error) {
	key, err := LookupSigningKey(oc.ks)
	if err != nil {
		return "", err
	}

	vid := &OTVID{}
	vid.ID = oc.sub
	vid.Issuer = oc.sub
	vid.Audience = oc.td.OTID()
	vid.Expiry = time.Now().Add(time.Minute * 10)
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
	cfg, err := oc.otDomain.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	selfToken, err := oc.SignSelf()
	if err != nil {
		return nil, err
	}
	output := &SignOutput{}
	h := AddTokenToHeader(make(http.Header), selfToken)
	// call with subject's self OTVID
	err = oc.HTTPClient.Do(ctx, "POST", cfg.Endpoint+"/sign", h, input, &Response{Result: output})
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

	// call with subject's OTVID that signing from OT-Auth service
	err := oc.otClient.Do(ctx, "POST", "/verify", nil, input, &Response{Result: jwt})
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
	cfg, err := oc.otDomain.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	aud := oc.sub
	if len(auds) > 0 {
		aud = auds[0]
	}
	vid, err := ParseOTVID(token, cfg.JWKSet, oc.td.OTID(), aud)
	if err != nil {
		return nil, err
	}
	if vid.MaybeRevoked() && cfg.Endpoint != "" && cfg.Endpoint != nullhost {
		vid, err = oc.Verify(ctx, token, aud)
	}
	if err != nil {
		return nil, err
	}
	return vid, nil
}

// DomainResolver ...
type DomainResolver struct {
	*domainRenewer
	oc *OTClient
}

// Resolve ...
func (dr *DomainResolver) Resolve(ctx context.Context) (*DomainConfig, error) {
	return dr.domainRenewer.Resolve(ctx, dr.oc)
}

// Domain ...
func (oc *OTClient) Domain(td TrustDomain) *DomainResolver {
	if err := td.Validate(); err != nil {
		panic(fmt.Errorf("invalid TrustDomain: %s", err.Error()))
	}
	renewer := oc.domainCache.Get(td.OTID()).(*domainRenewer)
	return &DomainResolver{domainRenewer: renewer, oc: oc}
}

// ServiceClient ...
type ServiceClient struct {
	*serviceRenewer
	oc *OTClient
}

// Service ...
func (oc *OTClient) Service(aud OTID) *ServiceClient {
	if err := aud.Validate(); err != nil {
		panic(fmt.Errorf("invalid audience OTID: %s", err.Error()))
	}
	renewer := oc.serviceCache.Get(aud).(*serviceRenewer)
	return &ServiceClient{serviceRenewer: renewer, oc: oc}
}

// Resolve ...
func (sc *ServiceClient) Resolve(ctx context.Context) (*ServiceConfig, error) {
	return sc.serviceRenewer.Resolve(ctx, sc.oc)
}

// Do ...
func (sc *ServiceClient) Do(ctx context.Context, method, path string, h http.Header, input, output interface{}) error {
	cfg, err := sc.Resolve(ctx)
	if err != nil {
		return err
	}
	if h == nil {
		h = make(http.Header)
	}
	AddTokenToHeader(h, cfg.OTVID.Token())
	return sc.oc.HTTPClient.Do(ctx, method, cfg.Endpoint+path, h, input, output)
}
