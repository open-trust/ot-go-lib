package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/subcommands"

	otgo "github.com/open-trust/ot-go-lib"
)

type ioGroup struct {
	ioOut io.Writer
	ioErr io.Writer
}

func (i *ioGroup) output(filename string, data []byte) error {
	var err error
	if filename != "" {
		err = ioutil.WriteFile(filename, data, 0644)
	} else {
		fmt.Fprintln(i.ioOut, string(data))
	}
	return err
}

type versionCmd struct {
	ioGroup
}

func (*versionCmd) Name() string { return "version" }
func (*versionCmd) Synopsis() string {
	return "print otgo version."
}
func (*versionCmd) Usage() string {
	return `version

Print otgo version.
`
}

func (c *versionCmd) SetFlags(_ *flag.FlagSet) {}

func (c *versionCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	fmt.Fprintln(c.ioOut, fmt.Sprintf("otgo version %s %s/%s", otgo.Version, runtime.GOOS, runtime.GOARCH))
	return subcommands.ExitSuccess
}

type keyCmd struct {
	ioGroup
	alg string
	jwk string
	out string
}

func (*keyCmd) Name() string { return "key" }
func (*keyCmd) Synopsis() string {
	return "generate a new private key or generate a public key from a private key."
}
func (*keyCmd) Usage() string {
	return `key [-alg algorithm] [-jwk privateKey] [-out filename]

Generate a new private key or generate a public key from a private key.
`
}

func (c *keyCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.alg, "alg", "", "algorithm should be one of RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512")
	f.StringVar(&c.jwk, "jwk", "", "privateKey should be a local file path or a string that private key represented by JWK [RFC7517].\nIf this flag exists, the -alg flag will be ignored.")
	f.StringVar(&c.out, "out", "", "if exists, the result will be written to the file, otherwise to stdout.")
}

func (c *keyCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	var err error
	switch {
	case c.jwk != "":
		err = c.genPublicKey()
	case c.alg != "":
		err = c.genPrivateKey()
	default:
		fmt.Fprintln(c.ioOut, c.Usage())
	}
	if err != nil {
		fmt.Fprintln(c.ioErr, err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *keyCmd) genPrivateKey() error {
	key, err := otgo.NewPrivateKey(c.alg)
	if err == nil {
		var data []byte
		if data, err = json.Marshal(key); err == nil {
			err = c.output(c.out, data)
		}
	}
	return err
}

func (c *keyCmd) genPublicKey() error {
	s := c.jwk
	if !strings.HasPrefix(s, "{") {
		b, err := ioutil.ReadFile(s)
		if err != nil {
			return err
		}
		s = string(b)
	}

	key, err := otgo.ParseKey(s)
	if err == nil {
		key, err = otgo.ToPublicKey(key)
		if err == nil {
			var data []byte
			if data, err = json.Marshal(key); err == nil {
				err = c.output(c.out, data)
			}
		}
	}
	return err
}

type signCmd struct {
	ioGroup
	jwk string
	out string
	sub string
	iss string
	aud string
	exp time.Duration
}

func (*signCmd) Name() string { return "sign" }
func (*signCmd) Synopsis() string {
	return "sign a OTVID with the given private key and payload."
}
func (*signCmd) Usage() string {
	return `sign [-jwk privateKey] [-out filename] [-sub subject] [-iss issuer] [-aud audience] [-exp expiry]

Sign a OTVID with the given private key and payload.
`
}

func (c *signCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.jwk, "jwk", "", "privateKey should be a local file path or a string that private key represented by JWK [RFC7517].")
	f.StringVar(&c.out, "out", "", "if exists, the result will be written to the file, otherwise to stdout.")
	f.StringVar(&c.sub, "sub", "", "subject should be a OTID")
	f.StringVar(&c.iss, "iss", "", "issuer should be a OTID")
	f.StringVar(&c.aud, "aud", "", "audience should be a OTID")
	f.DurationVar(&c.exp, "exp", time.Minute*10, `expiry should be a duration string, such as "30m", "1.5h" or "2h45m". Valid time units are "s", "m", "h".`)
}

func (c *signCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	var err error
	if c.jwk == "" {
		err = errors.New("the -jwk flag required")
	} else if c.sub == "" {
		err = errors.New("the -sub flag required")
	} else if c.iss == "" {
		err = errors.New("the -iss flag required")
	} else if c.aud == "" {
		err = errors.New("the -aud flag required")
	} else if c.exp < 1 {
		err = errors.New("the -exp value is invalid")
	}
	if err == nil {
		err = c.sign()
	}
	if err != nil {
		fmt.Fprintln(c.ioErr, err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *signCmd) sign() error {
	s := c.jwk
	if !strings.HasPrefix(s, "{") {
		b, err := ioutil.ReadFile(s)
		if err != nil {
			return err
		}
		s = string(b)
	}

	key, err := otgo.ParseKey(s)
	if err == nil {
		var ids otgo.OTIDs
		ids, err = otgo.ParseOTIDs(c.sub, c.iss, c.aud)
		if err == nil {
			vid := otgo.OTVID{
				ID:       ids[0],
				Issuer:   ids[1],
				Audience: otgo.OTIDs{ids[2]},
				Expiry:   time.Now().UTC().Add(c.exp).Truncate(time.Second),
			}

			var token string
			token, err = vid.Sign(key)
			if err == nil {
				err = c.output(c.out, []byte(token))
			}
		}
	}
	return err
}

type verifyCmd struct {
	ioGroup
	jwk string
	out string
}

func (*verifyCmd) Name() string { return "verify" }
func (*verifyCmd) Synopsis() string {
	return "parse and verify a OTVID with the given public key(s)."
}
func (*verifyCmd) Usage() string {
	return `verify [-jwk publicKey] [-out filename] [otvid]

Parse and verify a OTVID with the given public key(s).
`
}

func (c *verifyCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.jwk, "jwk", "", "publicKey should be a local file path or a JWK Set Url or a string that public key represented by JWK [RFC7517].")
	f.StringVar(&c.out, "out", "", "if exists, the result will be written to the file, otherwise to stdout.")
}

func (c *verifyCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	var err error
	args := f.Args()
	if c.jwk == "" {
		err = errors.New("the -jwk flag required")
	} else if len(args) == 0 {
		err = errors.New("otvid required")
	}
	if err == nil {
		err = c.verify(ctx, args[0])
	}
	if err != nil {
		fmt.Fprintln(c.ioErr, err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *verifyCmd) verify(ctx context.Context, token string) error {
	s := c.jwk
	var err error
	var ks *otgo.Keys
	if strings.HasPrefix(s, "http") {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		ks, err = otgo.FetchKeys(ctx, s, nil)
	} else {
		if !strings.HasPrefix(s, "{") {
			b, err := ioutil.ReadFile(s)
			if err != nil {
				return err
			}
			s = string(b)
		}

		ks, err = otgo.ParseKeys(s)
	}

	if err == nil {
		var vid *otgo.OTVID
		vid, err = otgo.ParseOTVIDInsecure(token)
		if err == nil {
			var data []byte
			if data, err = json.Marshal(vid.Claims); err == nil {
				err = c.output(c.out, data)
			}
		}
		if err == nil {
			err = vid.Verify(ks, vid.Issuer, vid.Audience[0])
			if err == nil {
				fmt.Fprintln(c.ioOut, fmt.Sprintf("\nVerify success!"))
			} else {
				err = fmt.Errorf("\nVerify failed: %s", err.Error())
			}
		}
	}
	return err
}

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	iog := ioGroup{ioOut: subcommands.DefaultCommander.Output, ioErr: subcommands.DefaultCommander.Error}
	subcommands.Register(&versionCmd{ioGroup: iog}, "")
	subcommands.Register(&keyCmd{ioGroup: iog}, "")
	subcommands.Register(&signCmd{ioGroup: iog}, "")
	subcommands.Register(&verifyCmd{ioGroup: iog}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
