package otgo

import (
	"fmt"
	"strconv"
	"strings"
)

// TrustDomain ...
type TrustDomain string

// Validate returns a error if the trust domain is invalid.
func (td TrustDomain) Validate() error {
	if td == "" {
		return fmt.Errorf("otgo.TrustDomain.Validate: trust domain required")
	}
	if qr := checkRunes(string(td)); qr != "" {
		return fmt.Errorf("otgo.TrustDomain.Validate: invalid trust domain rune %s", qr)
	}
	return nil
}

// String returns the trust domain as a string, e.g. example.org.
func (td TrustDomain) String() string {
	return string(td)
}

// OTID returns the Open Trust ID of the trust domain.
// The TrustDomain should be checked with Validate() method before using.
func (td TrustDomain) OTID() OTID {
	return OTID{trustDomain: td}
}

// NewOTID returns a Open Trust ID with the given subjectType and subjectID inside the trust domain.
// The OTID should be checked with Validate() method before using.
func (td TrustDomain) NewOTID(subjectType, subjectID string) OTID {
	id := td.OTID()
	id.subjectType = subjectType
	id.subjectID = subjectID
	return id
}

// OTID is a Open Trust Identity
type OTID struct {
	trustDomain TrustDomain
	subjectType string
	subjectID   string
	checkedErr  *string
}

// ParseOTID parses a Open Trust ID from a string.
func ParseOTID(s string) (OTID, error) {
	ss := strings.Split(s, ":")
	if len(ss) < 2 {
		return OTID{}, fmt.Errorf("otgo.ParseOTID: invalid OTID string '%s'", s)
	}
	if ss[0] != "otid" {
		return OTID{}, fmt.Errorf("otgo.ParseOTID: invalid OTID scheme '%s'", ss[0])
	}
	return NewOTID(ss[1], ss[2:]...)
}

// NewOTID creates a new OTID using the trust domain (e.g. example.org) and subject parameters (type and ID).
func NewOTID(trustDomain string, subject ...string) (OTID, error) {
	id := OTID{}
	id.trustDomain = TrustDomain(trustDomain)
	switch len(subject) {
	case 0: // do nothing
	case 2:
		id.subjectType = subject[0]
		id.subjectID = subject[1]
		if id.subjectType == "" || id.subjectID == "" {
			return id, fmt.Errorf("otgo.NewOTID: invalid subject params %#v", subject)
		}
	default:
		return id, fmt.Errorf("otgo.NewOTID: invalid subject params %#v", subject)
	}
	return id, id.Validate()
}

// Validate returns a error if the OTID is invalid.
func (id OTID) Validate() error {
	if id.checkedErr == nil {
		s := id.validate()
		id.checkedErr = &s
	}
	if *id.checkedErr == "" {
		return nil
	}
	return fmt.Errorf("otgo.OTID.Validate: %s", *id.checkedErr)
}

func (id OTID) validate() string {
	if err := id.trustDomain.Validate(); err != nil {
		return err.Error()
	}

	if id.subjectType != "" || id.subjectID != "" {
		if id.subjectType == "" {
			return "invalid OTID, subject type required"
		}
		if qr := checkRunes(id.subjectType); qr != "" {
			return fmt.Sprintf("invalid OTID subject type rune %s", qr)
		}
		if id.subjectID == "" {
			return "invalid OTID, subject ID required"
		}
		if qr := checkRunes(id.subjectID); qr != "" {
			return fmt.Sprintf("invalid OTID subject id rune %s", qr)
		}
	}

	if s := len(id.trustDomain) + len(id.subjectType) + len(id.subjectID); s > 1016 {
		return fmt.Sprintf("invalid OTID, %d is too long", s)
	}
	return ""
}

// MemberOf returns true if the OTID is a member of the given trust domain.
func (id OTID) MemberOf(td TrustDomain) bool {
	return id.trustDomain == td
}

// Equal returns true if the OTID is the same as another OTID.
func (id OTID) Equal(another OTID) bool {
	return id.trustDomain == another.trustDomain && id.subjectType == another.subjectType && id.subjectID == another.subjectID
}

// TrustDomain returns the OTID's trust domain.
func (id OTID) TrustDomain() TrustDomain {
	return id.trustDomain
}

// Type returns the OTID's subject type.
func (id OTID) Type() string {
	return id.subjectType
}

// ID returns the OTID's subject ID.
func (id OTID) ID() string {
	return id.subjectID
}

// String returns the string representation of the OTID.
// e.g., "otid:ot.example.com:user:9eebccd2-12bf-40a6-b262-65fe0487d453".
func (id OTID) String() string {
	s := "otid:" + string(id.trustDomain)
	if id.subjectType != "" {
		s = fmt.Sprintf("%s:%s:%s", s, id.subjectType, id.subjectID)
	}
	return s
}

// MarshalJSON implements the json.Marshaler interface.
func (id OTID) MarshalJSON() ([]byte, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return []byte(`"` + id.String() + `"`), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (id *OTID) UnmarshalJSON(data []byte) error {
	if string(data) == `""` || string(data) == "null" {
		return nil
	}
	if len(data) < 3 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("otgo.OTID.UnmarshalJSON: invalid string for OTID %s", string(data))
	}
	var err error
	*id, err = ParseOTID(string(data[1 : len(data)-1]))
	return err
}

// MarshalText implements the encoding.TextMarshaler interface.
func (id OTID) MarshalText() ([]byte, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return []byte(id.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (id *OTID) UnmarshalText(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var err error
	*id, err = ParseOTID(string(data))
	return err
}

// OTIDs ...
type OTIDs []OTID

// ParseOTIDs parses Open Trust IDs from a string slice.
func ParseOTIDs(ss ...string) (OTIDs, error) {
	r := make([]OTID, len(ss))
	for i, s := range ss {
		id, err := ParseOTID(s)
		if err != nil {
			return nil, err
		}
		r[i] = id
	}
	return r, nil
}

// Has ...
func (ids OTIDs) Has(id OTID) bool {
	for _, v := range ids {
		if v.Equal(id) {
			return true
		}
	}
	return false
}

// Strings ...
func (ids OTIDs) Strings() []string {
	ss := make([]string, len(ids))
	for i, v := range ids {
		ss[i] = v.String()
	}
	return ss
}

func (ids OTIDs) Validate() error {
	for _, v := range ids {
		if err := v.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// must be Lower ALPHA / DIGIT / "." / "-" / "_"
func checkRunes(s string) string {
	for _, rv := range s {
		switch {
		case rv >= 'a' && rv <= 'z':
			continue
		case rv >= '0' && rv <= '9':
			continue
		case rv == '.' || rv == '-' || rv == '_':
			continue
		default:
			return strconv.QuoteRune(rv) // invalid rune
		}
	}
	return ""
}
