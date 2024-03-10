package proxy

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrorNotTuicLink          = errors.New("not a correct tuic link")
)

type Tuic struct {
	Base
	UUID                 string            `yaml:"uuid" json:"uuid"`
	Password             string            `yaml:"password,omitempty" json:"password,omitempty"`
	ALPN                 []string          `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	CongestionCtrl       string            `yaml:"congestion-controller,omitempty" json:"congestion-controller,omitempty"`
	UDPRelayMode         string            `yaml:"udp-relay-mode,omitempty" json:"udp-relay-mode,omitempty"`
	SNI                  string            `yaml:"sni,omitempty" json:"sni,omitempty"`
	SkipCertVerify       bool              `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
}

func (t Tuic) Identifier() string {
	return net.JoinHostPort(t.Server, strconv.Itoa(t.Port)) + t.UUID + t.Password
}

func (t Tuic) String() string {
	data, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return string(data)
}

func (t Tuic) ToClash() string {
	data, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (t Tuic) ToSurge() string {
	return ""
}

func (t Tuic) Clone() Proxy {
	return &t
}

func (t Tuic) Link() (link string) {
	query := url.Values{}
	if len(t.ALPN) > 0 {
		query.Set("alpn", strings.Join(t.ALPN, ","))
	}
	if t.CongestionCtrl != "" {
		query.Set("congestion_control", t.CongestionCtrl)
	}
	if t.UDPRelayMode != "" {
		query.Set("udp_relay_mode", t.UDPRelayMode)
	}
	if t.SNI != "" {
		query.Set("sni", url.QueryEscape(t.SNI))
	}
	if t.SkipCertVerify {
		query.Set("allow_insecure", "1")
	}

	uri := url.URL{
		Scheme:   "tuic",
		User:     url.UserPassword(url.QueryEscape(t.UUID), url.QueryEscape(t.Password)),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		RawQuery: query.Encode(),
		Fragment: t.Name,
	}

	return uri.String()
}

func ParseTuicLink(link string) (*Tuic, error) {
	if !strings.HasPrefix(link, "tuic") {
		return nil, ErrorNotTuicLink
	}

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotTuicLink
	}

	username := uri.User.Username()
	username, _ = url.QueryUnescape(username)
	password, isSetPass := uri.User.Password()
	if isSetPass == false {
		return nil, ErrorNotTuicLink
	}
	password, _ = url.QueryUnescape(password)
	if len(username) == 0 || len(password) == 0 {
		return nil, ErrorNotTuicLink
	}
	
	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())

	moreInfos := uri.Query()

	alpn := ParseProxyALPN(moreInfos.Get("alpn"))

	congestion_control := moreInfos.Get("congestion_control")
	udp_relay_mode := moreInfos.Get("udp_relay_mode")

	sni := moreInfos.Get("sni")
	sni, _ = url.QueryUnescape(sni)

	skip_certverify := true
	if moreInfos.Get("allow_insecure") == "0" {
		skip_certverify = false
	}

	if port == 0 {
		return nil, ErrorNotTuicLink
	}

	return &Tuic{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "tuic",
		},
		UUID:              username,
		Password:          password,
		ALPN:              alpn,
		CongestionCtrl:    congestion_control,
		UDPRelayMode:      udp_relay_mode,
		SNI:               sni,
		SkipCertVerify:    skip_certverify,
	}, nil
}

var (
	tuicPlainRe = regexp.MustCompile("tuic://([A-Za-z0-9+/_&?=@:%.-])+")
)

func GrepTuicLinkFromString(text string) []string {
	results := make([]string, 0)
	texts := strings.Split(text, "tuic://")
	for _, text := range texts {
		results = append(results, tuicPlainRe.FindAllString("tuic://"+text, -1)...)
	}
	return results
}
