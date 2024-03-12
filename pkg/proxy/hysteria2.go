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
	ErrorNotHysteria2Link          = errors.New("not a correct hysteria2 link")
)

type Hysteria2 struct {
	Base
	Password             string            `yaml:"password" json:"password"`
	Obfs                 string            `yaml:"obfs,omitempty" json:"obfs,omitempty"`
	ObfsPassword         string            `yaml:"obfs-password,omitempty" json:"obfs-password,omitempty"`
	ALPN                 []string          `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	SNI                  string            `yaml:"sni,omitempty" json:"sni,omitempty"`
	SkipCertVerify       bool              `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
}

func (h Hysteria2) Identifier() string {
	return net.JoinHostPort(h.Server, strconv.Itoa(h.Port)) + h.Password
}

func (h Hysteria2) String() string {
	data, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return string(data)
}

func (h Hysteria2) ToClash() string {
	data, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (h Hysteria2) ToSurge() string {
	return ""
}

func (h Hysteria2) Clone() Proxy {
	return &h
}

func (h Hysteria2) Link() (link string) {
	query := url.Values{}
	if len(h.ALPN) > 0 {
		query.Set("alpn", strings.Join(h.ALPN, ","))
	}
	if h.SNI != "" {
		query.Set("sni", url.QueryEscape(h.SNI))
	}
	if h.Obfs != "" {
		query.Set("obfs", h.Obfs)
	}
	if h.ObfsPassword != "" {
		query.Set("obfs-password", h.ObfsPassword)
	}
	if h.SkipCertVerify {
		query.Set("insecure", "1")
	}

	uri := url.URL{
		Scheme:   "hysteria2",
		User:     url.User(url.QueryEscape(h.Password)),
		Host:     net.JoinHostPort(h.Server, strconv.Itoa(h.Port)),
		RawQuery: query.Encode(),
		Fragment: h.Name,
	}

	return uri.String()
}

func ParseHysteria2Link(link string) (*Hysteria2, error) {
	if !(strings.HasPrefix(link, "hysteria2://") || strings.HasPrefix(link, "hy2://")) {
		return nil, ErrorNotHysteria2Link
	}

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotHysteria2Link
	}

	password := uri.User.Username()
	password, _ = url.QueryUnescape(password)

	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())

	moreInfos := uri.Query()

	// sni or peer
	sni := moreInfos.Get("sni")
	if sni != "" {
		sni, _ = url.QueryUnescape(sni)
	} else {
		sni = moreInfos.Get("peer")
		if sni != "" {
			sni, _ = url.QueryUnescape(sni)
		}
	}

	// alpn
	alpn := ParseProxyALPN(moreInfos.Get("alpn"))

	skip_certverify := true
	if moreInfos.Get("insecure") == "0" {
		skip_certverify = false
	}

	obfs := moreInfos.Get("obfs")
	if obfs == "none" {
		obfs = ""
	}
	obfspassword := moreInfos.Get("obfs-password")

	if port == 0 {
		return nil, ErrorNotTuicLink
	}

	return &Hysteria2{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "hysteria2",
		},
		Password:          password,
		Obfs:              obfs,
		ObfsPassword:      obfspassword,
		ALPN:              alpn,
		SNI:               sni,
		SkipCertVerify:    skip_certverify,
		}, nil
}

var (
	hysteria2PlainRe = regexp.MustCompile("hysteria2://[A-Za-z0-9+/_&=@:%\\[\\].-]+(\\?[A-Za-z0-9+/_&?=@:%.-]+)?")
)

var (
	hy2PlainRe = regexp.MustCompile("hy2://[A-Za-z0-9+/_&=@:%\\[\\].-]+(\\?[A-Za-z0-9+/_&?=@:%.-]+)?")
)

func GrepHysteria2LinkFromString(text string) []string {
	results := make([]string, 0)
	texts := strings.Split(text, "hysteria2://")
	for _, text := range texts {
		results = append(results, hysteria2PlainRe.FindAllString("hysteria2://"+text, -1)...)
	}

	texts = strings.Split(text, "hy2://")
	for _, text := range texts {
		results = append(results, hy2PlainRe.FindAllString("hy2://"+text, -1)...)
	}
	return results
}
