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
	ErrorNotHysteriaLink          = errors.New("not a correct hysteria link")
)

type Hysteria struct {
	Base
	Auth                 string            `yaml:"auth_str" json:"auth_str"`
	MPorts               string            `yaml:"ports,omitempty" json:"ports,omitempty"`
	Obfs                 string            `yaml:"obfs,omitempty" json:"obfs,omitempty"`
	ALPN                 []string          `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	Protocol             string            `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	UpSpeed              string            `yaml:"up,omitempty" json:"up,omitempty"`
	DownSpeed            string            `yaml:"down,omitempty" json:"down,omitempty"`
	SNI                  string            `yaml:"sni,omitempty" json:"sni,omitempty"`
	SkipCertVerify       bool              `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
}

func (h Hysteria) Identifier() string {
	return net.JoinHostPort(h.Server, strconv.Itoa(h.Port)) + h.Auth
}

func (h Hysteria) String() string {
	data, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return string(data)
}

func (h Hysteria) ToClash() string {
	data, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (h Hysteria) ToSurge() string {
	return ""
}

func (h Hysteria) Clone() Proxy {
	return &h
}

func (h Hysteria) Link() (link string) {
	query := url.Values{}
	if h.Auth != "" {
		query.Set("auth", h.Auth)
	}
	if h.MPorts != "" {
		query.Set("mport", h.MPorts)
	}
	if h.Obfs != "" {
		query.Set("obfs", h.Obfs)
	}
	if len(h.ALPN) > 0 {
		query.Set("alpn", strings.Join(h.ALPN, ","))
	}
	if h.Protocol != "" {
		query.Set("protocol", h.Protocol)
	}
	if h.UpSpeed != "" {
		query.Set("upmbps", h.UpSpeed)
	}
	if h.DownSpeed != "" {
		query.Set("downmbps", h.DownSpeed)
	}
	if h.SNI != "" {
		query.Set("peer", url.QueryEscape(h.SNI))
	}
	if h.SkipCertVerify {
		query.Set("insecure", "1")
	}

	uri := url.URL{
		Scheme:   "hysteria",
		Host:     net.JoinHostPort(h.Server, strconv.Itoa(h.Port)),
		RawQuery: query.Encode(),
		Fragment: h.Name,
	}

	return uri.String()
}

func ParseHysteriaLink(link string) (*Hysteria, error) {
	if !(strings.HasPrefix(link, "hysteria://")) {
		return nil, ErrorNotHysteriaLink
	}

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotHysteriaLink
	}

	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())

	moreInfos := uri.Query()

	auth := moreInfos.Get("auth")
	mports := moreInfos.Get("mport")
	obfs := moreInfos.Get("obfs")
	protocol := moreInfos.Get("protocol")
	upspeed := moreInfos.Get("upmbps")
	downspeed := moreInfos.Get("downmbps")

	sni := moreInfos.Get("peer")
	if sni != "" {
		sni, _ = url.QueryUnescape(sni)
	}

	alpn := make([]string, 0)
	alpnStr := moreInfos.Get("alpn")
	if alpnStr != "" {
		for _, value := range strings.Split(alpnStr, ",") {
			if value == "" {
				continue
			}
			alpn = append(alpn, value)
		}
	}

	skip_certverify := true
	if moreInfos.Get("insecure") == "0" {
		skip_certverify = false
	}

	if port == 0 {
		return nil, ErrorNotTuicLink
	}

	return &Hysteria{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "hysteria",
		},
		Auth:              auth,
		MPorts:            mports,
		Obfs:              obfs,
		ALPN:              alpn,
		Protocol:          protocol,
		UpSpeed:           upspeed,
		DownSpeed:         downspeed,
		SNI:               sni,
		SkipCertVerify:    skip_certverify,
		}, nil
}

var (
	hysteriaPlainRe = regexp.MustCompile("hysteria://([A-Za-z0-9+/_&?=@:%.-])+")
)

func GrepHysteriaLinkFromString(text string) []string {
	results := make([]string, 0)
	texts := strings.Split(text, "hysteria://")
	for _, text := range texts {
		results = append(results, hysteriaPlainRe.FindAllString("hysteria://"+text, -1)...)
	}
	return results
}
