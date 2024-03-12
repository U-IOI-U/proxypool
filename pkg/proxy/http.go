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
	ErrorNotHttpLink = errors.New("not a correct http link")
)

type CHttp struct {
	Base
	UserName       string   `yaml:"username,omitempty" json:"username,omitempty"`
	Password       string   `yaml:"password,omitempty" json:"password,omitempty"`
	TLS            bool     `yaml:"tls,omitempty" json:"tls,omitempty"`
	SkipCertVerify bool     `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
	SNI            string   `yaml:"sni,omitempty" json:"sni,omitempty"`
}

func (t CHttp) Identifier() string {
	return net.JoinHostPort(t.Server, strconv.Itoa(t.Port)) + t.UserName + t.Password
}

func (t CHttp) String() string {
	data, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return string(data)
}

func (t CHttp) ToClash() string {
	data, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (t CHttp) ToSurge() string {
	return ""
}

func (t CHttp) Clone() Proxy {
	return &t
}

func (t CHttp) Link() (link string) {
	query := url.Values{}
	if t.SNI != "" {
		query.Set("sni", url.QueryEscape(t.SNI))
	}

	uri := url.URL{
		Scheme:   "https",
		User:     url.UserPassword(url.QueryEscape(t.UserName), url.QueryEscape(t.Password)),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		RawQuery: query.Encode(),
		Fragment: t.Name,
	}

	return uri.String()
}

func ParseHttpLink(link string) (*CHttp, error) {
	if !strings.HasPrefix(link, "https://") {
		return nil, ErrorNotHttpLink
	}

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotHttpLink
	}

	username := uri.User.Username()
	username, _ = url.QueryUnescape(username)
	password, isSetPass := uri.User.Password()
	if isSetPass == false {
		return nil, ErrorNotHttpLink
	}
	password, _ = url.QueryUnescape(password)
	if len(username) == 0 || len(password) == 0 {
		return nil, ErrorNotHttpLink
	}
	
	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())

	moreInfos := uri.Query()
	sni := moreInfos.Get("sni")
	sni, _ = url.QueryUnescape(sni)

	if port == 0 {
		return nil, ErrorNotHttpLink
	}

	return &CHttp{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "http",
		},
		UserName:       username,
		Password:       password,
		TLS:            true,
		SkipCertVerify: true,
		SNI:            sni,
	}, nil
}

var (
	httpPlainRe = regexp.MustCompile("https://[A-Za-z0-9+/_&=@:%\\[\\].-]+(\\?[A-Za-z0-9+/_&?=@:%.-]+)?")
)

func GrepHttpLinkFromString(text string) []string {
	results := make([]string, 0)
	texts := strings.Split(text, "https://")
	for _, text := range texts {
		results = append(results, httpPlainRe.FindAllString("https://"+text, -1)...)
	}
	return results
}
