package proxy

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	// "regexp"
	"strconv"
	"strings"
)

var (
	ErrorNotSnellLink          = errors.New("not a correct snell link")
)

type Snell struct {
	Base
	Password       string            `yaml:"psk" json:"psk"`
	Version        int               `yaml:"version,omitempty" json:"version,omitempty"`
	ObfsOpts       map[string]string `yaml:"obfs-opts,omitempty" json:"obfs-opts,omitempty"`
}

func (s Snell) Identifier() string {
	return net.JoinHostPort(s.Server, strconv.Itoa(s.Port)) + s.Password
}

func (s Snell) String() string {
	data, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(data)
}

func (s Snell) ToClash() string {
	data, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (s Snell) ToSurge() string {
	return ""
}

func (s Snell) Clone() Proxy {
	return &s
}

func (s Snell) Link() (link string) {
	query := url.Values{}
	if s.Version != 0 {
		query.Set("version",  strconv.Itoa(s.Version))
	}
	if len(s.ObfsOpts) != 0 {
		if mode, ok := s.ObfsOpts["mode"]; ok {
			query.Set("mode", url.QueryEscape(mode))
		}
		if host, ok := s.ObfsOpts["host"]; ok {
			query.Set("host", url.QueryEscape(host))
		}
	}

	uri := url.URL{
		Scheme:   "snell",
		User:     url.User(url.QueryEscape(s.Password)),
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		RawQuery: query.Encode(),
		Fragment: s.Name,
	}

	return uri.String()
}

func ParseSnellLink(link string) (*Snell, error) {
	if !strings.HasPrefix(link, "snell://") {
		return nil, ErrorNotSnellLink
	}

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotSnellLink
	}

	password := uri.User.Username()
	password, _ = url.QueryUnescape(password)
	if len(password) == 0 {
		return nil, ErrorNotSnellLink
	}

	server := uri.Hostname()

	port, _ := strconv.Atoi(uri.Port())
	if port == 0 {
		return nil, ErrorNotSnellLink
	}

	moreInfos := uri.Query()

	version := 0
	_version := moreInfos.Get("version")
	if _version != "" {
		version, _ = strconv.Atoi(_version)
	}

	obfsOpts := make(map[string]string)

	mode := moreInfos.Get("mode")
	mode, _ = url.QueryUnescape(mode)
	if mode != "" {
		obfsOpts["mode"] = mode
	}

	host := moreInfos.Get("host")
	host, _ = url.QueryUnescape(host)
	if host != "" {
		obfsOpts["host"] = host
	}

	return &Snell{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "snell",
			UDP:    false,
		},
		Password:       password,
		Version:        version,
		ObfsOpts:       obfsOpts,
	}, nil
}
