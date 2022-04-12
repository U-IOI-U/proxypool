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
	ErrorNotVlessLink          = errors.New("not a correct vless link")
)

type Vless struct {
	Base
	UUID           string            `yaml:"uuid" json:"uuid"`
	Network        string            `yaml:"network,omitempty" json:"network,omitempty"`
	WSPath         string            `yaml:"ws-path,omitempty" json:"ws-path,omitempty"`
	ServerName     string            `yaml:"servername,omitempty" json:"servername,omitempty"`
	WSHeaders      map[string]string `yaml:"ws-headers,omitempty" json:"ws-headers,omitempty"`
	// WSOpts         WSOptions         `yaml:"ws-opts,omitempty" json:"ws-opts,omitempty"`
	Flow           string            `yaml:"flow,omitempty" json:"flow,omitempty"`
	TLS            bool              `yaml:"tls,omitempty" json:"tls,omitempty"`
	SkipCertVerify bool              `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
}

func (v Vless) Identifier() string {
	return net.JoinHostPort(v.Server, strconv.Itoa(v.Port)) + v.UUID
}

func (v Vless) String() string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

func (v Vless) ToClash() string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (v Vless) ToSurge() string {
	return ""
}

func (v Vless) Clone() Proxy {
	return &v
}

func (v Vless) Link() (link string) {
	query := url.Values{}
	if v.ServerName != "" {
		query.Set("sni", url.QueryEscape(v.ServerName))
	}
	if v.Network != "" {
		query.Set("type", url.QueryEscape(v.Network))
	}
	if v.WSPath != "" {
		query.Set("path", url.QueryEscape(v.WSPath))
	}
	if v.Flow != "" {
		query.Set("flow", url.QueryEscape(v.Flow))
		query.Set("security", url.QueryEscape("xtls"))
	} else {
		query.Set("security", url.QueryEscape("tls"))
	}
	if _, ok := v.WSHeaders["Host"]; ok {
		query.Set("host", url.QueryEscape(v.WSHeaders["Host"]))
	}

	uri := url.URL{
		Scheme:   "vless",
		User:     url.User(url.QueryEscape(v.UUID)),
		Host:     net.JoinHostPort(v.Server, strconv.Itoa(v.Port)),
		RawQuery: query.Encode(),
		Fragment: v.Name,
	}

	return uri.String()
}

func ParseVlessLink(link string) (*Vless, error) {
	if !strings.HasPrefix(link, "vless") {
		return nil, ErrorNotVlessLink
	}

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotVlessLink
	}

	uuid := uri.User.Username()
	uuid, _ = url.QueryUnescape(uuid)

	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())

	moreInfos := uri.Query()
	sni := moreInfos.Get("sni")
	sni, _ = url.QueryUnescape(sni)
	transformType := moreInfos.Get("type")
	transformType, _ = url.QueryUnescape(transformType)
	// security := moreInfos.Get("security")
	// security, _ = url.QueryUnescape(security)
	host := moreInfos.Get("host")
	host, _ = url.QueryUnescape(host)
	path := moreInfos.Get("path")
	path, _ = url.QueryUnescape(path)
	// encryption := moreInfos.Get("encryption")
	// encryption, _ = url.QueryUnescape(encryption)
	// headerType := moreInfos.Get("headerType")
	// headerType, _ = url.QueryUnescape(headerType)
	flow := moreInfos.Get("flow")
	flow, _ = url.QueryUnescape(flow)

	// Port
	if port == 0 {
		return nil, ErrorNotVlessLink
	}
	// TLS
	// tls := true
	// if security == "tls" || security == "xtls" {
	// 	tls = true
	// } else {
	// 	tls = false
	// }
	wsHeaders := make(map[string]string)
	if host != "" {
		wsHeaders["Host"] = host
	}

	return &Vless{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "vless",
			UDP:    true,
		},
		UUID:           uuid,
		Network:        transformType,
		WSPath:         path,
		ServerName:     sni,
		WSHeaders:      wsHeaders,
		Flow:           flow,
		TLS:            true,
		SkipCertVerify: true,
	}, nil
}

var (
	vlessPlainRe = regexp.MustCompile("vless://([A-Za-z0-9+/_&?=@:%.-])+")
)

func GrepVlessLinkFromString(text string) []string {
	results := make([]string, 0)
	texts := strings.Split(text, "vless://")
	for _, text := range texts {
		results = append(results, vlessPlainRe.FindAllString("vless://"+text, -1)...)
	}
	return results
}
