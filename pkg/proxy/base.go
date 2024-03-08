package proxy

import (
	"encoding/json"
	"errors"
	"strings"

	"strconv"

	"github.com/u-ioi-u/proxypool/pkg/tool"
)

/* Base implements interface Proxy. It's the basic proxy struct. Vmess etc extends Base*/
type Base struct {
	Name    string `yaml:"name" json:"name" gorm:"index"`
	Server  string `yaml:"server" json:"server" gorm:"index"`
	Type    string `yaml:"type" json:"type" gorm:"index"`
	Country string `yaml:"country,omitempty" json:"country,omitempty" gorm:"index"`
	Port    int    `yaml:"port" json:"port" gorm:"index"`
	UDP     bool   `yaml:"udp,omitempty" json:"udp,omitempty"`
	Useable bool   `yaml:"useable,omitempty" json:"useable,omitempty" gorm:"index"`
}

type TCPOptions struct {
	Type    string  `yaml:"type,omitempty" json:"type,omitempty"`
	Host    string  `yaml:"host,omitempty" json:"host,omitempty"`
	Path    string  `yaml:"path,omitempty" json:"path,omitempty"`
}

type WSOptions struct {
	Path    string            `yaml:"path,omitempty" json:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	// EarlyDataMax    int       `yaml:"max-early-data,omitempty" json:"max-early-data,omitempty"`
	// EarlyDataHeader string    `yaml:"early-data-header-name,omitempty" json:"early-data-header-name,omitempty"`
}

type HTTPOptions struct {
	Method  string              `yaml:"method,omitempty" json:"method,omitempty"`
	Path    []string            `yaml:"path,omitempty" json:"path,omitempty"`
	Headers map[string][]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

type HTTP2Options struct {
	Host []string `yaml:"host,omitempty" json:"host,omitempty"`
	Path string   `yaml:"path,omitempty" json:"path,omitempty"` // 暂只处理一个Path
}

type GrpcOptions struct {
	GrpcServiceName string `yaml:"grpc-service-name,omitempty" json:"grpc-service-name,omitempty"`
	Mode            string `yaml:"mode,omitempty" json:"mode,omitempty"`
}

type QUICOptions struct {
	Type     string  `yaml:"type,omitempty" json:"type,omitempty"`
	Security string  `yaml:"security,omitempty" json:"security,omitempty"`
	Key      string  `yaml:"key,omitempty" json:"key,omitempty"`
}

type RealityOptions struct {
	PublicKey   string   `yaml:"public-key,omitempty" json:"public-key,omitempty"`
	ShortID     string   `yaml:"short-id,omitempty" json:"short-id,omitempty"`
	SpiderX     string   `yaml:"spiderx,omitempty" json:"spiderx,omitempty"`
}

// TypeName() Get specific proxy type
func (b *Base) TypeName() string {
	if b.Type == "" {
		return "unknown"
	}
	return b.Type
}

// SetName() to a proxy
func (b *Base) SetName(name string) {
	b.Name = name
}

func (b *Base) AddToName(name string) {
	b.Name = b.Name + name
}

func (b *Base) AddBeforeName(name string) {
	b.Name = name + b.Name
}

// SetIP() to a proxy
func (b *Base) SetIP(ip string) {
	b.Server = ip
}

// BaseInfo() get basic info struct of a proxy
func (b *Base) BaseInfo() *Base {
	return b
}

// Clone() returns a new basic proxy
func (b *Base) Clone() Base {
	c := *b
	return c
}

// SetUseable() set Base info "Useable" (true or false)
func (b *Base) SetUseable(useable bool) {
	b.Useable = useable
}

// SetUseable() set Base info "Country" (string)
func (b *Base) SetCountry(country string) {
	b.Country = country
}

type Proxy interface {
	String() string
	ToClash() string
	ToSurge() string
	Link() string
	Identifier() string
	SetName(name string)
	AddToName(name string)
	SetIP(ip string)
	TypeName() string //ss ssr vmess trojan
	BaseInfo() *Base
	Clone() Proxy
	SetUseable(useable bool)
	SetCountry(country string)
}

func ParseProxyFromLink(link string) (p Proxy, err error) {
	if strings.HasPrefix(link, "ssr://") {
		p, err = ParseSSRLink(link)
	} else if strings.HasPrefix(link, "vmess://") {
		p, err = ParseVmessLink(link)
	} else if strings.HasPrefix(link, "ss://") {
		p, err = ParseSSLink(link)
	} else if strings.HasPrefix(link, "trojan://") {
		p, err = ParseTrojanLink(link)
	} else if strings.HasPrefix(link, "vless://") {
		p, err = ParseVlessLink(link)
	} else if strings.HasPrefix(link, "https://") {
		p, err = ParseHttpLink(link)
	} else if strings.HasPrefix(link, "snell://") {
		p, err = ParseSnellLink(link)
	} else if strings.HasPrefix(link, "tuic://") {
		p, err = ParseTuicLink(link)
	} else if strings.HasPrefix(link, "hysteria2://") || strings.HasPrefix(link, "hy2://") {
		p, err = ParseHysteria2Link(link)
	} else if strings.HasPrefix(link, "hysteria://") {
		p, err = ParseHysteriaLink(link)
	}
	if err != nil || p == nil {
		return nil, errors.New("link parse failed")
	}
	return
}

func ParseProxyFromClashProxy(p map[string]interface{}) (proxy Proxy, err error) {
	if p == nil || len(p) == 0 || p["type"] == nil {
		// map 没有初始化???
		return nil, err
	}

	p["name"] = ""
	fixProxyFromClashProxy(p)
	pjson, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	switch p["type"].(string) {
	case "ss":
		var proxy Shadowsocks
		err := json.Unmarshal(pjson, &proxy)
		if err != nil {
			return nil, err
		}
		return &proxy, nil
	case "ssr":
		var proxy ShadowsocksR
		err := json.Unmarshal(pjson, &proxy)
		if err != nil {
			return nil, err
		}
		return &proxy, nil
	case "vmess":
		var proxy Vmess
		err := json.Unmarshal(pjson, &proxy)
		if err != nil {
			return nil, err
		}
		return &proxy, nil
	case "trojan":
		var proxy Trojan
		err := json.Unmarshal(pjson, &proxy)
		if err != nil {
			return nil, err
		}
		return &proxy, nil
	case "http":
		var proxy CHttp
		err := json.Unmarshal(pjson, &proxy)
		if err != nil {
			return nil, err
		}
		return &proxy, nil
	case "vless": // Clash目前不支持Vless格式, 万一呢
		var proxy Vless
		err := json.Unmarshal(pjson, &proxy)
		if err != nil {
			return nil, err
		}
		return &proxy, nil
	case "snell":
		var proxy Snell
		err := json.Unmarshal(pjson, &proxy)
		if err != nil {
			return nil, err
		}
		return &proxy, nil
	case "tuic":
		var proxy Tuic
		err := json.Unmarshal(pjson, &proxy)
		if err != nil {
			return nil, err
		}
		return &proxy, nil
	case "hysteria":
		var proxy Hysteria
		err := json.Unmarshal(pjson, &proxy)
		if err != nil {
			return nil, err
		}
		return &proxy, nil
	case "hysteria2":
		var proxy Hysteria2
		err := json.Unmarshal(pjson, &proxy)
		if err != nil {
			return nil, err
		}
		return &proxy, nil
	}
	return nil, errors.New("clash json parse failed")
}

func fixProxyFromClashProxy(p map[string]any) {
	// 修正类型错误
	switch p["type"].(string) {
	case "http":
		if _, ok := p["username"]; ok {
			if _, ok := p["username"].(string); !ok {
				if _, ok := p["username"].(int); ok {
					p["username"] = strconv.Itoa(p["username"].(int))
				}
			}
		}
	}
}

func CheckProxyValid(b Proxy) bool {
	if !tool.CheckPort(b.BaseInfo().Port) {
		return false
	}
	switch b.TypeName() {
	case "ss":
		ss := b.(*Shadowsocks)
		if !tool.CheckInList(SSCipherList, ss.Cipher) {
			return false
		}
		break
	case "ssr":
		break
	case "vmess":
		vmess := b.(*Vmess)
		if !tool.CheckVmessUUID(vmess.UUID) {
			return false
		}
		break
	case "trojan":
		break
	case "http":
		break
	case "vless":
		break
	case "snell":
		break
	case "tuic":
		break
	case "hysteria":
		break
	case "hysteria2":
		break
	}
	return true
}

func FixProxyValue(b Proxy) Proxy {
	switch b.TypeName() {
	case "ss":
		break
	case "ssr":
		break
	case "vmess":
		vmess := b.(*Vmess)
		switch vmess.Network {
		case "h2":
		case "grpc":
			vmess.TLS = true
			break
		}
		break
	case "trojan":
		break
	case "http":
		break
	case "vless":
		vless := b.(*Vless)
		if vless.Flow == "xtls-rprx-direct" || vless.Flow == "xtls-rprx-direct-udp443" {
			vless.Flow = ""
		}
		vless.TLS = true
		break
	case "snell":
		break
	case "tuic":
		break
	case "hysteria":
		break
	case "hysteria2":
		break
	}
	return b
}

func GoodNodeThatClashUnsupported(b Proxy) bool {
	switch b.TypeName() {
	case "ss":
		ss := b.(*Shadowsocks)
		if ss != nil {
			if ss.Cipher == "none" || ss.Cipher == "2022-blake3-aes-128-gcm" || ss.Cipher == "2022-blake3-aes-256-gcm" || ss.Cipher == "2022-blake3-chacha20-poly1305" {
				return true
			}
		}
		break
	// case "ssr":
	// 	ssr := b.(*ShadowsocksR)
	// 	if ssr == nil {
	// 		return false
	// 	}
	// 	return true
	}
	return false
}
