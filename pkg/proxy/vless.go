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
	Encryption     string            `yaml:"encryption,omitempty" json:"encryption,omitempty"`
	ALPN           []string          `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	SNI            string            `yaml:"servername,omitempty" json:"servername,omitempty"`
	SkipCertVerify bool              `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
	Network        string            `yaml:"network,omitempty" json:"network,omitempty"`
	CFingerPrint   string            `yaml:"client-fingerprint,omitempty" json:"client-fingerprint,omitempty"`
	Flow           string            `yaml:"flow,omitempty" json:"flow,omitempty"`
	TLS            bool              `yaml:"tls,omitempty" json:"tls,omitempty"`

	TcpOpts        *TCPOptions       `yaml:"tcp-opts,omitempty" json:"tcp-opts,omitempty"`
	H2Opts         *HTTP2Options     `yaml:"h2-opts,omitempty" json:"h2-opts,omitempty"`
	GrpcOpts       *GrpcOptions      `yaml:"grpc-opts,omitempty" json:"grpc-opts,omitempty"`
	WSOpts         *WSOptions        `yaml:"ws-opts,omitempty" json:"ws-opts,omitempty"`
	QuicOpts       *QUICOptions      `yaml:"quic-opts,omitempty" json:"quic-opts,omitempty"`
	RealityOpts    *RealityOptions   `yaml:"reality-opts,omitempty" json:"reality-opts,omitempty"`
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
	if v.Encryption != "" {
		query.Set("encryption", v.Encryption)
	} else {
		query.Set("encryption", "none")
	}
	if v.Flow != "" {
		query.Set("flow", v.Flow)
	}
	if v.RealityOpts != nil {
		query.Set("security", "reality")
		if v.RealityOpts.PublicKey != "" {
			query.Set("pbk", v.RealityOpts.PublicKey)
		}
		if v.RealityOpts.ShortID != "" {
			query.Set("sid", v.RealityOpts.ShortID)
		}
		if v.RealityOpts.SpiderX != "" {
			query.Set("spx", v.RealityOpts.SpiderX)
		}
	} else {
		query.Set("security", "tls")
	}
	if v.SNI != "" {
		query.Set("sni", url.QueryEscape(v.SNI))
	}
	if len(v.ALPN) > 0 {
		query.Set("alpn", strings.Join(v.ALPN, ","))
	}
	if v.CFingerPrint != "" {
		query.Set("fp", v.CFingerPrint)
	}

	switch v.Network {
	case "ws":
		query.Set("type", v.Network)
		if v.WSOpts != nil {
			if v.WSOpts.Path != "" {
				query.Set("path", url.QueryEscape(v.WSOpts.Path))
			}
			if len(v.WSOpts.Headers) > 0 {
				query.Set("host", url.QueryEscape(v.WSOpts.Headers["Host"]))
			}
		}
		break
	case "grpc":
		query.Set("type", v.Network)
		if v.GrpcOpts != nil {
			if v.GrpcOpts.GrpcServiceName != "" {
				query.Set("type", url.QueryEscape(v.GrpcOpts.GrpcServiceName))
			}
			if v.GrpcOpts.Mode != "" {
				query.Set("mode", v.GrpcOpts.Mode)
			}
		}
		break
	case "h2":
		query.Set("type", "http")
		if v.H2Opts != nil {
			if len(v.H2Opts.Host) > 0 {
				query.Set("host", url.QueryEscape(v.H2Opts.Host[0]))
			}
			if v.H2Opts.Path != "" {
				query.Set("path", url.QueryEscape(v.H2Opts.Path))
			}
		}
		break
	case "quic":
		query.Set("type", v.Network)
		if v.QuicOpts != nil {
			if v.QuicOpts.Type != "" {
				query.Set("headerType", v.QuicOpts.Type)
			}
			if v.QuicOpts.Security != "" {
				query.Set("quicSecurity", v.QuicOpts.Security)
			}
			if v.QuicOpts.Key != "" {
				query.Set("key", v.QuicOpts.Key)
			}
		}
		break
	case "tcp":
	default:
		if v.TcpOpts != nil {
			query.Set("type", "tcp")
			if v.TcpOpts.Type != "" {
				query.Set("headerType", v.TcpOpts.Type)
			}
			if v.TcpOpts.Host != "" {
				query.Set("host", url.QueryEscape(v.TcpOpts.Host))
			}
		}
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

	encryption := moreInfos.Get("encryption")
	if encryption == "none" {
		encryption = ""
	}

	flow := moreInfos.Get("flow")
	if flow == "xtls-rprx-direct" {
		flow = ""
	}

	var realityopts *RealityOptions
	security := moreInfos.Get("security")
	if security == "reality" {
		pbk := moreInfos.Get("pbk")
		sid := moreInfos.Get("sid")
		spx := moreInfos.Get("spx")
		if !(pbk == "" && sid == "" && spx == "") {
			realityopts = &RealityOptions{
				PublicKey: pbk,
				ShortID:   sid,
				SpiderX:   spx,
			}
		}
	}

	sni := moreInfos.Get("sni")
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

	fingerprint := moreInfos.Get("fp")
	if fingerprint == "随机" {
		fingerprint = "random"
	}

	var tcpopts *TCPOptions
	var wsopts *WSOptions
	var h2opts *HTTP2Options
	var grpcopts *GrpcOptions
	var quicopts *QUICOptions
	transformType := moreInfos.Get("type")
	switch transformType {
	case "tcp": /* default */
		host := moreInfos.Get("host")
		if host != "" {
			host, _ = url.QueryUnescape(host)
		}
		headertype := moreInfos.Get("headerType")
		if !(host == "" && (headertype == "" || headertype == "none")) {
			tcpopts = &TCPOptions{
				Host:   host,
				Type:   headertype,
			}
		}
		if tcpopts == nil {
			transformType = ""
		}
		break
	case "ws":
		host := moreInfos.Get("host")
		if host != "" {
			host, _ = url.QueryUnescape(host)
		}
		path := moreInfos.Get("path")
		if path != "" {
			path, _ = url.QueryUnescape(path)
		}
		if !(host == "" && path == "") {
			wsopts = &WSOptions{
				Path: path,
			}
			if host != "" {
				wsopts.Headers = make(map[string]string, 0)
				wsopts.Headers["Host"] = host
			}
		}
		break
	case "grpc":
		srvname := moreInfos.Get("serviceName")
		if srvname != "" {
			srvname, _ = url.QueryUnescape(srvname)
		}
		mode := moreInfos.Get("mode")
		if !(srvname == "" && mode == "") {
			grpcopts = &GrpcOptions{
				GrpcServiceName: srvname,
				Mode:            mode,
			}
		}
		break
	case "http": /* h2 */
		host := moreInfos.Get("host")
		if host != "" {
			host, _ = url.QueryUnescape(host)
		}
		path := moreInfos.Get("path")
		if path != "" {
			path, _ = url.QueryUnescape(path)
		}
		if !(host == "" && path == "") {
			h2opts = &HTTP2Options{
				Path: path,
			}
			if host != "" {
				h2opts.Host = make([]string, 0)
				h2opts.Host = append(h2opts.Host, host)
			}
		}
		transformType = "h2"
		break
	case "quic":
		headertype := moreInfos.Get("headerType")
		security := moreInfos.Get("quicSecurity")
		key := moreInfos.Get("key")
		if !(headertype == "" && security == "" && key == "") {
			quicopts = &QUICOptions{
				Type:     headertype,
				Security: security,
				Key:      key,
			}
		}
		break
	default:
	}
	// Port
	if port == 0 {
		return nil, ErrorNotVlessLink
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
		Encryption:     encryption,
		ALPN:           alpn,
		Network:        transformType,
		SNI:            sni,
		CFingerPrint:   fingerprint,
		Flow:           flow,
		TLS:            true,
		SkipCertVerify: true,

		TcpOpts:        tcpopts,
		H2Opts:         h2opts,
		GrpcOpts:       grpcopts,
		WSOpts:         wsopts,
		QuicOpts:       quicopts,
		RealityOpts:    realityopts,
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
