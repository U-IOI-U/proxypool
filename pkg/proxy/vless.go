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
	HTTPOpts       *HTTPOptions      `yaml:"http-opts,omitempty" json:"http-opts,omitempty"`
	H2Opts         *HTTP2Options     `yaml:"h2-opts,omitempty" json:"h2-opts,omitempty"`
	GrpcOpts       *GrpcOptions      `yaml:"grpc-opts,omitempty" json:"grpc-opts,omitempty"`
	WSOpts         *WSOptions        `yaml:"ws-opts,omitempty" json:"ws-opts,omitempty"`
	QuicOpts       *QUICOptions      `yaml:"quic-opts,omitempty" json:"quic-opts,omitempty"`
	RealityOpts    *RealityOptions   `yaml:"reality-opts,omitempty" json:"reality-opts,omitempty"`
	KcpOpts        *KCPOptions       `yaml:"kcp-opts,omitempty" json:"kcp-opts,omitempty"`
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
				query.Set("serviceName", url.QueryEscape(v.GrpcOpts.GrpcServiceName))
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
	case "kcp":
		query.Set("type", v.Network)
		if v.KcpOpts != nil {
			if v.KcpOpts.Type != "" {
				query.Set("headerType", v.KcpOpts.Type)
			}
			if v.KcpOpts.Seed != "" {
				query.Set("seed", v.KcpOpts.Seed)
			}
		}
		break
	case "http":
		query.Set("type", "tcp")
		query.Set("headerType", "http")
		if v.HTTPOpts != nil {
			if len(v.HTTPOpts.Path) > 0 {
				query.Set("path", url.QueryEscape(v.HTTPOpts.Path[0]))
			}
			if len(v.HTTPOpts.Headers) > 0 {
				if headers, ok := v.HTTPOpts.Headers["Host"]; ok {
					if len(headers) > 0 {
						query.Set("host", url.QueryEscape(headers[0]))
					}
				}
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
			if v.TcpOpts.Path != "" {
				query.Set("path", url.QueryEscape(v.TcpOpts.Path))
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

	flow, _ := ParseProxyFlow(moreInfos.Get("flow"))

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

	alpn := ParseProxyALPN(moreInfos.Get("alpn"))

	fingerprint := ParseProxyFingerPrint(moreInfos.Get("fp"))

	var tcpopts *TCPOptions
	var httpopts *HTTPOptions
	var wsopts *WSOptions
	var h2opts *HTTP2Options
	var grpcopts *GrpcOptions
	var quicopts *QUICOptions
	var kcpopts *KCPOptions
	transformType, _ := ParseProxyNetwork(moreInfos.Get("type"))
	switch transformType {
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
	case "kcp":
		headertype := moreInfos.Get("headerType")
		seed := moreInfos.Get("seed")
		if !(headertype == "" && seed == "") {
			kcpopts = &KCPOptions{
				Type: headertype,
				Seed: seed,
			}
		}
		break
	case "tcp": /* default */
	default:
		host := moreInfos.Get("host")
		if host != "" {
			host, _ = url.QueryUnescape(host)
		}
		path := moreInfos.Get("path")
		if path != "" {
			path, _ = url.QueryUnescape(path)
		}

		headertype := moreInfos.Get("headerType")
		if headertype == "http" {
			transformType = "http"
			httpopts = &HTTPOptions{
				Method: "GET",
			}
			if host != "" {
				httpopts.Headers = make(map[string][]string, 1)
				httpopts.Headers["Host"] = []string{host}
			}
			if path != "" {
				httpopts.Path = []string{path}
			} else {
				httpopts.Path = []string{"/"}
			}
		} else {
			transformType = "tcp"
			if !(host == "" && (headertype == "" || headertype == "none") && path == "") {
				tcpopts = &TCPOptions{
					Host:   host,
					Type:   headertype,
					Path:   path,
				}
			}
			if tcpopts == nil {
				transformType = ""
			}
		}
		break
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
		HTTPOpts:       httpopts,
		H2Opts:         h2opts,
		GrpcOpts:       grpcopts,
		WSOpts:         wsopts,
		QuicOpts:       quicopts,
		RealityOpts:    realityopts,
		KcpOpts:        kcpopts,
	}, nil
}

var (
	vlessPlainRe = regexp.MustCompile("vless://[A-Za-z0-9+/_&=@:%\\[\\].-]+(\\?[A-Za-z0-9+/_&?=@:%.-]+)?")
)

func GrepVlessLinkFromString(text string) []string {
	results := make([]string, 0)
	texts := strings.Split(text, "vless://")
	for _, text := range texts {
		results = append(results, vlessPlainRe.FindAllString("vless://"+text, -1)...)
	}
	return results
}
