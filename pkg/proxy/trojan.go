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
	ErrorNotTrojanink = errors.New("not a correct trojan link")
)

// TODO unknown field
// Link: host, path
// Trojan: Network GrpcOpts

type Trojan struct {
	Base
	Password       string   `yaml:"password" json:"password"`
	ALPN           []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	SNI            string   `yaml:"sni,omitempty" json:"sni,omitempty"`
	SkipCertVerify bool     `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`
	Network        string   `yaml:"network,omitempty" json:"network,omitempty"`
	CFingerPrint   string   `yaml:"client-fingerprint,omitempty" json:"client-fingerprint,omitempty"`
	Flow           string   `yaml:"flow,omitempty" json:"flow,omitempty"`

	TcpOpts        *TCPOptions     `yaml:"tcp-opts,omitempty" json:"tcp-opts,omitempty"`
	HTTPOpts       *HTTPOptions    `yaml:"http-opts,omitempty" json:"http-opts,omitempty"`
	H2Opts         *HTTP2Options   `yaml:"h2-opts,omitempty" json:"h2-opts,omitempty"`
	GrpcOpts       *GrpcOptions    `yaml:"grpc-opts,omitempty" json:"grpc-opts,omitempty"`
	WSOpts         *WSOptions      `yaml:"ws-opts,omitempty" json:"ws-opts,omitempty"`
	QuicOpts       *QUICOptions    `yaml:"quic-opts,omitempty" json:"quic-opts,omitempty"`
	RealityOpts    *RealityOptions `yaml:"reality-opts,omitempty" json:"reality-opts,omitempty"`
	KcpOpts        *KCPOptions     `yaml:"kcp-opts,omitempty" json:"kcp-opts,omitempty"`
}

/**
  - name: "trojan"
    type: trojan
    server: server
    port: 443
    password: yourpsk
    # udp: true
    # sni: example.com # aka server name
    # alpn:
    #   - h2
    #   - http/1.1
    # skip-cert-verify: true
*/

func (t Trojan) Identifier() string {
	return net.JoinHostPort(t.Server, strconv.Itoa(t.Port)) + t.Password
}

func (t Trojan) String() string {
	data, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return string(data)
}

func (t Trojan) ToClash() string {
	data, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (t Trojan) ToSurge() string {
	return ""
}

func (t Trojan) Clone() Proxy {
	return &t
}

// https://p4gefau1t.github.io/trojan-go/developer/url/
func (t Trojan) Link() (link string) {
	query := url.Values{}
	if t.Flow != "" {
		query.Set("flow", t.Flow)
	}
	if t.RealityOpts != nil {
		query.Set("security", "reality")
		if t.RealityOpts.PublicKey != "" {
			query.Set("pbk", t.RealityOpts.PublicKey)
		}
		if t.RealityOpts.ShortID != "" {
			query.Set("sid", t.RealityOpts.ShortID)
		}
		if t.RealityOpts.SpiderX != "" {
			query.Set("spx", t.RealityOpts.SpiderX)
		}
	} else {
		query.Set("security", "tls")
	}
	if t.SNI != "" {
		query.Set("sni", t.SNI)
	}
	if len(t.ALPN) > 0 {
		query.Set("alpn", strings.Join(t.ALPN, ","))
	}
	if t.CFingerPrint != "" {
		query.Set("fp", t.CFingerPrint)
	}

	switch t.Network {
	case "ws":
		query.Set("type", t.Network)
		if t.WSOpts != nil {
			if t.WSOpts.Path != "" {
				query.Set("path", t.WSOpts.Path)
			}
			if len(t.WSOpts.Headers) > 0 {
				query.Set("host", t.WSOpts.Headers["Host"])
			}
		}
		break
	case "grpc":
		query.Set("type", t.Network)
		if t.GrpcOpts != nil {
			if t.GrpcOpts.GrpcServiceName != "" {
				query.Set("serviceName", t.GrpcOpts.GrpcServiceName)
			}
			if t.GrpcOpts.Mode != "" {
				query.Set("mode", t.GrpcOpts.Mode)
			}
		}
		break
	case "h2": /* http2 */
		query.Set("type", "http")
		if t.H2Opts != nil {
			if len(t.H2Opts.Host) > 0 {
				query.Set("host", t.H2Opts.Host[0])
			}
			if t.H2Opts.Path != "" {
				query.Set("path", t.H2Opts.Path)
			}
		}
		break
	case "quic":
		query.Set("type", t.Network)
		if t.QuicOpts != nil {
			if t.QuicOpts.Type != "" {
				query.Set("headerType", t.QuicOpts.Type)
			}
			if t.QuicOpts.Security != "" {
				query.Set("quicSecurity", t.QuicOpts.Security)
			}
			if t.QuicOpts.Key != "" {
				query.Set("key", t.QuicOpts.Key)
			}
		}
		break
	case "kcp":
		query.Set("type", t.Network)
		if t.KcpOpts != nil {
			if t.KcpOpts.Type != "" {
				query.Set("headerType", t.KcpOpts.Type)
			}
			if t.KcpOpts.Seed != "" {
				query.Set("seed", t.KcpOpts.Seed)
			}
		}
		break
	case "http":
		query.Set("type", "tcp")
		query.Set("headerType", "http")
		if t.HTTPOpts != nil {
			if len(t.HTTPOpts.Path) > 0 {
				query.Set("path", t.HTTPOpts.Path[0])
			}
			if len(t.HTTPOpts.Headers) > 0 {
				if headers, ok := t.HTTPOpts.Headers["Host"]; ok {
					if len(headers) > 0 {
						query.Set("host", headers[0])
					}
				}
			}
		}
		break
	// case "tcp":
	default:
		if t.TcpOpts != nil {
			query.Set("type", "tcp")
			if t.TcpOpts.Type != "" {
				query.Set("headerType", t.TcpOpts.Type)
			}
			if t.TcpOpts.Host != "" {
				query.Set("host", t.TcpOpts.Host)
			}
			if t.TcpOpts.Path != "" {
				query.Set("path", t.TcpOpts.Path)
			}
		}
	}

	uri := url.URL{
		Scheme:   "trojan",
		User:     url.User(url.QueryEscape(t.Password)),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		RawQuery: query.Encode(),
		Fragment: t.Name,
	}

	return uri.String()
}

func ParseTrojanLink(link string) (*Trojan, error) {
	if !strings.HasPrefix(link, "trojan://") && !strings.HasPrefix(link, "trojan-go://") {
		return nil, ErrorNotTrojanink
	}

	/**
	trojan-go://
	    $(trojan-password)
	    @
	    trojan-host
	    :
	    port
	/?
	    sni=$(tls-sni.com)&
	    type=$(original|ws|h2|h2+ws)&
	        host=$(websocket-host.com)&
	        path=$(/websocket/path)&
	    encryption=$(ss;aes-256-gcm;ss-password)&
	    plugin=$(...)
	#$(descriptive-text)
	*/

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotSSLink
	}

	password := uri.User.Username()
	password, _ = url.QueryUnescape(password)

	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())

	moreInfos := uri.Query()

	flow := moreInfos.Get("flow")

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

	alpn := ParseProxyALPN(moreInfos.Get("alpn"))

	fingerprint := moreInfos.Get("fp")

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
		path := LoopQueryUnescape(moreInfos.Get("path"))
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
		srvname := LoopQueryUnescape(moreInfos.Get("serviceName"))
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
		path := moreInfos.Get("path")
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
	// case "tcp": /* default */
	default:
		host := moreInfos.Get("host")
		path := moreInfos.Get("path")
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

	if port == 0 {
		return nil, ErrorNotTrojanink
	}

	return &Trojan{
		Base: Base{
			Name:   "",
			Server: server,
			Port:   port,
			Type:   "trojan",
			UDP:    true,
		},
		Password:       password,
		ALPN:           alpn,
		SNI:            sni,
		SkipCertVerify: true,
		Network:        transformType,
		CFingerPrint:   fingerprint,
		Flow:           flow,

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
	trojanPlainRe = regexp.MustCompile("trojan(-go)?://[A-Za-z0-9+/_&=@:%\\[\\].-]+(\\?[A-Za-z0-9+/_&?=@:%.-]+)?")
)

func GrepTrojanLinkFromString(text string) []string {
	results := make([]string, 0)
	if !strings.Contains(text, "trojan://") {
		return results
	}
	texts := strings.Split(text, "trojan://")
	for _, text := range texts {
		results = append(results, trojanPlainRe.FindAllString("trojan://"+text, -1)...)
	}
	return results
}
