package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/u-ioi-u/proxypool/pkg/tool"
)

var (
	ErrorNotVmessLink          = errors.New("not a correct vmess link")
	ErrorVmessPayloadParseFail = errors.New("vmess link payload parse failed")
)

type Vmess struct {
	Base
	UUID           string       `yaml:"uuid" json:"uuid"`
	AlterID        int          `yaml:"alterId" json:"alterId"`
	Cipher         string       `yaml:"cipher" json:"cipher"`
	Network        string       `yaml:"network,omitempty" json:"network,omitempty"`
	CFingerPrint   string       `yaml:"client-fingerprint,omitempty" json:"client-fingerprint,omitempty"`
	ALPN           []string     `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	SNI            string       `yaml:"servername,omitempty" json:"servername,omitempty"`
	TLS            bool         `yaml:"tls,omitempty" json:"tls,omitempty"`
	SkipCertVerify bool         `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`

	TcpOpts        *TCPOptions   `yaml:"tcp-opts,omitempty" json:"tcp-opts,omitempty"`
	HTTPOpts       *HTTPOptions  `yaml:"http-opts,omitempty" json:"http-opts,omitempty"`
	H2Opts         *HTTP2Options `yaml:"h2-opts,omitempty" json:"h2-opts,omitempty"`
	GrpcOpts       *GrpcOptions  `yaml:"grpc-opts,omitempty" json:"grpc-opts,omitempty"`
	WSOpts         *WSOptions    `yaml:"ws-opts,omitempty" json:"ws-opts,omitempty"`
	QuicOpts       *QUICOptions  `yaml:"quic-opts,omitempty" json:"quic-opts,omitempty"`
	KcpOpts        *KCPOptions   `yaml:"kcp-opts,omitempty" json:"kcp-opts,omitempty"`
	SplitHttpOpts  *SplitHttpOptions `yaml:"splithttp-opts,omitempty" json:"splithttp-opts,omitempty"`
}

func (v *Vmess) UnmarshalJSON(data []byte) error {
	tmp := struct {
		Base
		UUID           string            `yaml:"uuid" json:"uuid"`
		AlterID        int               `yaml:"alterId" json:"alterId"`
		Cipher         string            `yaml:"cipher" json:"cipher"`
		Network        string            `yaml:"network,omitempty" json:"network,omitempty"`
		CFingerPrint   string            `yaml:"client-fingerprint,omitempty" json:"client-fingerprint,omitempty"`
		ALPN           []string          `yaml:"alpn,omitempty" json:"alpn,omitempty"`
		SNI            string            `yaml:"servername,omitempty" json:"servername,omitempty"`
		TLS            bool              `yaml:"tls,omitempty" json:"tls,omitempty"`
		SkipCertVerify bool              `yaml:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`

		TcpOpts        *TCPOptions       `yaml:"tcp-opts,omitempty" json:"tcp-opts,omitempty"`
		HTTPOpts       *HTTPOptions      `yaml:"http-opts,omitempty" json:"http-opts,omitempty"`
		H2Opts         *HTTP2Options     `yaml:"h2-opts,omitempty" json:"h2-opts,omitempty"`
		GrpcOpts       *GrpcOptions      `yaml:"grpc-opts,omitempty" json:"grpc-opts,omitempty"`
		WSOpts         *WSOptions        `yaml:"ws-opts,omitempty" json:"ws-opts,omitempty"`
		QuicOpts       *QUICOptions      `yaml:"quic-opts,omitempty" json:"quic-opts,omitempty"`
		KcpOpts        *KCPOptions       `yaml:"kcp-opts,omitempty" json:"kcp-opts,omitempty"`
		SplitHttpOpts  *SplitHttpOptions `yaml:"splithttp-opts,omitempty" json:"splithttp-opts,omitempty"`

		WSPath         string            `yaml:"ws-path,omitempty" json:"ws-path,omitempty"`
		WSHeaders      map[string]string `yaml:"ws-headers,omitempty" json:"ws-headers,omitempty"`
	}{}

	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}

	v.Base = tmp.Base
	v.UUID = tmp.UUID
	v.AlterID = tmp.AlterID
	v.Cipher = tmp.Cipher
	v.Network = tmp.Network
	v.CFingerPrint = tmp.CFingerPrint
	v.ALPN = tmp.ALPN
	v.SNI = tmp.SNI
	v.TLS = tmp.TLS
	v.SkipCertVerify = tmp.SkipCertVerify

	switch tmp.Network {
	case "ws", "httpupgrade":
		wsopts := WSOptions{}
		if tmp.WSPath != "" {
			wsopts.Path = tmp.WSPath
		}

		if len(tmp.WSHeaders) > 0 {
			wsopts.Headers = tmp.WSHeaders
		}

		if tmp.WSOpts != nil {
			if tmp.WSOpts.Path != "" {
				wsopts.Path = tmp.WSOpts.Path
			}

			if len(tmp.WSOpts.Headers) > 0 {
				wsopts.Headers = tmp.WSOpts.Headers
			}

			if tmp.WSOpts.V2rayHttpUpgradeFastOpen == true {
				wsopts.V2rayHttpUpgradeFastOpen = true
			}

			if tmp.WSOpts.MaxEarlyData != 0 {
				wsopts.MaxEarlyData = tmp.WSOpts.MaxEarlyData
				wsopts.EarlyDataHeaderName = tmp.WSOpts.EarlyDataHeaderName
			}
		}

		if !(wsopts.Path == "" && len(wsopts.Headers) == 0 && wsopts.V2rayHttpUpgradeFastOpen == false && wsopts.MaxEarlyData == 0) {
			v.WSOpts = &wsopts
		}
		break
	case "grpc":
		if tmp.GrpcOpts != nil {
			if !(tmp.GrpcOpts.GrpcServiceName == "" && tmp.GrpcOpts.Mode == "") {
				v.GrpcOpts = tmp.GrpcOpts
			}
		}
		break
	case "h2":
		if tmp.H2Opts != nil {
			if !(tmp.H2Opts.Path == "" && len(tmp.H2Opts.Host) == 0) {
				v.H2Opts = tmp.H2Opts
			}
		}
		break
	case "quic":
		if tmp.QuicOpts != nil {
			if !(tmp.QuicOpts.Type == "" && tmp.QuicOpts.Security == "" && tmp.QuicOpts.Key == "") {
				v.QuicOpts = tmp.QuicOpts
			}
		}
		break
	case "http":
		if tmp.HTTPOpts != nil {
			if !(tmp.HTTPOpts.Method == "" && len(tmp.HTTPOpts.Path) == 0 && len(tmp.HTTPOpts.Headers) == 0) {
				v.HTTPOpts = tmp.HTTPOpts
			}
		}
		break
	case "kcp":
		if tmp.KcpOpts != nil {
			if !(tmp.KcpOpts.Type == "" && tmp.KcpOpts.Seed == "") {
				v.KcpOpts = tmp.KcpOpts
			}
		}
		break
	case "splithttp":
		if tmp.SplitHttpOpts != nil {
			if !(tmp.SplitHttpOpts.Host == "" && tmp.SplitHttpOpts.Path == "") {
				v.SplitHttpOpts = tmp.SplitHttpOpts
			}
		}
	// case "tcp":
	default:
		v.Network = "tcp"
		if tmp.TcpOpts != nil {
			if !((tmp.TcpOpts.Type == "" || tmp.TcpOpts.Type == "none") && tmp.TcpOpts.Host == "" && tmp.TcpOpts.Path == "") {
				v.TcpOpts = tmp.TcpOpts
			}
		}
		break
	}

	return nil
}

func (v Vmess) Identifier() string {
	return net.JoinHostPort(v.Server, strconv.Itoa(v.Port)) + v.Cipher + v.UUID + strconv.Itoa(v.AlterID)
}

func (v Vmess) String() string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

func (v Vmess) ToClash() string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (v Vmess) ToSurge() string {
	// node2 = vmess, server, port, username=, ws=true, ws-path=, ws-headers=
	if v.Network == "ws" && v.WSOpts != nil {
		wsHeasers := ""
		for k, v := range v.WSOpts.Headers {
			if wsHeasers == "" {
				wsHeasers = k + ":" + v
			} else {
				wsHeasers += "|" + k + ":" + v
			}
		}
		text := fmt.Sprintf("%s = vmess, %s, %d, username=%s, ws=true, tls=%t, ws-path=%s",
			v.Name, v.Server, v.Port, v.UUID, v.TLS, v.WSOpts.Path)
		if wsHeasers != "" {
			text += ", ws-headers=" + wsHeasers
		}
		return text
	} else {
		return fmt.Sprintf("%s = vmess, %s, %d, username=%s, tls=%t",
			v.Name, v.Server, v.Port, v.UUID, v.TLS)
	}
}

func (v Vmess) Clone() Proxy {
	return &v
}

func (v Vmess) Link() (link string) {
	vjv, err := json.Marshal(v.toLinkJson())
	if err != nil {
		return
	}
	return fmt.Sprintf("vmess://%s", tool.Base64EncodeBytes(vjv))
}

type vmessLinkJson struct {
	Add  string `json:"add"`
	V    string `json:"v"`
	Ps   string `json:"ps"`
	Port int    `json:"port"`
	Id   string `json:"id"`
	Aid  string `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	Tls  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	Fp   string `json:"fp"`
}

func (v Vmess) toLinkJson() vmessLinkJson {
	vj := vmessLinkJson{
		Add:  v.Server,
		Ps:   v.Name,
		Port: v.Port,
		Id:   v.UUID,
		Aid:  strconv.Itoa(v.AlterID),
		Scy:  v.Cipher,
		Net:  v.Network,
		SNI:  v.SNI,
		Fp:   v.CFingerPrint,
		V:    "2",
	}
	if v.TLS {
		vj.Tls = "tls"
	}
	if len(v.ALPN) > 0 {
		vj.ALPN = strings.Join(v.ALPN, ",")
	}
	switch v.Network {
	case "ws", "httpupgrade":
		if v.WSOpts != nil {
			vj.Type = "none"
			vj.Path =  v.WSOpts.Path
			if len(v.WSOpts.Headers) > 0 {
				vj.Host = v.WSOpts.Headers["Host"]
			}
		}
		break
	case "grpc":
		if v.GrpcOpts != nil {
			vj.Type = v.GrpcOpts.Mode
			vj.Path = v.GrpcOpts.GrpcServiceName
		}
		break
	case "h2":
		if v.H2Opts != nil {
			vj.Type = "none"
			vj.Path =  v.H2Opts.Path
			if len(v.H2Opts.Host) > 0 {
				vj.Host = v.H2Opts.Host[0]
			}
		}
		break
	case "quic":
		if v.QuicOpts != nil {
			vj.Type = v.QuicOpts.Type
			vj.Host = v.QuicOpts.Security
			vj.Path = v.QuicOpts.Key
		}
		break
	case "http":
		vj.Net = "tcp"
		vj.Type = "http"
		if v.HTTPOpts != nil {
			if len(v.HTTPOpts.Path) > 0 {
				vj.Path = v.HTTPOpts.Path[0]
			}
			if len(v.HTTPOpts.Headers) > 0 {
				if headers, ok := v.HTTPOpts.Headers["Host"]; ok {
					if len(headers) > 0 {
						vj.Host = headers[0]
					}
				}
			}
		}
		break
	case "kcp":
		if v.KcpOpts != nil {
			vj.Type = v.KcpOpts.Type
			vj.Path = v.KcpOpts.Seed
		}
		break
	case "splithttp":
		if v.SplitHttpOpts != nil {
			vj.Host = v.SplitHttpOpts.Host
			vj.Path = v.SplitHttpOpts.Path
		}
	// case "tcp":
	default:
		if v.TcpOpts != nil {
			vj.Type = v.TcpOpts.Type
			vj.Host = v.TcpOpts.Host
			vj.Path = v.TcpOpts.Path
		} else {
			vj.Type = "none"
		}
		break
	}

	return vj
}

func ParseVmessLink(link string) (*Vmess, error) {
	if !strings.HasPrefix(link, "vmess") {
		return nil, ErrorNotVmessLink
	}

	vmessmix := strings.SplitN(link, "://", 2)
	if len(vmessmix) < 2 {
		return nil, ErrorNotVmessLink
	}
	linkPayload := vmessmix[1]
	if strings.Contains(linkPayload, "?") {
		// 使用第二种解析方法 目测是Shadowrocket格式
		var infoPayloads []string
		if strings.Contains(linkPayload, "/?") {
			infoPayloads = strings.SplitN(linkPayload, "/?", 2)
		} else {
			infoPayloads = strings.SplitN(linkPayload, "?", 2)
		}
		if len(infoPayloads) < 2 {
			return nil, ErrorNotVmessLink
		}

		baseInfo, err := tool.Base64DecodeString(infoPayloads[0])
		if err != nil {
			return nil, ErrorVmessPayloadParseFail
		}
		baseInfoPath := strings.Split(baseInfo, ":")
		if len(baseInfoPath) < 3 {
			return nil, ErrorPathNotComplete
		}
		// base info
		cipher := baseInfoPath[0]
		mixInfo := strings.SplitN(baseInfoPath[1], "@", 2)
		if len(mixInfo) < 2 {
			return nil, ErrorVmessPayloadParseFail
		}
		uuid := mixInfo[0]
		// UUID 不正确
		if !strings.Contains(uuid, "-") {
			return nil, ErrorVmessPayloadParseFail
		}
		server := mixInfo[1]
		portStr := baseInfoPath[2]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, ErrorVmessPayloadParseFail
		}

		moreInfo, _ := url.ParseQuery(infoPayloads[1])
		remarks := moreInfo.Get("remarks")

		// Transmission protocol
		// Network <- obfs=websocket
		obfs := moreInfo.Get("obfs")
		network := obfs
		host := moreInfo.Get("obfsParam")
		path := moreInfo.Get("path")
		tls := moreInfo.Get("tls") == "1"

		var httpOpt *HTTPOptions
		var h2opts *HTTP2Options
		var wsopts *WSOptions
		switch obfs {
		case "http":
			httpOpt.Method = "GET" // 不知道Headers为空时会不会报错
			if !(path == "") {
				httpOpt = &HTTPOptions{
					Method: "GET",
				}
				httpOpt.Path = []string{path}
			}
			break
		case "websocket":
			network = "ws"
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
		case "h2":
			if !(host == "" && path == "") {
				h2opts = &HTTP2Options{
					Path: path,
				}
				if host != "" {
					h2opts.Host = []string{host}
				}
			}
			tls = true
			break
		}

		// HTTP Object: Host <- obfsParam=www.036452916.xyz
		// HTTP Object: Path
		// allowInsecure=1 Clash config unsuported
		// alterId=64
		aid := 0
		aidStr := moreInfo.Get("alterId")
		if aidStr != "" {
			aid, _ = strconv.Atoi(aidStr)
		}

		v := Vmess{
			Base: Base{
				Name:   remarks + "_" + strconv.Itoa(rand.Int()),
				Server: server,
				Port:   port,
				Type:   "vmess",
				UDP:    false,
			},
			UUID:           uuid,
			AlterID:        aid,
			Cipher:         cipher,
			Network:        network,
			SNI:            server,
			TLS:            tls,
			SkipCertVerify: true,

			HTTPOpts:       httpOpt,
			H2Opts:         h2opts,
			WSOpts:         wsopts,
		}

		return &v, nil
	} else {
		// V2rayN ref: https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
		payload, err := tool.Base64DecodeString(linkPayload)
		if err != nil {
			return nil, ErrorVmessPayloadParseFail
		}
		vmessJson := vmessLinkJson{}
		jsonMap, err := str2jsonDynaUnmarshal(payload)
		if err != nil {
			return nil, err
		}
		vmessJson, err = mapStrInter2VmessLinkJson(jsonMap)
		if err != nil {
			return nil, err
		}
		// UUID 不正确
		if !strings.Contains(vmessJson.Id, "-") {
			return nil, ErrorVmessPayloadParseFail
		}

		alterId, err := strconv.Atoi(vmessJson.Aid)
		if err != nil {
			alterId = 0
		}

		tls := vmessJson.Tls == "tls"

		sni := ParseProxySni(vmessJson.SNI)

		alpn := ParseProxyALPN(vmessJson.ALPN)

		fingerprint := ParseProxyFingerPrint(vmessJson.Fp)

		var tcpopts *TCPOptions
		var wsopts *WSOptions
		var httpopts *HTTPOptions
		var h2opts *HTTP2Options
		var grpcopts *GrpcOptions
		var quicopts *QUICOptions
		var kcpopts *KCPOptions
		var splithttpopts *SplitHttpOptions
		switch vmessJson.Net {
		case "ws", "httpupgrade":
			fastopen := false
			if vmessJson.Net == "httpupgrade" {
				fastopen = true
			}
			ed := ParseEarlyData(vmessJson.Path)
			if !(vmessJson.Host == "" && vmessJson.Path == "" && fastopen == false && ed == 0) {
				wsopts = &WSOptions{
					Path: vmessJson.Path,
					V2rayHttpUpgradeFastOpen: fastopen,
				}
				if vmessJson.Host != "" {
					wsopts.Headers = make(map[string]string, 0)
					wsopts.Headers["Host"] = vmessJson.Host
				}
				if ed != 0 {
					wsopts.MaxEarlyData = ed
					wsopts.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
				}
			}
			break
		case "grpc":
			if !(vmessJson.Type == "" && vmessJson.Path == "") {
				grpcopts = &GrpcOptions{
					GrpcServiceName: vmessJson.Path,
					Mode:            vmessJson.Type,
				}
			}
			tls = true
			break
		case "h2":
			if !(vmessJson.Host == "" && vmessJson.Path == "") {
				h2opts = &HTTP2Options{
					Path: vmessJson.Path,
				}
				if vmessJson.Host != "" {
					h2opts.Host = []string{vmessJson.Host}
				}
			}
			tls = true
			break
		case "quic":
			if !((vmessJson.Type == "" || vmessJson.Type == "none") && vmessJson.Host == "" && vmessJson.Path == "") {
				quicopts = &QUICOptions{
					Type:     vmessJson.Type,
					Security: vmessJson.Host,
					Key:      vmessJson.Path,
				}
			}
			break
		case "kcp":
			if !(vmessJson.Type == "" && vmessJson.Path == "") {
				kcpopts = &KCPOptions{
					Type: vmessJson.Type,
					Seed: vmessJson.Path,
				}
			}
			break
		case "splithttp":
			if !(vmessJson.Host == "" && vmessJson.Path == "") {
				splithttpopts = &SplitHttpOptions{
					Host: vmessJson.Host,
					Path: vmessJson.Path,
				}
			}
		// case "tcp":
		default:
			if vmessJson.Type == "http" {
				vmessJson.Net = "http"
				httpopts = &HTTPOptions{
					Method: "GET",
				}
				if vmessJson.Host != "" {
					httpopts.Headers = make(map[string][]string, 0)
					httpopts.Headers["Host"] = []string{vmessJson.Host}
				}
				if vmessJson.Path != "" {
					httpopts.Path = []string{vmessJson.Path}
				} else {
					httpopts.Path = []string{"/"}
				}
			} else {
				vmessJson.Net = "tcp"
				if !((vmessJson.Type == "" || vmessJson.Type == "none" || vmessJson.Type == "<nil>") && vmessJson.Host == "" && vmessJson.Path == "") {
					tcpopts = &TCPOptions{
						Type: vmessJson.Type,
						Host: vmessJson.Host,
						Path: vmessJson.Path,
					}
				}
			}
			break
		}

		v := Vmess{
			Base: Base{
				Name:   "",
				Server: vmessJson.Add,
				Port:   vmessJson.Port,
				Type:   "vmess",
				UDP:    true,
			},
			UUID:           vmessJson.Id,
			AlterID:        alterId,
			Cipher:         vmessJson.Scy,
			Network:        vmessJson.Net,
			CFingerPrint:   fingerprint,
			ALPN:           alpn,
			SNI:            sni,
			TLS:            tls,
			SkipCertVerify: true,

			TcpOpts:        tcpopts,
			HTTPOpts:       httpopts,
			H2Opts:         h2opts,
			GrpcOpts:       grpcopts,
			WSOpts:         wsopts,
			QuicOpts:       quicopts,
			KcpOpts:        kcpopts,
			SplitHttpOpts:  splithttpopts,
		}

		return &v, nil
	}
}

var (
	vmessPlainRe = regexp.MustCompile("vmess://([A-Za-z0-9+/_?&=-])+")
)

func GrepVmessLinkFromString(text string) []string {
	results := make([]string, 0)
	if !strings.Contains(text, "vmess://") {
		return results
	}
	texts := strings.Split(text, "vmess://")
	for _, text := range texts {
		results = append(results, vmessPlainRe.FindAllString("vmess://"+text, -1)...)
	}
	return results
}

func str2jsonDynaUnmarshal(s string) (jsn map[string]interface{}, err error) {
	var f interface{}
	err = json.Unmarshal([]byte(s), &f)
	if err != nil {
		return nil, err
	}
	jsn, ok := f.(map[string]interface{}) // f is pointer point to map struct
	if !ok {
		return nil, ErrorVmessPayloadParseFail
	}
	return jsn, err
}

func mapStrInter2VmessLinkJson(jsn map[string]interface{}) (vmessLinkJson, error) {
	vmess := vmessLinkJson{}
	var err error

	vmessVal := reflect.ValueOf(&vmess).Elem()
	for i := 0; i < vmessVal.NumField(); i++ {
		tags := vmessVal.Type().Field(i).Tag.Get("json")
		tag := strings.Split(tags, ",")
		if jsnVal, ok := jsn[strings.ToLower(tag[0])]; ok {
			if strings.ToLower(tag[0]) == "port" { // set int in port
				switch jsnVal := jsnVal.(type) {
				case float64:
					vmessVal.Field(i).SetInt(int64(jsnVal))
				case string: // Force Convert
					valInt, err := strconv.Atoi(jsnVal)
					if err != nil {
						valInt = 443
					}
					vmessVal.Field(i).SetInt(int64(valInt))
				default:
					vmessVal.Field(i).SetInt(443)
				}
			} else if strings.ToLower(tag[0]) == "ps" {
				continue
			} else { // set string in other fields
				switch jsnVal := jsnVal.(type) {
				case string:
					vmessVal.Field(i).SetString(jsnVal)
				default: // Force Convert
					vmessVal.Field(i).SetString(fmt.Sprintf("%v", jsnVal))
				}
			}
		}
	}
	return vmess, err
}
