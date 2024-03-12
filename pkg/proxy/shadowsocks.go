package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/u-ioi-u/proxypool/pkg/tool"
)

var (
	// ErrorNotSSLink is an error type
	ErrorNotSSLink = errors.New("not a correct ss link")
)

// Shadowsocks is a type of proxy
type Shadowsocks struct {
	Base
	Password   string                 `yaml:"password" json:"password"`
	Cipher     string                 `yaml:"cipher" json:"cipher"`
	Plugin     string                 `yaml:"plugin,omitempty" json:"plugin,omitempty"`
	PluginOpts map[string]interface{} `yaml:"plugin-opts,omitempty" json:"plugin-opts,omitempty"`
}

// Identifier generates an unique identifier of one proxy
func (ss Shadowsocks) Identifier() string {
	return net.JoinHostPort(ss.Server, strconv.Itoa(ss.Port)) + ss.Password
}

func (ss Shadowsocks) String() string {
	data, err := json.Marshal(ss)
	if err != nil {
		return ""
	}
	return string(data)
}

// ToClash converts proxy to clash proxy string
func (ss Shadowsocks) ToClash() string {
	data, err := json.Marshal(ss)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

// ToSurge converts proxy to surge proxy string
func (ss Shadowsocks) ToSurge() string {
	// node1 = ss, server, port, encrypt-method=, password=, obfs=, obfs-host=, udp-relay=false
	if ss.Plugin == "obfs" {
		text := fmt.Sprintf("%s = ss, %s, %d, encrypt-method=%s, password=%s, obfs=%s, udp-relay=false",
			ss.Name, ss.Server, ss.Port, ss.Cipher, ss.Password, ss.PluginOpts["mode"])
		if ss.PluginOpts["host"] != nil && ss.PluginOpts["host"].(string) != "" {
			text += ", obfs-host=" + ss.PluginOpts["host"].(string)
		}
		return text
	} else {
		return fmt.Sprintf("%s = ss, %s, %d, encrypt-method=%s, password=%s, udp-relay=false",
			ss.Name, ss.Server, ss.Port, ss.Cipher, ss.Password)
	}
}

func (ss Shadowsocks) Clone() Proxy {
	return &ss
}

// https://shadowsocks.org/en/config/quick-guide.html
// Link converts a ss proxy to string
func (ss Shadowsocks) Link() (link string) {
	query := url.Values{}

	if ss.Plugin != "" {
		plugins := make([]string, 0)
		switch ss.Plugin {
		case "obfs":
			plugins = append(plugins, "obfs-local")
			if obfs, ok := ss.PluginOpts["mode"]; ok {
				plugins = append(plugins, "obfs=" + obfs.(string))
			}
			if obfsHost, ok := ss.PluginOpts["host"]; ok {
				plugins = append(plugins, "obfs-host=" + obfsHost.(string))
			}
			break
		case "v2ray-plugin":
			plugins = append(plugins, "v2ray-plugin")
			if obfs, ok := ss.PluginOpts["mode"]; ok {
				plugins = append(plugins, "mode=" + obfs.(string))
			}
			if obfsHost, ok := ss.PluginOpts["host"]; ok {
				plugins = append(plugins, "host=" + obfsHost.(string))
			}
			if obfsPath, ok := ss.PluginOpts["path"]; ok {
				plugins = append(plugins, "path=" + obfsPath.(string))
			}
			if obfsTls, ok := ss.PluginOpts["tls"]; ok {
				if obfsTls.(bool) {
					plugins = append(plugins, "tls")
				}
			}
		case "shadow-tls":
		case "restls":
		}
		if len(plugins) > 0 {
			query.Set("plugin", strings.Join(plugins, ";"))
		}
	}

	uri := url.URL{
		Scheme:   "ss",
		User:     url.User(strings.TrimRight(tool.Base64EncodeString(fmt.Sprintf("%s:%s", ss.Cipher, ss.Password), false), "=")),
		Host:     net.JoinHostPort(ss.Server, strconv.Itoa(ss.Port)),
		RawQuery: query.Encode(),
		Fragment: ss.Name,
	}

	return uri.String()

	// payload := fmt.Sprintf("%s:%s@%s:%d", ss.Cipher, ss.Password, ss.Server, ss.Port)
	// payload = tool.Base64EncodeString(payload, false)
	// return fmt.Sprintf("ss://%s#%s", payload, ss.Name)
}

// ParseSSLink() parses an ss link to ss proxy
func ParseSSLink(link string) (*Shadowsocks, error) {
	if !strings.HasPrefix(link, "ss://") {
		return nil, ErrorNotSSRLink
	}

	uri, err := url.Parse(link)
	if err != nil {
		return nil, ErrorNotSSLink
	}

	remarks := uri.Fragment

	cipher := ""
	password := ""
	if uri.User.String() == "" {
		// base64的情况
		infos, err := tool.Base64DecodeString(uri.Hostname())
		if err != nil {
			return nil, err
		}
		uri, err = url.Parse("ss://" + infos)
		if err != nil {
			return nil, err
		}
		cipher = uri.User.Username()
		password, _ = uri.User.Password()
	} else {
		cipherInfoString, err := tool.Base64DecodeString(uri.User.Username())
		if err != nil {
			return nil, ErrorPasswordParseFail
		}
		cipherInfo := strings.SplitN(cipherInfoString, ":", 2)
		if len(cipherInfo) < 2 {
			return nil, ErrorPasswordParseFail
		}
		cipher = strings.ToLower(cipherInfo[0])
		password = cipherInfo[1]
	}
	server := uri.Hostname()
	port, _ := strconv.Atoi(uri.Port())

	moreInfos := uri.Query()
	pluginString := moreInfos.Get("plugin")
	plugin := ""
	pluginOpts := make(map[string]interface{})
	if strings.Contains(pluginString, ";") {
		pluginInfos, err := url.ParseQuery("plugin=" + strings.ReplaceAll(pluginString, ";", "&"))
		if err == nil {
			plugin = pluginInfos.Get("plugin")
			switch plugin {
			case "obfs":
			case "obfs-local":
				plugin = "obfs"
				if _mode := pluginInfos.Get("obfs"); _mode != "" {
					pluginOpts["mode"] = _mode
				}
				if _host := pluginInfos.Get("obfs-host"); _host != "" {
					pluginOpts["host"] = _host
				}
				break
			case "v2ray-plugin":
				if _mode := pluginInfos.Get("mode"); _mode != "" {
					pluginOpts["mode"] = _mode
				}
				if _host := pluginInfos.Get("host"); _host != "" {
					pluginOpts["host"] = _host
				}
				if _path := pluginInfos.Get("path"); _path != "" {
					pluginOpts["path"] = _path
				}
				if strings.Contains(pluginString, "tls") {
					pluginOpts["tls"] = true
				}
				break
			}
		}
	} else {
		plugin = pluginString
	}
	if port == 0 || cipher == "" || !tool.CheckInList(SSCipherList, cipher) {
		return nil, ErrorNotSSLink
	}

	return &Shadowsocks{
		Base: Base{
			Name:   remarks,
			Server: server,
			Port:   port,
			Type:   "ss",
			UDP:    true,
		},
		Password:   password,
		Cipher:     cipher,
		Plugin:     plugin,
		PluginOpts: pluginOpts,
	}, nil
}

var (
	ssPlainRe = regexp.MustCompile("ss://([A-Za-z0-9+/_&?=@:%.-])+")
)

// GrepSSLinkFromString() remove web fuzz characters before a ss link
func GrepSSLinkFromString(text string) []string {
	results := make([]string, 0)
	if !strings.Contains(text, "ss://") {
		return results
	}
	texts := strings.Split(text, "ss://")
	for _, text := range texts {
		results = append(results, ssPlainRe.FindAllString("ss://"+text, -1)...)
	}
	return results
}
