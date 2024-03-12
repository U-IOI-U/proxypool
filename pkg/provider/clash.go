package provider

import (
	"strings"

	"github.com/u-ioi-u/proxypool/pkg/proxy"
)

// Clash provides functions that make proxies support clash client
type Clash struct {
	Base
}

// CleanProxies cleans unsupported proxy type of clash
func (c Clash) CleanProxies() (proxies proxy.ProxyList) {
	proxies = make(proxy.ProxyList, 0)
	for _, p := range *c.Proxies {
		if checkClashSupport(p) {
			proxies = append(proxies, p)
		}
	}
	return
}

// Provide of clash generates providers for clash configuration
func (c Clash) Provide() string {
	c.preFilter()

	var resultBuilder strings.Builder
	resultBuilder.WriteString("proxies:\n")
	for _, p := range *c.Proxies {
		if checkClashSupport(p) {
			if s := p.ToClash(); len(s) > 0 {
				resultBuilder.WriteString(s + "\n")
			}
		}
	}
	if resultBuilder.Len() == 9 { //如果没有proxy，添加无效的NULL节点，防止Clash对空节点的Provider报错
		resultBuilder.WriteString("- {\"name\":\"NULL\",\"server\":\"NULL\",\"port\":11708,\"type\":\"ssr\",\"country\":\"NULL\",\"password\":\"sEscPBiAD9K$\\u0026@79\",\"cipher\":\"aes-256-cfb\",\"protocol\":\"origin\",\"protocol_param\":\"NULL\",\"obfs\":\"http_simple\"}")
	}
	return resultBuilder.String()
}

// 检查单个节点的加密方式、协议类型与混淆是否是Clash所支持的
func checkClashSupport(p proxy.Proxy) bool {
	return proxy.CheckProxyClashSupported(p)
}
