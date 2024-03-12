package provider

import (
	"strings"

	"github.com/u-ioi-u/proxypool/pkg/proxy"
)

// Surge provides functions that make proxies support clash client
type Surge struct {
	Base
}

// Provide of Surge generates proxy list supported by surge
func (s Surge) Provide() string {
	s.preFilter()

	var resultBuilder strings.Builder
	for _, p := range *s.Proxies {
		if checkSurgeSupport(p) {
			if s := p.ToSurge(); len(s) > 0 {
				resultBuilder.WriteString(s + "\n")
			}
		}
	}
	return resultBuilder.String()
}

func checkSurgeSupport(p proxy.Proxy) bool {
	switch p.TypeName() {
	case "ssr":
		return false
	case "vmess":
		return true
	case "ss":
		return true
	default:
		return false
	}
	return false
}
