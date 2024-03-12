package provider

import (
	"os"
	"strings"
)

// Clash provides functions that make proxies support clash client
type Pfile struct {
	Base
}

func (c Pfile) Provide() string {
	var resultBuilder strings.Builder
	resultBuilder.WriteString("proxies:\n")
	for _, p := range *c.Proxies {
		if s := p.ToClash(); len(s) > 0 {
			resultBuilder.WriteString(s + "\n")
		}
	}
	return resultBuilder.String()
}

func (c Pfile) SaveProxies(path string) {
	proxystr := c.Provide()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return
	}
	f.WriteString(proxystr)
	f.Close()
}
