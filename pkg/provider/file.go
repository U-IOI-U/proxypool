package provider

import (
	"os"
	"fmt"
	"strings"

	"github.com/u-ioi-u/proxypool/log"
	"github.com/u-ioi-u/proxypool/pkg/proxy"
)

// Clash provides functions that make proxies support clash client
type Pfile struct {
	Base
}

func (c Pfile) Provide(mode string) string {
	var resultBuilder strings.Builder
	if mode == "clash" {
		resultBuilder.WriteString("proxies:\n")
		for _, p := range *c.Proxies {
			if s := p.ToClash(); len(s) > 0 {
				resultBuilder.WriteString(s + "\n")
			}
		}
	} else {/* link */
		for _, p := range *c.Proxies {
			if s := p.Link(); len(s) > 0 {
				pp, _ := proxy.ParseProxyFromLink(s)
				if pp == nil {
					l := p.String()
					if l == "" {
						fmt.Println(p)
					} else {
						log.Debugln(l)
					}
				} else {
					resultBuilder.WriteString(s + "\n")
				}
			}
		}
	}

	return resultBuilder.String()
}

func (c Pfile) SaveProxies(path string, mode string) {
	proxystr := c.Provide(mode)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return
	}
	f.WriteString(proxystr)
	f.Close()
}
