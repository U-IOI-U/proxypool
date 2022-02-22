package getter

import (
	"github.com/ssrlive/proxypool/log"
	"io/ioutil"
	"strings"
	"sync"
	"gopkg.in/yaml.v3"
	"github.com/ssrlive/proxypool/pkg/proxy"
	"github.com/ssrlive/proxypool/pkg/tool"
)

// Add key value pair to creatorMap(string → creator) in base.go
func init() {
	Register("subscribe", NewSubscribe)
}

// Subscribe is A Getter with an additional property
type Subscribe struct {
	Url string
}

// Get() of Subscribe is to implement Getter interface
func (s *Subscribe) Get() proxy.ProxyList {
	if tool.SubScribeHistoryCheckUrlIn(s.Url) { return nil }
	resp, err := tool.GetHttpClient().Get(s.Url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	if strings.Contains(string(body), "proxies:") {
		conf := config{}
		err = yaml.Unmarshal(body, &conf)
		if err != nil {
			return nil
		}
	
		result := ClashProxy2ProxyArray(conf.Proxy)
		tool.SubScribeHistoryUpdateRet(s.Url, len(result))
		return result
	} else {
		if strings.Contains(string(body), "ss://") || strings.Contains(string(body), "ssr://") || strings.Contains(string(body), "vmess://") || strings.Contains(string(body), "trojan://") {
			result := FuzzParseProxyFromString(string(body))
			tool.SubScribeHistoryUpdateRet(s.Url, len(result))
			return result
		} else {
			nodesString, err := tool.Base64DecodeString(string(body))
			if err != nil {
				return nil
			}
			nodesString = strings.ReplaceAll(nodesString, "\t", "")
		
			nodes := strings.Split(nodesString, "\n")
			result := StringArray2ProxyArray(nodes)
			tool.SubScribeHistoryUpdateRet(s.Url, len(result))
			return result
		}
	}
}

// Get2Chan() of Subscribe is to implement Getter interface. It gets proxies and send proxy to channel one by one
func (s *Subscribe) Get2ChanWG(pc chan proxy.Proxy, wg *sync.WaitGroup) {
	defer wg.Done()
	nodes := s.Get()
	log.Infoln("STATISTIC: Subscribe\tcount=%-5d\turl=%s\n", len(nodes), s.Url)
	for _, node := range nodes {
		pc <- node
	}
}

func (s *Subscribe) Get2Chan(pc chan proxy.Proxy) {
	nodes := s.Get()
	log.Infoln("STATISTIC: Subscribe\tcount=%-5d\turl=%s\n", len(nodes), s.Url)
	for _, node := range nodes {
		pc <- node
	}
}

func NewSubscribe(options tool.Options) (getter Getter, err error) {
	urlInterface, found := options["url"]
	if found {
		url, err := AssertTypeStringNotNull(urlInterface)
		if err != nil {
			return nil, err
		}
		return &Subscribe{
			Url: url,
		}, nil
	}
	return nil, ErrorUrlNotFound
}
