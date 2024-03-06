package getter

import (
	"io"
	"strings"
	"sync"
	"gopkg.in/yaml.v3"
	"github.com/u-ioi-u/proxypool/log"

	"github.com/u-ioi-u/proxypool/pkg/proxy"
	"github.com/u-ioi-u/proxypool/pkg/tool"
)

// Add key value pair to creatorMap(string → creator) in base.go
func init() {
	Register("subscribe", NewSubscribe)
}

// Subscribe is A Getter with an additional property
type Subscribe struct {
	Url string
}

// 全部并发处理，处理量过大
func (s *Subscribe) QueueGet(urls []string) proxy.ProxyList {
	if len(urls) > 0 {
		var qc = make(chan proxy.Proxy)
		proxies := make(proxy.ProxyList, 0)
		queueWg := &sync.WaitGroup{}
		queueWg.Add(len(urls))
		for _, u := range urls {
			url := u
			go func() {
				defer queueWg.Done()
				nodes := (&Subscribe{Url: url}).Get()
				for _, node := range nodes {
					qc <- node
				}
			}()
		}

		go func() {
			queueWg.Wait()
			close(qc)
		}()

		for q := range qc {
			if q != nil {
				proxies = append(proxies, q)
			}
		}
		return proxies.Deduplication()
	}

	return nil
}

func (s *Subscribe) newGet() proxy.ProxyList {
	resp, err := tool.GetHttpClient().Get(s.Url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	tool.SubScribeHistoryUpdateResponseSize(s.Url, len(string(body)))
	if strings.Contains(string(body), "proxies:") {
		conf := config{}
		err = yaml.Unmarshal(body, &conf)
		if err != nil {
			return nil
		}
	
		return ClashProxy2ProxyArray(conf.Proxy)
	} else {
		nodesString, err := tool.Base64DecodeString(string(body))
		if err != nil {
			return FuzzParseProxyFromString(string(body))
		}
		nodesString = strings.ReplaceAll(nodesString, "\t", "")

		nodes := strings.Split(nodesString, "\n")
		return StringArray2ProxyArray(nodes)
	}
}

func (s *Subscribe) GetAndBlock() proxy.ProxyList {
	defer tool.SubScribeHistoryBlockSuccess(s.Url)
	return s.Get()
}

// Get() of Subscribe is to implement Getter interface
func (s *Subscribe) Get() proxy.ProxyList {
	if tool.SubScribeHistoryCheckUrlIn(s.Url) {
		return nil
	}
	tool.SubScribeHistoryUpdateRet(s.Url, 0)
	tool.SubScribeHistoryUpdateResponseSize(s.Url, 0)

	nodes := s.newGet()
	if (nodes != nil) {
		tool.SubScribeHistoryUpdateRet(s.Url, len(nodes))
	}

	return nodes
}

// Subscribe is to implement Getter interface. It gets proxies and send proxy to channel one by one
func (s *Subscribe) Get2ChanWG(pc chan proxy.Proxy, wg *sync.WaitGroup) {
	defer wg.Done()
	nodes := s.Get()
	log.Infoln("STATISTIC: Subscribe \tcount=%-5d\turl=%s", len(nodes), s.Url)
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
