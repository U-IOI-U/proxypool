package getter

import (
	"github.com/ssrlive/proxypool/log"
	"io/ioutil"
	"sync"

	"github.com/ssrlive/proxypool/pkg/proxy"
	"github.com/ssrlive/proxypool/pkg/tool"
)

func init() {
	Register("webfuzzsub", NewWebFuzzSubGetter)
}

type WebFuzzSub struct {
	Url string
}

func (w *WebFuzzSub) Get() proxy.ProxyList {
	resp, err := tool.GetHttpClient().Get(w.Url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	text := string(body)
	subUrls := FindAllSubscribeUrl(text, -1)
	result := make(proxy.ProxyList, 0)
	for _, url := range subUrls {
		newResult := (&Subscribe{Url: url}).Get()
		// newResultLen := len(newResult)
		// if newResultLen == 0 {
		// 	log.Debugln("\tSTATISTIC: WebFuzzSub\tcount=%-5d sub url=%s\n", newResultLen, url)
		// }
		result = result.UniqAppendProxyList(newResult)
	}
	return result
}

func (w *WebFuzzSub) Get2ChanWG(pc chan proxy.Proxy, wg *sync.WaitGroup) {
	defer wg.Done()
	nodes := w.Get()
	log.Infoln("STATISTIC: WebFuzzSub\tcount=%-5d\turl=%s\n", len(nodes), w.Url)
	for _, node := range nodes {
		pc <- node
	}
}

func (w *WebFuzzSub) Get2Chan(pc chan proxy.Proxy) {
	nodes := w.Get()
	log.Infoln("STATISTIC: WebFuzzSub\tcount=%-5d\turl=%s\n", len(nodes), w.Url)
	for _, node := range nodes {
		pc <- node
	}
}

func NewWebFuzzSubGetter(options tool.Options) (getter Getter, err error) {
	urlInterface, found := options["url"]
	if found {
		url, err := AssertTypeStringNotNull(urlInterface)
		if err != nil {
			return nil, err
		}
		return &WebFuzzSub{Url: url}, nil
	}
	return nil, ErrorUrlNotFound
}
