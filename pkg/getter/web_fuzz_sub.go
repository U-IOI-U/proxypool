package getter

import (
	"io"
	"sync"

	"github.com/u-ioi-u/proxypool/log"

	"github.com/u-ioi-u/proxypool/pkg/proxy"
	"github.com/u-ioi-u/proxypool/pkg/tool"
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	text := string(body)
	subUrls := FindAllSubscribeUrl(text, -1)
	result := (&Subscribe{}).QueueGet(subUrls)
	return result
}

func (w *WebFuzzSub) Get2ChanWG(pc chan proxy.Proxy, wg *sync.WaitGroup) {
	defer wg.Done()
	nodes := w.Get()
	log.Infoln("STATISTIC: WebFuzzSub\tcount=%-5d\turl=%s", len(nodes), w.Url)
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
