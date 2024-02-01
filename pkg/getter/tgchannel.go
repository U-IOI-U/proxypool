package getter

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"html"

	"github.com/ssrlive/proxypool/log"
	C "github.com/ssrlive/proxypool/config"
	"github.com/gocolly/colly"
	"github.com/ssrlive/proxypool/pkg/proxy"
	"github.com/ssrlive/proxypool/pkg/tool"
)

func init() {
	Register("tgchannel", NewTGChannelGetter)
}

type TGChannelGetter struct {
	c         *colly.Collector
	NumNeeded int
	results   []string
	Url       string
	apiUrl    string
}

func NewTGChannelGetter(options tool.Options) (getter Getter, err error) {
	num, found := options["num"]
	t := 200
	switch num := num.(type) {
	case int:
		t = num
	case float64:
		t = int(num)
	}

	if !found || t <= 0 {
		t = 200
	}
	urlInterface, found := options["channel"]
	if found {
		url, err := AssertTypeStringNotNull(urlInterface)
		if err != nil {
			return nil, err
		}
		return &TGChannelGetter{
			c:         tool.GetColly(),
			NumNeeded: t,
			Url:       "https://t.me/s/" + url,
			apiUrl:    C.Config.TGFileApi + url + "?limit=30",
		}, nil
	}
	return nil, ErrorUrlNotFound
}

func (g *TGChannelGetter) Get() proxy.ProxyList {
	result := make(proxy.ProxyList, 0)
	subHtmls := make([]string, 0)
	g.results = make([]string, 0)
	// 找到所有的文字消息
	g.c.OnHTML("div.tgme_widget_message_text", func(e *colly.HTMLElement) {
		g.results = append(g.results, GrepLinksFromString(e.Text)...)
		// 抓取到http链接，有可能是订阅链接或其他链接，无论如何试一下
		subHtmls = append(subHtmls, html.UnescapeString(e.Text))
	})

	// 找到之前消息页面的链接，加入访问队列
	g.c.OnHTML("link[rel=prev]", func(e *colly.HTMLElement) {
		if (len(g.results) < g.NumNeeded) && (len(subHtmls) < g.NumNeeded) { // 逻辑用找到的节点的数量和消息的数量做判断，预防处理时间太长
			_ = e.Request.Visit(e.Attr("href"))
		}
	})

	// g.c.OnRequest(func(r *colly.Request) {
	// 	log.Debugln("Visiting %s\n", r.URL)
	// })

	// 在通过Text获取网页内容之前，把网页内容进行分割，以防内容粘在一起无法识别
	g.c.OnResponse(func(r *colly.Response) {
		body := string(r.Body)
		body = strings.ReplaceAll(strings.ReplaceAll(body, "<", " <"), ">", "> ")
		r.Body = []byte(body)
	})

	g.results = make([]string, 0)
	err := g.c.Visit(g.Url)
	if err != nil {
		_ = fmt.Errorf("%s", err.Error())
	}
	result = append(result, StringArray2ProxyArray(g.results)...)

	// 获取文件(api需要维护)
	resp, err := tool.GetHttpClient().Get(g.apiUrl)
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			items := strings.Split(string(body), "\n")
			for _, s := range items {
				if strings.Contains(s, "enclosure url") { // get to xml node
					elements := strings.Split(s, "\"")
					for _, e := range elements {
						if strings.Contains(e, "https://") || strings.Contains(e, "http://") { // http存在公网传输时内容泄露的风险，仅用于内网自行搭建服务器
							if !CheckSubscribeUrlValid(e) {
								continue
							}
							newResult := (&Subscribe{Url: e}).GetAndBlock() // fileapi请求受限，不能并发处理
							if len(newResult) > 0 {
								result = append(result, newResult...)
							}
						}
					}
				}
			}
		}
	}
	
	// 处理订阅链接
	subUrls := FindAllSubscribeUrl(strings.Join(subHtmls, " "), -1)
	newResult := (&Subscribe{}).QueueGet(subUrls)
	if len(newResult) > 0 {
		result = append(result, newResult...)
	}

	return result
}

func (g *TGChannelGetter) Get2ChanWG(pc chan proxy.Proxy, wg *sync.WaitGroup) {
	defer wg.Done()
	nodes := g.Get()
	log.Infoln("STATISTIC: TGChannel \tcount=%-5d\turl=%s", len(nodes), g.Url)
	for _, node := range nodes {
		pc <- node
	}
}
