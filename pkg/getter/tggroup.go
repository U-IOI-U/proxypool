package getter

import (
	"io/ioutil"
	"strings"
	"strconv"
	"sync"
	"html"

	"github.com/ssrlive/proxypool/log"
	C "github.com/ssrlive/proxypool/config"
	"github.com/ssrlive/proxypool/pkg/proxy"
	"github.com/ssrlive/proxypool/pkg/tool"
	"github.com/gocolly/colly"
)

func init() {
	Register("tggroup", NewTGGroupGetter)
}

type TGGroupGetter struct {
	c         *colly.Collector
	NumNeeded int
	results   []string
	Url       string
}

func NewTGGroupGetter(options tool.Options) (getter Getter, err error) {
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
		return &TGGroupGetter{
			c:         tool.GetColly(),
			NumNeeded: t,
			Url:       C.Config.TGFileApi + url,
		}, nil
	}
	return nil, ErrorUrlNotFound
}

func (g *TGGroupGetter) Get() proxy.ProxyList {
	onePageMsg := 100
	subHtmls := make([]string, 0)
	result := make(proxy.ProxyList, 0)
	
	for pageNum, j := 1, g.NumNeeded; j > 0; pageNum, j = pageNum + 1, j - onePageMsg {
		// 获取文件(api需要维护)
		resp, err := tool.GetHttpClient().Get(g.Url + "/" + strconv.Itoa(pageNum) + "?limit=" + strconv.Itoa(onePageMsg))
		if err != nil {
			break
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			break
		}
		subHtmls = append(subHtmls, string(body))
		// 先处理文件
		items := strings.Split(string(body), "\n")
		for _, s := range items {
			if strings.Contains(s, "enclosure url") { // get to xml node
				elements := strings.Split(s, "\"")
				for _, e := range elements {
					if strings.Contains(e, "https://") || strings.Contains(e, "http://") { // http存在公网传输时内容泄露的风险，仅用于内网自行搭建服务器
						if !CheckSubscribeUrlValid(e) {
							continue
						}
						newResult := (&Subscribe{Url: e}).Get() // fileapi请求受限，不能并发处理
						if len(newResult) > 0 {
							result = append(result, newResult...)
						}
					}
				}
			}
		}
	}
	// 没有获取到网页
	if len(subHtmls) == 0 {
		return nil
	}
	
	allHtmls := strings.Join(subHtmls, " ")
	// 获取内容中的 vmess://, ss://, ssr://, trojan:// 等格式的节点信息
	result = append(result, StringArray2ProxyArray(GrepLinksFromString(allHtmls))...)

	// 抓取到http链接，有可能是订阅链接或其他链接，无论如何试一下
	subUrls := FindAllSubscribeUrl(html.UnescapeString(allHtmls), -1)
	newResult := (&Subscribe{}).QueueGet(subUrls)
	if len(newResult) > 0 {
		result = append(result, newResult...)
	}
	
	return result
}

func (g *TGGroupGetter) Get2ChanWG(pc chan proxy.Proxy, wg *sync.WaitGroup) {
	defer wg.Done()
	nodes := g.Get()
	log.Infoln("STATISTIC: TGGroup   \tcount=%-5d\turl=%s\n", len(nodes), g.Url)
	for _, node := range nodes {
		pc <- node
	}
}
func (g *TGGroupGetter) Get2Chan(pc chan proxy.Proxy) {
	nodes := g.Get()
	log.Infoln("STATISTIC: TGGroup   \tcount=%-5d\turl=%s\n", len(nodes), g.Url)
	for _, node := range nodes {
		pc <- node
	}
}
