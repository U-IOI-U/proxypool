package getter

import (
	"errors"
	"sync"
	"regexp"
	"strings"
	C "github.com/ssrlive/proxypool/config"
	"github.com/ssrlive/proxypool/pkg/proxy"
	"github.com/ssrlive/proxypool/pkg/tool"
)

// functions for getters
type Getter interface {
	Get() proxy.ProxyList
	Get2ChanWG(pc chan proxy.Proxy, wg *sync.WaitGroup)
}

// function type that creates getters
type creator func(options tool.Options) (getter Getter, err error)

// map str sourceType -> func creating getters,
// registered in package init()
var creatorMap = make(map[string]creator)

func Register(sourceType string, c creator) {
	creatorMap[sourceType] = c
}

func NewGetter(sourceType string, options tool.Options) (getter Getter, err error) {
	c, ok := creatorMap[sourceType]
	if ok {
		return c(options)
	}
	return nil, ErrorCreaterNotSupported
}

func StringArray2ProxyArray(origin []string) proxy.ProxyList {
	results := make(proxy.ProxyList, 0)
	for _, link := range origin {
		p, err := proxy.ParseProxyFromLink(link)
		if err == nil && p != nil {
			results = append(results, p)
		}
	}
	return results
}

func ClashProxy2ProxyArray(origin []map[string]interface{}) proxy.ProxyList {
	results := make(proxy.ProxyList, 0, len(origin))
	for _, pjson := range origin {
		p, err := proxy.ParseProxyFromClashProxy(pjson)
		if err == nil && p != nil {
			results = append(results, p)
		}
	}
	return results
}

func GrepLinksFromString(text string) []string {
	results := proxy.GrepSSRLinkFromString(text)
	results = append(results, proxy.GrepVmessLinkFromString(text)...)
	results = append(results, proxy.GrepSSLinkFromString(text)...)
	results = append(results, proxy.GrepTrojanLinkFromString(text)...)
	results = append(results, proxy.GrepHttpLinkFromString(text)...)
	results = append(results, proxy.GrepVlessLinkFromString(text)...)
	return results
}

func FuzzParseProxyFromString(text string) proxy.ProxyList {
	return StringArray2ProxyArray(GrepLinksFromString(text))
}

var (
	ErrorUrlNotFound         = errors.New("url should be specified")
	ErrorCreaterNotSupported = errors.New("type not supported")
)

func AssertTypeStringNotNull(i interface{}) (str string, err error) {
	switch i := i.(type) {
	case string:
		str = i
		if str == "" {
			return "", errors.New("string is null")
		}
		return str, nil
	default:
		return "", errors.New("type is not string")
	}
}

var urlRe = regexp.MustCompile(urlPattern)

const (
	// 匹配 IP4
	ip4Pattern = `((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)`

	// 匹配 IP6，参考以下网页内容：
	// http://blog.csdn.net/jiangfeng08/article/details/7642018
	ip6Pattern = `(([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|` +
		`(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|` +
		`(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|` +
		`(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|` +
		`(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|` +
		`(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|` +
		`(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|` +
		`(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))`

	// 同时匹配 IP4 和 IP6
	ipPattern = "(" + ip4Pattern + ")|(" + ip6Pattern + ")"

	// 匹配域名
	domainPattern = `[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9_-]{0,62})*(\.[a-zA-Z][a-zA-Z0-9]{0,10}){1}`

	// 匹配 URL
	urlPattern = `((https|http)?://)?` + // 协议
		`(([0-9a-zA-Z]+:)?[0-9a-zA-Z_-]+@)?` + // pwd:user@
		"(" + ipPattern + "|(" + domainPattern + "))" + // IP 或域名
		`(:\d{1,5})?` + // 端口
		`(/+[a-zA-Z0-9_#\@\%\.\-][a-zA-Z0-9_#\@\%\.\-]*)*/*` + // path
		`(\?([a-zA-Z0-9_\-]+(=[^<>"'\(\)\s]*&?)*)*)*` // query
)

func RemoveDuplication_map(arr []string) []string {
	set := make(map[string]struct{}, len(arr))
	j := 0
	for _, v := range arr {
		_, ok := set[v]
		if ok {
			continue
		}
		set[v] = struct{}{}
		arr[j] = v
		j++
	}
	return arr[:j]
}

func FindAllUrl(html string, num int) []string {
	subUrls := urlRe.FindAllString(html, num)
	if len(subUrls) > 1 {
		retUrls := RemoveDuplication_map(subUrls)
		return retUrls
	}
	return subUrls
}

func CheckSubscribeUrlValid(url string) bool {
	if url == "" {
		return false
	}
	if strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") {
		if len(C.Config.SubUrlsBlackPrefix) > 0 {
			for _, prefix := range C.Config.SubUrlsBlackPrefix {
				if strings.HasPrefix(url, prefix) {
					return false
				}
			}
		}
		if (strings.Count(url, "/") >= 3) && (len(C.Config.SubUrlsBlackSuffix) > 0) {
			for _, suffix := range C.Config.SubUrlsBlackSuffix {
				if strings.HasSuffix(url, suffix) {
					return false
				}
			}
		}
		if len(C.Config.SubUrlsBlackList) > 0 {
			if _, ok := C.Config.SubUrlsBlackList[url]; ok {
				return false
			}
		}
		return true
	}
	return false
}

func FindAllSubscribeUrl(html string, num int) []string {
	subUrls := urlRe.FindAllString(html, num)
	subUrlsLen := len(subUrls)
	if subUrlsLen > 0 {
		set := make(map[string]struct{}, subUrlsLen)
		j := 0
		for _, v := range subUrls {
			if !CheckSubscribeUrlValid(v) {
				continue
			}
			if _, ok := set[v]; ok {
				continue
			}
			set[v] = struct{}{}
			subUrls[j] = v
			j++
		}
		if j > 0 {
			return subUrls[:j]
		}
	}
	return make([]string, 0)
}
