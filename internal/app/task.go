package app

import (
	"fmt"
	"sync"
	"time"

	C "github.com/ssrlive/proxypool/config"
	"github.com/ssrlive/proxypool/internal/cache"
	"github.com/ssrlive/proxypool/internal/database"
	"github.com/ssrlive/proxypool/log"
	"github.com/ssrlive/proxypool/pkg/geoIp"
	"github.com/ssrlive/proxypool/pkg/healthcheck"
	"github.com/ssrlive/proxypool/pkg/provider"
	"github.com/ssrlive/proxypool/pkg/proxy"
	"github.com/ssrlive/proxypool/pkg/tool"
)

var location, _ = time.LoadLocation("Asia/Shanghai")

var isCrawlGoRunning bool = false
var crawlGoSync sync.Mutex

func CrawlGoWithSync() {
	crawlGoSync.Lock()
	if isCrawlGoRunning == true {
		crawlGoSync.Unlock()
		log.Debugln("CrawlGo: is Running!")
		return
	}
	isCrawlGoRunning = true
	crawlGoSync.Unlock()

	sTime := time.Now()

	CrawlGo(Getters)

	cost := time.Since(sTime)
	log.Debugln("CrawlGo: is ended after %s!", cost)

	// 运行到这里的只有一个线程,不用加锁了
	isCrawlGoRunning = false 
}

func CrawlGo(pGetters PGetterList) {
	wg := &sync.WaitGroup{}
	var pc = make(chan proxy.Proxy)
	for _, g := range *pGetters {
		wg.Add(1)
		go g.Get2ChanWG(pc, wg)
	}
	proxies := cache.GetProxies("allproxies")
	dbProxies := database.GetAllProxies()
	// Show last time result when launch
	if proxies == nil && dbProxies != nil {
		cache.SetProxies("proxies", dbProxies)
		cache.LastCrawlTime = "抓取中，已载入上次数据库数据"
		log.Infoln("Database: loaded")
	}
	if dbProxies != nil {
		proxies = dbProxies.UniqAppendProxyList(proxies)
	}
	if proxies == nil {
		proxies = make(proxy.ProxyList, 0)
	}

	go func() {
		wg.Wait()
		close(pc)
	}() // Note: 为何并发？可以一边抓取一边读取而非抓完再读

	var proxiesNum int = 0
	sTime := time.Now()
	if C.Config.ProxiesMergeMode == 1 {
		proxiesMap := make(map[string]struct{}, len(proxies))
		for _, value := range proxies {
			if _, ok := proxiesMap[value.Identifier()]; !ok {
				proxiesMap[value.Identifier()] = struct{}{}
			}
		}
	
		for p := range pc {
			if p != nil {
				proxiesNum = proxiesNum + 1
				if _, ok := proxiesMap[p.Identifier()]; !ok {
					proxies = append(proxies, p)
					proxiesMap[p.Identifier()] = struct{}{}
				}
			}
		}
	} else if C.Config.ProxiesMergeMode == 2 {
		for p := range pc {
			if p != nil {
				proxiesNum = proxiesNum + 1
				proxies = append(proxies, p)
			}
		}
		proxies = proxies.Deduplication()
	} else {
		// for 用于阻塞goroutine
		for p := range pc { // Note: pc关闭后不能发送数据可以读取剩余数据
			if p != nil {
				proxiesNum = proxiesNum + 1
				proxies = proxies.UniqAppendProxy(p)
			}
		}
	}
	cost := time.Since(sTime)
	log.Debugln("CrawlGo: MergeMode %d merge %d proxy used %s!", C.Config.ProxiesMergeMode, proxiesNum, cost)

	tool.SubScribeHistoryShow("debug")
	proxies.NameClear()
	proxies = proxies.Derive()
	log.Infoln("CrawlGo unique proxy count: %d", len(proxies))

	// Clean Clash unsupported proxy because health check depends on clash
	proxies = provider.Clash{
		Base: provider.Base{
			Proxies: &proxies,
		},
	}.CleanProxies()
	log.Infoln("CrawlGo clash supported proxy count: %d", len(proxies))

	cache.SetProxies("allproxies", proxies)
	cache.AllProxiesCount = proxies.Len()
	log.Infoln("AllProxiesCount: %d", cache.AllProxiesCount)
	cache.SSProxiesCount = proxies.TypeLen("ss")
	log.Infoln("SSProxiesCount: %d", cache.SSProxiesCount)
	cache.SSRProxiesCount = proxies.TypeLen("ssr")
	log.Infoln("SSRProxiesCount: %d", cache.SSRProxiesCount)
	cache.VmessProxiesCount = proxies.TypeLen("vmess")
	log.Infoln("VmessProxiesCount: %d", cache.VmessProxiesCount)
	cache.TrojanProxiesCount = proxies.TypeLen("trojan")
	log.Infoln("TrojanProxiesCount: %d", cache.TrojanProxiesCount)
	cache.LastCrawlTime = time.Now().In(location).Format("2006-01-02 15:04:05")

	// Health Check
	log.Infoln("Now proceed proxy health check...")
	healthcheck.SpeedConn = C.Config.SpeedConnection
	healthcheck.DelayConn = C.Config.HealthCheckConnection
	if C.Config.HealthCheckTimeout > 0 {
		healthcheck.DelayTimeout = time.Second * time.Duration(C.Config.HealthCheckTimeout)
		log.Infoln("CONF: Health check timeout is set to %d seconds", C.Config.HealthCheckTimeout)
	}

	proxies = healthcheck.CleanBadProxiesWithGrpool(proxies)

	// proxies = healthcheck.CleanBadProxies(proxies)

	log.Infoln("CrawlGo clash usable proxy count: %d", len(proxies))

	// Format name like US_01 sorted by country
	proxies.NameAddCounrty().Sort()
	log.Infoln("Proxy rename DONE!")

	// Relay check and rename
	if C.Config.RelayTest {
		healthcheck.RelayCheck(proxies)
		for i := range proxies {
			if s, ok := healthcheck.ProxyStats.Find(proxies[i]); ok {
				if s.Relay {
					_, c, e := geoIp.GeoIpDB.Find(s.OutIp)
					if e == nil {
						proxies[i].SetName(fmt.Sprintf("Relay_%s-%s", proxies[i].BaseInfo().Name, c))
					}
				} else if s.Pool {
					proxies[i].SetName(fmt.Sprintf("Pool_%s", proxies[i].BaseInfo().Name))
				}
			}
		}
	}

	proxies.NameAddIndex()

	// 可用节点存储
	cache.SetProxies("proxies", proxies)
	cache.UsefullProxiesCount = proxies.Len()
	// 后台处理数据库操作
	go func () {
		database.SaveProxyList(proxies)
		database.ClearOldItems()
	}()

	log.Infoln("Usablility checking done. Open %s to check", C.Config.HostUrl())

	// 测速
	speedTestNew(proxies)
	cache.SetString("clashproxies", provider.Clash{
		Base: provider.Base{
			Proxies: &proxies,
		},
	}.Provide()) // update static string provider
	cache.SetString("surgeproxies", provider.Surge{
		Base: provider.Base{
			Proxies: &proxies,
		},
	}.Provide())
}

// Speed test for new proxies
func speedTestNew(proxies proxy.ProxyList) {
	if C.Config.SpeedTest {
		cache.IsSpeedTest = "已开启"
		if C.Config.SpeedTimeout > 0 {
			healthcheck.SpeedTimeout = time.Second * time.Duration(C.Config.SpeedTimeout)
			log.Infoln("config: Speed test timeout is set to %d seconds", C.Config.SpeedTimeout)
		}
		healthcheck.SpeedTestNew(proxies)
	} else {
		cache.IsSpeedTest = "未开启"
	}
}

// Speed test for all proxies in proxy.ProxyList
func SpeedTest(proxies proxy.ProxyList) {
	if C.Config.SpeedTest {
		cache.IsSpeedTest = "已开启"
		if C.Config.SpeedTimeout > 0 {
			log.Infoln("config: Speed test timeout is set to %d seconds", C.Config.SpeedTimeout)
			healthcheck.SpeedTimeout = time.Second * time.Duration(C.Config.SpeedTimeout)
		}
		healthcheck.SpeedTestAll(proxies)
	} else {
		cache.IsSpeedTest = "未开启"
	}
}
