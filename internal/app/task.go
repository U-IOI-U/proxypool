package app

import (
	"fmt"
	"sync"
	"time"

	C "github.com/u-ioi-u/proxypool/config"
	"github.com/u-ioi-u/proxypool/internal/cache"
	"github.com/u-ioi-u/proxypool/internal/database"
	"github.com/u-ioi-u/proxypool/log"
	"github.com/u-ioi-u/proxypool/pkg/geoIp"
	"github.com/u-ioi-u/proxypool/pkg/healthcheck"
	"github.com/u-ioi-u/proxypool/pkg/provider"
	"github.com/u-ioi-u/proxypool/pkg/proxy"
	"github.com/u-ioi-u/proxypool/pkg/tool"

	"github.com/ivpusic/grpool"
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

func runGetters(pGetters PGetterList, pc chan proxy.Proxy, wg *sync.WaitGroup) {
	pool := grpool.NewPool(100, 20)
	pool.WaitCount(len(*pGetters))

	for _, g := range *pGetters {
		gg := g
		pool.JobQueue <- func() {
			defer pool.JobDone()
			gg.Get2ChanWG(pc, wg)
		}
	}

	pool.WaitAll()
	pool.Release()
}

func CrawlGo(pGetters PGetterList) {
	wg := &sync.WaitGroup{}
	var pc = make(chan proxy.Proxy)
	wg.Add(len(*pGetters))
	go runGetters(pGetters, pc, wg)
	// 	for _, g := range *pGetters {
	// 		wg.Add(1)
	// 		go g.Get2ChanWG(pc, wg)
	// 	}
	proxies := cache.GetProxies("allproxies")
	if proxies == nil {
		// Show last time result when launch
		dbProxies := database.GetAllProxies()
		if dbProxies != nil {
			cache.SetProxies("proxies", dbProxies)
			cache.LastCrawlTime = "抓取中，已载入上次数据库数据"
			log.Infoln("Database: loaded")

			proxies = dbProxies.UniqAppendProxyList(proxies)
		}
	}

	if proxies == nil {
		proxies = make(proxy.ProxyList, 0)
	}

	go func() {
		wg.Wait()
		close(pc)
	}() // Note: 为何并发？可以一边抓取一边读取而非抓完再读
	// for 用于阻塞goroutine
	for p := range pc { // Note: pc关闭后不能发送数据可以读取剩余数据
		if p != nil {
			if proxy.CheckProxyValid(p) {
				proxies = append(proxies, proxy.FixProxyValue(p))
			}
		}
	}
	proxies = proxies.Deduplication()

	// show subscribe url
	if C.Config.ShowSubscribe == "showall" || C.Config.ShowSubscribe == "showsuc" {
		log.Debugln(tool.SubScribeHistoryShow(C.Config.ShowSubscribe))
	} else {
		tool.SubScribeHistoryShow("debug")
	}
	
	proxies.NameClear()
	proxies = proxies.Derive()
	log.Infoln("CrawlGo unique proxy count: %d", len(proxies))

	// Clean Clash unsupported proxy because health check depends on clash
	// proxies = provider.Clash{
	// 	Base: provider.Base{
	// 		Proxies: &proxies,
	// 	},
	// }.CleanProxies()
	// log.Infoln("CrawlGo clash supported proxy count: %d", len(proxies))

	cache.SetProxies("allproxies", proxies)
	cache.AllProxiesCount = proxies.Len()
	log.Infoln("AllProxiesCount: %d", cache.AllProxiesCount)
	cache.SSProxiesCount = proxies.TypeLen("ss")
	log.Infoln("SSProxiesCount: %d", cache.SSProxiesCount)
	cache.SSRProxiesCount = proxies.TypeLen("ssr")
	log.Infoln("SSRProxiesCount: %d", cache.SSRProxiesCount)
	cache.VmessProxiesCount = proxies.TypeLen("vmess")
	log.Infoln("VmessProxiesCount: %d", cache.VmessProxiesCount)
	log.Infoln("VlessProxiesCount: %d", proxies.TypeLen("vless"))
	cache.TrojanProxiesCount = proxies.TypeLen("trojan")
	log.Infoln("TrojanProxiesCount: %d", cache.TrojanProxiesCount)
	log.Infoln("HttpProxiesCount: %d", proxies.TypeLen("http"))
	log.Infoln("SnellProxiesCount: %d", proxies.TypeLen("snell"))
	log.Infoln("TuicProxiesCount: %d", proxies.TypeLen("tuic"))
	log.Infoln("HysteriaProxiesCount: %d", proxies.TypeLen("hysteria"))
	log.Infoln("Hysteria2ProxiesCount: %d", proxies.TypeLen("hysteria2"))
	cache.LastCrawlTime = time.Now().In(location).Format("2006-01-02 15:04:05")

	// save all proxy
	if C.Config.SaveProxyFile != "" {
		provider.Pfile{
			Base: provider.Base{
				Proxies: &proxies,
			},
		}.SaveProxies(C.Config.SaveProxyFile + "_all", C.Config.SaveProxyMode)
	}

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
	// 节点添加Country信息
	proxies.AddCountry()
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

	log.Infoln("Usablility checking done. Open %s to check", C.Config.HostUrl())

	// save proxy
	if C.Config.SaveProxyFile != "" {
		provider.Pfile{
			Base: provider.Base{
				Proxies: &proxies,
			},
		}.SaveProxies(C.Config.SaveProxyFile, C.Config.SaveProxyMode)
		return
	}

	// 后台处理数据库操作
	go func () {
		database.SaveProxyList(proxies)
		database.ClearOldItems()
	}()

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
