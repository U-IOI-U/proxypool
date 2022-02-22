package tool

import (
	"sync"
	"github.com/ssrlive/proxypool/log"
)

var subScribeHistory = make(map[string]int, 1000)
var subScribeHistoryLock sync.Mutex

func subScribeHistoryCheckUrlIn(url string) bool {
	subScribeHistoryLock.Lock()
	defer subScribeHistoryLock.Unlock()

	if _, ok := subScribeHistory[url]; ok {
		return true
	}
	subScribeHistory[url] = 0
	return false
}

func subScribeHistoryUpdateRet(url string, num int) {
	subScribeHistoryLock.Lock()
	defer subScribeHistoryLock.Unlock()

	subScribeHistory[url] = num
}

func subScribeHistoryClean() {
	subScribeHistoryLock.Lock()
	defer subScribeHistoryLock.Unlock()
	
	subScribeHistory = make(map[string]int, 1000)
}

func subScribeHistoryShow() {
	if (len(subScribeHistory) > 0) {
		for key, value := range subScribeHistory {
			log.Debugln("STATISTIC: Subscribe\t count= %-5d, url=%s\n", value, key)
		}
	}
}
