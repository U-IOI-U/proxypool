package tool

import (
	"sync"
	"github.com/ssrlive/proxypool/log"
)

var subScribeHistory = make(map[string]int, 1000)
var subScribeHistoryLock sync.Mutex

func SubScribeHistoryCheckUrlIn(url string) bool {
	subScribeHistoryLock.Lock()
	defer subScribeHistoryLock.Unlock()

	if _, ok := subScribeHistory[url]; ok {
		return true
	}
	subScribeHistory[url] = 0
	return false
}

func SubScribeHistoryUpdateRet(url string, num int) {
	subScribeHistoryLock.Lock()
	defer subScribeHistoryLock.Unlock()

	subScribeHistory[url] = num
}

func SubScribeHistoryClean() {
	subScribeHistoryLock.Lock()
	defer subScribeHistoryLock.Unlock()
	
	subScribeHistory = make(map[string]int, 1000)
}

func SubScribeHistoryShow() {
	defer SubScribeHistoryClean()

	if (len(subScribeHistory) > 0) {
		for key, value := range subScribeHistory {
			log.Debugln("STATISTIC: Subscribe\tcount=%-5d\turl=%s\n", value, key)
		}
	}
}
