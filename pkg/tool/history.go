package tool

import (
	"fmt"
	"sync"
	"strings"
	"github.com/ssrlive/proxypool/log"
)

type HistoryInfo struct {
	accessRq        bool
	nodeNum         int
	zeroCount       int
	zeroMultiFactor int
}

var subScribeHistory = make(map[string]*HistoryInfo, 1000)
var subScribeHistoryLock sync.Mutex
var defaultZeroMultiFactor int = 20
var defatltZeroFailNum int = 10
var defaultZeroFail bool = false

func SubScribeHistorySetDefaultValue(fail bool, failNum int, failMultiFactor int) {
	defaultZeroMultiFactor = failMultiFactor
	defatltZeroFailNum = failNum
	defaultZeroFail = fail
}

func SubScribeHistoryCheckUrlIn(url string) bool {
	subScribeHistoryLock.Lock()
	defer subScribeHistoryLock.Unlock()

	if _, ok := subScribeHistory[url]; ok {
		return subScribeHistory[url].accessRq
	}
	subScribeHistory[url] = &HistoryInfo{accessRq: true, nodeNum: 0, zeroCount: 0, zeroMultiFactor: defaultZeroMultiFactor}
	return false
}

func SubScribeHistoryUpdateRet(url string, num int) {
	subScribeHistoryLock.Lock()
	defer subScribeHistoryLock.Unlock()

	subScribeHistory[url].nodeNum = num
}

func SubScribeHistoryClean() {
	subScribeHistoryLock.Lock()
	defer subScribeHistoryLock.Unlock()
	
	if defaultZeroFail {
		for _, value := range subScribeHistory {
			if value.nodeNum == 0 {
				value.zeroCount = value.zeroCount + 1
			} else {
				value.zeroCount = 0
				value.zeroMultiFactor = defaultZeroMultiFactor
			}
	
			if (value.zeroCount > value.zeroMultiFactor) {
				value.zeroCount = 0
				value.zeroMultiFactor = value.zeroMultiFactor + defaultZeroMultiFactor
			}
	
			if (value.zeroCount <= defatltZeroFailNum) {
				value.accessRq = false
			} else {
				value.accessRq = true
			}
		}
	} else {
		for _, value := range subScribeHistory {
			value.accessRq = false
		}
	}
}

func SubScribeHistoryShow (mode string) string {
	if (len(subScribeHistory) > 0) {
		if strings.Compare(mode, "debug") == 0 {
			defer SubScribeHistoryClean()
			log.Debugln("STATISTIC: Subscribe\tcount=%-5d\n", len(subScribeHistory))
		} else if strings.Compare(mode, "web") == 0 {
			retString := make([]string, len(subScribeHistory))
			for key, value := range subScribeHistory {
				retString = append(retString, fmt.Sprintf("Subscribe accessRq=%t zeroCount=%-3d zeroMultiFactor=%-4d count=%-5d url = %s\n", value.accessRq, value.zeroCount, value.zeroMultiFactor, value.nodeNum, key))

			}
			return strings.Join(retString, "")
		}
	}

	return ""
}
