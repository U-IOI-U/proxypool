package tool

import (
	"fmt"
	"sync"
	"strings"
	"github.com/ssrlive/proxypool/log"
)

type HistoryInfo struct {
	accessRq        bool
	resPonSize      int
	nodeNum         int
	zeroCount       int
	zeroMultiFactor int
}

var subScribeHistory = make(map[string]*HistoryInfo, 1000)
var subScribeHistoryLock sync.Mutex
var defaultZeroMultiFactorMax int = 9999
var defaultZeroMultiFactor int = 20
var defatltZeroFailNum int = 10
var defaultZeroFail bool = false

func SubScribeHistorySetDefaultValue(fail bool, failNum int, failMultiFactor int, failMultiFactorMax int) {
	if failMultiFactorMax > 0 {
		defaultZeroMultiFactorMax = failMultiFactorMax
	}
	if failMultiFactor > 0 {
		defaultZeroMultiFactor = failMultiFactor
	}
	if failNum > 0 {
		defatltZeroFailNum = failNum
	}
	defaultZeroFail = fail
}

func SubScribeHistoryCheckUrlIn(url string) bool {
	if defaultZeroFail {
		subScribeHistoryLock.Lock()
		if _, ok := subScribeHistory[url]; ok {
			if subScribeHistory[url].accessRq {
				subScribeHistoryLock.Unlock()
				return true
			}
			subScribeHistory[url].accessRq = true
			subScribeHistoryLock.Unlock()
			return false
		}
		subScribeHistory[url] = &HistoryInfo{accessRq: true, resPonSize: 0, nodeNum: 0, zeroCount: 0, zeroMultiFactor: defaultZeroMultiFactor}
		subScribeHistoryLock.Unlock()
	}
	return false
}

func SubScribeHistoryUpdateRet(url string, num int) {
	if defaultZeroFail {
		subScribeHistoryLock.Lock()
		subScribeHistory[url].nodeNum = num
		subScribeHistoryLock.Unlock()
	}
}

func SubScribeHistoryBlockSuccess(url string) {
	if defaultZeroFail {
		subScribeHistoryLock.Lock()
		if subScribeHistory[url].resPonSize > 0 {
			subScribeHistory[url].zeroMultiFactor = defaultZeroMultiFactorMax
		}
		subScribeHistoryLock.Unlock()
	}
}

func SubScribeHistoryBlockAdd(url string) {
	if defaultZeroFail {
		subScribeHistoryLock.Lock()
		if _, ok := subScribeHistory[url]; ok {
			subScribeHistory[url].accessRq = true
			subScribeHistory[url].zeroMultiFactor = defaultZeroMultiFactorMax
		} else {
			subScribeHistory[url] = &HistoryInfo{accessRq: true, resPonSize: 0, nodeNum: 0, zeroCount: 0, zeroMultiFactor: defaultZeroMultiFactorMax}
		}
		subScribeHistoryLock.Unlock()
	}
}

func SubScribeHistoryBlockRemove(url string) {
	if defaultZeroFail {
		subScribeHistoryLock.Lock()
		if _, ok := subScribeHistory[url]; ok {
			delete(subScribeHistory, url)
		}
		subScribeHistoryLock.Unlock()
	}
}

func SubScribeHistoryUpdateResponseSize(url string, num int) {
	if defaultZeroFail {
		subScribeHistoryLock.Lock()
		subScribeHistory[url].resPonSize = num
		subScribeHistoryLock.Unlock()
	}
}

func SubScribeHistoryClean() {
	if defaultZeroFail {
		subScribeHistoryLock.Lock()
		for _, value := range subScribeHistory {
			if (value.accessRq == true) && (value.zeroMultiFactor < defaultZeroMultiFactorMax) {
				if value.nodeNum == 0 {
					if value.resPonSize > 0 { // 如果请求到数据又无法解析，直接封禁，等待解封
						value.zeroCount = defatltZeroFailNum + 1
						value.resPonSize = 0
					} else {
						value.zeroCount = value.zeroCount + 1
					}
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
					value.accessRq = true // 等待解封
					if (value.zeroMultiFactor + defaultZeroMultiFactor) > defaultZeroMultiFactorMax { // 永久封禁
						value.zeroMultiFactor = defaultZeroMultiFactorMax
					}
				}
			}
		}
		subScribeHistoryLock.Unlock()
	}
}

func SubScribeHistoryShow (mode string) string {
	if defaultZeroFail {
		subScribeHistoryLock.Lock()
		lenHis := len(subScribeHistory)
		subScribeHistoryLock.Unlock()
		if lenHis > 0 {
			if strings.Compare(mode, "debug") == 0 {
				defer SubScribeHistoryClean()
				log.Debugln("STATISTIC: Subscribe\tcount=%-5d\n", lenHis)
			} else if strings.Compare(mode, "showall") == 0 {
				retString := make([]string, lenHis)
				subScribeHistoryLock.Lock()
				for key, value := range subScribeHistory {
					retString = append(retString, fmt.Sprintf("Subscribe accessRq=%-5t resPonSize=%-6d zeroCount=%-3d zeroMultiFactor=%-4d count=%-5d url = %s\n", value.accessRq, value.resPonSize, value.zeroCount, value.zeroMultiFactor, value.nodeNum, key))
				}
				subScribeHistoryLock.Unlock()
				return strings.Join(retString, "")
			} else if strings.Compare(mode, "showsuc") == 0 {
				retString := make([]string, lenHis)
				subScribeHistoryLock.Lock()
				for key, value := range subScribeHistory {
					if value.nodeNum > 0 && value.zeroMultiFactor < defaultZeroMultiFactorMax {
						retString = append(retString, fmt.Sprintf("Subscribe accessRq=%-5t resPonSize=%-6d zeroCount=%-3d zeroMultiFactor=%-4d count=%-5d url = %s\n", value.accessRq, value.resPonSize, value.zeroCount, value.zeroMultiFactor, value.nodeNum, key))
					}
				}
				subScribeHistoryLock.Unlock()
				return strings.Join(retString, "")
			}
		}
	}

	return ""
}
