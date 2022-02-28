package config

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/ssrlive/proxypool/log"

	"github.com/ghodss/yaml"
	"github.com/ssrlive/proxypool/pkg/tool"
)

var configFilePath = "config.yaml"

type ConfigOptions struct {
	Domain                string   `json:"domain" yaml:"domain"`
	Port                  string   `json:"port" yaml:"port"`
	DatabaseUrl           string   `json:"database_url" yaml:"database_url"`
	CrawlInterval         uint64   `json:"crawl-interval" yaml:"crawl-interval"`
	CFEmail               string   `json:"cf_email" yaml:"cf_email"`
	CFKey                 string   `json:"cf_key" yaml:"cf_key"`
	TGFileApi             string   `json:"tg_file_api" yaml:"tg_file_api"`
	RouteHistoryApi       bool     `json:"route_history_api" yaml:"route_history_api"`
	RouteUpdateApi        bool     `json:"route_update_api" yaml:"route_update_api"`
	SourceFiles           []string `json:"source-files" yaml:"source-files"`
	ProxiesMergeMode      int      `json:"proxies_merge_mode" yaml:"proxies_merge_mode"`
	GetterBlackList       map[string]map[string]interface{} `json:"getter_black_list" yaml:"getter_black_list"`
	ZeroFail              bool     `json:"zero_fail" yaml:"zero_fail"`
	ZeroFailNum           int      `json:"zero_fail_num" yaml:"zero_fail_num"`
	ZeroFailMultiFactor   int      `json:"zero_fail_multifactor" yaml:"zero_fail_multifactor"`
	SubUrlsBlackPrefix    []string `json:"suburl-blacklist-prefix" yaml:"suburl-blacklist-prefix"`
	SubUrlsBlackSuffix    []string `json:"suburl-blacklist-suffix" yaml:"suburl-blacklist-suffix"`
	HealthCheckTimeout    int      `json:"healthcheck-timeout" yaml:"healthcheck-timeout"`
	HealthCheckConnection int      `json:"healthcheck-connection" yaml:"healthcheck-connection"`
	RelayTest             bool     `json:"relaytest" yaml:"relaytest"`
	SpeedTest             bool     `json:"speedtest" yaml:"speedtest"`
	SpeedTestInterval     uint64   `json:"speedtest-interval" yaml:"speedtest-interval"`
	SpeedTimeout          int      `json:"speed-timeout" yaml:"speed-timeout"`
	SpeedConnection       int      `json:"speed-connection" yaml:"speed-connection"`
	ActiveFrequency       uint16   `json:"active-frequency" yaml:"active-frequency" `
	ActiveInterval        uint64   `json:"active-interval" yaml:"active-interval"`
	ActiveMaxNumber       uint16   `json:"active-max-number" yaml:"active-max-number"`
}

// Config 配置
var Config *ConfigOptions // 多线程下访问Parse函数可能会造成Unmarshal函数崩溃，改成指针赋值

func (config ConfigOptions) HostUrl() string {
	url := config.Domain
	if len(strings.Split(url, ":")) <= 1 {
		url = url + ":" + config.Port
	}
	return url
}

func SetFilePath(path string) {
	configFilePath = extractFullPath(path)
}

func FilePath() string {
	return configFilePath
}

func configFileFullPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	exPath, _ := os.Getwd()

	return filepath.Join(exPath, path)
}

func extractFullPath(path string) string {
	if IsLocalFile(path) {
		path = configFileFullPath(path)
	}
	return path
}

// Parse 解析配置文件，支持本地文件系统和网络链接
func Parse() error {
	fileData, err := ReadFile(configFilePath)
	if err != nil {
		return err
	}
	newConfig := ConfigOptions{}
	err = yaml.Unmarshal(fileData, &newConfig)
	if err != nil {
		return err
	}

	// set default
	if newConfig.SpeedConnection <= 0 {
		newConfig.SpeedConnection = 5
	}
	if newConfig.SpeedTimeout <= 0 {
		newConfig.SpeedTimeout = 10
	}

	// set default
	if newConfig.HealthCheckConnection <= 0 {
		newConfig.HealthCheckConnection = 500
	}
	if newConfig.Port == "" {
		newConfig.Port = "12580"
	}
	if newConfig.CrawlInterval == 0 {
		newConfig.CrawlInterval = 60
	}
	if newConfig.TGFileApi == "" {
		newConfig.TGFileApi = "https://tg.i-c-a.su/rss/"
	}
	if newConfig.ZeroFailNum == 0 {
		newConfig.ZeroFailNum = 10
	}
	if newConfig.ZeroFailMultiFactor == 0 {
		newConfig.ZeroFailMultiFactor = 20
	}
	if newConfig.SpeedTestInterval == 0 {
		newConfig.SpeedTestInterval = 720
	}
	if newConfig.ActiveInterval == 0 {
		newConfig.ActiveInterval = 60
	}
	if newConfig.ActiveFrequency == 0 {
		newConfig.ActiveFrequency = 100
	}
	if newConfig.ActiveMaxNumber == 0 {
		newConfig.ActiveMaxNumber = 100
	}
	tool.SubScribeHistorySetDefaultValue(newConfig.ZeroFail, newConfig.ZeroFailNum, newConfig.ZeroFailMultiFactor)
	// 部分配置环境变量优先
	if domain := os.Getenv("DOMAIN"); domain != "" {
		newConfig.Domain = domain
	}
	if cfEmail := os.Getenv("CF_API_EMAIL"); cfEmail != "" {
		newConfig.CFEmail = cfEmail
	}
	if cfKey := os.Getenv("CF_API_KEY"); cfKey != "" {
		newConfig.CFKey = cfKey
	}
	s, _ := json.Marshal(newConfig)
	log.Debugln("Config options: %s", string(s))
	Config = &newConfig
	return nil
}

func IsLocalFile(path string) bool {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return false
	}
	return true
}

// 从本地文件或者http链接读取配置文件内容
func ReadFile(path string) ([]byte, error) {
	if !IsLocalFile(path) {
		resp, err := tool.GetHttpClient().Get(path)
		if err != nil {
			return nil, errors.New("config file http get fail")
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	} else {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, err
		}
		return os.ReadFile(path)
	}
}

func fullDirOfExecutable() string {
	exePath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	res, _ := filepath.EvalSymlinks(filepath.Dir(exePath))
	return res
}

func moduleName() string {
	info, _ := debug.ReadBuildInfo()
	_, name := filepath.Split(info.Main.Path)
	return name
}

// 返回資源文件所在的根目錄.
func ResourceRoot() string {
	exe, _ := os.Executable()
	_, file := filepath.Split(exe)

	currDir, _ := os.Getwd()
	exeDir := fullDirOfExecutable()
	if exeDir != currDir {
		// 從 go run 運行, 或者從 別的目錄 運行.
		module := moduleName()
		os := runtime.GOOS
		if os == "windows" {
			module = module + ".exe"
		}
		if file == module {
			// 可執行文件在別的目錄運行.
			return exeDir
		} else {
			// 從 go run 運行, 可執行文件生成在臨時目錄,
			// 於是返回當前目錄作爲資源根目錄.
			return currDir
		}
	} else {
		// 從 exe 所在目錄運行.
		return exeDir
	}
}
