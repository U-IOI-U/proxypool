package app

import (
	"errors"
	"path/filepath"

	"github.com/ssrlive/proxypool/log"

	"github.com/ssrlive/proxypool/internal/cache"

	"github.com/ghodss/yaml"

	"github.com/ssrlive/proxypool/config"
	"github.com/ssrlive/proxypool/pkg/getter"
)

var Getters = make([]getter.Getter, 0)

func InitConfigAndGetters() (err error) {
	err = config.Parse()
	if err != nil {
		return
	}
	if s := config.Config.SourceFiles; len(s) == 0 {
		return errors.New("no sources")
	} else {
		for index, path := range s {
			if config.IsLocalFile(path) && !filepath.IsAbs(path) {
				var configDir = filepath.Dir(config.FilePath())
				s[index] = filepath.Join(configDir, path)
			}
		}
		initGetters(s)
	}
	return
}

func initGetters(sourceFiles []string) {
	Getters = make([]getter.Getter, 0)
	for _, path := range sourceFiles {
		data, err := config.ReadFile(path)
		if err != nil {
			log.Errorln("Init SourceFile Error: %s\n", err.Error())
			continue
		}
		sourceList := make([]config.Source, 0)
		err = yaml.Unmarshal(data, &sourceList)
		if err != nil {
			log.Errorln("Init SourceFile Error: %s\n", err.Error())
			continue
		}
		for _, source := range sourceList {
			if source.Options == nil {
				continue
			}
			if isSourceInBlackList(source) {
				continue
			}
			g, err := getter.NewGetter(source.Type, source.Options)
			if err == nil && g != nil {
				Getters = append(Getters, g)
				log.Debugln("init getter: %s %v", source.Type, source.Options)
			}
		}
	}
	log.Infoln("Getter count: %d", len(Getters))
	cache.GettersCount = len(Getters)
}

func isSourceInBlackList(source config.Source) bool {
	if urls, ok := config.Config.GetterBlackList[source.Type]; ok {
		if _, ok := urls["-"]; ok { // "-"代表屏蔽该种类型
			return true
		}
		if channel, ok := source.Options["channel"]; ok {
			if channel.(string) != "" {
				if _, ok := urls[channel.(string)]; ok {
					return true
				}
			}
		}
		if url, ok := source.Options["url"]; ok {
			if url.(string) != "" {
				if _, ok := urls[url.(string)]; ok {
					return true
				}
			}
		}
	}
	return false
}
