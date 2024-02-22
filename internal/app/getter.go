package app

import (
	"errors"
	"path/filepath"

	"github.com/u-ioi-u/proxypool/log"

	"github.com/u-ioi-u/proxypool/internal/cache"

	"github.com/ghodss/yaml"

	"github.com/u-ioi-u/proxypool/config"
	"github.com/u-ioi-u/proxypool/pkg/getter"
)

type PGetterList *[]getter.Getter
var Getters PGetterList = nil

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
	newGetters := make([]getter.Getter, 0)
	GettersList := map[string]struct{}{}
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
			if isSourceInBlackList(source) || isGetterExist(source, &GettersList) {
				continue
			}
			g, err := getter.NewGetter(source.Type, source.Options)
			if err == nil && g != nil {
				newGetters = append(newGetters, g)
				log.Debugln("init getter: %s %v", source.Type, source.Options)
			}
		}
	}
	log.Infoln("Getter count: %d", len(newGetters))
	cache.GettersCount = len(newGetters)
	Getters = &newGetters
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

func isGetterExist(source config.Source, getterList *map[string]struct{}) bool {
	if channel, ok := source.Options["channel"]; ok {
		if _, ok := (*getterList)[channel.(string) + source.Type]; ok {
			return true
		}
		(*getterList)[channel.(string) + source.Type] = struct{}{}
	}
	if url, ok := source.Options["url"]; ok {
		if _, ok := (*getterList)[url.(string) + source.Type]; ok {
			return true
		}
		(*getterList)[url.(string) + source.Type] = struct{}{}
	}
	return false
}
