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
	for _, bl := range config.Config.GetterBlackList {
		if (bl.Type == source.Type) {
			if (bl.Type == "tgchannel") && (bl.Options["channel"] == source.Options["channel"]) {
				return true
			} else if bl.Options["url"] == source.Options["url"] {
				return true
			}
		}
	}
	return false
}
