package proxy

import (
	"encoding/json"
	"errors"
	"net"
	// "net/url"
	// "regexp"
	"strconv"
	// "strings"
)

var (
	ErrorNotSnellLink          = errors.New("not a correct snell link")
)

type Snell struct {
	Base
	Password       string            `yaml:"psk" json:"psk"`
	Version        int               `yaml:"version,omitempty" json:"version,omitempty"`
	ObfsOpts       map[string]string `yaml:"obfs-opts,omitempty" json:"obfs-opts,omitempty"`
}

func (s Snell) Identifier() string {
	return net.JoinHostPort(s.Server, strconv.Itoa(s.Port)) + s.Password
}

func (s Snell) String() string {
	data, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(data)
}

func (s Snell) ToClash() string {
	data, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return "- " + string(data)
}

func (s Snell) ToSurge() string {
	return ""
}

func (s Snell) Clone() Proxy {
	return &s
}

func (s Snell) Link() (link string) {
	return ""
}
