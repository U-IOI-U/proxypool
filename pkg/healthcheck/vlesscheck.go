package healthcheck

import (
	"context"
	"fmt"
	C "github.com/U-IOI-U/Clash.Meta/constant"
	// "github.com/ssrlive/proxypool/pkg/proxy"
	// "io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"
	clash_vless "github.com/U-IOI-U/Clash.Meta/adapter"
)

func ParseVless(pmap map[string]interface{}) (C.Proxy, error) {
	return clash_vless.ParseProxy(pmap)
}

// DO NOT EDIT. Copied from clash because it's an unexported function
func _urlToMetadata(rawURL string) (addr C.Metadata, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			err = fmt.Errorf("%s scheme not Support", rawURL)
			return
		}
	}

	addr = C.Metadata{
		AddrType: C.AtypDomainName,
		Host:     u.Hostname(),
		DstIP:    nil,
		DstPort:  port,
	}
	return
}

func HTTPHeadViaVless(clashProxy C.Proxy, url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), DelayTimeout)
	defer cancel()

	addr, err := _urlToMetadata(url)
	if err != nil {
		return err
	}
	conn, err := clashProxy.DialContext(ctx, &addr) // 建立到proxy server的connection，对Proxy的类别做了自适应相当于泛型
	if err != nil {
		return err
	}
	defer conn.Close()

	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)

	transport := &http.Transport{
		// Note: Dial specifies the dial function for creating unencrypted TCP connections.
		// When httpClient sets this transport, it will use the tcp/udp connection returned from
		// function Dial instead of default tcp/udp connection. It's the key to set custom proxy for http transport
		Dial: func(string, string) (net.Conn, error) {
			return conn, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%d %s for proxy %s %s", resp.StatusCode, resp.Status, clashProxy.Name(), clashProxy.Addr())
	}
	resp.Body.Close()
	return nil
}
