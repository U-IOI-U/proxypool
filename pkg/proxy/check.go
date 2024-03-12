package proxy

import (
	"strings"

	"github.com/u-ioi-u/proxypool/pkg/tool"
)

func CheckVmessUUID(uuid string) bool {
	if len(uuid) != 36 {
		return false
	}
	return true
}

func CheckVlessUUID(uuid string) bool {
	if len(uuid) == 0 {
		return false
	}
	return true
}

func CheckPort(port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	return true
}

func CheckAddress(addr string) bool {
	// a.b
	if len := len(addr); len < 3 {
		return false
	}
	// ipv6
	if strings.Contains(addr, "[") {
		if strings.ContainsAny(addr, ".-") {
			return false
		}
		if !strings.ContainsAny(addr, ":]") {
			return false
		}
	}

	if strings.ContainsAny(addr, " /\\&?,@") {
		return false
	}

	return true
}


var ssrObfsList = []string{
	"plain",
	"http_simple",
	"http_post",
	"random_head",
	"tls1.2_ticket_auth",
	"tls1.2_ticket_fastauth",
}

var ssrProtocolList = []string{
	"origin",
	"verify_deflate",
	"verify_sha1",
	"auth_sha1",
	"auth_sha1_v2",
	"auth_sha1_v4",
	"auth_aes128_md5",
	"auth_aes128_sha1",
	"auth_chain_a",
	"auth_chain_b",
}

var vmessCipherList = []string{
	"auto",
	"aes-128-gcm",
	"chacha20-poly1305",
	"none",
	"zero",
}

func CheckSSCipher(cipher string) bool {
	return tool.CheckInList(SSCipherList, cipher)
}

func CheckSSRCipher(cipher string) bool {
	return tool.CheckInList(SSRCipherList, cipher)
}

func CheckClashSSRObfs(obfs string) bool {
	return tool.CheckInList(ssrObfsList, obfs)
}

func CheckClashSSRProtocol(proto string) bool {
	return tool.CheckInList(ssrProtocolList, proto)
}

func CheckVmessCipher(cipher string) bool {
	if cipher == "" {
		return true
	}
	return tool.CheckInList(vmessCipherList, cipher)
}
