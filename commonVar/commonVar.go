package commonvar

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
)

var (
	Data             sync.Map
	TargetAddr       string
	LocalAddrAndPort string
	ServerName       string
	ServerAddr       string
	Key              = []byte("452tfgr24j9j9a9721")
	Encrypt          bool
	Mode             bool
	ReplyServer      = "8.210.34.161:33318"
	ReplyServerQuic  = "8.210.34.161:33317"
	Cookie           = gerateCookie()
	Conn1            *net.UDPConn
	NAT              bool
)

func gerateCookie() string {
	// 生成4个随机字节（4字节 == 8十六进制字符）
	buffer := make([]byte, 4)
	_, err := rand.Read(buffer)
	if err != nil {
		panic("Failed to generate random bytes.")
	}

	// 将字节转换为十六进制字符串
	return hex.EncodeToString(buffer)
}
