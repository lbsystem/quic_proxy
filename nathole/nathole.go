package nathole

import (
	"bytes"
	"fmt"
	"net"
	"quic_proxy/commonVar"
	"strings"
	"time"
)

func EncodePacket(name, cookie string, code uint8) []byte {
	b := new(bytes.Buffer)
	b.Write([]byte("changeport"))
	b.Write([]byte{code})
	b.Write([]byte{uint8(len(name))})
	b.Write([]byte(name))
	if code == 3 || code == 5 {
		b.Write([]byte(cookie))
	}
	return b.Bytes()
}

func RegAddr(name string) {
	b := EncodePacket(commonvar.ServerName, "", 1)
	addr, _ := net.ResolveUDPAddr("udp", commonvar.ReplyServer)
	_, err := commonvar.Conn1.WriteToUDP(b, addr)
	if err != nil {
		fmt.Println("11  ", err.Error())
	}
	for {
		time.Sleep(time.Second)
		_, err = commonvar.Conn1.WriteToUDP(b, addr)
		if err != nil {
			fmt.Println("----------------")
			fmt.Println(err.Error())
		}
	}
}
func QuiryIP(name string, code uint8) string {
	now := time.Now().Add(time.Second)
	addr, _ := net.ResolveUDPAddr("udp", commonvar.ReplyServer)
	var n int
	b := EncodePacket(name, commonvar.Cookie, code)
SEND:
	_, err := commonvar.Conn1.WriteToUDP(b, addr)
	if err != nil {
		fmt.Println(err.Error())
	}
	b1 := make([]byte, 1024)
	var a *net.UDPAddr
	if code == 3 {
		for {
			n, a, err = commonvar.Conn1.ReadFromUDP(b1)
			if err != nil || n < 6 {
				time.Sleep(time.Second)
				goto SEND
			}
			if a.String() == commonvar.ReplyServer {
				fmt.Println("get really name: ", string(b1[:n]))
				break
			}

			if now.Before(time.Now()) {
				fmt.Println("udp send again")
				time.Sleep(time.Second)
				goto SEND
			}
		}
		return strings.Trim(string(b1[:n]), " ")
	} else {
		return ""
	}

}

func HandleNatConn(data []byte) {
	addr, err := net.ResolveUDPAddr("udp", string(data))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	commonvar.Conn1.WriteToUDP([]byte(""), addr)
	commonvar.Conn1.WriteToUDP([]byte(""), addr)
	commonvar.Conn1.WriteToUDP([]byte(""), addr)
	fmt.Println("Nat connecting : ", addr.String())

}

func ChangeIP(name string, code uint8) {
	for {
		time.Sleep(time.Second * 2)
		QuiryIP(name, 5)
	}
}
