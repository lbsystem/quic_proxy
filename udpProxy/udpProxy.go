package udpproxy

import (
	"fmt"
	"net"
	"os"
	"quic_proxy/commonVar"
	"quic_proxy/nathole"
	"sync"
	"time"
)

var (
	proxyAddr      *net.UDPAddr
	CleanupTimeout = 35 * time.Second
)

func UdpProxy() {
	laddr, err := net.ResolveUDPAddr("udp", commonvar.LocalAddrAndPort)
	commonvar.Conn1, err = net.ListenUDP("udp", laddr)
	var natTcp *nathole.NatTcp
	if commonvar.NAT {
		natTcp, err = nathole.NewNatTcp()
		natTcp.VerifyTcp()
		if err != nil {
			fmt.Println("Error resolving address:", err)
			return
		}
	}

	if commonvar.Mode {
		if commonvar.NAT {
			go nathole.RegAddr(commonvar.ServerName)
			time.Sleep(time.Millisecond * 35)
			natTcp.RegisterServerTcp()
		}

	} else if commonvar.NAT {
		natTcp.RegisterClientTcp()
		i := 0
	TryIt:
		commonvar.TargetAddr = nathole.QuiryIP(commonvar.ServerName, 3)
		if commonvar.TargetAddr == "----" {
			i++
			fmt.Println("The server or server name is incorrect.\n I will try again in ten seconds.")
			time.Sleep(time.Second * 10)
			if i > 35 {
				fmt.Println("Too many attempts, program exiting.")
				os.Exit(1)
			}
			goto TryIt
		}
		fmt.Println("get IP: ", commonvar.TargetAddr)
		natTcp.RegisterClientTcp()
		go nathole.ChangeIP(commonvar.ServerName, 5)
	}
	if commonvar.NAT {
		go func() {
			for {
				b, err := natTcp.WaitingSignal()
				if err != nil {
					fmt.Println("NAT SERVER TCP is LOST")
					time.Sleep(time.Second * 3)
					natTcp.ReConnect(2)
				}
				if len(b) > 9 {
					nathole.HandleNatConn(b)
				}
			}
		}()
	}

	if err != nil {
		fmt.Println("Error setting up listener:", err)
		return
	}

	handleClient(commonvar.Conn1)
}

func handleClient(conn *net.UDPConn) {
	b := make([]byte, 1500)

	for {
		n, addr, err := conn.ReadFromUDP(b)
		if err != nil {
			fmt.Println("Error reading from client:", err)
			continue
		}
		if commonvar.NAT {
			if addr.String() == commonvar.ReplyServer {
				continue
			}
		}
		proxyConn, ok := commonvar.Data.Load(addr.String())
		if !ok {

			proxyAddr, err = net.ResolveUDPAddr("udp", commonvar.TargetAddr)
			if err != nil {
				fmt.Println("addr err :", err.Error())
			}
			newProxyConn, err := net.ListenUDP("udp", nil)

			if err != nil {
				fmt.Println("Error connecting to proxy:", err)
				continue
			}
			proxyConn, _ = commonvar.Data.LoadOrStore(addr.String(), newProxyConn)

			go readFromProxy(conn, addr, proxyConn.(*net.UDPConn))

		}
		pconn := proxyConn.(*net.UDPConn)
		_, err = pconn.WriteToUDP(XorCipher(b[:n]), proxyAddr)
		if err != nil {
			fmt.Println("Error writing to proxy:", err)
			continue
		}
	}
}

func readFromProxy(conn *net.UDPConn, addr *net.UDPAddr, pconn *net.UDPConn) {
	b := make([]byte, 1500)
	for {
		// 设置读取超时
		if addr.String() == commonvar.ReplyServer {
			continue
		}
		pconn.SetReadDeadline(time.Now().Add(CleanupTimeout))
		n, err := pconn.Read(b)
		if err != nil {
			// 如果读取超时，则触发清理逻辑
			cleanupConnection(addr.String())
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Println("Read timeout for:", addr.String(), ". Cleaning up...")
				return
			}
			fmt.Println("Error reading from proxy:", err)
			return
		}
		_, err = conn.WriteToUDP(XorCipher(b[:n]), addr)
		if err != nil {
			fmt.Println("Error sending back to client:", err)
			break
		}
	}
}
func XorCipher(data []byte) []byte {
	encrypted := make([]byte, len(data))
	keyLen := len(commonvar.Key)
	for i := range data {
		encrypted[i] = data[i] ^ commonvar.Key[i%keyLen]
	}
	return encrypted
}
func cleanupConnection(addr string) {
	if conn, ok := commonvar.Data.Load(addr); ok {
		c := conn.(*net.UDPConn)
		c.Close()
		commonvar.Data.Delete(addr)
		fmt.Println("clean: ", c)
	}
}
func cleanupProxyConnection() {
	fmt.Println("clean all........")
	commonvar.Data = sync.Map{}
}
