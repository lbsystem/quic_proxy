package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"quic_proxy/commonVar"
	"quic_proxy/nathole"
	"quic_proxy/udpProxy"
	"time"
	"github.com/quic-go/quic-go"
)

var natTcp *nathole.NatTcp

type myUdpconn struct {
	net.UDPConn
}

func (c myUdpconn) Write(b []byte) (int, error) {
	return c.UDPConn.Write(b)
}
func (c myUdpconn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return c.UDPConn.WriteToUDP(b, addr)
}
func (c myUdpconn) Read(b []byte) (int, error) {
	// n, err := c.UDPConn.Read(b)
	// n = copy(b, XorCipher(b))
	return c.UDPConn.Read(b)
}
func (c myUdpconn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	// n, addr, err := c.UDPConn.ReadFromUDP(b)
	// n = copy(b, XorCipher(b))
	return c.UDPConn.ReadFromUDP(b)
}

var session quic.Connection
var newUdpConn net.PacketConn
var tlsConfig *tls.Config

var err error

func newSession() quic.Connection {
	var i = 0
	session = nil
	var session1 quic.Connection

	for {
		i++
		if i > 350 {

			os.Exit(1)
		}
		udpAddr, err := net.ResolveUDPAddr("udp", commonvar.TargetAddr)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		if commonvar.Encrypt {
			newUdpConn = &myUdpconn{*commonvar.Conn1}
			session1, err = quic.Dial(context.Background(), newUdpConn, udpAddr, tlsConfig, &quic.Config{
				KeepAlivePeriod: 200 * time.Millisecond,
				MaxIdleTimeout:  time.Second * 1,
				Versions:        []quic.VersionNumber{quic.Version2},
			})
			if err != nil {
				fmt.Println("create new session", err.Error())
			}

		} else {
			session1, err = quic.Dial(context.Background(), commonvar.Conn1, udpAddr, tlsConfig, &quic.Config{
				KeepAlivePeriod: 1 * time.Second,
				MaxIdleTimeout:  time.Second * 6,
				Versions:        []quic.VersionNumber{quic.Version2},
			})
			if err != nil {
				fmt.Println("create new session", err.Error())
			}
		}
		if session1 != nil {
			break
		}
	}

	return session1

}

func main() {
	targetAddr1 := flag.String("target", "127.0.0.1:22", "target server ip")
	localAddrAndPort1 := flag.String("local", "0.0.0.0:33306", "local ip")
	serverName1 := flag.String("name", "lbsystem2", "server name")
	passWord := flag.String("password", "grasdvvd", "passWord")
	mode := flag.Bool("server", false, "server mode")
	udp := flag.Bool("udp", false, "udp mode")
	encrypt1 := flag.Bool("encrypt", false, "encrypt mode")
	NAT := flag.Bool("NAT", false, "encrypt mode")
	flag.Parse()
	commonvar.TargetAddr = *targetAddr1
	commonvar.LocalAddrAndPort = *localAddrAndPort1
	commonvar.ServerName = *serverName1
	commonvar.Encrypt = *encrypt1
	commonvar.Mode = *mode
	commonvar.NAT = *NAT
	fmt.Println("NAT mode is : ", commonvar.NAT)
	h := sha512.New()
	h.Write(commonvar.Key)
	h.Write([]byte(*passWord))
	commonvar.Key = h.Sum(nil)
	fmt.Println(commonvar.Key)
	if *udp {
		udpproxy.UdpProxy()
		return
	}
	var err error
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	if commonvar.NAT {
		natTcp, err = nathole.NewNatTcp()
		if err != nil {
			fmt.Println("NAT server TCP is close")
		}
		natTcp.VerifyTcp()
	}

	if *mode {
		reverseProxy()
	} else {
		proxy()
	}
}
func proxy() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
		}
	}()
	lister, err := net.Listen("tcp", commonvar.LocalAddrAndPort)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("have a proxy")
	tlsConfig = &tls.Config{
		InsecureSkipVerify: true, // 不要在生产中这样做，这里仅用于示例
		NextProtos:         []string{"quic-echo-example"},
	}
	// 使用QUIC拨号到服务器
	// 创建UDP连接
	commonvar.Conn1, err = net.ListenUDP("udp", nil)

	if err != nil {
		fmt.Println(err.Error())
	}
	// 创建quic

	if commonvar.NAT {
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
		session = newSession()
		fmt.Println("get IP: ", commonvar.TargetAddr)
		natTcp.RegisterClientTcp()
		go nathole.ChangeIP(commonvar.ServerName, 5)

		go func() {
			for {
				if session == nil {
					time.Sleep(time.Second)
					continue
				}
				<-session.Context().Done()
				fmt.Println("proxy session close")
				session.CloseWithError(quic.ApplicationErrorCode(35), "connetion is close")
				commonvar.TargetAddr = nathole.QuiryIP(commonvar.ServerName, 3)
				session = newSession()
			}
		}()
		go func() {
			for {
				b, err := natTcp.WaitingSignal()
				if err != nil {
					fmt.Println("NAT server TCP is close")
					natTcp.ReConnect(1)
				}
				if len(b) > 9 {
					fmt.Println(string(b))
					nathole.HandleNatConn(b)
				}

			}
		}()
	} else {
		session = newSession()
		go func() {
			for {
				if session == nil {
					time.Sleep(time.Second)
					continue
				}
				<-session.Context().Done()
				fmt.Println("proxy session close")
				session.CloseWithError(quic.ApplicationErrorCode(35), "connetion is close")
				session = newSession()
			}
		}()

	}

	if err != nil {
		fmt.Println(err.Error())
	}
	for {
		conn, err := lister.Accept()
		tcpConn, ok := conn.(*net.TCPConn)
		if ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(time.Second * 3)
		}
		
		conn.SetDeadline(time.Now().Add(time.Hour))
		if err != nil {
			fmt.Println(err.Error())
		}
		if session == nil {
			conn.Close()
			continue
		}
		go TcpHandleConn(conn)
	}
}

func generateTLSConfig() *tls.Config {
	// 生成RSA密钥对
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	// 创建一个自签名证书
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	// 将密钥和证书编码为PEM格式
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	// 返回包含TLS证书的TLS配置，并指定应用协议名称
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}

func handleQuic(stream quic.Stream) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
			stream.Close()

		}
	}()
	fmt.Println("handleQuic")

	fmt.Println(commonvar.TargetAddr)
	conn, err := net.Dial("tcp", commonvar.TargetAddr)
	tcpConn, ok := conn.(*net.TCPConn)
	if ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(time.Second * 3)
	}
	fmt.Println(conn.LocalAddr())
	conn.SetDeadline(time.Now().Add(time.Hour))
	if err != nil {
		panic(err)
	}
	go remoteToLocal(stream, conn)
	localToRemote(stream, conn)

}

func reverseProxy() {

	config := generateTLSConfig()
	fmt.Println("sever start")
	addr, _ := net.ResolveUDPAddr("udp", commonvar.LocalAddrAndPort)
	var lister *quic.Listener
	var newUdpConn net.PacketConn
	var err error
	commonvar.Conn1, err = net.ListenUDP("udp", addr)

	if commonvar.NAT {
		go nathole.RegAddr(commonvar.ServerName)
		time.Sleep(time.Millisecond * 35)
		natTcp.RegisterServerTcp()
		go func() {
			for {
				b, err := natTcp.WaitingSignal()
				if err != nil {
					fmt.Println(err.Error())
					fmt.Println("NAT SERVER TCP is LOST")
					natTcp.ReConnect(1)
					break
				}
				nathole.HandleNatConn(b)
			}
		}()
	}

	if commonvar.Encrypt {
		fmt.Println("encrypt yes:", commonvar.Encrypt)

		if err != nil {
			fmt.Println(err.Error())
			return
		}
		newUdpConn = &myUdpconn{*commonvar.Conn1}
		lister, err = quic.Listen(newUdpConn, config, &quic.Config{
			KeepAlivePeriod: 200 * time.Millisecond,
			EnableDatagrams: true,
			MaxIdleTimeout:  1,
		})
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	} else {
		fmt.Println("encrypt not:", commonvar.Encrypt)
		lister, err = quic.Listen(commonvar.Conn1, config, &quic.Config{
			KeepAlivePeriod: 200 * time.Millisecond,
			EnableDatagrams: true,
			MaxIdleTimeout:  1,
		})
		if err != nil {
			fmt.Println(err.Error())
			return
		}
	}

	for {
		session, err := lister.Accept(context.Background())
		fmt.Println("have new proxy")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		go handleSession(session)
	}

}

func handleSession(session quic.Connection) {
	defer func() {
		session.CloseWithError(quic.ApplicationErrorCode(41), "unknow")
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()
	for {

		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		stream.SetDeadline(time.Now().Add(time.Hour))
		go handleQuic(stream)
	}

}

func TcpHandleConn(conn net.Conn) {
	defer func() {
		r := recover()
		if r != nil {
			fmt.Println(r)
		}
		fmt.Println(conn.RemoteAddr().String(), "TCP is close")
	}()
	// 打开一个新的流
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		fmt.Println("open stream", err.Error())
	}
	go localToRemote(stream, conn)
	remoteToLocal(stream, conn)
}

func localToRemote(dst quic.Stream, src net.Conn) {
	defer func() {
		r := recover()
		if r != nil {
			fmt.Println(r)
		}

	}()
	b := make([]byte, 1024*1024*2)
	io.CopyBuffer(dst, src, b)
	defer func() {
		dst.Close()
		src.Close()
		fmt.Println("localToRemote close")
	}()
}
func remoteToLocal(src quic.Stream, dst net.Conn) {
	defer func() {
		r := recover()
		if r != nil {
			fmt.Println(r)
		}
	}()
	b := make([]byte, 1024*1024*2)
	io.CopyBuffer(dst, src, b)
	defer func() {
		dst.Close()
		src.Close()
		fmt.Println("Remote close")
	}()

}
func dolXorCipher(data []byte) []byte {
	encrypted := make([]byte, len(data))
	keyLen := len(commonvar.Key)
	for i := range data {
		encrypted[i] = data[i] ^ commonvar.Key[i%keyLen]
	}
	return encrypted
}


func XorCipher(data []byte) []byte {
	packetLength := len(data)
	packetLengthByte := byte(packetLength) // 包长转成ASCII字符

	// 用包长改变密钥
	modifiedKey := make([]byte, len(commonvar.Key))
	for i, keyByte := range commonvar.Key {
		modifiedKey[i] = keyByte ^ packetLengthByte
	}

	// 用修改后的密钥进行XOR加密
	encrypted := make([]byte, packetLength)
	keyLen := len(modifiedKey)
	for i := range data {
		j := i % keyLen
		encrypted[i] = data[i] ^ modifiedKey[j]
	}

	return encrypted
}