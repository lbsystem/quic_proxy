package nathole

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	commonvar "quic_proxy/commonVar"
	"time"
)

type NatTcp struct {
	Conn     quic.Stream
	Session  quic.Connection
	initFlag bool
}

func NewNatTcp() (*NatTcp, error) {
	session, err := quic.DialAddr(context.Background(), commonvar.ReplyServerQuic, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}, &quic.Config{
		KeepAlivePeriod: 200 * time.Millisecond,
		MaxIdleTimeout:  time.Second * 1,
		Versions:        []quic.VersionNumber{quic.Version2},
	})
	if err != nil {

		fmt.Println("new NATserver quic", err.Error())
		return nil, err
	}

	conn, err := session.OpenStream()
	if err != nil {

		fmt.Println(err.Error())
		return nil, err
	}
	return &NatTcp{conn, session, false}, err
}

func (t *NatTcp) ReConnect1(code int) error {
	for {
		session, err := quic.DialAddr(context.Background(), commonvar.ReplyServerQuic, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"quic-echo-example"},
		}, &quic.Config{
			KeepAlivePeriod: 1 * time.Second,
			MaxIdleTimeout:  time.Second * 35,
			Versions:        []quic.VersionNumber{quic.Version2},
		})

		fmt.Println("Attempting to reconnect TCP in quic")

		if err != nil {
			fmt.Println("Failed to connect, retrying:", err)
			time.Sleep(5 * time.Second) // wait before retrying
			continue
		}

		conn, err := session.OpenStream()
		if err != nil {
			fmt.Println("Failed to open stream, retrying:", err)
			time.Sleep(5 * time.Second) // wait before retrying
			continue
		}

		t.Session = session
		t.Conn = conn
		if err := t.VerifyTcp(); err != nil {
			fmt.Println("Failed to verify TCP, retrying:", err)
			time.Sleep(5 * time.Second) // wait before retrying
			continue
		}

		if code == 1 {
			if err := t.RegisterClientTcp(); err != nil {
				fmt.Println("Failed to register client TCP, retrying:", err)
				time.Sleep(5 * time.Second) // wait before retrying
				continue
			}
		}

		if code == 2 {
			if err := t.RegisterServerTcp(); err != nil {
				fmt.Println("Failed to register server TCP, retrying:", err)
				time.Sleep(5 * time.Second) // wait before retrying
				continue
			}
		}

		fmt.Println("Successfully reconnected")
		return nil
	}
}

func (t *NatTcp) ReConnect(code int) error {
	session, err := quic.DialAddr(context.Background(), commonvar.ReplyServerQuic, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}, &quic.Config{
		KeepAlivePeriod: 200 * time.Millisecond,
		MaxIdleTimeout:  time.Second * 1,
		Versions:        []quic.VersionNumber{quic.Version2},
	})

	fmt.Println("reconnect TCP in quic")
	t.initFlag = false
	if err != nil {
		return err
	} else {
		conn, err := session.OpenStream()
		if err != nil {
			return err
		}
		t.Session = session
		t.Conn = conn
		t.VerifyTcp()
		t.initFlag = true
		if code == 1 {
			t.RegisterServerTcp()
		}
		if code == 2 {
			t.RegisterClientTcp()
		}
		return nil
	}

}

func (t *NatTcp) VerifyTcp() error {
	if t.initFlag {
		return errors.New("it inited")
	}
	t.Conn.Write([]byte("helloNATserver"))
	t.initFlag = true
	return nil
}
func (t *NatTcp) RegisterServerTcp() error {
	b := append([]byte{1}, []byte(commonvar.ServerName)...)
	_, err := t.Conn.Write(b)
	return err
}
func (t *NatTcp) RegisterClientTcp() error {
	b := append([]byte{2}, []byte(commonvar.Cookie)...)
	_, err := t.Conn.Write(b)
	return err
}

func (t *NatTcp) WaitingSignal() ([]byte, error) {
	defer func() {
		r := recover()
		if r != nil {
			fmt.Println(r)
		}
	}()
	b := make([]byte, 256)
	n, err := t.Conn.Read(b)
	if err != nil {
		fmt.Println(err.Error())
		t.Conn.Close()
		t.Session.CloseWithError(quic.ApplicationErrorCode(35), "changIP")
		return []byte(""), err
	}
	return b[:n], nil
}
