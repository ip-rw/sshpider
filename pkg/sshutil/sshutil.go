package sshutil

import (
	"context"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"time"
	"github.com/ip-rw/sshpider/pkg/structs"
)

func GetVersion(host string, timeout time.Duration) (string, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", host)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	bytes := make([]byte, 255)
	n, err := conn.Read(bytes)
	if err != nil {
		return "", err
	}

	for i := 0; i < n; i++ {
		if bytes[i] < 32 {
			return string(bytes[:i]), nil
		}
	}

	return "unknown", nil

}

func GetPublicKey(host string, timeout time.Duration) (key ssh.PublicKey, err error) {
	d := net.Dialer{Timeout: timeout}
	ctx, _ := context.WithTimeout(context.TODO(), timeout)
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second * 10))
	config := ssh.ClientConfig{
		HostKeyCallback: hostKeyCallback(&key),
		Timeout:         5 * time.Second,
	}
	sshconn, _, _, err := ssh.NewClientConn(conn, host, &config)
	if err == nil {
		sshconn.Close()
	}
	return key, nil
}

func hostKeyCallback(publicKey *ssh.PublicKey) func(hostname string, remote net.Addr, key ssh.PublicKey) error {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		*publicKey = key
		return nil
	}
}

func TestSSHLogin(t *structs.Target) (bool, error) {
	sshSession := Config{
		User:    t.User,
		KeyPath: t.Key.Path,
		Host:    t.Ip,
		Port:    fmt.Sprintf("%d", t.Port),
	}
	err := sshSession.Connect()
	if err != nil {
		//logrus.WithField("target", t).WithError(err).Warn("connect failed")
		return false, err
	}
	err = sshSession.Client.Close()
	if err != nil {
		return false, err
	}
	//session, err := sshSession.Client.NewSession()
	//if err != nil {
	//	logrus.WithField("target", t).WithError(err).Warn("connect failed")
		//return false, err
	//}
	return true, nil
}
