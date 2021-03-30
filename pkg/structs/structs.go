package structs

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"strconv"
)

type PrivateKey struct {
	//hash.Hash64
	Path   string
	Signer ssh.Signer
	Size   int
	Owner  string
}

type Target struct {
	User string
	Ip   string
	Port int
	Key  *PrivateKey
}

func (t *Target) String() string {
	return fmt.Sprintf("%s@%s:%d (%s)", t.User, t.Ip, t.Port, t.Key.Path)
}

type KnownHost struct {
	Hostname   string
	IP         string
	Port       int
	Salt, Hash []byte // hashed hostname
	Key        ssh.PublicKey
	Owner      string
}
type Host struct {
	Ip   string
	Port int64
	User string
}

func (h *Host) String() string {
	return fmt.Sprintf("%s@%s:%d", h.User, h.Ip, h.Port)
}

func ParseHost(host string) *Host {
	host, port, err := net.SplitHostPort(host)
	var h *Host
	if err != nil {
		return nil
	}
	p, _ := strconv.Atoi(port)
	h = &Host{
		Ip:   host,
		Port: int64(p),
		//Proto: NetProto{L4: L4ProtoTcp},
	}
	return h
}

type NetConn struct {
	Dst, Src Host
	Pid      int // process ID of this network connection, if applicable.
	Proto    NetProto
}

type NetProto struct {
	L3, L4 int
}
