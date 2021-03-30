package search

import (
	netstat "github.com/drael/GOnetstat"
	"github.com/ip-rw/sshpider/pkg/structs"
	"github.com/ip-rw/sshpider/pkg/utils"
)

const (
	L3ProtoIpv4 = iota
	L3ProtoIpv6 = iota
)

const (
	L4ProtoTcp = iota
	L4ProtoUdp = iota
)

// getNetworkConnections returns all established tcp/udp ipv4/ipv6 network connections.
func GetNetworkConnections() []structs.NetConn {
	found := []structs.NetConn{}

	for _, conn := range netstat.Tcp() {
		//if conn.State == "ESTABLISHED" {
		found = append(found, structs.NetConn{
			Src: structs.Host{
				Ip:   conn.Ip,
				Port: conn.Port,
			},
			Dst: structs.Host{
				Ip:   conn.ForeignIp,
				Port: conn.ForeignPort,
			},
			Proto: structs.NetProto{
				L3: L3ProtoIpv4,
				L4: L4ProtoTcp,
			},
			Pid: utils.SringToIntOrZero(conn.Pid),
		})
		//}
	}
	/*
		for _, conn := range netstat.Udp() {
			if conn.State == "ESTABLISHED" {
				found = append(found, NetConn{
					srcIp:   conn.Ip,
					dstIp:   conn.ForeignIp,
					srcPort: conn.Port,
					dstPort: conn.ForeignPort,
					l3Proto: L3ProtoIpv4,
					l4Proto: L4ProtoUdp,
					pid:     stringToIntOrZero(conn.Pid),
				})
			}
		}
		for _, conn := range netstat.Tcp6() {
			if conn.State == "ESTABLISHED" {
				found = append(found, NetConn{
					srcIp:   conn.Ip,
					dstIp:   conn.ForeignIp,
					srcPort: conn.Port,
					dstPort: conn.ForeignPort,
					l3Proto: L3ProtoIpv6,
					l4Proto: L4ProtoTcp,
					pid:     stringToIntOrZero(conn.Pid),
				})
			}
		}
		for _, conn := range netstat.Udp6() {
			if conn.State == "ESTABLISHED" {
				found = append(found, NetConn{
					srcIp:   conn.Ip,
					dstIp:   conn.ForeignIp,
					srcPort: conn.Port,
					dstPort: conn.ForeignPort,
					l3Proto: L3ProtoIpv6,
					l4Proto: L4ProtoUdp,
					pid:     stringToIntOrZero(conn.Pid),
				})
			}
		}
	*/

	return found
}
// establishConns grabs currently established network connections
// and looks for the connection characteristics in "needle".
func establishedConnections(conns []structs.NetConn, needle structs.NetConn) []structs.NetConn {
	found := []structs.NetConn{}

	for _, nc := range conns {
		if needle.Src.Ip != "" && needle.Src.Ip != nc.Src.Ip {
			continue
		}
		if needle.Dst.Ip != "" && needle.Dst.Ip != nc.Dst.Ip {
			continue
		}
		if needle.Src.Port != 0 && needle.Src.Port != nc.Src.Port {
			continue
		}
		if needle.Dst.Port != 0 && needle.Dst.Port != nc.Dst.Port {
			continue
		}
		if needle.Proto.L3 != 0 && needle.Proto.L3 != nc.Proto.L3 {
			continue
		}
		if needle.Proto.L4 != 0 && needle.Proto.L4 != nc.Proto.L4 {
			continue
		}
		if needle.Pid != 0 && needle.Pid != nc.Pid {
			continue
		}
		found = append(found, nc)
	}

	return found
}
