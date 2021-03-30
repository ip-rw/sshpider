package search

import (
	"regexp"
	"strings"
	"github.com/ip-rw/sshspider/pkg/structs"
)

var (
	numBlock    = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	ipPattern   = `\b(?:ssh|scp|rsync)\b\s*([a-zA-Z0-9]{3,})@(` + numBlock + `\.` + numBlock + `\.` + numBlock + `\.` + numBlock + `)`
	hostPattern = `\b(?:ssh|scp|rsync)\b\s*([a-zA-Z0-9]{3,})@([A-Za-z0-9_\.]{5,}\.[A-Za-z\.]+)`
	ipRegex     = regexp.MustCompile(ipPattern)
	hostRegex   = regexp.MustCompile(hostPattern)
)

func ExtractTargets(full []byte) []*structs.Host {
	foundIps := ipRegex.FindAllSubmatch(full, -1)
	foundHosts := hostRegex.FindAllSubmatch(full, -1)
	targets := make([]*structs.Host, len(foundIps)+len(foundHosts))
	i := 0
	for _, match := range foundIps {
		if string(match[1]) != "" {
			targets[i] = &structs.Host{User: string(match[1]), Ip: strings.Trim(string(match[2]), "\r"), Port: 22}
		}
		i++
	}
	for _, match := range foundHosts {
		if string(match[1]) != "" {
			targets[i] = &structs.Host{User: string(match[1]), Ip: strings.Trim(string(match[2]), "\r"), Port: 22}
		}
		i++
	}
	return targets
}

func SniffIps() []*structs.Host {
	hosts := []*structs.Host{}
	conns := GetNetworkConnections()
	conns = establishedConnections(conns, structs.NetConn{})
	for _, conn := range conns {
		if conn.Dst.Port == 22 {
			hosts = append(hosts, &structs.Host{
				Ip:   conn.Dst.Ip,
				Port: conn.Dst.Port,
			})
			hosts = append(hosts, &structs.Host{
				Ip:   conn.Dst.Ip,
				Port: 22,
			})
		}
	}
	return hosts
}
