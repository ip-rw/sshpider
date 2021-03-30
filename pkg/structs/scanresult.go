package structs

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"strings"
	"sync"
)

type ScanResults struct {
	PrivateKeys      []*PrivateKey
	Targets          *sync.Map
	Hosts            []*Host
	KnownHosts       []*KnownHost
	HashedKnownHosts []*KnownHost

	dupMap *sync.Map
}

func NewScanResults() *ScanResults {
	return &ScanResults{
		PrivateKeys:      make([]*PrivateKey, 0),
		Targets:          &sync.Map{},
		Hosts:            make([]*Host, 0),
		KnownHosts:       make([]*KnownHost, 0),
		HashedKnownHosts: make([]*KnownHost, 0),
		dupMap:           &sync.Map{},
	}
}

func (s *ScanResults) AddPrivateKey(key *PrivateKey) bool {
	if key != nil {
		if _, loaded := s.dupMap.LoadOrStore("PrivateKey"+string(key.Signer.PublicKey().Marshal()), 1); !loaded {
			s.PrivateKeys = append(s.PrivateKeys, key)
			return true
		}
	}
	return false
}

func (s *ScanResults) AddHost(host *Host) bool {
	if host != nil {
		if _, loaded := s.dupMap.LoadOrStore("Host" + host.String(),1); !loaded {
			if host.User != "git" && host.Ip != "openssh.com" && host.Ip != "github.com" && host.Ip != "bitbucket.org" && !strings.Contains(host.String(), "example")                                          {
				//logrus.WithFields(logrus.Fields{"host": host.String(), "user": host.User}).Info("host added")
				s.Hosts = append(s.Hosts, host)
				return true
			}
		}
	}
	return false
}

func (s *ScanResults) AddKnownHost(knownhost *KnownHost) bool {
	if knownhost != nil {
		if knownhost.Hostname != "" {
			h := ParseHost(fmt.Sprintf("%s:%d", knownhost.Hostname, knownhost.Port))
			if knownhost.Owner != "" {
				h.User = knownhost.Owner
			}
			if s.AddHost(h) {
				return true
			}
		}

		if knownhost.IP != "" {
			h := ParseHost(fmt.Sprintf("%s:%d", knownhost.IP, knownhost.Port))
			if knownhost.Owner != "" {
				h.User = knownhost.Owner
			}
			if s.AddHost(h) {
				return true
			}
		}

		if knownhost.Hash != nil && knownhost.Salt != nil {
			if _, loaded := s.dupMap.LoadOrStore("knownhost"+string(knownhost.Hash), 1); !loaded {
				logrus.WithFields(logrus.Fields{"hash": string(knownhost.Hash)}).Info("host hashed known host found")
				s.HashedKnownHosts = append(s.HashedKnownHosts, knownhost)
			}
			return true
		}
	}
	return false
}
