package hooks

import (
	"bytes"
	"github.com/sirupsen/logrus"
	"github.com/ip-rw/sshpider/pkg/knownhosts"
	"github.com/ip-rw/sshpider/pkg/structs"
)

type KnownHosts struct {}

func (p *KnownHosts) Log() *logrus.Entry {
	return logrus.WithField("plugin", p.Name())
}

func (p *KnownHosts)Name() string {
	return "known hosts"
}

func (p *KnownHosts)Search(results *structs.ScanResults, file FileInfo, data []byte) (bool, error) {
	username := knownhosts.GetOwner(file.Path)
	kh, err := knownhosts.ParseKnownHosts(bytes.NewReader(data), username)
	if err != nil {
		//p.Log().WithError(err).Debu("error parsing")
		return true, err
	}
	if len(kh) > 0 {
		logrus.WithField("path", file.Path).WithField("count", len(kh)).Info("found .known_hosts")
		for _, host := range kh {
			results.AddKnownHost(host)
		}
	}
	return false, nil
}

