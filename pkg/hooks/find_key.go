package hooks

import (
	"bytes"
	"errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"regexp"
	"strings"
	"github.com/ip-rw/sshpider/pkg/knownhosts"
	"github.com/ip-rw/sshpider/pkg/structs"
)

type FindKey struct{}

func (p *FindKey) Name() string {
	return "keyfinder"
}

func (p *FindKey) Log() *logrus.Entry {
	return logrus.WithField("plugin", p.Name())
}

var privBytes =  []byte("-----BEGIN ")
var privRegex = regexp.MustCompile("-----BEGIN.*PRIVATE KEY-----\n")
var ossh64 = []byte("b3BlbnNzaC1rZXktdjE")

func (p *FindKey) Search(results *structs.ScanResults, file FileInfo, data []byte) (bool, error) {
	if bytes.Index(data, privBytes) > -1 {
		if !bytes.Contains(data, ossh64) || strings.Index(file.Name(), "id_") == 0 {
			return true, errors.New("bad type")
		}

		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return true, err
		}
		//if signer.PublicKey().Type() == "ssh-rsa"
		k := &structs.PrivateKey{
			Path:   file.Path,
			Signer: signer,
			Size:   len(data),
			Owner:  knownhosts.GetOwner(file.Path),
		}
		if results.AddPrivateKey(k) {
			p.Log().WithFields(logrus.Fields{"path": file.Path, "type": k.Signer.PublicKey().Type(), "size": k.Size}).Info("found private key")
			return false, nil
		}
	}
	return true, nil
}
