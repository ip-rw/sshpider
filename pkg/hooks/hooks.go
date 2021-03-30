package hooks

import (
	"os"
	"strings"
	"github.com/ip-rw/sshpider/pkg/structs"
)

type FileInfo struct {
	os.FileInfo
	Path string
}

func (p *FileInfo) Lpath() string {
	return strings.ToLower(p.Path)
}

type Plugin interface {
	Search(*structs.ScanResults, FileInfo, []byte) (bool, error)
	Name() string
}