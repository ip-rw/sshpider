package knownhosts

import (
	"crypto/hmac"
	"crypto/sha1"
	netutils "github.com/akihiro/go-net-utils"
	"github.com/sirupsen/logrus"
	"go.uber.org/atomic"
	"net"
	"sync"
	"github.com/ip-rw/sshpider/pkg/search"
	"github.com/ip-rw/sshpider/pkg/structs"
)

func checkHash(ip string, kh *structs.KnownHost) bool {
	mac := hmac.New(sha1.New, kh.Salt)
	mac.Write([]byte(ip))
	hash := mac.Sum(nil)
	return hmac.Equal(kh.Hash, hash)
}

var attempts = atomic.NewInt64(0)
var chLock = &sync.Mutex{}

func CheckHashes(result *structs.ScanResults, targetChan chan string) {
	var wg = &sync.WaitGroup{}
	for ip := range targetChan {
		//fmt.Println(ip)
		if n := attempts.Load(); n%10000 == 0 {
			logrus.WithField("hashed_known_hosts", len(result.HashedKnownHosts)).WithField("attempts", n).Info("cracking hashed known hosts")
		}
		var done = []int{}
		for k := range result.HashedKnownHosts {
			wg.Add(1)
			go func(i string, k int) {
				attempts.Inc()

				chLock.Lock()
				kh := result.HashedKnownHosts[k]
				chLock.Unlock()
				if checkHash(i, kh) {

					kh.IP = ip
					if kh.Port == 0 {
						kh.Port = 22
					}
					logrus.WithField("plain", kh.IP).Info("cracked known host")
					result.AddKnownHost(kh)
					done = append(done, k)
				}
				wg.Done()
			}(ip, k)
		}
		wg.Wait()
		n := make([]*structs.KnownHost, len(result.HashedKnownHosts)-len(done))
		c := 0
		for hi, k := range result.HashedKnownHosts {
			skip := false
			for _, i := range done {
				if i == hi {
					skip = true
					break
				}
			}
			if !skip {
				n[c] = k
				c++
			}
		}
		result.HashedKnownHosts = n
		if len(result.HashedKnownHosts) == 0 {
			logrus.Infof("Finished cracking hashed hosts after %d attempts.\n", attempts.Load())
			return
		}
	}
}

func CrackKnownHosts(result *structs.ScanResults) {
	//logrus.WithField("hashed_known_hosts", len(result.HashedKnownHosts)).Infof("Found %d hashed hosts in .known_hosts")
	nets := map[*net.IPNet]bool{}
	prefixes := []net.IPNet{}
	for _, host := range result.Hosts {
		_, ipn, err := net.ParseCIDR(host.Ip + "/22")
		if err != nil {
			continue
		}
		if _, ok := nets[ipn]; !ok {
			nets[ipn] = true
			prefixes = append(prefixes, *ipn)
		}
	}
	agg := netutils.Aggregate(prefixes)

	logrus.WithFields(logrus.Fields{"prefixes": len(prefixes), "aggregated": len(agg)}).Info("aggregated prefixes")
	logrus.WithFields(logrus.Fields{"hashed_known_hosts": len(result.HashedKnownHosts)}).Info("cracking hashed known host entries")
	targetChan := make(chan string, 1)
	go CheckHashes(result, targetChan)
	for _, ipn := range agg {
		targetChan <- <- search.ExpandNetworkToChan(&net.IPNet{IP: ipn.IP, Mask: ipn.Mask})
	}
	close(targetChan)
}
