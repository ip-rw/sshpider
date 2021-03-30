package utils

import (
	"encoding/base64"
	"golang.org/x/crypto/ssh"
	"log"
	"regexp"
	"strconv"
	"strings"
)

var wildcardExpr = strings.NewReplacer(
	"\\*", ".*",
	"\\?", ".?",
)

func SringToIntOrZero(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		i = 0
	}
	return i
}

// TODO: error reporting
func Wildcards(wcs []string) (rs []*regexp.Regexp) {
	for _, wc := range wcs {
		wc := wildcardExpr.Replace(regexp.QuoteMeta(wc))
		if r, err := regexp.Compile(wc); err == nil {
			rs = append(rs, r)
		} else {
			log.Println("Wildcard failed:", err)
		}
	}
	return
}

// Format a host to be in `[host]:port` or `host` format
func CanonicalHost(s string) string {
	var host, port string
	if strings.HasPrefix(s, "[") {
		c := strings.Index(s, "]")
		if c < 0 {
			return s
		}
		host = s[1:c]
		if strings.HasPrefix(s[c+1:], ":") {
			// Junk at the end shouldn't result in a valid match
			port = s[c+2:]
		}
	} else if c := strings.LastIndex(s, ":"); c > 0 {
		host = s[:c]
		port = s[c+1:]
	} else {
		host = s
	}
	if port == "22" {
		port = ""
	}
	if port != "" {
		return "[" + host + "]:" + port
	}
	return host
}

func Pubkey(pk ssh.PublicKey) string {
	t := pk.Type()
	b := base64.StdEncoding.EncodeToString(pk.Marshal())
	return t + " " + b
}
