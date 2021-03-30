package knownhosts

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"github.com/ip-rw/sshpider/pkg/structs"
)

const (
	sshHashDelim  = "|" // hostfile.h
	sshHashPrefix = "|1|"
)


func GetOwner(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	var uid int
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid = int(stat.Uid)
	} else {
		uid = os.Getuid()
	}
	user, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return ""
	}
	return user.Username
}

// ReadKnownHostsFile reads the known_hosts file at path.
func ReadKnownHostsFile(path string) ([]*structs.KnownHost, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	username := GetOwner(path)
	defer f.Close()
	return ParseKnownHosts(f, username)
}

// ParseKnownHosts parses an SSH known_hosts file.
func ParseKnownHosts(r io.Reader, owner string) ([]*structs.KnownHost, error) {
	var khs []*structs.KnownHost
	s := bufio.NewScanner(r)
	n := 0
	for s.Scan() {
		n++
		line := s.Bytes()

		kh, err := parseKnownHostsLine(line)
		if err != nil {
			return nil, fmt.Errorf("parsing known_hosts: %s (line %d)", err, n)
		}
		if kh == nil {
			// empty line
			continue
		}
		kh.Owner = owner
		khs = append(khs, kh)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return khs, nil
}

func parseNamePort(hn string) (string, int) {
	var port = 22
	var h = hn
	if len(h) > 0 && !strings.Contains(h, ":") {
		h += ":22"
	}
	hostname, p, err := net.SplitHostPort(h)
	if err != nil {
		//fmt.Println(hn, port)
		return hn, port
	} else {
		port, _ = strconv.Atoi(p)
	}
	return hostname, port
}

// parseKnownHostsLine parses a line from a known hosts file.  It
// returns a string containing the hosts section of the line, an
// sshutil.PublicKey parsed from the line, and any error encountered
// during the parsing.
func parseKnownHostsLine(line []byte) (*structs.KnownHost, error) {
	// Skip any leading whitespace.
	line = bytes.TrimLeft(line, "\t ")

	// Skip comments and empty lines.
	if bytes.HasPrefix(line, []byte("#")) || len(line) == 0 {
		return nil, nil
	}

	// Skip markers.
	if bytes.HasPrefix(line, []byte("@")) {
		return nil, errors.New("marker functionality not implemented")
	}

	// Find the end of the hostname(s) portion.
	end := bytes.IndexAny(line, "\t ")
	if end <= 0 {
		return nil, errors.New("bad format (insufficient fields)")
	}
	hosts := line[:end]
	keyBytes := line[end+1:]

	kh := &structs.KnownHost{}
	// Check for hashed hostnames.
	if bytes.HasPrefix(hosts, []byte(sshHashPrefix)) {
		hosts = bytes.TrimPrefix(hosts, []byte(sshHashPrefix))
		// Hashed hostname format:
		//  <host>     = the hostname/address to be hashed
		//  <salt_b64> = base64(random 64 bits)
		//  <hash_b64> = base64(SHA1(<salt> <host>))
		//  <salt/hash pair> = '|1|' salt_b64 '|' hash_b64
		delim := bytes.Index(hosts, []byte(sshHashDelim))
		if delim <= 0 || delim >= len(hosts) {
			return nil, errors.New("bad hashed hostname format")
		}
		salt64 := hosts[:delim]
		hash64 := hosts[delim+1:]
		b64 := base64.StdEncoding
		kh.Salt = make([]byte, b64.DecodedLen(len(salt64)))
		kh.Hash = make([]byte, b64.DecodedLen(len(hash64)))
		if n, err := b64.Decode(kh.Salt, salt64); err != nil {
			return nil, err
		} else {
			kh.Salt = kh.Salt[:n]
		}
		if n, err := b64.Decode(kh.Hash, hash64); err != nil {
			return nil, err
		} else {
			kh.Hash = kh.Hash[:n]
		}
	} else {
		hn := strings.Split(string(hosts), ",")
		if len(hn) > 1 {
			h, p := parseNamePort(hn[0])
			kh.Hostname = h
			kh.Port = p
			h, p = parseNamePort(hn[1])
			kh.IP = h
		} else if len(hn) > 0 {
			h, p := parseNamePort(hn[0])
			kh.IP = h
			kh.Port = p
		}
	}

	// Finally, actually try to extract the key.
	key, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing key: %v", err)
	}
	kh.Key = key

	return kh, nil
}
