package search

import (
	"github.com/willdonnelly/passwd"
	"strings"
)

func GetUsers() []string {
	users, err := passwd.ParseFile("/etc/passwd")
	if err != nil {
		return []string{"root"}
	}
	usr := []string{"root"}
	for k, u := range users {
		if !strings.Contains(u.Shell, "nologin") && strings.Contains(u.Home, "/home/") {
			usr = append(usr, k)
		}
	}
	return usr
}
