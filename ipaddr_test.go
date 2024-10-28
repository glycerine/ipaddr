package ipaddr

import (
	"fmt"
	"strings"
	"testing"
)

func Test100(t *testing.T) {
	server := "67.88.192.17:999"
	local, err := LocalAddrMatching(server)
	panicOn(err)
	fmt.Printf("server %v  ->  client %v\n", server, local)
	if strings.HasPrefix(local, "100.") {
		panic(fmt.Sprintf("100. should be private and 67 public; we got local '%v' -> '%v'", local, server))
	}

	server = "100.78.59.117:999"
	local, err = LocalAddrMatching(server)
	panicOn(err)
	fmt.Printf("server %v  ->  client %v\n", server, local)
	if !strings.HasPrefix(local, "100.") {
		panic(fmt.Sprintf("server starts with 100. so should client. got local '%v' -> '%v'", local, server))
	}

}

func panicOn(err error) {
	if err != nil {
		panic(err)
	}
}
