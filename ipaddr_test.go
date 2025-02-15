package ipaddr

import (
	"fmt"
	"net"
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

func TestIPv6(t *testing.T) {
	return // will not work except on specific test host, of course.

	// should find local [fd7a:115c:a1e0:ab12:4843:cd96:624e:3b75] when from appropriate test box.
	server := "[fd7a:115c:a1e0:ab12:4843:cd96:6258:d622]:9999"
	local, err := LocalAddrMatching(server)
	panicOn(err)
	fmt.Printf("server %v  ->  client %v\n", server, local)
	if !strings.HasPrefix(local, "[fd7a") {
		panic(fmt.Sprintf("fd7a not found.  we got local '%v' -> '%v'", local, server))
	}
}

func panicOn(err error) {
	if err != nil {
		panic(err)
	}
}

func TestParseURLAddress(t *testing.T) {

	addrURL := "tcp://[::]:8443"
	scheme, ip, port, isUnspecified, isIPv6, err := ParseURLAddress(addrURL)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Scheme: %s\n", scheme)             // tcp
	fmt.Printf("IP: %s\n", ip)                     // ::
	fmt.Printf("Port: %s\n", port)                 // 8443
	fmt.Printf("Unspecified: %v\n", isUnspecified) // true
	fmt.Printf("IPv6: %v\n", isIPv6)               // true

	// You can now use the net.IP type directly for comparisons
	if ip.Equal(net.IPv6unspecified) {
		fmt.Println("This is the IPv6 unspecified address")
	}

}
