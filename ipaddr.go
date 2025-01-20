package ipaddr

import (
	"fmt"
	"net"
	"net/url"

	//"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var validIPv4addr = regexp.MustCompile(`^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$`)

var privateIPv4addr = regexp.MustCompile(`(^127\.0\.0\.1)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)`)

// IsRoutableIPv4 returns true if the string in ip represents an IPv4 address that is not
// private. See http://en.wikipedia.org/wiki/Private_network#Private_IPv4_address_spaces
// for the numeric ranges that are private. 127.0.0.1, 192.168.0.1, and 172.16.0.1 are
// examples of non-routables IP addresses.
func IsRoutableIPv4(ip string) bool {
	match := privateIPv4addr.FindStringSubmatch(ip)
	if match != nil {
		return false
	}
	return true
}

// GetExternalIP tries to determine the external IP address
// used on this host. net.IP is just []byte
func GetExternalIP() string {

	str, netIP := GetExternalIP2()
	_ = netIP
	return str
}

// GetExternalIP2 tries to determine the external IP address
// used on this host. net.IP is just []byte, defined in the net package.
func GetExternalIP2() (string, net.IP) {
	if runtime.GOOS == "windows" {
		s := "127.0.0.1"
		return s, net.ParseIP(s)
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}

	valid := []string{}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			addr := ipnet.IP.String()
			match := validIPv4addr.FindStringSubmatch(addr)
			if match != nil {
				if addr != "127.0.0.1" {
					valid = append(valid, addr)
				}
			}
		}
	}
	switch len(valid) {
	case 0:
		return "127.0.0.1", net.ParseIP("127.0.0.1")
	case 1:
		return valid[0], net.ParseIP(valid[0])
	default:
		// try to get a routable ip if possible.
		for _, ip := range valid {
			if IsRoutableIPv4(ip) {
				return ip, net.ParseIP(ip)
			}
		}
		// give up, just return the first.
		return valid[0], net.ParseIP(valid[0])
	}
}

// GetExternalIPAsInt calls GetExternalIP() and then converts
// the resulting IPv4 string into an integer.
func GetExternalIPAsInt() int {
	s := GetExternalIP()
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0
	}
	sum := 0
	for i := 0; i < 4; i++ {
		mult := 1 << (8 * uint64(3-i))
		//fmt.Printf("mult = %d\n", mult)
		sum += int(mult) * int(ip[i])
		//fmt.Printf("sum = %d\n", sum)
	}
	//fmt.Printf("GetExternalIPAsInt() returns %d\n", sum)
	return sum
}

// GetAvailPort asks the OS for an unused port.
// There's a race here, where the port could be grabbed by someone else
// before the caller gets to Listen on it, but in practice such races
// are rare. Uses net.Listen("tcp", ":0") to determine a free port, then
// releases it back to the OS with Listener.Close().
func GetAvailPort() int {
	l, _ := net.Listen("tcp", ":0")
	r := l.Addr()
	l.Close()
	return r.(*net.TCPAddr).Port
}

// GenAddress generates a local address by calling GetAvailPort() and
// GetExternalIP(), then prefixing them with 'tcp://'.
func GenAddress() string {
	port := GetAvailPort()
	ip := GetExternalIP()
	s := fmt.Sprintf("tcp://%s:%d", ip, port)
	//fmt.Printf("GenAddress returning '%s'\n", s)
	return s
}

// reduce `tcp://blah:port` to `blah:port`
var validSplitOffProto = regexp.MustCompile(`^[^:]*://(.*)$`)

// StripNanomsgAddressPrefix removes the 'tcp://' prefix from
// nanomsgAddr.
func StripNanomsgAddressPrefix(nanomsgAddr string) (suffix string, err error) {

	match := validSplitOffProto.FindStringSubmatch(nanomsgAddr)
	if match == nil || len(match) != 2 {
		return "", fmt.Errorf("could not strip prefix tcp:// from nanomsg address '%s'", nanomsgAddr)
	}
	return match[1], nil
}

func WaitUntilCanConnect(addr string) {

	stripped, err := StripNanomsgAddressPrefix(addr)
	if err != nil {
		panic(err)
	}

	//t0 := time.Now()
	for {
		cn, err := net.Dial("tcp", stripped)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		cn.Close()
		break
	}
	//vv("WaitUntilCanConnect finished after %v", time.Since(t0))
}

func RemoveNetworkPrefix(address string) string {
	// Split the address into two parts, at the first occurrence of "://"
	parts := strings.SplitN(address, "://", 2)

	// If the split resulted in two parts, return the second part (i.e., address without prefix)
	if len(parts) == 2 {
		return parts[1]
	}

	// Otherwise, return the original address (no prefix found)
	return address
}

// if it needs [] ipv6 brackets, add them
func WrapWithBrackets(local string) string {

	if local == "" {
		return local
	}
	if local[0] == '[' {
		return local
	}

	ip := net.ParseIP(local)
	if ip != nil {
		if ip.To4() == nil {
			// is IP v6
			return "[" + local + "]"
		}
	}
	return local
}

// LocalAddrMatching finds a matching interface IP to a server destination address
//
// addr should b "host:port" of server, we'll find the local IP to use.
func LocalAddrMatching(addr string) (local string, err error) {

	defer func() {
		// wrap IPv6 in [] if need be.
		if local != "" && err == nil {
			if local[0] == '[' {
				return
			}
			ip := net.ParseIP(local)
			if ip != nil {
				if ip.To4() == nil {
					// is IP v6
					local = "[" + local + "]"
				}
			}
		}
	}()

	// Resolve the server address
	addr = RemoveNetworkPrefix(addr)

	// if localhost, return same
	isLocal, host := IsLocalhost(addr)
	if isLocal {
		return host, nil
	}

	serverAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return "", fmt.Errorf("Failed to resolve server address: %v", err)
	}

	remote6 := serverAddr.IP.To4() == nil

	_, tailscale100net, err := net.ParseCIDR("100.1.1.1/8")
	if err != nil {
		panic(err)
	}
	//fmt.Printf("tailscale100net = '%s'\n", tailscale100net)
	isServerTailscale := tailscale100net.Contains(serverAddr.IP)

	// Get a list of network interfaces on the machine
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("Failed to get network interfaces: %v", err)
	}

	// Iterate over interfaces and inspect their addresses
	var selectedIP net.IP
	for _, iface := range interfaces {
		// Ignore down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			//fmt.Printf("Failed to get addresses for interface %s: %v\n", iface.Name, err)
			continue
		}

		// Iterate over each address of the interface
		for _, addr := range addrs {
			var ip net.IP
			var ipNet *net.IPNet

			// Check if the address is an IPNet (which gives both IP and mask)
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				ipNet = v
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip if no IPNet
			if ip == nil {
				continue
			}
			if ipNet == nil {
				//fmt.Printf("skipping %s b/c no ipNet ?\n", ip)
				continue
			}
			//fmt.Printf("ip '%s' has  ipNet='%v'\n", ip, ipNet)

			local6 := ip.To4() == nil
			if local6 != remote6 {
				continue
			}

			// In Tailscale,
			// client 100.x.y.z should be allowed to match server 100.q.r.s
			// but the ipNet here is /32 instead of /8, so we hard code this.
			isClientTailscale := tailscale100net.Contains(ip)
			if isServerTailscale {
				if isClientTailscale {
					return ip.String(), nil
				} else {
					// wait for a tailscale client.
					continue
				}
			}
			// INVAR: not a Tailscale server.
			if isClientTailscale {
				// don't match with non-Tailscale server
				continue
			}

			// If the server IP is private, check for same subnet
			if IsPrivateIP(serverAddr.IP) && IsPrivateIP(ip) {
				//fmt.Printf("private server '%s', consider private client : %s; ipNet='%s'\n", serverAddr.IP, ip.String(), ipNet)
				if ipNet.Contains(serverAddr.IP) {
					return ip.String(), nil
				}
				if remote6 && strings.HasPrefix(ip.String(), serverAddr.IP.String()[:5]) {
					// best guess with matching first 4 bytes.
					return ip.String(), nil
				}
			} else if !IsPrivateIP(serverAddr.IP) {
				// If the server has a public IP, we (client) are probably NAT-ed anyway.
				// so don't ask for a public client IP address, or we'll not find an IP.
				//fmt.Printf("for server '%s', selected local interface: %s, IP: %s\n", serverAddr.IP, iface.Name, ip.String())
				return ip.String(), nil
			}
		}

		// Stop searching if a valid IP is found
		if selectedIP != nil {
			break
		}
	}

	if selectedIP == nil {
		return "", fmt.Errorf("No suitable local interface found that can connect to the server '%v'", serverAddr)
	}

	return selectedIP.String(), nil
}

// IsCGNAT checks if the given IP falls within the CGNAT range 100.64.0.0 - 100.127.255.255
func IsCGNAT(ip net.IP) bool {
	_, cgnatRange, _ := net.ParseCIDR("100.64.0.0/10")
	return cgnatRange.Contains(ip)
}

// Helper function to check if an IP is private
func IsPrivateIP(ip net.IP) bool {
	// Check for IPv4 private addresses
	if ip.To4() != nil {
		privateIPv4Blocks := []*net.IPNet{
			// 10.0.0.0/8
			{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
			// 172.16.0.0/12
			{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
			// 192.168.0.0/16
			{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
			// 127.0.0.0/8 (loopback)
			{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
			// 169.254.0.0/16 (link-local)
			{IP: net.IPv4(169, 254, 0, 0), Mask: net.CIDRMask(16, 32)},
		}
		for _, block := range privateIPv4Blocks {
			if block.Contains(ip) {
				return true
			}
		}
		isNat := IsCGNAT(ip)
		//fmt.Printf("isNat = '%v' for '%v'\n", isNat, ip.String())
		return isNat
	}

	// Check for IPv6 private addresses
	privateIPv6Blocks := []*net.IPNet{
		// fe80::/10 (link-local)
		{IP: net.ParseIP("fe80::"), Mask: net.CIDRMask(10, 128)},
		// fc00::/7 (unique local addresses)
		{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7, 128)},
		// ::1/128 (loopback)
		{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		// ::/128 (unspecified)
		{IP: net.ParseIP("::"), Mask: net.CIDRMask(128, 128)},
	}

	for _, block := range privateIPv6Blocks {
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

func IsLocalhost(ipStr string) (isLocal bool, hostOnlyNoPort string) {
	host, _, err := net.SplitHostPort(ipStr)
	if err == nil {
		ipStr = host
	}
	hostOnlyNoPort = ipStr
	ip := net.ParseIP(ipStr)
	if ip == nil {
		isLocal = false // Invalid IP
	}
	isLocal = ip.IsLoopback() || ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback)
	return
}

func ParseURLAddress(addr string) (scheme string, ip net.IP, port string, isUnspecified bool, isIPv6 bool, err error) {
	// Parse the URL
	u, err := url.Parse(addr)
	if err != nil {
		return "", nil, "", false, false, fmt.Errorf("parsing URL: %w", err)
	}

	// Split host and port
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", nil, "", false, false, fmt.Errorf("splitting host/port: %w", err)
	}

	// Remove the brackets from IPv6 address
	host = strings.Trim(host, "[]")

	// Parse the IP using net.ParseIP
	ip = net.ParseIP(host)
	if ip == nil {
		return "", nil, "", false, false, fmt.Errorf("invalid IP address: %s", host)
	}

	isUnspecified = ip.IsUnspecified()
	isIPv6 = ip.To4() == nil && ip.To16() != nil

	return u.Scheme, ip, port, isUnspecified, isIPv6, nil

}
