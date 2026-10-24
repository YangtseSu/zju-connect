package gvisor

import (
	"context"
	"net"

	clientpkg "github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/resolve"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// trafficObserver is implemented by clients that prove a session with real
// application traffic. The aTrust client leaves its restoring state on it; a
// client that does not track session state (easyconnect) simply does not
// implement it.
type trafficObserver interface {
	ObserveTunnelTraffic(ok bool)
}

// reportTunnelTraffic tells the client that one connection crossed the tunnel.
func reportTunnelTraffic(client clientpkg.Client) {
	if observer, ok := client.(trafficObserver); ok {
		observer.ObserveTunnelTraffic(true)
	}
}

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if s.endpoint.client.CanUseTCPTunnel() && !resolve.TCPPrefersL3(ctx) {
		// The TCP tunnel reports its own traffic after the handshake.
		return s.endpoint.client.DialTCP(ctx, addr)
	}

	conn, err := gonet.DialTCP(s.gvisorStack, tcpip.FullAddress{
		NIC:  NICID,
		Port: uint16(addr.Port),
		Addr: tcpip.AddrFromSlice(addr.IP),
	}, header.IPv4ProtocolNumber)
	if err != nil {
		return nil, err
	}

	// The connection is established through the packet stack, which is real
	// application traffic. Without this a restored session stays "restoring"
	// even though the tunnel works, because only the TCP tunnel reported.
	reportTunnelTraffic(s.endpoint.client)
	return conn, nil
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	return gonet.DialUDP(s.gvisorStack, nil, &tcpip.FullAddress{
		NIC:  NICID,
		Port: uint16(addr.Port),
		Addr: tcpip.AddrFromSlice(addr.IP),
	}, header.IPv4ProtocolNumber)
}
