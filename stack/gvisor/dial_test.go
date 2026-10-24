package gvisor

import (
	"testing"

	clientpkg "github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/atrust"
)

// trafficClient records what the packet stack reports and borrows the rest of
// the client interface, which the adapter never calls.
type trafficClient struct {
	clientpkg.Client
	reports int
}

func (c *trafficClient) ObserveTunnelTraffic(ok bool) {
	if ok {
		c.reports++
	}
}

// The aTrust client is the one whose session state waits for this report.
var _ trafficObserver = (*atrust.Client)(nil)

// quietClient is any other client: it satisfies the client interface but does
// not track session traffic.
type quietClient struct{ clientpkg.Client }

func TestReportTunnelTrafficReachesTheObserver(t *testing.T) {
	client := &trafficClient{}
	reportTunnelTraffic(client)
	if client.reports != 1 {
		t.Fatalf("reports = %d, want 1", client.reports)
	}
}

func TestReportTunnelTrafficIgnoresClientsWithoutAnObserver(t *testing.T) {
	reportTunnelTraffic(quietClient{})
}
