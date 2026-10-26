package atrust

import "testing"

// The L3 environment reports the configured process block, and keeps the
// default for a field the caller left empty.
func TestDefaultEnvUsesTheConfiguredProcess(t *testing.T) {
	env := defaultEnv(clientInfo{
		processName:    "agent",
		processPath:    "/opt/agent/bin/agent",
		processVersion: "1.2.3",
	})
	process := env.Application.Runtime.Process
	if process.Name != "agent" || process.Path != "/opt/agent/bin/agent" || process.Version != "1.2.3" {
		t.Fatalf("process = %+v", process)
	}
	if process.DigitalSignature != "TrustAppClosed" {
		t.Fatalf("signature = %q, want the default placeholder", process.DigitalSignature)
	}
}

func TestDefaultEnvKeepsTheFallbacks(t *testing.T) {
	process := defaultEnv(clientInfo{}).Application.Runtime.Process
	if process.Name != "zju-connect" || process.Path != "/usr/bin/zju-connect" || process.Version != "TrustAppClosed" {
		t.Fatalf("process = %+v", process)
	}
}

// The L3 environment reports the client that runs it, not the TCP requester:
// the two options are separate on purpose.
func TestL3ClientInfoUsesTheClientProcess(t *testing.T) {
	client := &Client{
		Username:      "user",
		tunnelProcess: TunnelProcess{Name: "browser", Path: "/usr/bin/browser"},
		clientProcess: TunnelProcess{Name: "client", Path: "/opt/client/bin/client", Version: "1.0"},
	}
	info := l3ClientInfo(client)
	if info.processName != "client" || info.processPath != "/opt/client/bin/client" || info.processVersion != "1.0" {
		t.Fatalf("info = %+v", info)
	}
}

// Without a client process the upstream default stays, so a plain CLI that
// passes neither option behaves as before.
func TestL3ClientInfoKeepsTheDefaultWithoutAProcess(t *testing.T) {
	info := l3ClientInfo(&Client{})
	env := defaultEnv(info)
	if env.Application.Runtime.Process.Name != "zju-connect" {
		t.Fatalf("process name = %q", env.Application.Runtime.Process.Name)
	}
}
