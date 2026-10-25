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
