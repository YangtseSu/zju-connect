package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryTerminalsSplitsTrustedAndTemporary(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/v1/security/queryDevice" {
			t.Errorf("path = %q", r.URL.Path)
		}
		switch r.URL.Query().Get("status") {
		case "trust":
			fmt.Fprint(w, `{"code":0,"data":{"selfId":"self","currentTrustStatus":0,"currentTrustDeviceCount":1,"maxDeviceCount":50,"deviceTrusted":false,"deviceTrustedByOne":0,"trustDeviceConfig":{"limit":3},"data":[{"devDbId":"trusted-1","id":"trusted-1","deviceName":"desk-01","deviceType":"SDPClient","os":"Linux","osVersion":"7.3.0","onlineStatus":true,"lastLoginAddress":"Example City","lastLoginIp":"192.0.2.10","lastLoginTime":"2026-10-25 13:17:59"}]}}`)
		case "untrust":
			fmt.Fprint(w, `{"code":0,"data":{"selfId":"self","data":[{"devDbId":"self","id":"self","deviceName":"desk-02","deviceType":"browser","os":"Linux x86_64","onlineStatus":true,"lastLoginTime":"-"}]}}`)
		default:
			t.Errorf("status = %q", r.URL.Query().Get("status"))
		}
	}))
	defer server.Close()

	terminals, err := newTLSTestSession(server).QueryTerminals()
	if err != nil {
		t.Fatal(err)
	}
	if terminals.SelfID != "self" || len(terminals.Trusted) != 1 || len(terminals.Temporary) != 1 {
		t.Fatalf("terminals = %+v", terminals)
	}
	if terminals.MaxDeviceCount != 50 || terminals.CurrentTrustDeviceCount != 1 {
		t.Fatalf("counts = %+v", terminals)
	}
	if got := terminals.Trusted[0]; got.DeviceName != "desk-01" || got.OSVersion != "7.3.0" || !got.OnlineStatus {
		t.Fatalf("trusted = %+v", got)
	}
	if got := terminals.Temporary[0]; got.ID != "self" || !got.OnlineStatus {
		t.Fatalf("temporary = %+v", got)
	}
}

// A failure in the second list must not be reported as an empty history.
func TestQueryTerminalsReportsTheSecondFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("status") == "untrust" {
			fmt.Fprint(w, `{"code":10000001,"message":"denied"}`)
			return
		}
		fmt.Fprint(w, `{"code":0,"data":{"selfId":"self"}}`)
	}))
	defer server.Close()

	if _, err := newTLSTestSession(server).QueryTerminals(); err == nil {
		t.Fatal("expected the untrust failure")
	}
}
