package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A caller that presents an installation identity replaces the UA of every
// request the session sends; the default stays for a caller that does not.
func TestSetUserAgentReplacesTheDefault(t *testing.T) {
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("User-Agent"))
		fmt.Fprint(w, `{"code":0,"data":{"selfId":"self","deviceTrusted":false}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	if _, err := session.QueryDevice(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != UserAgent {
		t.Fatalf("user agent = %v, want the package default", seen)
	}

	seen = nil
	custom := "Mozilla/5.0 (X11; Linux x86_64) aTrustTray-Test"
	session.SetUserAgent(custom)
	if _, err := session.QueryDevice(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != custom {
		t.Fatalf("user agent = %v, want %q", seen, custom)
	}

	session.SetUserAgent("")
	if session.userAgent != custom {
		t.Fatalf("an empty override replaced the UA with %q", session.userAgent)
	}
}
