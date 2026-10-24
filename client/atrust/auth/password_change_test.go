package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// newPasswordTestSession returns a session with a generated portal key that the
// test can use to decrypt what the client sent.
func newPasswordTestSession(t *testing.T, server *httptest.Server) (*Session, *rsa.PrivateKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	session := newTLSTestSession(server)
	session.pubKey = privateKey.PublicKey.N.Text(16)
	session.pubKeyExp = strconv.Itoa(privateKey.PublicKey.E)
	session.antiReplayRand = "nonce"
	return session, privateKey
}

// decryptSecret reverses the client's hex PKCS#1 v1.5 encryption.
func decryptSecret(t *testing.T, privateKey *rsa.PrivateKey, encoded string) string {
	t.Helper()

	raw, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode the cipher text: %v", err)
	}
	blockSize := privateKey.PublicKey.Size()
	if len(raw)%blockSize != 0 {
		t.Fatalf("cipher text length %d is not a multiple of %d", len(raw), blockSize)
	}
	plaintext := make([]byte, 0, len(raw))
	for offset := 0; offset < len(raw); offset += blockSize {
		chunk, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, raw[offset:offset+blockSize])
		if err != nil {
			t.Fatalf("decrypt block at %d: %v", offset, err)
		}
		plaintext = append(plaintext, chunk...)
	}
	return string(plaintext)
}

func TestPswImplCapturesForcedPasswordChange(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":0,"data":{"ticket":"t","nextService":"auth/modifyPwd","modifyPwdCode":75500402,`+
			`"modifyPwdMessage":"your password expired","pswStrategy":{"enablePswLength":{"enable":true,"value":"10"}},`+
			`"username":"student","domain":"local","pwdRulePrompt":"mix it up"}}`)
	}))
	defer server.Close()

	session, _ := newPasswordTestSession(t, server)
	if _, err := session.pswImpl("student", "old-password", "local", ""); err != nil {
		t.Fatalf("pswImpl() error = %v", err)
	}

	challenge := session.pendingPasswordChange()
	if challenge.Code != 75500402 || !challenge.ShowAccount || challenge.CanSkip {
		t.Fatalf("challenge = %+v, want code 75500402 with the account field and no skip", challenge)
	}
	if challenge.Message != "your password expired" || challenge.Prompt != "mix it up" {
		t.Fatalf("challenge text = %+v", challenge)
	}
	if challenge.Username != "student" || challenge.Domain != "local" || challenge.CustomizePwd {
		t.Fatalf("challenge account = %+v", challenge)
	}
	if !challenge.Strategy.EnablePswLength.Enable || challenge.Strategy.EnablePswLength.Value != 10 {
		t.Fatalf("strategy = %+v, want a minimum length of 10", challenge.Strategy)
	}
}

func TestCompletePasswordChangeRequiresAHandler(t *testing.T) {
	session := NewSession("vpn.example.com", nil)
	session.passwordChange = &PasswordChangeChallenge{Code: 75500404, CanSkip: true}

	_, err := session.completePasswordChange()
	var required *PasswordChangeRequiredError
	if !errors.As(err, &required) {
		t.Fatalf("completePasswordChange() error = %v, want *PasswordChangeRequiredError", err)
	}
	if !required.Challenge.CanSkip {
		t.Fatalf("challenge = %+v, want the skip offer", required.Challenge)
	}
}

func TestLoginCompletesForcedPasswordChange(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	var sentOld, sentNew, sentName string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/passport/v1/public/authConfig":
			fmt.Fprintf(w, `{"code":0,"data":{"isLogin":0,"csrfToken":"csrf","pubKey":"%s","pubKeyExp":"%d",`+
				`"authServerInfoList":[{"loginDomain":"local","authType":"auth/psw"}]}}`,
				privateKey.PublicKey.N.Text(16), privateKey.PublicKey.E)
		case "/passport/v1/auth/psw":
			fmt.Fprint(w, `{"code":0,"data":{"ticket":"t","nextService":"auth/modifyPwd","modifyPwdCode":75500402,`+
				`"modifyPwdMessage":"expired","username":"student","domain":"local"}}`)
		case "/controller/v1/public/reportEnv":
			fmt.Fprint(w, `{"code":0}`)
		case "/passport/v1/auth/modifyPwd":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse the modifyPwd form: %v", err)
			}
			if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
				t.Errorf("Content-Type = %q", got)
			}
			sentOld = decryptSecret(t, privateKey, r.PostForm.Get("oldPassword"))
			sentNew = decryptSecret(t, privateKey, r.PostForm.Get("newPassword"))
			sentName = r.PostForm.Get("newUserName")
			fmt.Fprint(w, `{"code":0,"data":{}}`)
		case "/passport/v1/auth/authCheck":
			fmt.Fprint(w, `{"code":0,"data":{"nextService":""}}`)
		case "/passport/v1/user/onlineInfo":
			fmt.Fprint(w, `{"code":0,"data":{"username":"student"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.pubKey = privateKey.PublicKey.N.Text(16)
	session.pubKeyExp = strconv.Itoa(privateKey.PublicKey.E)
	session.antiReplayRand = "nonce"

	notified := ""
	_, err = session.Login(PasswordLogin{Username: "student", Password: "old-password", Domain: "local"}, LoginOptions{
		DeviceID: "0123456789abcdef0123456789abcdef",
		PasswordChangeHandler: PasswordChangeHandlerFunc(func(challenge PasswordChangeChallenge) (PasswordChangeResponse, error) {
			if challenge.Code != 75500402 || !challenge.ShowAccount || challenge.CanSkip {
				t.Errorf("challenge = %+v", challenge)
			}
			return PasswordChangeResponse{
				OldPassword: "old-password",
				NewPassword: "new-password",
				NewUserName: "renamed",
			}, nil
		}),
		OnPasswordChanged: func(newPassword string) { notified = newPassword },
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if sentOld != "old-password" || sentNew != "new-password" {
		t.Fatalf("modifyPwd passwords = %q / %q", sentOld, sentNew)
	}
	if sentName != "renamed" {
		t.Fatalf("newUserName = %q, want renamed", sentName)
	}
	if notified != "new-password" {
		t.Fatalf("OnPasswordChanged = %q, want new-password", notified)
	}
}

func TestLoginSkipsForcedPasswordChange(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	var skipSent bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/passport/v1/public/authConfig":
			fmt.Fprintf(w, `{"code":0,"data":{"isLogin":0,"csrfToken":"csrf","pubKey":"%s","pubKeyExp":"%d",`+
				`"authServerInfoList":[{"loginDomain":"local","authType":"auth/psw"}]}}`,
				privateKey.PublicKey.N.Text(16), privateKey.PublicKey.E)
		case "/passport/v1/auth/psw":
			fmt.Fprint(w, `{"code":0,"data":{"ticket":"t","nextService":"auth/modifyPwd","modifyPwdCode":75500404,"domain":"local"}}`)
		case "/controller/v1/public/reportEnv":
			fmt.Fprint(w, `{"code":0}`)
		case "/passport/v1/auth/modifyPwd":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse the modifyPwd form: %v", err)
			}
			skipSent = r.PostForm.Get("skip") == "true" && r.PostForm.Get("newPassword") == ""
			fmt.Fprint(w, `{"code":0,"data":{"remainedSkipTimes":2}}`)
		case "/passport/v1/auth/authCheck":
			fmt.Fprint(w, `{"code":0,"data":{"nextService":""}}`)
		case "/passport/v1/user/onlineInfo":
			fmt.Fprint(w, `{"code":0,"data":{"username":"student"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session, _ := newPasswordTestSession(t, server)
	_, err = session.Login(PasswordLogin{Username: "student", Password: "old-password", Domain: "local"}, LoginOptions{
		DeviceID: "0123456789abcdef0123456789abcdef",
		PasswordChangeHandler: PasswordChangeHandlerFunc(func(PasswordChangeChallenge) (PasswordChangeResponse, error) {
			return PasswordChangeResponse{Skip: true}, nil
		}),
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if !skipSent {
		t.Fatal("the skip answer did not reach /passport/v1/auth/modifyPwd")
	}
}

func TestResetPasswordUsesTheSecurityEndpoint(t *testing.T) {
	var received map[string]string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/v1/security/modifyPwd" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Errorf("Content-Type = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &received); err != nil {
			t.Errorf("decode the request: %v", err)
		}
		fmt.Fprint(w, `{"code":0}`)
	}))
	defer server.Close()

	session, privateKey := newPasswordTestSession(t, server)
	if err := session.ResetPassword(context.Background(), "old-password", "new-password"); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}
	if got := decryptSecret(t, privateKey, received["oldPassword"]); got != "old-password" {
		t.Fatalf("oldPassword = %q", got)
	}
	if got := decryptSecret(t, privateKey, received["newPassword"]); got != "new-password" {
		t.Fatalf("newPassword = %q", got)
	}
}

func TestChangePasswordUsesTheForcedEndpoint(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	var sentOld, sentNew string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/v1/auth/modifyPwd" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse the change form: %v", err)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		if r.PostForm.Get("skip") != "" || r.PostForm.Get("newUserName") != "" {
			t.Errorf("unexpected form fields: %v", r.PostForm)
		}
		sentOld = decryptSecret(t, privateKey, r.PostForm.Get("oldPassword"))
		sentNew = decryptSecret(t, privateKey, r.PostForm.Get("newPassword"))
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.pubKey = privateKey.PublicKey.N.Text(16)
	session.pubKeyExp = strconv.Itoa(privateKey.PublicKey.E)
	session.antiReplayRand = "nonce"

	if err := session.ChangePassword(context.Background(), "old-password", "new-password"); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}
	if sentOld != "old-password" || sentNew != "new-password" {
		t.Fatalf("passwords = %q / %q", sentOld, sentNew)
	}
}

func TestChangePasswordReportsAPortalCode(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":75500403,"message":"the old password is wrong"}`)
	}))
	defer server.Close()

	session, _ := newPasswordTestSession(t, server)
	err := session.ChangePassword(context.Background(), "wrong", "new-password")
	var coded *PortalCodeError
	if !errors.As(err, &coded) || coded.Code != 75500403 {
		t.Fatalf("ChangePassword() error = %v, want code 75500403", err)
	}
}

func TestPasswordStrategyAndWeakPassword(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/passport/v1/user/pswStrategy":
			fmt.Fprint(w, `{"code":0,"data":{"enablePswLength":{"enable":true,"value":"12"},`+
				`"enablePswCombination":{"enable":true,"value":{"enableAllLetter":true,"enableUpperAndLowerLetter":true,"enableNumber":true,"enableSpecialLetter":true}},`+
				`"enablePswNotContainName":true,"notContainContChar":{"enable":true,"value":3},"notBelongToWeakDb":1}}`)
		case "/passport/v1/public/weakpwd":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"password":"123456"`) {
				t.Errorf("weakpwd body = %s", body)
			}
			fmt.Fprint(w, `{"code":0,"validate":false,"msg":"common password"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session, _ := newPasswordTestSession(t, server)
	strategy, err := session.PasswordStrategy(context.Background())
	if err != nil {
		t.Fatalf("PasswordStrategy() error = %v", err)
	}
	if strategy.EnablePswLength.Value != 12 || !bool(strategy.EnablePswNotContainName) {
		t.Fatalf("strategy = %+v", strategy)
	}
	violations := strategy.Violations("short", "student")
	if len(violations) < 3 {
		t.Fatalf("Violations(short) = %v, want length, letter and character-class failures", violations)
	}

	result, err := session.CheckWeakPassword(context.Background(), "123456")
	if err != nil {
		t.Fatalf("CheckWeakPassword() error = %v", err)
	}
	if result.Validate || result.Message != "common password" {
		t.Fatalf("weak result = %+v", result)
	}
}

func TestPasswordStrategyAcceptsAValidPassword(t *testing.T) {
	strategy := PasswordStrategy{}
	strategy.EnablePswLength.Enable = true
	strategy.EnablePswLength.Value = 8
	strategy.EnablePswCombination.Enable = true
	strategy.EnablePswCombination.Value.EnableAllLetter = true
	strategy.EnablePswCombination.Value.EnableUpperAndLowerLetter = true
	strategy.EnablePswCombination.Value.EnableNumber = true
	strategy.EnablePswCombination.Value.EnableSpecialLetter = true
	strategy.EnablePswNotContainName = true
	strategy.NotContainContChar.Enable = true
	strategy.NotContainContChar.Value = 3

	if violations := strategy.Violations("Str0ng!pass", "student"); len(violations) != 0 {
		t.Fatalf("Violations(Str0ng!pass) = %v", violations)
	}
	if violations := strategy.Violations("Student1!", "student"); len(violations) != 1 {
		t.Fatalf("Violations(Student1!) = %v, want the account-name failure", violations)
	}
	if violations := strategy.Violations("Aa1!aaaa", "student"); len(violations) != 1 {
		t.Fatalf("Violations(Aa1!aaaa) = %v, want the repetition failure", violations)
	}
}
