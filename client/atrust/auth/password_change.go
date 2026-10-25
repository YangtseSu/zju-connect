package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/mythologyli/zju-connect/log"
)

// The portal's forced-change answer carries these codes next to
// nextService:"auth/modifyPwd": 75500402 asks for a new account name on top of
// the password, and 75500404 lets the user skip the change.
const (
	codePasswordAccountRename   = 75500402
	codePasswordChangeSkippable = 75500404
)

// flexibleBool accepts both a JSON boolean and the 0/1 numbers the portlet
// answers use for the same field.
type flexibleBool bool

func (b *flexibleBool) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	switch string(data) {
	case "true", "1", `"1"`, `"true"`:
		*b = true
	case "false", "0", "null", `"0"`, `"false"`, `""`:
		*b = false
	default:
		var number json.Number
		if err := json.Unmarshal(data, &number); err != nil {
			return fmt.Errorf("parse a password rule flag: %w", err)
		}
		*b = number.String() != "0"
	}
	return nil
}

// flexibleInt accepts a number or a numeric string: the portal answers both for
// rule values such as the minimum length.
type flexibleInt int

func (i *flexibleInt) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	var number int
	if err := json.Unmarshal(data, &number); err == nil {
		*i = flexibleInt(number)
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("parse a password rule value: %w", err)
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		return fmt.Errorf("parse a password rule value %q: %w", text, err)
	}
	*i = flexibleInt(parsed)
	return nil
}

// PasswordStrategy is the account's password policy as /passport/v1/user/pswStrategy
// (and the forced-change answer's pswStrategy) reports it.
type PasswordStrategy struct {
	EnablePswLength struct {
		Enable flexibleBool `json:"enable"`
		Value  flexibleInt  `json:"value"`
	} `json:"enablePswLength"`
	EnablePswCombination struct {
		Enable flexibleBool `json:"enable"`
		Value  struct {
			EnableAllLetter           flexibleBool `json:"enableAllLetter"`
			EnableUpperAndLowerLetter flexibleBool `json:"enableUpperAndLowerLetter"`
			EnableNumber              flexibleBool `json:"enableNumber"`
			EnableSpecialLetter       flexibleBool `json:"enableSpecialLetter"`
		} `json:"value"`
	} `json:"enablePswCombination"`
	EnablePswNotContainName  flexibleBool `json:"enablePswNotContainName"`
	EnablePswNotEqualHistory struct {
		Enable flexibleBool `json:"enable"`
		Value  flexibleInt  `json:"value"`
	} `json:"enablePswNotEqualHistory"`
	NotContainContChar struct {
		Enable flexibleBool `json:"enable"`
		Value  flexibleInt  `json:"value"`
	} `json:"notContainContChar"`
	NotContainKeyboardContChar struct {
		Enable flexibleBool `json:"enable"`
		Value  flexibleInt  `json:"value"`
	} `json:"notContainKeyboardContChar"`
	NotBelongToWeakDb flexibleBool `json:"notBelongToWeakDb"`
	// EffectiveTime is the validity a changed password gets, in days, and
	// EnablePswExpire says whether the account expires passwords at all.
	EffectiveTime   flexibleInt  `json:"effectiveTime"`
	EnablePswExpire flexibleBool `json:"enablePswExpire"`
	// ChangeFirstLogin and ChangeMangerResetPwd are the vendor's own policy
	// flags; they are kept so the rules panel can explain a forced change.
	ChangeFirstLogin     flexibleBool `json:"changeFirstLogin"`
	ChangeMangerResetPwd flexibleBool `json:"changeMangerResetPwd"`
}

// PasswordStrategy decodes a raw strategy object. A gateway may double-encode
// the object as a JSON string; an empty answer is an empty policy.
func decodePasswordStrategy(raw json.RawMessage) PasswordStrategy {
	var strategy PasswordStrategy
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return strategy
	}
	if err := json.Unmarshal(raw, &strategy); err == nil {
		return strategy
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		log.Printf("Warning: unreadable password strategy: %v", err)
		return PasswordStrategy{}
	}
	if err := json.Unmarshal([]byte(encoded), &strategy); err != nil {
		log.Printf("Warning: unreadable password strategy: %v", err)
		return PasswordStrategy{}
	}
	return strategy
}

// PasswordRuleCode names one rule, so a UI can render its own wording instead
// of showing the English text of the protocol layer.
type PasswordRuleCode string

const (
	RuleLength        PasswordRuleCode = "length"
	RuleLetters       PasswordRuleCode = "letters"
	RuleUpperAndLower PasswordRuleCode = "upper-lower"
	RuleNumber        PasswordRuleCode = "number"
	RuleSpecial       PasswordRuleCode = "special"
	RuleNoUsername    PasswordRuleCode = "username"
	RuleNoRepeat      PasswordRuleCode = "repeat"
	RuleNoSequence    PasswordRuleCode = "sequence"
	RuleNotWeak       PasswordRuleCode = "weak"
	RuleNotInHistory  PasswordRuleCode = "history"
)

// PasswordRule is one line of the rules panel. Satisfied is only meaningful for
// a rule the client can check itself; ServerCheck rules (the weak-password
// database and the history) are validated by the portal when the change is
// submitted.
type PasswordRule struct {
	Code        PasswordRuleCode
	Enabled     bool
	Satisfied   bool
	ServerCheck bool
	// Value is the rule's parameter: the minimum length, the number of
	// repeated or sequential characters, or the number of remembered
	// passwords.
	Value int
}

// Rules lists the policy's rules in the order the vendor's panel shows them.
func (s PasswordStrategy) Rules(username string) []PasswordRule {
	combination := s.EnablePswCombination.Value
	allLetters := bool(s.EnablePswCombination.Enable) && bool(combination.EnableAllLetter)
	upperAndLower := bool(s.EnablePswCombination.Enable) && bool(combination.EnableAllLetter) && bool(combination.EnableUpperAndLowerLetter)

	rules := []PasswordRule{
		{Code: RuleLength, Enabled: bool(s.EnablePswLength.Enable), Value: int(s.EnablePswLength.Value)},
		{Code: RuleLetters, Enabled: allLetters && !upperAndLower},
		{Code: RuleUpperAndLower, Enabled: upperAndLower},
		{Code: RuleNumber, Enabled: bool(s.EnablePswCombination.Enable) && bool(combination.EnableNumber)},
		{Code: RuleSpecial, Enabled: bool(s.EnablePswCombination.Enable) && bool(combination.EnableSpecialLetter)},
		{Code: RuleNoUsername, Enabled: bool(s.EnablePswNotContainName)},
		{Code: RuleNoRepeat, Enabled: bool(s.NotContainContChar.Enable), Value: int(s.NotContainContChar.Value)},
		{Code: RuleNoSequence, Enabled: bool(s.NotContainKeyboardContChar.Enable), Value: int(s.NotContainKeyboardContChar.Value), ServerCheck: true},
		{Code: RuleNotWeak, Enabled: bool(s.NotBelongToWeakDb), ServerCheck: true},
		{Code: RuleNotInHistory, Enabled: bool(s.EnablePswNotEqualHistory.Enable), ServerCheck: true, Value: int(s.EnablePswNotEqualHistory.Value)},
	}
	return rules
}

// Violations checks a new password against the rules the client can evaluate.
// It deliberately does not judge the weak-password database, the history or the
// keyboard-sequence rule: those are the portal's answers, and a wrong local
// verdict would refuse a password the portal accepts. A username-match rule
// with an empty username is skipped for the same reason.
func (s PasswordStrategy) Violations(password, username string) []string {
	var violations []string
	add := func(message string) {
		violations = append(violations, message)
	}

	if s.EnablePswLength.Enable && len([]rune(password)) < int(s.EnablePswLength.Value) {
		add(fmt.Sprintf("the password must be at least %d characters", s.EnablePswLength.Value))
	}
	combination := s.EnablePswCombination.Value
	enabled := bool(s.EnablePswCombination.Enable)
	if enabled && bool(combination.EnableAllLetter) {
		if !bool(combination.EnableUpperAndLowerLetter) {
			if !strings.ContainsFunc(password, func(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }) {
				add("the password must contain a letter")
			}
		} else {
			hasLower := strings.ContainsFunc(password, func(r rune) bool { return r >= 'a' && r <= 'z' })
			hasUpper := strings.ContainsFunc(password, func(r rune) bool { return r >= 'A' && r <= 'Z' })
			if !hasLower || !hasUpper {
				add("the password must contain both an upper-case and a lower-case letter")
			}
		}
	}
	if enabled && bool(combination.EnableNumber) && !strings.ContainsFunc(password, func(r rune) bool { return r >= '0' && r <= '9' }) {
		add("the password must contain a digit")
	}
	if enabled && bool(combination.EnableSpecialLetter) && !strings.ContainsFunc(password, isSpecialCharacter) {
		add("the password must contain a special character")
	}
	if bool(s.EnablePswNotContainName) && username != "" && strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
		add("the password must not contain the account name")
	}
	if s.NotContainContChar.Enable {
		run := int(s.NotContainContChar.Value)
		if run <= 1 {
			run = 2
		}
		if hasRepeatedRun(password, run) {
			add(fmt.Sprintf("the password must not repeat one character %d times in a row", run))
		}
	}
	return violations
}

// isSpecialCharacter is the vendor's special-character class.
func isSpecialCharacter(r rune) bool {
	return strings.ContainsRune(`~!@#$%^&*()_+{}|:"<>?`+"`"+`-=[]\;',./ `, r)
}

// hasRepeatedRun reports whether one character repeats run times in a row,
// the vendor's "(\w|\W)\1{n-1}" rule.
func hasRepeatedRun(password string, run int) bool {
	if run <= 1 {
		return false
	}
	runes := []rune(password)
	for index := 0; index+run <= len(runes); index++ {
		repeated := true
		for offset := 1; offset < run; offset++ {
			if runes[index+offset] != runes[index] {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}
	return false
}

// passwordChangeData is the forced-change payload a portal answer carries
// next to nextService:"auth/modifyPwd". It appears in the password answer and
// again in the authCheck answer, which is where the live gateway announces the
// change.
type passwordChangeData struct {
	ModifyPwdCode    flexibleInt     `json:"modifyPwdCode"`
	ModifyPwdMessage string          `json:"modifyPwdMessage"`
	PswStrategy      json.RawMessage `json:"pswStrategy"`
	Username         string          `json:"username"`
	Domain           string          `json:"domain"`
	PwdRulePrompt    string          `json:"pwdRulePrompt"`
}

// passwordChangeFromData builds the challenge the window shows. The fallbacks
// are the account the login used, because a portal may omit the pair in the
// authCheck answer.
func passwordChangeFromData(data passwordChangeData, username, domain string) PasswordChangeChallenge {
	challenge := PasswordChangeChallenge{
		Code:         int(data.ModifyPwdCode),
		Message:      data.ModifyPwdMessage,
		Username:     data.Username,
		Domain:       data.Domain,
		Prompt:       data.PwdRulePrompt,
		Strategy:     decodePasswordStrategy(data.PswStrategy),
		CanSkip:      int(data.ModifyPwdCode) == codePasswordChangeSkippable,
		ShowAccount:  int(data.ModifyPwdCode) == codePasswordAccountRename || int(data.ModifyPwdCode) == codePasswordChangeSkippable,
		CustomizePwd: data.Domain != "" && data.Domain != "local",
	}
	if challenge.Username == "" {
		challenge.Username = username
	}
	if challenge.Domain == "" {
		challenge.Domain = domain
	}
	if challenge.Username == "" && challenge.Domain == "" {
		challenge.CustomizePwd = false
	}
	return challenge
}

// loginUsername is the account part of the name the password login sent.
func (s *Session) loginUsername() string {
	if at := strings.LastIndex(s.username, "@"); at >= 0 {
		return s.username[:at]
	}
	return s.username
}

// capturePasswordChange stores the demand when the answer announced one. The
// login and the authCheck answer both go through here: the live gateway names
// the change in authCheck, not in the password answer, and the code there is
// what brings the account field and the skip offer.
func (s *Session) capturePasswordChange(nextService string, data passwordChangeData, username, domain string) {
	if nextService != "auth/modifyPwd" {
		return
	}
	challenge := passwordChangeFromData(data, username, domain)
	s.stateMu.Lock()
	s.passwordChange = &challenge
	s.stateMu.Unlock()
}

// ErrReauthRequired reports that the forced-change step completed (the password
// changed, or the user skipped it) and the pending authentication cannot
// continue: the portal counts the account as logged in and refuses the
// follow-up authCheck with 75500006. The caller has to start a fresh login,
// with the new password after a change.
var ErrReauthRequired = errors.New("the portal requires a fresh login after the password change step")

// PasswordChangeChallenge is the gateway's forced password change: the account
// has to choose a new password before the login can finish.
type PasswordChangeChallenge struct {
	Code     int
	Message  string
	Username string
	Domain   string
	Prompt   string
	Strategy PasswordStrategy
	// CanSkip is the portal's 75500404: the user may postpone the change.
	CanSkip bool
	// ShowAccount is the portal's 75500402 (or a skippable change): the account
	// name itself may be changed with the password.
	ShowAccount bool
	// CustomizePwd is a non-local login domain, whose policy comes from the
	// server and may not carry a local rule list.
	CustomizePwd bool
}

// PasswordChangeResponse answers a forced change. Skip is only sent when the
// challenge allowed it.
type PasswordChangeResponse struct {
	OldPassword string
	NewPassword string
	NewUserName string
	Skip        bool
}

// PasswordChangeHandler asks the user for the new password. It is called from
// the login goroutine and may block; the login attempt's context cancellation
// is the caller's responsibility to observe.
type PasswordChangeHandler interface {
	HandlePasswordChange(challenge PasswordChangeChallenge) (PasswordChangeResponse, error)
}

// PasswordChangeHandlerFunc adapts a function to PasswordChangeHandler.
type PasswordChangeHandlerFunc func(challenge PasswordChangeChallenge) (PasswordChangeResponse, error)

func (f PasswordChangeHandlerFunc) HandlePasswordChange(challenge PasswordChangeChallenge) (PasswordChangeResponse, error) {
	return f(challenge)
}

// PasswordChangeRequiredError is what Login returns when the gateway demands a
// new password and no handler was supplied. A caller with a UI installs a
// handler; a headless caller reports this error instead of guessing.
type PasswordChangeRequiredError struct {
	Challenge PasswordChangeChallenge
}

func (e *PasswordChangeRequiredError) Error() string {
	reason := e.Challenge.Message
	if reason == "" {
		reason = "the gateway requires a password change"
	}
	return reason
}

// SkipPasswordChangeResult is the portal's answer to skipping the forced
// change: RemainedSkipTimes is how many postponements the account has left.
type SkipPasswordChangeResult struct {
	RemainedSkipTimes int
}

// WeakPasswordResult is the portal's answer to a weak-password probe.
type WeakPasswordResult struct {
	Validate bool
	Code     int
	Message  string
}

// passwordChangeResult is the shared answer shape of the portal's password
// calls.
type passwordChangeResult struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		NextService       string `json:"nextService"`
		RemainedSkipTimes int    `json:"remainedSkipTimes"`
		Ticket            string `json:"ticket"`
	} `json:"data"`
}

// completePasswordChange answers nextService:"auth/modifyPwd" inside the auth
// chain. A handler turns the demand into a new password (or a skip) and the
// chain continues afterwards, exactly as the portal's own page does.
func (s *Session) completePasswordChange() (authStep, error) {
	challenge := s.pendingPasswordChange()
	handler := s.passwordChangeHandlerValue()
	if handler == nil {
		return authStep{}, &PasswordChangeRequiredError{Challenge: challenge}
	}

	log.Printf("The gateway requires a password change (code %d)", challenge.Code)
	response, err := handler.HandlePasswordChange(challenge)
	if err != nil {
		return authStep{}, fmt.Errorf("complete the password change: %w", err)
	}

	if response.Skip {
		if !challenge.CanSkip {
			return authStep{}, fmt.Errorf("the gateway does not allow skipping the password change")
		}
		result, err := s.skipPasswordChange(s.lifetimeCtx())
		if err != nil {
			return authStep{}, err
		}
		s.clearPasswordChange()
		log.Printf("Skipped the password change, %d skip(s) left", result.Data.RemainedSkipTimes)
		return authStep{}, ErrReauthRequired
	}

	if strings.TrimSpace(response.NewPassword) == "" {
		return authStep{}, fmt.Errorf("the password change response carries no new password")
	}
	// The vendor's form requires the account field whenever it is shown (code
	// 75500402 and a skippable 75500404): the page starts it empty and refuses
	// to submit without it.
	if challenge.ShowAccount && strings.TrimSpace(response.NewUserName) == "" {
		return authStep{}, fmt.Errorf("the password change response carries no new account name")
	}
	nextService, err := s.changePasswordForm(s.lifetimeCtx(), challenge, response)
	if err != nil {
		return authStep{}, err
	}
	s.clearPasswordChange()
	if notify := s.passwordChangedNotifier(); notify != nil {
		notify(response.NewPassword)
	}
	log.Printf("Password changed; a fresh login is required (nextService=%q)", nextService)
	return authStep{}, ErrReauthRequired
}

// pendingPasswordChange returns the challenge the password answer described.
func (s *Session) pendingPasswordChange() PasswordChangeChallenge {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.passwordChange == nil {
		return PasswordChangeChallenge{}
	}
	return *s.passwordChange
}

func (s *Session) clearPasswordChange() {
	s.stateMu.Lock()
	s.passwordChange = nil
	s.stateMu.Unlock()
}

func (s *Session) passwordChangeHandlerValue() PasswordChangeHandler {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.passwordChangeHandler
}

func (s *Session) passwordChangedNotifier() func(string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.onPasswordChanged
}

// ChangePassword posts a change to /passport/v1/auth/modifyPwd outside the
// login chain, for a caller that caught *PasswordChangeRequiredError instead of
// installing a handler. The challenge's optional account rename is not carried
// here; use a handler for that. The calling login cannot be resumed, so the
// caller has to log in again with the new password afterwards.
func (s *Session) ChangePassword(ctx context.Context, oldPassword, newPassword string) error {
	_, err := s.changePasswordForm(ctx, PasswordChangeChallenge{}, PasswordChangeResponse{
		OldPassword: oldPassword,
		NewPassword: newPassword,
	})
	return err
}

// changePasswordForm posts the forced change to /passport/v1/auth/modifyPwd.
// The endpoint is form-urlencoded and encrypts both passwords; unlike the login
// it does not append the anti-replay nonce.
func (s *Session) changePasswordForm(ctx context.Context, challenge PasswordChangeChallenge, response PasswordChangeResponse) (string, error) {
	oldCipher, err := s.encryptChallengeResponse(response.OldPassword)
	if err != nil {
		return "", err
	}
	newCipher, err := s.encryptChallengeResponse(response.NewPassword)
	if err != nil {
		return "", err
	}

	form := url.Values{
		"oldPassword": {oldCipher},
		"newPassword": {newCipher},
	}
	if challenge.ShowAccount {
		form.Set("newUserName", strings.TrimSpace(response.NewUserName))
	}
	result, err := s.postPasswordForm(ctx, "/passport/v1/auth/modifyPwd", form)
	if err != nil {
		return "", err
	}
	if result.Code != 0 {
		return "", &PortalCodeError{Op: "modifyPwd", Code: result.Code, Message: result.Message}
	}
	return result.Data.NextService, nil
}

// ResetPassword changes the password of the live session through
// /passport/v1/security/modifyPwd (个人信息 → 密码安全 → 重置密码). Both
// passwords are RSA-encrypted and sent as JSON.
func (s *Session) ResetPassword(ctx context.Context, oldPassword, newPassword string) error {
	log.Println("Perform POST /passport/v1/security/modifyPwd")
	// The vendor page encrypts both passwords as
	// "<password>_<antiReplayRand>" with the key its SDK store holds. That
	// store is updated from the login answer (and the renewal loop), so the
	// session's own key and nonce are the ones the portal expects. Fetching
	// authConfig here would rotate both and can drop the login's CSRF token.
	oldCipher, err := s.encryptChallengeResponse(oldPassword)
	if err != nil {
		return err
	}
	newCipher, err := s.encryptChallengeResponse(newPassword)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]string{
		"oldPassword": oldCipher,
		"newPassword": newCipher,
	})
	if err != nil {
		return err
	}

	u := s.baseURL + "/passport/v1/security/modifyPwd?" + WithSharedParams(nil).Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	s.setPortalHeaders(req, "application/json;charset=utf-8")

	resp, err := s.request(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.DebugPrintf("Received security modifyPwd: %s", log.RedactSecrets(string(body)))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("security/modifyPwd returned HTTP status %d", resp.StatusCode)
	}

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &re); err != nil {
		return fmt.Errorf("parse the password change answer: %w", err)
	}
	if re.Code != 0 {
		log.Printf("security/modifyPwd failed with code %d: %s", re.Code, re.Message)
		return &PortalCodeError{Op: "security/modifyPwd", Code: re.Code, Message: re.Message}
	}
	return nil
}

// SkipPasswordChange postpones the forced change when the portal allows it.
func (s *Session) SkipPasswordChange(ctx context.Context) (SkipPasswordChangeResult, error) {
	result, err := s.skipPasswordChange(ctx)
	if err != nil {
		return SkipPasswordChangeResult{}, err
	}
	return SkipPasswordChangeResult{RemainedSkipTimes: result.Data.RemainedSkipTimes}, nil
}

func (s *Session) skipPasswordChange(ctx context.Context) (passwordChangeResult, error) {
	result, err := s.postPasswordForm(ctx, "/passport/v1/auth/modifyPwd", url.Values{"skip": {"true"}})
	if err != nil {
		return passwordChangeResult{}, err
	}
	if result.Code != 0 {
		return passwordChangeResult{}, &PortalCodeError{Op: "modifyPwd", Code: result.Code, Message: result.Message}
	}
	return result, nil
}

// PasswordStrategy fetches the account's password policy.
func (s *Session) PasswordStrategy(ctx context.Context) (PasswordStrategy, error) {
	log.Println("Perform GET /passport/v1/user/pswStrategy")
	u := s.baseURL + "/passport/v1/user/pswStrategy?" + WithSharedParams(nil).Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return PasswordStrategy{}, err
	}
	s.setPortalHeaders(req, "")

	resp, err := s.request(req)
	if err != nil {
		return PasswordStrategy{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return PasswordStrategy{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return PasswordStrategy{}, fmt.Errorf("pswStrategy returned HTTP status %d", resp.StatusCode)
	}

	var re struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &re); err != nil {
		return PasswordStrategy{}, fmt.Errorf("parse the password strategy: %w", err)
	}
	if re.Code != 0 {
		return PasswordStrategy{}, &PortalCodeError{Op: "pswStrategy", Code: re.Code, Message: re.Message}
	}
	return decodePasswordStrategy(re.Data), nil
}

// CheckWeakPassword asks the portal's weak-password database about a candidate
// password. The vendor's page encrypts it with the portal key and the current
// anti-replay nonce before sending it (the same `ti` helper the password
// change uses), so the body carries "<password>_<nonce>", not the plaintext.
func (s *Session) CheckWeakPassword(ctx context.Context, password string) (WeakPasswordResult, error) {
	log.Println("Perform POST /passport/v1/public/weakpwd")
	encrypted, err := s.encryptChallengeResponse(password)
	if err != nil {
		return WeakPasswordResult{}, err
	}
	payload, err := json.Marshal(map[string]string{"password": encrypted})
	if err != nil {
		return WeakPasswordResult{}, err
	}

	u := s.baseURL + "/passport/v1/public/weakpwd?" + WithSharedParams(nil).Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return WeakPasswordResult{}, err
	}
	s.setPortalHeaders(req, "application/json;charset=utf-8")

	resp, err := s.request(req)
	if err != nil {
		return WeakPasswordResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return WeakPasswordResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return WeakPasswordResult{}, fmt.Errorf("weakpwd returned HTTP status %d", resp.StatusCode)
	}

	var re struct {
		Code     int    `json:"code"`
		Message  string `json:"message"`
		Msg      string `json:"msg"`
		Validate bool   `json:"validate"`
	}
	if err := json.Unmarshal(body, &re); err != nil {
		return WeakPasswordResult{}, fmt.Errorf("parse the weak-password answer: %w", err)
	}
	message := re.Message
	if message == "" {
		message = re.Msg
	}
	log.Printf("weakpwd answered code=%d validate=%t", re.Code, re.Validate)
	return WeakPasswordResult{Validate: re.Validate, Code: re.Code, Message: message}, nil
}

// postPasswordForm posts a form-urlencoded answer to a password endpoint.
func (s *Session) postPasswordForm(ctx context.Context, path string, form url.Values) (passwordChangeResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+path+"?"+WithSharedParams(nil).Encode(), strings.NewReader(form.Encode()))
	if err != nil {
		return passwordChangeResult{}, err
	}
	s.setPortalHeaders(req, "application/x-www-form-urlencoded")

	resp, err := s.request(req)
	if err != nil {
		return passwordChangeResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return passwordChangeResult{}, err
	}
	log.DebugPrintf("Received %s: %s", path, log.RedactSecrets(string(body)))
	if resp.StatusCode != http.StatusOK {
		return passwordChangeResult{}, fmt.Errorf("%s returned HTTP status %d", path, resp.StatusCode)
	}

	var result passwordChangeResult
	if err := json.Unmarshal(body, &result); err != nil {
		return passwordChangeResult{}, fmt.Errorf("parse the password answer: %w", err)
	}
	if result.Data.Ticket != "" {
		s.stateMu.Lock()
		s.ticket = result.Data.Ticket
		s.stateMu.Unlock()
	}
	return result, nil
}

// setPortalHeaders applies the headers every passport request needs.
func (s *Session) setPortalHeaders(req *http.Request, contentType string) {
	req.Header.Set("User-Agent", s.userAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("x-csrf-token", s.CSRFToken())
	req.Header.Set("x-sdp-rid", s.rid)
	req.Header.Set("x-sdp-traceid", s.randSdpId())
}
