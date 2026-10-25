package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/mythologyli/zju-connect/log"
)

// DeviceBindChallenge is the portal's request to bind this installation to
// the account. A caller with no handler answers automatically, as the CLI
// always did.
type DeviceBindChallenge struct {
	DeviceID string
	AuthID   string
}

// DeviceBindHandler answers a device-binding request. A false answer aborts
// the login with ErrDeviceBindDeclined.
type DeviceBindHandler func(DeviceBindChallenge) (bool, error)

// ErrDeviceBindDeclined reports that the user refused the binding.
var ErrDeviceBindDeclined = errors.New("device binding declined")

var enhancedAuthServices = map[string]struct{}{
	"auth/preEnhancedAuth": {},
	"auth/enhancedConfirm": {},
	"auth/enhancedDone":    {},
}

func (s *Session) completeEnhancedAuth(step authStep) (authStep, error) {
	if _, ok := enhancedAuthServices[step.Service]; !ok {
		return authStep{}, fmt.Errorf("unsupported enhanced authentication service: %s", step.Service)
	}
	return s.requestAuthStep(http.MethodGet, step, nil)
}

func (s *Session) bindAuthDevice(step authStep) (authStep, error) {
	if s.deviceBindHandler != nil {
		allowed, err := s.deviceBindHandler(DeviceBindChallenge{DeviceID: s.deviceID, AuthID: step.AuthID})
		if err != nil {
			return authStep{}, err
		}
		if !allowed {
			return authStep{}, ErrDeviceBindDeclined
		}
	}
	payload := map[string]string{"deviceId": s.deviceID}
	if step.AuthID != "" {
		payload["authId"] = step.AuthID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return authStep{}, err
	}
	return s.requestAuthStep(http.MethodPost, step, body)
}

func (s *Session) requestAuthStep(method string, step authStep, body []byte) (authStep, error) {
	path := "/passport/v1/" + step.Service
	log.Printf("Perform %s %s", method, path)
	params := WithSharedParams(nil)
	if step.AuthID != "" {
		params.Set("authId", step.AuthID)
	}

	var requestBody io.Reader
	if body != nil {
		requestBody = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, s.baseURL+path+"?"+params.Encode(), requestBody)
	if err != nil {
		return authStep{}, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-env", s.env)
	req.Header.Set("x-sdp-traceid", s.randSdpId())
	if body != nil {
		req.Header.Set("Content-Type", "application/json;charset=utf-8")
	}

	resp, err := s.request(req)
	if err != nil {
		return authStep{}, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return authStep{}, err
	}
	log.DebugPrintf("Received %s: %s", step.Service, string(responseBody))

	var result tokenResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return authStep{}, err
	}
	if result.Code != 0 {
		return authStep{}, fmt.Errorf("%s failed with code %d: %s", step.Service, result.Code, result.Message)
	}
	return authStepFromData(result.Data), nil
}
