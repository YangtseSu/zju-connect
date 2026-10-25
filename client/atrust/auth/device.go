package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/mythologyli/zju-connect/log"
)

// TerminalInfo is one row of the portal's 终端管理 lists. The portal returns
// the trusted endpoints and the temporary login history as two status lists;
// the fields are the ones its page renders.
type TerminalInfo struct {
	DevDBID          string   `json:"devDbId"`
	ID               string   `json:"id"`
	DeviceName       string   `json:"deviceName"`
	DeviceType       string   `json:"deviceType"`
	OS               string   `json:"os"`
	OSVersion        string   `json:"osVersion"`
	Browser          string   `json:"browser"`
	OnlineStatus     bool     `json:"onlineStatus"`
	LastLoginAddress string   `json:"lastLoginAddress"`
	LastLoginIP      string   `json:"lastLoginIp"`
	LastLoginTime    string   `json:"lastLoginTime"`
	NetworkZoneList  []string `json:"networkZoneList"`
}

// QueryDeviceResult is the portal answer for one status list.
type QueryDeviceResult struct {
	SelfID                  string         `json:"selfId"`
	DeviceTrusted           bool           `json:"deviceTrusted"`
	Data                    []TerminalInfo `json:"data"`
	CurrentTrustStatus      int            `json:"currentTrustStatus"`
	CurrentTrustDeviceCount int            `json:"currentTrustDeviceCount"`
	MaxDeviceCount          int            `json:"maxDeviceCount"`
	DeviceTrustedByOne      int            `json:"deviceTrustedByOne"`
	TrustDeviceConfig       struct {
		Limit int `json:"limit"`
	} `json:"trustDeviceConfig"`
}

// Terminals is both lists the portal's 终端管理 page shows.
type Terminals struct {
	Trusted                 []TerminalInfo
	Temporary               []TerminalInfo
	SelfID                  string
	DeviceTrusted           bool
	CurrentTrustStatus      int
	CurrentTrustDeviceCount int
	MaxDeviceCount          int
	DeviceTrustedByOne      int
}

// QueryDevice asks for the trusted list.
func (s *Session) QueryDevice() (*QueryDeviceResult, error) {
	return s.QueryDevices("trust")
}

// QueryDevices asks for one terminal list. status is "trust" or "untrust".
func (s *Session) QueryDevices(status string) (*QueryDeviceResult, error) {
	log.Printf("Perform GET /passport/v1/security/queryDevice status=%s", status)

	u := s.baseURL + "/passport/v1/security/queryDevice"
	params := WithSharedParams(url.Values{
		"status": {status},
	})
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received query device: %s", string(body))

	var re struct {
		Code    int               `json:"code"`
		Message string            `json:"message"`
		Data    QueryDeviceResult `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return nil, err
	}
	log.DebugPrintf("Parsed query device: %+v", re)

	if re.Code != 0 {
		log.Printf("queryDevice failed with code %d: %s", re.Code, re.Message)
		return nil, fmt.Errorf("queryDevice failed with code %d: %s", re.Code, re.Message)
	}

	return &re.Data, nil
}

// QueryTerminals loads the trusted and the temporary lists in one call.
func (s *Session) QueryTerminals() (*Terminals, error) {
	trusted, err := s.QueryDevices("trust")
	if err != nil {
		return nil, err
	}
	temporary, err := s.QueryDevices("untrust")
	if err != nil {
		return nil, err
	}
	return &Terminals{
		Trusted:                 trusted.Data,
		Temporary:               temporary.Data,
		SelfID:                  trusted.SelfID,
		DeviceTrusted:           trusted.DeviceTrusted,
		CurrentTrustStatus:      trusted.CurrentTrustStatus,
		CurrentTrustDeviceCount: trusted.CurrentTrustDeviceCount,
		MaxDeviceCount:          trusted.MaxDeviceCount,
		DeviceTrustedByOne:      trusted.DeviceTrustedByOne,
	}, nil
}

func (s *Session) TrustDevice(idList []string) error {
	log.Println("Perform POST /passport/v1/security/trustDevice")

	u := s.baseURL + "/passport/v1/security/trustDevice"
	payload := map[string]interface{}{
		"idList": idList,
	}
	bdy, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(bdy))
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received trust device: %s", string(body))

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}
	log.DebugPrintf("Parsed trust device: %+v", re)

	if re.Code != 0 {
		log.Printf("trustDevice failed with code %d: %s", re.Code, re.Message)
		return fmt.Errorf("trustDevice failed with code %d: %s", re.Code, re.Message)
	}

	return nil
}

func (s *Session) UntrustDevice(idList []string) error {
	log.Println("Perform POST /passport/v1/security/untrustDevice")

	u := s.baseURL + "/passport/v1/security/untrustDevice"
	payload := map[string]interface{}{
		"idList": idList,
	}
	bdy, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(bdy))
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received untrust device: %s", string(body))

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}
	log.DebugPrintf("Parsed untrust device: %+v", re)

	if re.Code != 0 {
		log.Printf("untrustDevice failed with code %d: %s", re.Code, re.Message)
		return fmt.Errorf("untrustDevice failed with code %d: %s", re.Code, re.Message)
	}

	return nil
}
