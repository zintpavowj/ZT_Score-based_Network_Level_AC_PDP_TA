package additive

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// The function gets information about the device
func (a *AdditiveAlgorithm) getDevice() error {
	var d pipDeviceT

	data, err := a.r.Run(fmt.Sprintf("/devices/%s", a.sc.Device.Name))
	if err != nil {
		return err
	}

	if data.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status code: %d", data.StatusCode)
	}

	err = json.NewDecoder(data.Body).Decode(&d)
	if err != nil {
		return err
	}
	a.device = d
	return nil
}

// The function gets information about the device trust history
func (a *AdditiveAlgorithm) getDeviceTrustHistory() error {
	var th []float32

	data, err := a.r.Run(fmt.Sprintf("/devices/%s/trusthistory", a.sc.Device.Name))
	if err != nil {
		return err
	}

	if data.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status code: %d", data.StatusCode)
	}

	err = json.NewDecoder(data.Body).Decode(&th)
	if err != nil {
		return err
	}

	a.deviceTrustHistory = th
	return nil
}

// The function gets information about the device IP history
func (a *AdditiveAlgorithm) getDeviceIPHistory() error {
	var history []string

	data, err := a.r.Run(fmt.Sprintf("/devices/%s/iphistory", a.sc.Device.Name))
	if err != nil {
		return err
	}

	if data.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status code: %d", data.StatusCode)
	}

	err = json.NewDecoder(data.Body).Decode(&history)
	if err != nil {
		return err
	}

	a.deviceIPHistory = history
	return nil
}

// The function gets information about the device service usage history
func (a *AdditiveAlgorithm) getDeviceServiceUsageHistory() error {
	var s []string

	data, err := a.r.Run(fmt.Sprintf("/devices/%s/serviceusage", a.sc.Device.Name))
	if err != nil {
		return err
	}

	if data.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status code: %d", data.StatusCode)
	}

	err = json.NewDecoder(data.Body).Decode(&s)
	if err != nil {
		return err
	}

	a.deviceServiceUsageHistory = s
	return nil
}

// The function gets information about the device user usage history
func (a *AdditiveAlgorithm) getDeviceUserUsageHistory() error {
	var s []string

	data, err := a.r.Run(fmt.Sprintf("/devices/%s/userusage", a.sc.Device.Name))
	if err != nil {
		return err
	}

	if data.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status code: %d", data.StatusCode)
	}

	err = json.NewDecoder(data.Body).Decode(&s)
	if err != nil {
		return err
	}

	a.deviceUserUsageHistory = s
	return nil
}

// The function gets a lst of authPatterns, used by the device before
func (a *AdditiveAlgorithm) getDeviceAuthPatternHistory() error {
	var h []string

	data, err := a.r.Run(fmt.Sprintf("/devices/%s/authpatterns", a.sc.Device.Name))
	if err != nil {
		return err
	}

	if data.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status code: %d", data.StatusCode)
	}

	err = json.NewDecoder(data.Body).Decode(&h)
	if err != nil {
		return err
	}
	a.deviceAuthPatternsHistory = h
	return nil
}
