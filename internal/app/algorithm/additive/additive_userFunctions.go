package additive

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// The function gets information about the user
func (a *AdditiveAlgorithm) getUser() error {
	var u pipUserT

	data, err := a.r.Run(fmt.Sprintf("/users/%s", a.sc.User.Name))
	if err != nil {
		return err
	}

	if data.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status code: %d", data.StatusCode)
	}

	err = json.NewDecoder(data.Body).Decode(&u)
	if err != nil {
		return err
	}
	a.user = u
	return nil
}

// The function gets information about the user trust history
func (a *AdditiveAlgorithm) getUserTrustHistory() error {
	var th []float32

	data, err := a.r.Run(fmt.Sprintf("/users/%s/trusthistory", a.sc.User.Name))
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

	a.userTrustHistory = th
	return nil
}

// The function gets information about the user service usage history
func (a *AdditiveAlgorithm) getUserServiceUsageHistory() error {
	var s []string

	data, err := a.r.Run(fmt.Sprintf("/users/%s/serviceusage", a.sc.User.Name))
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

	a.userServiceUsageHistory = s
	return nil
}

// The function gets information about the user access rate history
func (a *AdditiveAlgorithm) getUserAccessRateHistory() error {
	var s []float32

	data, err := a.r.Run(fmt.Sprintf("/users/%s/accessratehistory", a.sc.User.Name))
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

	a.userAccessRateHistory = s
	return nil
}

// The function gets information about the user input behavior history
func (a *AdditiveAlgorithm) getUserInputBehaviorHistory() error {
	var s []float32

	data, err := a.r.Run(fmt.Sprintf("/users/%s/inputbehavior", a.sc.User.Name))
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

	a.userInputBevhaviorHistory = s
	return nil
}

// The function gets information about the user device usage history
func (a *AdditiveAlgorithm) getUserDeviceUsageHistory() error {
	var s []string

	data, err := a.r.Run(fmt.Sprintf("/users/%s/deviceusage", a.sc.User.Name))
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

	a.userDeviceUsageHistory = s
	return nil
}

// The function gets a lst of authPatterns, used by the user before
func (a *AdditiveAlgorithm) getUserAuthPatternHistory() error {
	var h []string

	data, err := a.r.Run(fmt.Sprintf("/users/%s/authpatterns", a.sc.User.Name))
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
	a.userAuthPatternsHistory = h
	return nil
}
