package subjective

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// The function gets information about the current system state for the trust calculation algorithms
func (a *SubjectiveAlgorithm) getSystemState() error {
	s := pipSystemStateT{}

	data, err := a.r.Run("/system")
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
	a.system = s
	return nil
}

// The function gets information about the service
func (a *SubjectiveAlgorithm) getService() error {
	s := pipServiceT{}

	data, err := a.r.Run(fmt.Sprintf("/services/%s", a.sc.Service))
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
	a.service = s
	return nil
}
