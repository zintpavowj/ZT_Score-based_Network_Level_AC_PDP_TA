package additive

import (
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/requester"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/scenario"
)

type pipSystemStateT struct {
	State              string `json:"state"`
	PatchLevel         string `json:"patch_level"`
	ThreatLevel        int    `json:"threat_level"`
	NetworkState       string `json:"network_state"`
	NetworkThreatLevel int    `json:"network_threat_level"`
}

type pipUserT struct {
	Name               string    `json:"name"`
	Email              string    `json:"email"`
	LastAccessTime     time.Time `json:"last_access_time"`
	Expected           float32   `json:"expected"`
	AccessTimeMin      time.Time `json:"access_time_min"`
	AccessTimeMax      time.Time `json:"access_time_max"`
	DatabaseUpdateTime time.Time `json:"database_update_time"`
}

type pipDeviceT struct {
	Name               string    `json:"name"`
	CertCN             string    `json:"cert_cn"`
	LastAccessTime     time.Time `json:"last_access_time"`
	Expected           float32   `json:"expected"`
	DatabaseUpdateTime time.Time `json:"database_update_time"`
}

type pipServiceT struct {
	Name               string `json:"name"`
	SNI                string `json:"sni"`
	DataSensitivity    int    `json:"data_sensitivity"`
	SoftwarePatchLevel string `json:"software_patch_level"`
}

type AdditiveAlgorithm struct {
	sc                                 *scenario.Scenario
	r                                  *requester.Requester
	logger                             *logrus.Logger
	system                             pipSystemStateT
	user                               pipUserT
	thresholdType                      string
	userAuthPatternsHistory            []string
	userTrustHistory                   []float32
	userAccessRateHistory              []float32
	userInputBevhaviorHistory          []float32
	userServiceUsageHistory            []string
	userDeviceUsageHistory             []string
	device                             pipDeviceT
	deviceAuthPatternsHistory          []string
	deviceTrustHistory                 []float32
	deviceIPHistory                    []string
	deviceServiceUsageHistory          []string
	deviceUserUsageHistory             []string
	device_vulnerability_scan          map[int]float32
	device_management_levels           map[int]float32
	service                            pipServiceT
	trustWeights                       TrustWeightsT
	riskWeights                        RiskWeightsT
	device_connection_security         map[string]float32
	channel_authentication             map[string]float32
	channel_confidentiality            map[string]float32
	channel_integrity                  map[string]float32
	request_action                     map[string]float32
	request_protocol                   map[string]float32
	risk_data_sensitivity              map[int]float32
	risk_service_software_patch_levels map[string]float32
	risk_system_states                 map[string]float32
	risk_system_patch_levels           map[string]float32
	risk_system_threat_levels          map[int]float32
	risk_system_network_states         map[string]float32
	risk_system_network_threat_levels  map[int]float32
}

func New(sc *scenario.Scenario, r *requester.Requester, threshold string, logger *logrus.Logger) *AdditiveAlgorithm {
	return &AdditiveAlgorithm{
		sc:                                 sc,
		r:                                  r,
		logger:                             logger,
		thresholdType:                      threshold,
		trustWeights:                       make(TrustWeightsT),
		riskWeights:                        make(RiskWeightsT),
		device_connection_security:         make(map[string]float32),
		device_vulnerability_scan:          make(map[int]float32),
		device_management_levels:           make(map[int]float32),
		channel_authentication:             make(map[string]float32),
		channel_confidentiality:            make(map[string]float32),
		channel_integrity:                  make(map[string]float32),
		request_action:                     make(map[string]float32),
		request_protocol:                   make(map[string]float32),
		risk_data_sensitivity:              make(map[int]float32),
		risk_service_software_patch_levels: make(map[string]float32),
		risk_system_states:                 make(map[string]float32),
		risk_system_patch_levels:           make(map[string]float32),
		risk_system_threat_levels:          make(map[int]float32),
		risk_system_network_states:         make(map[string]float32),
		risk_system_network_threat_levels:  make(map[int]float32),
	}
}

type TrustWeightsT map[string]float32
type RiskWeightsT map[string]float32

func (a *AdditiveAlgorithm) Run() (bool, []string, error) {
	var riskScore float32
	output := make([]string, 0)

	if err := a.updateTrustWeights(); err != nil {
		return false, []string{}, err
	}

	// Calculate user trust score
	userTrustScore := a.calculateUserTrustScore()
	// fmt.Printf("userTrustScore = %f\n", userTrustScore)
	output = append(output, fmt.Sprintf("userTrustScore = %f", userTrustScore))

	// Calculate device trust score
	deviceTrustScore := a.calculateDeviceTrustScore()
	// fmt.Printf("deviceTrustScore = %f\n", deviceTrustScore)
	output = append(output, fmt.Sprintf("deviceTrustScore = %f", deviceTrustScore))

	// Calculate channel trust score
	channelTrustScore := a.calculateChannelTrustScore()
	// fmt.Printf("channelTrustScore = %f\n", channelTrustScore)
	output = append(output, fmt.Sprintf("channelTrustScore = %f", channelTrustScore))

	// Calculate risk score
	switch a.thresholdType {

	case "static":
		riskScore = a.getStaticRiskScore()
		output = append(output, fmt.Sprintf("static riskScore = %f", riskScore))
		// fmt.Printf("static riskScore = %f\n", riskScore)

	case "dynamic":
		if err := a.updateRiskWeights(); err != nil {
			return false, []string{}, err
		}
		riskScore = a.calculateDynamicRiskScore()
		output = append(output, fmt.Sprintf("dynamic riskScore = %f", riskScore))
		// fmt.Printf("dynamic riskScore = %f\n", riskScore)

	default:
		return false, []string{}, errors.New("unknown type of risk calculation")
	}

	return userTrustScore+deviceTrustScore+channelTrustScore >= riskScore, output, nil
}

func (a *AdditiveAlgorithm) EnrichData() error {
	var err error

	//
	// SERVICE
	//

	// Get service info
	err = a.getService()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getService",
		}).Error(err)

		return err
	}
	// fmt.Printf("service = %#v\n", a.service)

	//
	// USER
	//

	// Get user info
	err = a.getUser()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getUser",
		}).Error(err)

		return err
	}
	// fmt.Printf("user = %v\n", a.user)

	// Get user trust history
	err = a.getUserTrustHistory()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getUserTrustHistory",
		}).Error(err)

		return err
	}
	// fmt.Printf("userTrustHistory = %v\n", a.userTrustHistory)

	// Get user service usage
	err = a.getUserServiceUsageHistory()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getUserServiceUsageHistory",
		}).Error(err)

		return err
	}
	// fmt.Printf("userServiceUsageHistory = %v\n", a.userServiceUsageHistory)

	// Get user device usage
	err = a.getUserDeviceUsageHistory()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getUserDeviceUsageHistory",
		}).Error(err)

		return err
	}
	// fmt.Printf("userDeviceUsageHistory = %v\n", a.userDeviceUsageHistory)

	// Get user access rate history
	err = a.getUserAccessRateHistory()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getUserAccessRateHistory",
		}).Error(err)

		return err
	}
	// fmt.Printf("userAccessRateHistory = %v\n", a.userAccessRateHistory)

	// Get user device usage
	err = a.getUserInputBehaviorHistory()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getUserInputBehaviorHistory",
		}).Error(err)

		return err
	}
	// fmt.Printf("userInputBevhaviorHistory = %v\n", a.userInputBevhaviorHistory)

	// User Authentication patterns history
	err = a.getUserAuthPatternHistory()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getUserAuthPatternHistory",
		}).Error(err)

		return err
	}
	// fmt.Printf("userAuthPatternsHistory = %v\n", a.userAuthPatternsHistory)

	//
	// DEVICE
	//

	// Get device info
	err = a.getDevice()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getDevice",
		}).Error(err)

		return err
	}
	// fmt.Printf("device = %v\n", a.device)

	// Device Authentication patterns history
	err = a.getDeviceAuthPatternHistory()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getDeviceAuthPatternHistory",
		}).Error(err)

		return err
	}
	// fmt.Printf("deviceAuthPatternsHistory = %v\n", a.deviceAuthPatternsHistory)

	// Get device trust history
	err = a.getDeviceTrustHistory()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getDeviceTrustHistory",
		}).Error(err)

		return err
	}
	// fmt.Printf("deviceTrustHistory = %v\n", a.deviceTrustHistory)

	// Get device trust history
	err = a.getDeviceIPHistory()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getDeviceIPHistory",
		}).Error(err)

		return err
	}
	// fmt.Printf("deviceIPHistory = %v\n", a.deviceIPHistory)

	// Get device service usage
	err = a.getDeviceServiceUsageHistory()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getDeviceServiceUsageHistory",
		}).Error(err)

		return err
	}
	// fmt.Printf("deviceServiceUsageHistory = %v\n", a.deviceServiceUsageHistory)

	// Get device user usage
	err = a.getDeviceUserUsageHistory()
	if err != nil {

		a.logger.WithFields(logrus.Fields{
			"package":  "additive",
			"function": "getDeviceUserUsageHistory",
		}).Error(err)

		return err
	}
	// fmt.Printf("deviceUserUsageHistory = %v\n", a.deviceUserUsageHistory)

	//
	// SYSTEM
	//

	if a.thresholdType == "dynamic" {
		// System state
		err = a.getSystemState()
		if err != nil {

			a.logger.WithFields(logrus.Fields{
				"package":  "additive",
				"function": "getSystemState",
			}).Error(err)

			return err
		}
		// fmt.Printf("systemState = %v\n", a.system)
	}

	return nil
}
