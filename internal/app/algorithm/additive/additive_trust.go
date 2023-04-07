package additive

import (
	"time"

	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/floatlib"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/stringslib"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/timelib"
)

var staticRiskScore float32 = 34.0

// The function initializes the trust attributes weights
func (a *AdditiveAlgorithm) updateTrustWeights() error {

	// USER
	a.trustWeights["user_passw_auth"] = 3.5
	a.trustWeights["user_hwtoken_auth"] = 6.5
	a.trustWeights["user_faceid_auth"] = 8.0

	a.trustWeights["user_input_behavior"] = 3.0
	a.trustWeights["user_access_rate"] = 5.0

	a.trustWeights["user_service_usage"] = 3.0
	a.trustWeights["user_device_usage"] = 5.0
	a.trustWeights["user_auth_patterns"] = 2.0
	a.trustWeights["user_enterprise_presence_time"] = 3.0
	a.trustWeights["user_enterprise_presence_expected"] = 2.0
	a.trustWeights["user_access_time"] = 5.0
	a.trustWeights["user_database_update_date"] = 3.0
	a.trustWeights["user_trust_history"] = 5.0

	// DEVICE
	a.trustWeights["device_cert_auth"] = 8.0
	a.trustWeights["device_hwtoken_auth"] = 10.0

	a.device_connection_security["tls"] = 5.0

	a.trustWeights["device_software_patch_level"] = 2.0
	a.trustWeights["device_system_patch_level"] = 3.0
	a.trustWeights["device_fingerprint"] = 10.0
	a.trustWeights["device_setup_date"] = 3.0
	a.trustWeights["device_location_ip"] = 3.0
	a.trustWeights["device_health"] = 7.0
	a.device_vulnerability_scan[1] = 5.0
	a.device_vulnerability_scan[2] = 3.0
	a.device_vulnerability_scan[3] = 0.0

	a.device_management_levels[1] = 10.0
	a.device_management_levels[2] = 8.0
	a.device_management_levels[3] = 8.0
	a.device_management_levels[4] = 8.0
	a.device_management_levels[5] = 8.0
	a.device_management_levels[6] = 6.0
	a.device_management_levels[7] = 6.0
	a.device_management_levels[8] = 6.0
	a.device_management_levels[9] = 2.0
	a.device_management_levels[10] = 1.0

	a.trustWeights["device_enterprise_presence_time"] = 3.0
	a.trustWeights["device_enterprise_presence_expected"] = 2.0
	a.trustWeights["device_trust_history"] = 5.0
	a.trustWeights["device_service_usage"] = 10.0
	a.trustWeights["device_user_usage"] = 10.0
	a.trustWeights["device_database_update_date"] = 10.0

	// CHANNEL
	a.channel_authentication["SHA256-RSA"] = 5.0
	a.channel_authentication["SHA128-RSA"] = 3.0

	a.channel_confidentiality["AES"] = 5.0
	a.channel_confidentiality["DES"] = 3.0

	a.channel_integrity["SHA256-RSA"] = 5.0
	a.channel_integrity["SHA128-RSA"] = 2.0

	return nil
}

// The function initializes the risk attributes weights
func (a *AdditiveAlgorithm) updateRiskWeights() error {

	// RISK
	a.request_protocol["HTTPS"] = 3.0
	a.request_protocol["HTTP"] = 15.0
	a.request_protocol["FTPS"] = 5.0
	a.request_protocol["SSH"] = 8.0
	a.request_protocol["WS"] = 5.0

	a.request_action["GET"] = 6.0
	a.request_action["POST"] = 10.0
	a.request_action["PUT"] = 10.0
	a.request_action["DELETE"] = 15.0

	a.risk_data_sensitivity[1] = 2.0
	a.risk_data_sensitivity[1] = 3.0
	a.risk_data_sensitivity[2] = 4.0
	a.risk_data_sensitivity[3] = 4.0
	a.risk_data_sensitivity[4] = 4.5
	a.risk_data_sensitivity[5] = 7.0
	a.risk_data_sensitivity[6] = 9.0
	a.risk_data_sensitivity[7] = 9.0
	a.risk_data_sensitivity[8] = 10.0
	a.risk_data_sensitivity[9] = 14.0
	a.risk_data_sensitivity[10] = 20.0

	a.risk_service_software_patch_levels["up-to-date"] = 3.0
	a.risk_service_software_patch_levels["outdated"] = 8.0

	a.risk_system_states["operational"] = 3.0
	a.risk_system_states["maintenance"] = 10.0

	a.risk_system_patch_levels["outdated"] = 15.0
	a.risk_system_patch_levels["patched"] = 5.0

	a.risk_system_network_states["operational"] = 3.0
	a.risk_system_network_states["maintenance"] = 7.0

	a.risk_system_threat_levels[1] = 2.0
	a.risk_system_threat_levels[2] = 3.0
	a.risk_system_threat_levels[3] = 4.0
	a.risk_system_threat_levels[4] = 5.0
	a.risk_system_threat_levels[5] = 7.0
	a.risk_system_threat_levels[6] = 9.0
	a.risk_system_threat_levels[7] = 12.0
	a.risk_system_threat_levels[8] = 15.0
	a.risk_system_threat_levels[9] = 20.0
	a.risk_system_threat_levels[10] = 25.0

	a.risk_system_network_threat_levels[1] = 2.0
	a.risk_system_network_threat_levels[2] = 3.0
	a.risk_system_network_threat_levels[3] = 4.0
	a.risk_system_network_threat_levels[4] = 5.0
	a.risk_system_network_threat_levels[5] = 7.0
	a.risk_system_network_threat_levels[6] = 9.0
	a.risk_system_network_threat_levels[7] = 12.0
	a.risk_system_network_threat_levels[8] = 15.0
	a.risk_system_network_threat_levels[9] = 20.0
	a.risk_system_network_threat_levels[10] = 25.0

	return nil
}

// The function calculates the user trust score
func (a *AdditiveAlgorithm) calculateUserTrustScore() float32 {
	var score float32

	// Authentication patterns
	score += a.getUserPasswdAuthWeight()
	score += a.getUserHWTokenAuthWeight()
	score += a.getUserFaceIDAuthWeight()

	// User enterprise presence
	score += a.getUserEnterpricePresenceWeight()

	// Input behavior
	score += a.getUserUsualInputBehaviorWeight()

	// User service usage
	score += a.getUserServiceUsageWeight()

	// User device usage
	score += a.getUserDeviceUsageWeight()

	// Access time
	score += a.getUserAccessTimeWeight()

	// Access rate
	score += a.getUserUsualAccessRateWeight()

	// User database update date
	score += a.getUserDatabaseUpdateWeight()

	// Add another N trust points if the calculated score is similar to the user trust history
	score += a.getUserTrustHistoryWeight(score)

	return score
}

// The function calculates the device trust score
func (a *AdditiveAlgorithm) calculateDeviceTrustScore() float32 {
	var score float32

	// Authentication patterns
	score += a.getDeviceCertAuthWeight()
	score += a.getDeviceHWTokenAuthWeight()

	// Connection security
	score += a.getDeviceConnectionSecurityWeight()

	// Software patch level
	score += a.getDeviceSoftwarePatchLevelWeight()

	// System patch level
	score += a.getDeviceSystemPatchLevelWeight()

	//! ToDo: implement device fingerprint checking!!!
	//fmt.Printf("========== ToDo: implement device fingerprint checking!!!\n")

	// Device setup date
	score += a.getDeviceSetupDateWeight()

	// Device IP history
	score += a.getDeviceLocationIPHistoryWeight()

	// Health
	score += a.getDeviceHealthWeight()

	// Device enterprise presence
	score += a.getDeviceEnterpricePresenceWeight()

	// Device service usage
	score += a.getDeviceServiceUsageWeight()

	// Device user usage
	score += a.getDeviceUserUsageWeight()

	// Vulnerability scan
	score += a.getDeviceVulnerabilityScanWeight()

	// Managed device
	score += a.getDeviceManageLevelWeight()

	// Device database update date
	score += a.getDeviceDatabaseUpdateWeight()

	// Add another N trust points if the calculated score is similar to the device trust history
	score += a.getDeviceTrustHistoryWeight(score)

	return score
}

// The function calculates the channel trust score
func (a *AdditiveAlgorithm) calculateChannelTrustScore() float32 {
	var score float32

	// Authentication
	score += a.getChannelAuthenticationWeight()

	// Confidentiality
	score += a.getChannelConfidentialityWeight()

	// Integrity
	score += a.getChannelIntegrityWeight()

	return score
}

// The function returns the static risk score
func (a *AdditiveAlgorithm) getStaticRiskScore() float32 {
	return staticRiskScore
}

// The function calculates the dynamic risk score
func (a *AdditiveAlgorithm) calculateDynamicRiskScore() float32 {
	var score float32

	// Request protocol
	score += a.getRiskRequestProtocolWeight()

	// Request action
	score += a.getRiskRequestActionWeight()

	// Data sensitivity
	score += a.getRiskDataSensitivityWeight()

	// Service software patch level
	score += a.getRiskServiceSoftwarePatchWeight()

	// System state
	score += a.getRiskSystemStateWeight()

	// System patch level
	score += a.getRiskSystemPatchWeight()

	// System threat level
	score += a.getRiskSystemThreatLevelWeight()

	// System network state
	score += a.getRiskSystemNetworkStateWeight()

	// System network threat level
	score += a.getRiskSystemNetworkThreatLevelWeight()

	return score
}

//
// USER
//

// The function returns a weight of the user password authentication
func (a *AdditiveAlgorithm) getUserPasswdAuthWeight() float32 {

	// If a user used password authentication and he used it before
	if a.sc.User.PasswAuth && stringslib.StringInSlice("PasswAuth", a.userAuthPatternsHistory) {
		return a.trustWeights["user_passw_auth"]
	}
	return 0.0
}

// The function returns a weight of the user hardware token authentication
func (a *AdditiveAlgorithm) getUserHWTokenAuthWeight() float32 {

	// If a user used hardware token authentication and he used it before
	if a.sc.User.HWTokenAuth && stringslib.StringInSlice("HWTokenAuth", a.userAuthPatternsHistory) {
		return a.trustWeights["user_hwtoken_auth"]
	}
	return 0.0
}

// The function returns a weight of the user hardware token authentication
func (a *AdditiveAlgorithm) getUserFaceIDAuthWeight() float32 {

	// If a user used FaceID authentication and he used it before
	if a.sc.User.FaceIDAuth && stringslib.StringInSlice("FaceIDAuth", a.userAuthPatternsHistory) {
		return a.trustWeights["user_faceid_auth"]
	}
	return 0.0
}

// The function returns a trust weight for usual user input behavior
func (a *AdditiveAlgorithm) getUserUsualInputBehaviorWeight() float32 {

	// Get the lowest and the highest input behavior values
	mn, mx, err := floatlib.MinMax(a.userInputBevhaviorHistory)
	if err != nil {
		return 0.0
	}

	// If the current input behavior is in the range min <= current <= max, add the trust score
	if (a.sc.User.InputBehavior <= mx) && (a.sc.User.InputBehavior >= mn) {
		return a.trustWeights["user_input_behavior"]
	}
	return 0.0
}

// The function returns a trust weight for usual user devices usage
func (a *AdditiveAlgorithm) getUserServiceUsageWeight() float32 {

	if stringslib.StringInSlice(a.sc.Service, a.userServiceUsageHistory) {
		return a.trustWeights["user_service_usage"]
	}

	return 0.0
}

// The function returns a trust weight for usual user devices usage
func (a *AdditiveAlgorithm) getUserDeviceUsageWeight() float32 {

	if stringslib.StringInSlice(a.sc.Device.Name, a.userDeviceUsageHistory) {
		return a.trustWeights["user_device_usage"]
	}

	return 0.0
}

// The function returns a trust weight for usual user access time
func (a *AdditiveAlgorithm) getUserAccessTimeWeight() float32 {

	currentAccessTime := timelib.GetTimeOfDay(a.sc.AccessTime)

	// The min usual acces time is greated then the max.
	// It means, the user works at night and the usual access time includes the midnight.
	if a.user.AccessTimeMin.After(a.user.AccessTimeMax) {

		// 00:00 ++++++++++ a.user.AccessTimeMax ---------- a.user.AccessTimeMin ++++++++++ 23:59
		if currentAccessTime.Before(a.user.AccessTimeMax) || currentAccessTime.After(a.user.AccessTimeMin) {
			return a.trustWeights["user_access_time"]
		}

		return 0.0
	}

	// 00:00 ---------- a.user.AccessTimeMin ++++++++++ a.user.AccessTimeMax ---------- 23:59
	if currentAccessTime.After(a.user.AccessTimeMin) && currentAccessTime.Before(a.user.AccessTimeMax) {
		return a.trustWeights["user_access_time"]
	}

	return 0.0
}

// The function returns a trust weight for usual user access rate
func (a *AdditiveAlgorithm) getUserUsualAccessRateWeight() float32 {

	// Get the lowest and the highest access rate values
	mn, mx, err := floatlib.MinMax(a.userAccessRateHistory)
	if err != nil {
		return 0.0
	}

	// If the current access rate is in the range min <= current <= max, add the trust score
	if (a.sc.User.AccessRate <= mx) && (a.sc.User.AccessRate >= mn) {
		return a.trustWeights["user_access_rate"]
	}
	return 0.0
}

// The function returns the trust score values for the user enterprice presence attributes
func (a *AdditiveAlgorithm) getUserEnterpricePresenceWeight() float32 {
	var score float32 = 0

	// Find, when the user was online
	hoursOfAbsence := time.Since(a.user.LastAccessTime).Hours()
	if hoursOfAbsence <= 24*7 {
		score += a.trustWeights["user_enterprise_presence_time"]
	}

	// Add the score if the user is expected to request the service
	if a.user.Expected >= 0.5 {
		score += a.trustWeights["user_enterprise_presence_expected"]
	}
	return score
}

// The function returns a trust weight for latest user update time in the database
func (a *AdditiveAlgorithm) getUserDatabaseUpdateWeight() float32 {

	// If the latest database update was not earlier then a weeek ago
	if time.Since(a.user.DatabaseUpdateTime).Hours() <= 24*7 {
		return a.trustWeights["user_database_update_date"]
	}

	return 0.0
}

// The function returns a trust weight for usual user trust history values
func (a *AdditiveAlgorithm) getUserTrustHistoryWeight(currentTrust float32) float32 {

	// Get the lowest and the highest input behavior values
	mn, mx, err := floatlib.MinMax(a.userTrustHistory)
	if err != nil {
		return 0.0
	}

	// If the current trust value is in the range min <= current <= max, add the trust score
	if (currentTrust <= mx) && (currentTrust >= mn) {
		return a.trustWeights["user_trust_history"]
	}
	return 0.0
}

//
// DEVICE
//

// The function returns a weight of the device password authentication
func (a *AdditiveAlgorithm) getDeviceCertAuthWeight() float32 {

	// If the device used certificate authentication and it used it before
	if a.sc.Device.CertAuth && stringslib.StringInSlice("CertAuth", a.deviceAuthPatternsHistory) {
		return a.trustWeights["device_cert_auth"]
	}
	return 0.0
}

// The function returns a weight of the device hardware token authentication
func (a *AdditiveAlgorithm) getDeviceHWTokenAuthWeight() float32 {

	// If the device used hardware token authentication and it used it before
	if a.sc.Device.HWTokenAuth && stringslib.StringInSlice("HWTokenAuth", a.deviceAuthPatternsHistory) {
		return a.trustWeights["device_hwtoken_auth"]
	}
	return 0.0
}

// The function returns a weight for the used device connection security
func (a *AdditiveAlgorithm) getDeviceConnectionSecurityWeight() float32 {

	score, ok := a.device_connection_security[a.sc.Device.ConnectionSecurity]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a weight for the current device software patch level
func (a *AdditiveAlgorithm) getDeviceSoftwarePatchLevelWeight() float32 {

	if a.sc.Device.SoftwarePatchLevel == "up-to-date" {
		return a.trustWeights["device_software_patch_level"]
	}

	return 0.0
}

// The function returns a weight for the current device system patch level
func (a *AdditiveAlgorithm) getDeviceSystemPatchLevelWeight() float32 {

	if a.sc.Device.SystemPatchLevel == "up-to-date" {
		return a.trustWeights["device_system_patch_level"]
	}

	return 0.0
}

// The function returns a weight for the device setup date
func (a *AdditiveAlgorithm) getDeviceSetupDateWeight() float32 {

	// Check if there are not more than 365 days since the system setup date
	if time.Since(a.sc.Device.SetupDate).Hours() <= 365*24*7 {
		return a.trustWeights["device_setup_date"]
	}

	return 0.0
}

// The function returns a weight for the device location IP history
func (a *AdditiveAlgorithm) getDeviceLocationIPHistoryWeight() float32 {

	// Check if the current IP is in the history DB
	if stringslib.StringInSlice(a.sc.RemoteAddr, a.deviceIPHistory) {
		return a.trustWeights["device_location_ip"]
	}
	return 0.0
}

// The function returns a trust value for the given device health state
func (a *AdditiveAlgorithm) getDeviceHealthWeight() float32 {

	// if CPU, RAM and network load are less then 75%, then give the trust score
	if (a.sc.Device.Health.Cpu < 0.75) && (a.sc.Device.Health.Ram < 0.75) && (a.sc.Device.Health.Network < 0.75) {
		return a.trustWeights["device_health"]
	}

	return 0.0
}

// The function returns the trust score values for the device enterprice presence attributes
func (a *AdditiveAlgorithm) getDeviceEnterpricePresenceWeight() float32 {
	var score float32 = 0

	// Find, when the device was online
	hoursOfAbsence := time.Since(a.device.LastAccessTime).Hours()
	if hoursOfAbsence <= 24*7 {
		score += a.trustWeights["device_enterprise_presence_time"]
	}

	// Add the score if the device is expected to request the service
	if a.device.Expected >= 0.5 {
		score += a.trustWeights["device_enterprise_presence_expected"]
	}

	return score
}

// The function returns a trust weight for usual device services usage
func (a *AdditiveAlgorithm) getDeviceServiceUsageWeight() float32 {

	if stringslib.StringInSlice(a.sc.Service, a.deviceServiceUsageHistory) {
		return a.trustWeights["device_service_usage"]
	}

	return 0.0
}

// The function returns a trust weight for usual device users usage
func (a *AdditiveAlgorithm) getDeviceUserUsageWeight() float32 {

	if stringslib.StringInSlice(a.sc.User.Name, a.deviceUserUsageHistory) {
		return a.trustWeights["device_user_usage"]
	}

	return 0.0
}

// The function returns a trust weight for the device last vulnerability scan results
func (a *AdditiveAlgorithm) getDeviceVulnerabilityScanWeight() float32 {

	score, ok := a.device_vulnerability_scan[a.sc.Device.VulnerabilityScan]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a trust weight depending on the device management level
func (a *AdditiveAlgorithm) getDeviceManageLevelWeight() float32 {

	score, ok := a.device_management_levels[a.sc.Device.ManagedDevice]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a trust weight for latest device update time in the database
func (a *AdditiveAlgorithm) getDeviceDatabaseUpdateWeight() float32 {

	// If the latest database update was not earlier then a weeek ago
	if time.Since(a.device.DatabaseUpdateTime).Hours() <= 24*7 {
		return a.trustWeights["device_database_update_date"]
	}

	return 0.0
}

// The function returns a trust weight for usual device trust history values
func (a *AdditiveAlgorithm) getDeviceTrustHistoryWeight(currentTrust float32) float32 {

	// Get the lowest and the highest input behavior values
	mn, mx, err := floatlib.MinMax(a.deviceTrustHistory)
	if err != nil {
		return 0.0
	}

	// If the current trust value is in the range min <= current <= max, add the trust score
	if (currentTrust <= mx) && (currentTrust >= mn) {
		return a.trustWeights["device_trust_history"]
	}

	return 0.0
}

//
// CHANNEL
//

// The function returns a trust weight for the channel authentication
func (a *AdditiveAlgorithm) getChannelAuthenticationWeight() float32 {

	score, ok := a.channel_authentication[a.sc.Channel.Authentication]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a trust weight for the channel confidentiality
func (a *AdditiveAlgorithm) getChannelConfidentialityWeight() float32 {

	score, ok := a.channel_confidentiality[a.sc.Channel.Confidentiality]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a trust weight for the channel integrity
func (a *AdditiveAlgorithm) getChannelIntegrityWeight() float32 {

	score, ok := a.channel_integrity[a.sc.Channel.Integrity]
	if ok {
		return score
	}

	return 0.0
}

//
// RISK
//

// The function returns a risk weight for the request protocol
func (a *AdditiveAlgorithm) getRiskRequestProtocolWeight() float32 {

	score, ok := a.request_protocol[a.sc.Protocol]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a risk weight for the request action
func (a *AdditiveAlgorithm) getRiskRequestActionWeight() float32 {

	score, ok := a.request_action[a.sc.Action]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a risk weight for the request service sensitivity
func (a *AdditiveAlgorithm) getRiskDataSensitivityWeight() float32 {

	score, ok := a.risk_data_sensitivity[a.service.DataSensitivity]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a risk weight for the request service software patch level
func (a *AdditiveAlgorithm) getRiskServiceSoftwarePatchWeight() float32 {

	score, ok := a.risk_service_software_patch_levels[a.service.SoftwarePatchLevel]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a risk weight for the current system state
func (a *AdditiveAlgorithm) getRiskSystemStateWeight() float32 {

	score, ok := a.risk_system_states[a.system.State]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a risk weight for the system patch level
func (a *AdditiveAlgorithm) getRiskSystemPatchWeight() float32 {

	score, ok := a.risk_system_patch_levels[a.system.PatchLevel]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a risk weight for the system threat level
func (a *AdditiveAlgorithm) getRiskSystemThreatLevelWeight() float32 {

	score, ok := a.risk_system_network_threat_levels[a.system.NetworkThreatLevel]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a risk weight for the system network state
func (a *AdditiveAlgorithm) getRiskSystemNetworkStateWeight() float32 {

	score, ok := a.risk_system_network_states[a.system.NetworkState]
	if ok {
		return score
	}

	return 0.0
}

// The function returns a risk weight for the system network threat level
func (a *AdditiveAlgorithm) getRiskSystemNetworkThreatLevelWeight() float32 {

	score, ok := a.risk_system_network_threat_levels[a.system.NetworkThreatLevel]
	if ok {
		return score
	}

	return 0.0
}
