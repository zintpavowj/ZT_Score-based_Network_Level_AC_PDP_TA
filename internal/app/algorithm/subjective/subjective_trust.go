package subjective

var staticRiskProjectedProbability float32 = 0.59

// The function calculates the user trust score
func (a *SubjectiveAlgorithm) calculateUserTrustProjectedProbability() float32 {
	var opinions []OpinionT

	// Authentication patterns
	opinions = append(opinions, a.getUserPasswdAuthOpinion())
	opinions = append(opinions, a.getUserHWTokenAuthOpinion())
	opinions = append(opinions, a.getUserFaceIDAuthOpinion())

	// User enterprise presence
	opinions = append(opinions, a.getUserEnterpricePresenceOpinion())

	// Input behavior
	opinions = append(opinions, a.getUserUsualInputBehaviorOpinion())

	// User service usage
	opinions = append(opinions, a.getUserServiceUsageOpinion())

	// User device usage
	opinions = append(opinions, a.getUserDeviceUsageOpinion())

	// Access time
	opinions = append(opinions, a.getUserAccessTimeOpinion())

	// Access rate
	opinions = append(opinions, a.getUserUsualAccessRateOpinion())

	// User database update date
	opinions = append(opinions, a.getUserDatabaseUpdateOpinion())

	// // Add another N trust points if the calculated score is similar to the user trust history
	// opinions = append(opinions, a.getUserTrustHistoryOpinion(score))

	fusedOpinion := WeightedFusionOperator(opinions)
	// fmt.Printf("user fusedOpinion = %v\n", fusedOpinion)

	return fusedOpinion.b + fusedOpinion.u*fusedOpinion.a
}

// The function calculates the device trust score
func (a *SubjectiveAlgorithm) calculateDeviceTrustProjectedProbability() float32 {
	var opinions []OpinionT

	// Authentication patterns
	opinions = append(opinions, a.getDeviceCertAuthOpinion())
	opinions = append(opinions, a.getDeviceHWTokenAuthOpinion())

	// Connection security
	opinions = append(opinions, a.getDeviceConnectionSecurityOpinion())

	// Software patch level
	opinions = append(opinions, a.getDeviceSoftwarePatchLevelOpinion())

	// System patch level
	opinions = append(opinions, a.getDeviceSystemPatchLevelOpinion())

	//! ToDo: implement device fingerprint checking!!!
	// fmt.Printf("========== ToDo: implement device fingerprint checking!!!\n")

	// Device setup date
	opinions = append(opinions, a.getDeviceSetupDateOpinion())

	// Device IP history
	opinions = append(opinions, a.getDeviceLocationIPHistoryOpinion())

	// Health
	opinions = append(opinions, a.getDeviceHealthOpinion())

	// Device enterprise presence
	opinions = append(opinions, a.getDeviceEnterpricePresenceOpinion())

	// Device service usage
	opinions = append(opinions, a.getDeviceServiceUsageOpinion())

	// Device user usage
	opinions = append(opinions, a.getDeviceUserUsageOpinion())

	// Vulnerability scan
	opinions = append(opinions, a.getDeviceVulnerabilityScanOpinion())

	// Managed device
	opinions = append(opinions, a.getDeviceManageLevelOpinion())

	// Device database update date
	opinions = append(opinions, a.getDeviceDatabaseUpdateOpinion())

	// // Add another N trust points if the calculated score is similar to the device trust history
	// opinions = append(opinions, a.getDeviceTrustHistoryWeight(score))

	fusedOpinion := WeightedFusionOperator(opinions)
	// fmt.Printf("device fusedOpinion = %v\n", fusedOpinion)

	return fusedOpinion.b + fusedOpinion.u*fusedOpinion.a
}

// The function calculates the channel trust score
func (a *SubjectiveAlgorithm) calculateChannelTrustProjectedProbability() float32 {
	var opinions []OpinionT

	// Authentication
	opinions = append(opinions, a.getChannelAuthenticationOpinion())

	// Confidentiality
	opinions = append(opinions, a.getChannelConfidentialityOpinion())

	// Integrity
	opinions = append(opinions, a.getChannelIntegrityOpinion())

	fusedOpinion := WeightedFusionOperator(opinions)
	// fmt.Printf("channel fusedOpinion = %v\n", fusedOpinion)

	return fusedOpinion.b + fusedOpinion.u*fusedOpinion.a
}

// The function returns the static risk score
func (a *SubjectiveAlgorithm) getStaticRiskProjectedProbability() float32 {
	return staticRiskProjectedProbability
}

// The function calculates the dynamic risk score
func (a *SubjectiveAlgorithm) calculateDynamicRiskProjectedProbability() float32 {
	var opinions []OpinionT
	var fusedOpinion OpinionT

	// Request protocol
	opinions = append(opinions, a.getRiskRequestProtocolOpinion())

	// Request action
	opinions = append(opinions, a.getRiskRequestActionOpinion())

	// Data sensitivity
	opinions = append(opinions, a.getRiskDataSensitivityOpinion())

	// Service software patch level
	opinions = append(opinions, a.getRiskServiceSoftwarePatchOpinion())

	// System state
	opinions = append(opinions, a.getRiskSystemStateOpinion())

	// System patch level
	opinions = append(opinions, a.getRiskSystemPatchOpinion())

	// System threat level
	opinions = append(opinions, a.getRiskSystemThreatLevelOpinion())

	// System network state
	opinions = append(opinions, a.getRiskSystemNetworkStateOpinion())

	// System network threat level
	opinions = append(opinions, a.getRiskSystemNetworkThreatLevelOpinion())

	for _, opinion := range opinions {
		fusedOpinion = cumulativeFusionCase1(fusedOpinion, opinion)
	}

	return fusedOpinion.b + fusedOpinion.a*fusedOpinion.u
}

//
// USER
//

// The function returns an opinion about the user password authentication
func (a *SubjectiveAlgorithm) getUserPasswdAuthOpinion() OpinionT {

	var o OpinionT
	o.u = 0.2
	o.a = 0.5

	switch a.user.PasswordFailedAttempts {
	case 0:
		o.b = 0.6
	case 1:
		o.b = 0.5
	case 2:
		o.b = 0.4
	case 3:
		o.b = 0.3
	case 4:
		o.b = 0.2
	case 5:
		o.b = 0.15
	default:
		o.b = 0.1
	}

	return o
}

// The function returns an opinion about the user HW token authentication
func (a *SubjectiveAlgorithm) getUserHWTokenAuthOpinion() OpinionT {

	var o OpinionT

	o.b = 0.6
	o.u = 0.2
	o.a = 0.5

	return o
}

// The function returns an opinion about the user Face ID authentication
func (a *SubjectiveAlgorithm) getUserFaceIDAuthOpinion() OpinionT {

	var o OpinionT

	o.b = 0.8
	o.u = 0.1
	o.a = 0.5

	return o
}

// The function returns an opinion about the user Face ID authentication
func (a *SubjectiveAlgorithm) getUserEnterpricePresenceOpinion() OpinionT {

	var o OpinionT

	o.b = 0.4
	o.u = 0.3
	o.a = 0.5

	return o
}

// The function returns an opinion about the user Face ID authentication
func (a *SubjectiveAlgorithm) getUserUsualInputBehaviorOpinion() OpinionT {

	var o OpinionT

	o.b = 0.4
	o.u = 0.3
	o.a = 0.5

	return o
}

// The function returns an opinion about the user Face ID authentication
func (a *SubjectiveAlgorithm) getUserServiceUsageOpinion() OpinionT {

	var o OpinionT

	o.b = 0.4
	o.u = 0.3
	o.a = 0.5

	return o
}

// The function returns an opinion about the user Face ID authentication
func (a *SubjectiveAlgorithm) getUserDeviceUsageOpinion() OpinionT {

	var o OpinionT

	o.b = 0.4
	o.u = 0.3
	o.a = 0.5

	return o
}

// The function returns an opinion about the user Face ID authentication
func (a *SubjectiveAlgorithm) getUserAccessTimeOpinion() OpinionT {

	var o OpinionT

	o.b = 0.4
	o.u = 0.3
	o.a = 0.5

	return o
}

// The function returns an opinion about the user Face ID authentication
func (a *SubjectiveAlgorithm) getUserUsualAccessRateOpinion() OpinionT {

	var o OpinionT

	o.b = 0.4
	o.u = 0.3
	o.a = 0.5

	return o
}

// The function returns an opinion about the user Face ID authentication
func (a *SubjectiveAlgorithm) getUserDatabaseUpdateOpinion() OpinionT {

	var o OpinionT

	o.b = 0.4
	o.u = 0.3
	o.a = 0.5

	return o
}

// // The function returns an opinion about the user Face ID authentication
// func (a *SubjectiveAlgorithm) getUserTrustHistoryOpinion(ts float32) OpinionT {

// 	var o OpinionT

// 	o.b = 0.4
// 	o.u = 0.3
// 	o.a = 0.5

// 	return o
// }

//
// DEVICE
//

func (a *SubjectiveAlgorithm) getDeviceCertAuthOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceHWTokenAuthOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceConnectionSecurityOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceSoftwarePatchLevelOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceSystemPatchLevelOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceSetupDateOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceLocationIPHistoryOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceHealthOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceEnterpricePresenceOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceServiceUsageOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceUserUsageOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceVulnerabilityScanOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceManageLevelOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getDeviceDatabaseUpdateOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

//
// CHANNEL
//

func (a *SubjectiveAlgorithm) getChannelAuthenticationOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getChannelConfidentialityOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getChannelIntegrityOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

//
// RISK
//

func (a *SubjectiveAlgorithm) getRiskRequestProtocolOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getRiskRequestActionOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getRiskDataSensitivityOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getRiskServiceSoftwarePatchOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getRiskSystemStateOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getRiskSystemPatchOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getRiskSystemThreatLevelOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getRiskSystemNetworkStateOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}

func (a *SubjectiveAlgorithm) getRiskSystemNetworkThreatLevelOpinion() OpinionT {
	return OpinionT{b: 0.4, u: 0.2, a: 0.5}
}
