package subjective

func WeightedFusionOperator(opinions []OpinionT) OpinionT {
	caseNum := 3
	numAgents := len(opinions)
	for i := 0; i < numAgents; i++ {
		if opinions[i].u == 0.0 {
			caseNum = 2
			break
		} else if opinions[i].u < 1.0 {
			caseNum = 1
		}
	}

	switch caseNum {
	case 1:
		return weightedFusionCase1(opinions)
	case 2:
		return weightedFusionCase2(opinions)
	case 3:
		return weightedFusionCase3(opinions)
	}
	return OpinionT{}
}

func weightedFusionCase1(opinions []OpinionT) OpinionT {
	var (
		SumAllU        float32 = 0.0
		ProdAllU       float32 = 1.0
		SumAllEvid     float32 = 0.0
		SumAllSubsetsU float32 = 0.0
		CommonDenom    float32 = 0.0
		a_nomin        float32 = 0.0
		b_nomin        float32 = 0.0
		evid           float32 = 0.0
		o              OpinionT
	)

	var numAgents int = len(opinions)

	ProdSubsetsU := make([]float32, numAgents)

	for i := 0; i < numAgents; i++ {
		SumAllU += opinions[i].u
		ProdAllU *= opinions[i].u
	}

	for i := 0; i < numAgents; i++ {
		ProdSubsetsU[i] = ProdAllU / opinions[i].u
		SumAllSubsetsU += ProdSubsetsU[i]
	}

	CommonDenom = SumAllSubsetsU - float32(numAgents)*ProdAllU
	SumAllEvid = float32(numAgents) - SumAllU

	for i := 0; i < numAgents; i++ {
		evid = 1 - opinions[i].u
		a_nomin += opinions[i].a * evid
		b_nomin += opinions[i].b * evid * ProdSubsetsU[i]
	}

	o.b = b_nomin / CommonDenom
	o.u = SumAllEvid * ProdAllU / CommonDenom
	o.a = a_nomin / SumAllEvid

	return o
}

func weightedFusionCase2(opinions []OpinionT) OpinionT {
	var (
		a_diam float32 = 0.0
		b_diam float32 = 0.0
		u_diam float32 = 0.0
		gamma  float32 = 0.5
		o      OpinionT
	)

	dogmOpinions := make([]OpinionT, 0)

	numAgents := len(opinions)

	for i := 0; i < numAgents; i++ {
		if opinions[i].u == 0.0 {
			dogmOpinions = append(dogmOpinions, opinions[i])
		}
	}

	numDogmAgents := len(dogmOpinions)

	for i := 0; i < numDogmAgents; i++ {
		a_diam += gamma * dogmOpinions[i].a
		b_diam += gamma * dogmOpinions[i].b
	}

	o.b = b_diam
	o.a = a_diam
	o.u = u_diam

	return o
}

func weightedFusionCase3(opinions []OpinionT) OpinionT {
	var o OpinionT
	o.a = 0.0
	o.b = 0.0
	o.u = 1.0

	var numAgents int = len(opinions)

	for i := 0; i < numAgents; i++ {
		o.a += opinions[i].a
	}

	o.a /= float32(numAgents)

	return o
}
