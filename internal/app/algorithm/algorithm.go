package algorithm

import "github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/scenario"

type Algorithm interface {
	Run(sc *scenario.Scenario) (bool, []string, error)
}
