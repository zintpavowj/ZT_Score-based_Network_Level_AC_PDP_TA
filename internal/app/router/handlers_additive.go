package router

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/algorithm/additive"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/scenario"
)

// HandlerAdditivePost() ...
func (r *Router) handlerAdditivePost(w http.ResponseWriter, req *http.Request) {

	vars := mux.Vars(req)

	thresholdType, ok := vars["threshold"]
	if !ok {
		r.sysLogger.WithFields(logrus.Fields{
			"package":  "router",
			"function": "handlerAdditivePost",
			"comment":  "a threshold calculation type is missed",
		}).Error("unsupported route")

		// Correct sequence of actions: set headers, then status, then write data
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode([]string{"unsupported route"})

		return
	}

	sc := &scenario.Scenario{}

	if err := json.NewDecoder(req.Body).Decode(sc); err != nil {

		r.sysLogger.WithFields(logrus.Fields{
			"package":  "router",
			"function": "handlerAdditivePost",
			"comment":  "unable to decode the request body as json",
		}).Error(err)

		// Correct sequence of actions: set headers, then status, then write data
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode([]string{"unable to decode the request body as json"})

		return
	}

	algorithm := additive.New(sc, r.requester, thresholdType, r.sysLogger)

	if err := algorithm.EnrichData(); err != nil {

		r.sysLogger.WithFields(logrus.Fields{
			"package":   "router",
			"function":  "handlerAdditivePost",
			"algorithm": "additive",
			"threshold": thresholdType,
			"comment":   "unable to enrich the data",
		}).Error(err)

		// Correct sequence of actions: set headers, then status, then write data
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode([]string{"unable to decode the request body as json"})

		return
	}

	// t := time.Now()

	decision, output, err := algorithm.Run()
	if err != nil {

		r.sysLogger.WithFields(logrus.Fields{
			"package":   "router",
			"function":  "handlerAdditivePost",
			"algorithm": "additive",
			"threshold": thresholdType,
			"comment":   "algorithm returned an error",
		}).Error(err)

		// Correct sequence of actions: set headers, then status, then write data
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode([]string{"trust calculation algorithm returned an error"})

		return
	}
	// fmt.Printf("Additive %s algorithm took %v\n", thresholdType, time.Since(t))

	if !decision {

		r.sysLogger.WithFields(logrus.Fields{
			"package":    "router",
			"function":   "handlerAdditivePost",
			"algorithm":  "additive",
			"threshold":  thresholdType,
			"decision":   "DENIED",
			"scenarioID": sc.Id,
		}).Info(output)

		// Correct sequence of actions: set headers, then status, then write data
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(output)

		return
	}

	output = append(output, "the calculated trust score is sufficient to access the service")

	r.sysLogger.WithFields(logrus.Fields{
		"package":    "router",
		"function":   "handlerAdditivePost",
		"algorithm":  "additive",
		"threshold":  thresholdType,
		"decision":   "GRANTED",
		"scenarioID": sc.Id,
	}).Info(output)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(output)
}
