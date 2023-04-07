// Package router contains the main routine of the Trust Algorithms service.
package router

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/config"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/logger"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/requester"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/scenario"
)

type Router struct {
	tlsConfig *tls.Config
	frontend  *http.Server
	sysLogger *logrus.Logger
	requester *requester.Requester
}

func New(logger *logrus.Logger) (*Router, error) {
	var err error
	router := new(Router)

	// Set sysLogger to the one created in the init function
	router.sysLogger = logger

	// Configure the TLS configuration of the router
	router.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		// ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs:      config.Config.CACertPoolToVerifyClientRequests,
		Certificates: []tls.Certificate{config.Config.TaCert},
	}

	// Frontend Handlers
	muxRouter := mux.NewRouter()

	muxRouter.HandleFunc("/additive/{threshold}", router.handlerAdditivePost).Methods("POST")
	muxRouter.HandleFunc("/subjective/{threshold}", router.handlerSubjectivePost).Methods("POST")

	w := logger.Writer()

	// Setting Up the Frontend Server
	router.frontend = &http.Server{
		Addr:         config.Config.Ta.ListenAddr,
		TLSConfig:    router.tlsConfig,
		ReadTimeout:  time.Hour * 1,
		WriteTimeout: time.Hour * 1,
		Handler:      muxRouter,
		ErrorLog:     log.New(w, "", 0),
	}

	router.requester, err = requester.New(logger)
	if err != nil {
		logger.Errorf("main: main(): unable to create a requester: %s", err.Error())
	}
	logger.Debug("a new requester has been created")

	return router, nil
}

// ServeHTTP gets called if a request receives the PEP. The function implements
// the PEP's main routine: It performs basic authentication, authorization with
// help of the PEP, transformation from SFCs into SFPs with help of the SFP
// Logic, and then forwards the package along the SFP.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var err error

	// Log all http requests incl. TLS informaion in the case of a successful TLS handshake
	r.sysLogger.Debugf("############################################################")
	logger.LogHTTPRequest(r.sysLogger, req)

	var sc scenario.Scenario
	err = json.NewDecoder(req.Body).Decode(&sc)
	if err != nil {
		r.sysLogger.Errorf("router: ServeHTTP(): unable to parse a form from the incoming request: %s", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

func (r *Router) ListenAndServeTLS() error {
	return r.frontend.ListenAndServeTLS("", "")
}
