// Package init validates the parameters from the config file and transforms
// different values into the adequate data structures.
// Each section in example_config.yml corresponds to a function of this package.
package init

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/config"
)

// The function initializes the 'ta' section of the config file and
// loads the Trust Algorithms certificate(s).
func initTa(sysLogger *logrus.Logger) error {
	var err error
	var fields string = ""

	if config.Config.Ta.ListenAddr == "" {
		fields += "listen_addr,"
	}

	if config.Config.Ta.SSLCert == "" {
		fields += "ssl_cert,"
	}

	if config.Config.Ta.SSLCertKey == "" {
		fields += "ssl_cert_key,"
	}

	if config.Config.Ta.CACertsToVerifyClientRequests == nil {
		fields += "ca_certs_to_verify_client_certs,"
	}

	if fields != "" {
		return fmt.Errorf("initTa(): in the section 'ta' the following required fields are missed: '%s'", strings.TrimSuffix(fields, ","))
	}

	// Read CA certs used to verify certs to be accepted
	for _, acceptedClientCert := range config.Config.Ta.CACertsToVerifyClientRequests {

		err = loadCACertificate(acceptedClientCert, config.Config.CACertPoolToVerifyClientRequests)
		if err != nil {
			sysLogger.WithFields(logrus.Fields{
				"package":  "init",
				"function": "initTa",
				"comment":  "unable to load a CA certificate to eccept incoming requests",
				"cafile":   acceptedClientCert,
			}).Error(err)
			return err
		}

		sysLogger.WithFields(logrus.Fields{
			"package":  "init",
			"function": "initTa",
			"cafile":   acceptedClientCert,
		}).Debug("a CA certificate has been loaded successfully")

	}

	// Load Trust Algorithms certificate
	config.Config.TaCert, err = loadX509KeyPair(config.Config.Ta.SSLCert, config.Config.Ta.SSLCertKey)
	if err != nil {
		sysLogger.WithFields(logrus.Fields{
			"package":  "init",
			"function": "initTa",
			"comment":  "unable to load a x509 certificate",
			"certfile": config.Config.Ta.SSLCert,
			"keyfile":  config.Config.Ta.SSLCertKey,
		}).Error(err)
	}

	sysLogger.WithFields(logrus.Fields{
		"package":  "init",
		"function": "initTa",
		"certfile": config.Config.Ta.SSLCert,
		"keyfile":  config.Config.Ta.SSLCertKey,
	}).Debug("a x509 certificate has been loaded successfully")

	return nil
}
