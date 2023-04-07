package requester

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/zintpavowj/Zero_Trust_Score-based_Network_Level_AC_PDP_TA/internal/app/config"
)

type Requester struct {
	client    *http.Client
	target    string
	sysLogger *logrus.Logger
}

func New(logger *logrus.Logger) (*Requester, error) {

	requester := new(Requester)
	requester.target = config.Config.Pip.TargetAddr
	requester.sysLogger = logger

	cert, err := tls.LoadX509KeyPair(config.Config.Ta.SSLCert, config.Config.Ta.SSLCertKey)
	if err != nil {
		log.Fatal(err)
	}

	// Create a CA certificate pool
	caCert, err := os.ReadFile(config.Config.Ta.CACertsToVerifyClientRequests[0])
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a HTTPS client and supply the created CA pool and certificate
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	requester.client = client

	return requester, nil
}

func (r *Requester) Run(path string) (*http.Response, error) {
	return r.client.Get(r.target + path)
}
