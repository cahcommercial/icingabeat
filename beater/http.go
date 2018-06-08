package beater

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/elastic/beats/libbeat/logp"
)

type Results struct {
	Results []Result
}

// nested within sbserver response
type Result struct {
	Name       string
	Attributes struct {
		Variables struct {
			ClientEndpoint  string `json:"client_endpoint"`
			Environment     string `json:"env"`
			OperatingSystem string `json:"os"`
			Product         string `json:"product"`
			Brand           string `json:"brand"`
			HTTP            struct {
				Custom struct {
					URL       string `json:"http_vhost"`
					HostGroup string `json:"hostgroup"`
				} `json:"custom_vars"`
			} `json:"http_vars"`
		} `json:"vars"`
	} `json:"attrs"`
}

func getIcingaHostTags(host string, icingaURL string, icingaPort string, user string, password string) map[string]string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	apiEndpoint := "https://" + icingaURL + ":" + icingaPort + "/v1/objects/hosts/" + host + "?attrs=name&attrs=vars"
	req, err := http.NewRequest("GET", apiEndpoint, nil)
	req.SetBasicAuth(user, password)

	res, err := client.Do(req)
	if err != nil {
		panic(err.Error())
	}

	bytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err.Error())
	}

	var results = new(Results)
	err = json.Unmarshal(bytes, &results)
	if err != nil {
		panic(err.Error())
	}

	hostObject := results.Results[0]
	tags := make(map[string]string)
	if hostObject.Attributes.Variables.Product != "" {
		tags["fuse_product"] = hostObject.Attributes.Variables.Product
	}
	if hostObject.Attributes.Variables.Brand != "" {
		tags["fuse_brand"] = hostObject.Attributes.Variables.Brand
	}
	if hostObject.Attributes.Variables.Environment != "" {
		tags["fuse_env"] = hostObject.Attributes.Variables.Environment
	}
	if hostObject.Attributes.Variables.OperatingSystem != "" {
		tags["fuse_os"] = hostObject.Attributes.Variables.OperatingSystem
	}
	if hostObject.Attributes.Variables.HTTP.Custom.URL != "" {
		tags["fuse_url"] = hostObject.Attributes.Variables.OperatingSystem
	}

	return tags
}

func requestURL(bt *Icingabeat, method string, URL *url.URL) (*http.Response, error) {

	var skipSslVerify bool
	certPool := x509.NewCertPool()

	if bt.config.SSL.Verify {
		skipSslVerify = false

		for _, ca := range bt.config.SSL.CertificateAuthorities {
			cert, err := ioutil.ReadFile(ca)
			if err != nil {
				logp.Warn("Could not load certificate: %v", err)
			}
			certPool.AppendCertsFromPEM(cert)
		}
	} else {
		skipSslVerify = true
	}

	fmt.Print(bt.config.SSL.CertificateAuthorities)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipSslVerify,
		RootCAs:            certPool,
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
	}

	logp.Debug("icingabeat", "Requested URL: %v", URL.String())

	request, err := http.NewRequest(method, URL.String(), nil)

	if err != nil {
		logp.Info("Request: %v", err)
	}

	request.Header.Add("Accept", "application/json")
	request.SetBasicAuth(bt.config.User, bt.config.Password)
	response, err := client.Do(request)

	if err != nil {
		return nil, err
	}

	switch response.StatusCode {
	case 401:
		err = errors.New("Authentication failed for user " + bt.config.User)
		defer response.Body.Close()
	}

	return response, err
}
