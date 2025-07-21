package http

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	nativehttp "net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"text/template"
)

type Backend struct {
	conf            *Config
	tlsConfig       *tls.Config
	client          *nativehttp.Client
	urlTemplate     *template.Template
	payloadTemplate *template.Template
}

func New(config json.RawMessage, methodsAllowed []string) (*Backend, error) {
	conf := &Config{}
	if err := json.Unmarshal(config, conf); err != nil {
		return nil, err
	}

	if !slices.Contains(methodsAllowed, conf.Method) {
		return nil, errors.New("invalid method " + conf.Method)
	}

	if conf.Url == "" {
		return nil, errors.New("URL is not set")
	}

	url, err := url.Parse(conf.Url)
	if err != nil {
		return nil, err
	}

	host := strings.Split(url.Host, ":")[0]

	if conf.Method == nativehttp.MethodGet && !conf.GetMethodPayload && (conf.PayloadTemplate != "" || conf.PayloadTemplateFile != "") {
		return nil, errors.New("payload template is not supported for GET requests")
	}

	if conf.PayloadTemplate != "" && conf.PayloadTemplateFile != "" {
		return nil, errors.New("payload template and payload template file are both set")
	}

	// Parse the URL template
	var urlTemplate *template.Template
	if strings.Contains(conf.Url, "{{") {
		var err error
		urlTemplate, err = template.New("URL").Parse(conf.Url)
		if err != nil {
			return nil, err
		}
	}

	// Parse the payload template
	var payloadTemplate *template.Template
	if conf.PayloadTemplate != "" {
		// payloadTemplate contains a bas64 encoded string, so we need to decode it first
		var err error
		decodedBytes, err := base64.StdEncoding.DecodeString(conf.PayloadTemplate)
		if err != nil {
			return nil, err
		}
		payloadTemplate, err = template.New("payload").Parse(string(decodedBytes))
		if err != nil {
			return nil, err
		}
	} else if conf.PayloadTemplateFile != "" {
		var err error
		payloadTemplate, err = template.ParseFiles(conf.PayloadTemplateFile)
		if err != nil {
			return nil, err
		}
	}

	// Load client certificates if mTLS is configured
	var tlsConfig *tls.Config
	if conf.MTls != nil {
		if url.Scheme != "https" {
			return nil, errors.New("only https scheme supported with mTLS")
		}

		cert, err := tls.LoadX509KeyPair(conf.MTls.CertFile, conf.MTls.KeyFile)
		if err != nil {
			return nil, err
		}

		caCert, err := os.ReadFile(conf.MTls.RootCAFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		}
	}

	var httpClient *nativehttp.Client
	if tlsConfig != nil {
		// client with mTLS (first check in the pool of clients)
		if cachedClient := HttpClientPool.Get(host); cachedClient != nil {
			httpClient = cachedClient
		} else {
			tr := &nativehttp.Transport{
				TLSClientConfig: tlsConfig,
			}
			httpClient = &nativehttp.Client{
				Transport: tr,
			}
			HttpClientPool.Set(host, httpClient)
		}
	} else {
		httpClient = nativehttp.DefaultClient
	}

	return &Backend{
		conf:            conf,
		client:          httpClient,
		urlTemplate:     urlTemplate,
		payloadTemplate: payloadTemplate,
	}, nil
}
