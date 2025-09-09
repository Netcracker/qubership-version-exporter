// Copyright 2024-2025 NetCracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	collectorModel "github.com/Netcracker/qubership-version-exporter/pkg/model/http"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/jsonpath"
)

func init() {
	registerCollector(HttpType.String(), defaultEnabled, newHttpCollector)
}

func (httpCollector *HttpCollector) Close() {
	httpCollector.requests = httpCollector.requests[:0]
	httpCollector.httpClient = nil
}

func newHttpCollector(logger slog.Logger) (Collector, error) {
	return &HttpCollector{
		desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", HttpType.String()),
			"List of versions from http requests",
			nil, nil),
		valueType: prometheus.GaugeValue,
		logger:    logger,
	}, nil
}

var (
	re          = regexp.MustCompile(`[\x5D\x5B]|]|\x5B`)
	rangeRegexp = regexp.MustCompile("^{ *range.*{end}$")
)

type (
	HttpCollector struct {
		desc         *prometheus.Desc
		valueType    prometheus.ValueType
		logger       slog.Logger
		requests     []*HttpRequest
		k8sClientSet kubernetes.Interface
		httpClient   *http.Client
	}

	HttpRequest struct {
		path        string
		method      string
		metrics     []HttpMetric
		auth        *User
		transport   *http.Transport
		metricName  string
		description string
	}

	User struct {
		name     string
		password string
		token    string
	}

	HttpMetric struct {
		jsonPathStr string
		jsonPath    *jsonpath.JSONPath
		labels      []Label
	}

	Label struct {
		name        *model.LabelName
		valueRegexp *regexp.Regexp
	}

	Labels struct {
		Name  []string
		Value []string
	}
)

func (httpCollector *HttpCollector) Initialize(ctx context.Context, config interface{}) error {

	var httpConfigs collectorModel.Collectors
	cfg := reflect.ValueOf(config)
	switch cfg.Kind() {
	case reflect.Struct:
		httpConfigs = config.(collectorModel.Collectors)
	default:
		return errors.Errorf("Unsupported type: %v", cfg.Type())
	}
	httpCollector.k8sClientSet = httpConfigs.ClientSet
	httpCollector.httpClient = &http.Client{
		Timeout: time.Second * 10,
	}

	for _, urlConfig := range httpConfigs.Connections {

		user, tlsConfig, err := httpCollector.getCredentialsAndCertificates(urlConfig, ctx)
		if err != nil {
			return err
		}

		connections := len(urlConfig.Requests)
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxIdleConns = connections
		transport.MaxConnsPerHost = connections
		transport.MaxIdleConnsPerHost = connections
		transport.TLSClientConfig = tlsConfig

		for _, reqConfig := range urlConfig.Requests {
			var fullUrl *url.URL
			fullUrl, err = url.Parse(urlConfig.Host + reqConfig.Path)
			if err != nil {
				return err
			}

			var metrics []HttpMetric
			metrics, err = httpCollector.InitializeConfig(reqConfig.Metrics)
			if err != nil {
				return err
			}

			req := &HttpRequest{
				path:        fullUrl.String(),
				method:      strings.ToUpper(reqConfig.Method),
				metrics:     metrics,
				auth:        user,
				transport:   transport,
				metricName:  reqConfig.MetricName,
				description: reqConfig.Description,
			}
			httpCollector.requests = append(httpCollector.requests, req)
		}
	}

	return nil
}

func (httpCollector *HttpCollector) InitializeConfig(metrics []collectorModel.Metric) (hMetrics []HttpMetric, err error) {
	for _, metric := range metrics {
		var jPath *jsonpath.JSONPath
		if metric.JsonPath != "" {
			jPath = jsonpath.New(metric.JsonPath)
			if err = jPath.Parse(metric.JsonPath); err != nil {
				httpCollector.logger.Error("Error occurred while parsing jsonpath", "jsonpath: ", metric.JsonPath, "error", err)
				return nil, err
			}
			jPath.EnableJSONOutput(true)
		}

		var labels []Label
		for _, label := range metric.Labels {
			var name *model.LabelName
			if label.Name != "" {
				if model.UTF8Validation.IsValidLabelName(label.Name) {
					l := model.LabelName(label.Name)
					name = &l
				} else {
					return nil, errors.Errorf("Label name %s is not a valid", label.Name)
				}
			}

			var regXp *regexp.Regexp
			if label.Regexp != "" {
				regXp = regexp.MustCompile(label.Regexp)
			}

			labels = append(labels, Label{name: name, valueRegexp: regXp})
		}

		hMetrics = append(hMetrics, HttpMetric{jsonPathStr: metric.JsonPath, jsonPath: jPath, labels: labels})
	}

	return
}

func (httpCollector *HttpCollector) Scrape(ctx context.Context, metrics *Metrics, ch chan<- prometheus.Metric) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, req := range httpCollector.requests {
		wg.Add(1)
		go func(req *HttpRequest) {
			defer wg.Done()
			err := httpCollector.doScrape(req, ch)
			if err != nil {
				label := collectorPrefix + httpCollector.Name() + req.path
				httpCollector.logger.Error(fmt.Sprintf("Error from scraper %s", httpCollector.Name()+req.path), "error", err)
				metrics.ScrapeErrors.WithLabelValues(label).Inc()
				metrics.Error.Set(1)
			}
		}(req)
	}

	return nil
}

func (httpCollector *HttpCollector) doScrape(req *HttpRequest, ch chan<- prometheus.Metric) error {
	var err error
	var requestObj *http.Request
	var res *http.Response

	switch req.method {
	case http.MethodGet:
		requestObj, err = http.NewRequest(http.MethodGet, req.path, nil)
	case http.MethodPost:
		requestObj, err = http.NewRequest(http.MethodPost, req.path, nil)
	default:
		httpCollector.logger.Error("Wrong request method", "method", req.method)
		return nil
	}
	if err != nil {
		httpCollector.logger.Error("Failed to create HTTP request", "error", err)
		return nil
	}
	httpCollector.setAuthHeader(req, requestObj)

	client := &http.Client{
		Transport: req.transport,
		Timeout:   httpCollector.httpClient.Timeout,
	}
	res, err = client.Do(requestObj)

	if err != nil {
		httpCollector.logger.Error("Response is bad", "error", err)
		return nil
	}
	if res.StatusCode != 200 {
		httpCollector.logger.Error("Response status code is not acceptable", "statusCode", res.StatusCode)
		_ = res.Body.Close()
		return nil
	}

	metricLabels := httpCollector.parseResponse(res, req.metrics)
	req.sendMetrics(metricLabels, ch, httpCollector.logger)

	if err = res.Body.Close(); err != nil {
		httpCollector.logger.Error("Error occurred when closing response body", "error", err)
		return nil
	}

	httpCollector.httpClient.CloseIdleConnections()

	return nil
}

func (httpCollector *HttpCollector) Type() Type {
	return HttpType
}

// Name of the Scraper. Should be unique.
func (httpCollector *HttpCollector) Name() string {
	return HttpType.String()
}

func (httpCollector *HttpCollector) parseResponse(res *http.Response, metrics []HttpMetric) (metricLabels [][]Labels) {

	if res != nil && res.Body != nil {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			httpCollector.logger.Error("Error while reading response body", "error", err)
			return
		}

		contentType := res.Header.Get("Content-Type")
		if contentType != "" && strings.Contains(contentType, "application/json") {
			var responseJson interface{}
			if err = json.Unmarshal(body, &responseJson); err != nil {
				httpCollector.logger.Error("Error while parsing response body", "error", err)
				return
			}
			metricLabels = httpCollector.parseJsonResponse(responseJson, metrics)
		} else if contentType != "" && strings.Contains(contentType, "text/plain") {
			metricLabels = httpCollector.parseTextResponse(string(body), metrics)
		} else {
			httpCollector.logger.Error(fmt.Sprintf("Unsupported content type: %s", contentType))
		}
	}

	return
}

func (httpCollector *HttpCollector) parseJsonResponse(responseJson interface{}, metrics []HttpMetric) (metricLabels [][]Labels) {
	var err error
	if len(metrics) > 0 {
		metricLabels = make([][]Labels, len(metrics))
	}
	for m, metric := range metrics {
		if metric.jsonPath != nil {
			isRange := rangeRegexp.MatchString(metric.jsonPathStr)
			if isRange {
				//If jsonPath has `{range}{end}` function, it sets value of `lastEndNode` in Execute() and does not clear it
				//`lastEndNode` is not nil, it causes error "not in range, nothing to end".
				//To avoid it JSONPath object must be created each time when it is executed.
				jPath := jsonpath.New(metric.jsonPathStr)
				if err = jPath.Parse(metric.jsonPathStr); err != nil {
					httpCollector.logger.Error("Error occurred while parsing jsonpath", "jsonpath: ", metric.jsonPathStr, "error", err)
					continue
				}
				jPath.EnableJSONOutput(true)
				metric.jsonPath = jPath
			}

			value := new(bytes.Buffer)

			metric.jsonPath.AllowMissingKeys(isRange)
			if err = metric.jsonPath.Execute(value, responseJson); err != nil {
				httpCollector.logger.Error(fmt.Sprintf("Error occurred while getting value. jsonpath : %s", metric.jsonPathStr), "error", err)

				metricLabels[m] = make([]Labels, 1)
				for _, label := range metric.labels {
					metricLabels[m][0].Name = append(metricLabels[m][0].Name, string(*label.name))
					metricLabels[m][0].Value = append(metricLabels[m][0].Value, "")
				}
				continue
			}

			var result []string

			emptyResult := true
			if isRange {
				split := re.Split(strings.ReplaceAll(value.String(), "\n", ""), -1)

				for i := 1; i < len(split); i = i + 2 {
					labelValue := strings.TrimRight(strings.TrimLeft(strings.TrimSpace(split[i]), "\""), "\"")
					result = append(result, labelValue)
					if emptyResult {
						emptyResult = len(labelValue) < 1
					}
				}
			} else {
				if err = json.Unmarshal(value.Bytes(), &result); err != nil {
					httpCollector.logger.Error("Error while parsing response body", "error", err)
					continue
				}
				emptyResult = false
			}

			if len(result) == 1 && result[0] == metric.jsonPathStr || emptyResult {
				httpCollector.logger.Debug(fmt.Sprintf("Nothing found. The jsonpath: %s", metric.jsonPathStr))
				result = nil
				continue
			}

			numberOfLabels := len(metric.labels)
			resultSize := len(result)

			if resultSize%numberOfLabels != 0 {
				httpCollector.logger.Error(
					fmt.Sprintf("The jsonpath: %s result does not match the number of labels configured. Perhaps some keys don't have values. Try more specified jsonpath request.", metric.jsonPathStr))
				continue
			}

			labelStep := resultSize / numberOfLabels
			metricLabels[m] = make([]Labels, labelStep)
			for i := 0; i < labelStep; i++ {
				for j, label := range metric.labels {
					metricLabels[m][i].Name = append(metricLabels[m][i].Name, string(*label.name))
					if isRange {
						if label.valueRegexp != nil {
							metricLabels[m][i].Value = append(metricLabels[m][i].Value, label.valueRegexp.FindString(result[i*numberOfLabels+j]))
						} else {
							metricLabels[m][i].Value = append(metricLabels[m][i].Value, result[i*numberOfLabels+j])
						}
					} else {
						if label.valueRegexp != nil {
							metricLabels[m][i].Value = append(metricLabels[m][i].Value, label.valueRegexp.FindString(result[labelStep*j+i]))
						} else {
							metricLabels[m][i].Value = append(metricLabels[m][i].Value, result[labelStep*j+i])
						}
					}
				}
			}

		} else {
			httpCollector.logger.Error("Invalid configuration. Response type is: 'application/json'. JsonPath can't be empty in the configuration")
		}
	}

	return
}

func (httpCollector *HttpCollector) parseTextResponse(responseText string, metrics []HttpMetric) (metricLabels [][]Labels) {
	if len(metrics) > 0 {
		metricLabels = make([][]Labels, len(metrics))
	}
	for m, metric := range metrics {
		var length int
		for _, label := range metric.labels {
			if label.valueRegexp != nil {

				var results []string
				subNames := deleteEmpty(label.valueRegexp.SubexpNames())
				if len(subNames) == 0 {
					results = label.valueRegexp.FindAllString(responseText, -1)
				} else {
					resSubMatch := label.valueRegexp.FindAllStringSubmatch(responseText, -1)
					for _, submatch := range resSubMatch {
						results = append(results, strings.Join(submatch[1:], "-"))
					}

				}

				var resultLength int
				if len(results) > length {
					if length == 0 {
						resultLength = len(results)
						length += resultLength
					} else {
						resultLength = len(results) - length
						length += resultLength
					}
				}

				metricLabels[m] = append(metricLabels[m], make([]Labels, resultLength)...)
				for i, str := range results {
					metricLabels[m][i].Name = append(metricLabels[m][i].Name, string(*label.name))
					metricLabels[m][i].Value = append(metricLabels[m][i].Value, str)
				}
			} else {
				httpCollector.logger.Error("Invalid configuration. Response type is: 'text/plain'. Regexp can't be empty in the configuration")
				metricLabels[m] = append(metricLabels[m], make([]Labels, 1)...)
				metricLabels[m][length].Name = append(metricLabels[m][length].Name, string(*label.name))
				metricLabels[m][length].Value = append(metricLabels[m][length].Value, "")
				length++
			}
		}
	}

	return
}

func (request *HttpRequest) sendMetrics(metricLabels [][]Labels, ch chan<- prometheus.Metric, logger slog.Logger) {
	help := "A metric generated by qubership-version-exporter http collector."
	if len(strings.TrimSpace(request.description)) > 0 {
		help = fmt.Sprintf("%s Description: %s.", help, request.description)
	}

	cache := make(map[string]*prometheus.CounterVec)
	for _, mLabel := range metricLabels {
		for _, lPair := range mLabel {
			lPair.Name = append(lPair.Name, commonLabel)
			lPair.Value = append(lPair.Value, commonLabelValue)

			desc := prometheus.NewDesc(
				request.metricName,
				help,
				lPair.Name,
				map[string]string{},
			).String()

			if v, found := cache[desc]; found && v != nil {
				v.WithLabelValues(lPair.Value...).Inc()
			} else {
				if found && v == nil {
					logger.Error(
						fmt.Sprintf("Counter with description <<%s>> doesn't have a CounterVec predefined", desc))

				}
				resultMetric := prometheus.NewCounterVec(
					prometheus.CounterOpts{
						Name: request.metricName,
						Help: help,
					},
					lPair.Name,
				)
				resultMetric.WithLabelValues(lPair.Value...).Inc()
				cache[desc] = resultMetric
			}
		}
	}

	for _, v := range cache {
		v.Collect(ch)
	}
}

func (httpCollector *HttpCollector) setAuthHeader(requestObj *HttpRequest, request *http.Request) {
	if requestObj.auth != nil {
		var b bytes.Buffer
		if requestObj.auth.name != "" && requestObj.auth.password != "" {
			b.WriteString("Basic ")
			b.WriteString(base64.StdEncoding.EncodeToString([]byte(
				fmt.Sprintf("%s:%s", requestObj.auth.name, requestObj.auth.password))))
		} else if requestObj.auth.token != "" {
			b.WriteString(fmt.Sprintf("Bearer %s", requestObj.auth.token))
		}
		request.Header.Add("Authorization", b.String())
	}
}

func (httpCollector *HttpCollector) getCredentialsAndCertificates(config collectorModel.Connector, ctx context.Context) (user *User, tlsConf *tls.Config, err error) {

	var name, pwd, token string
	if config.Credentials.User.Name != "" && config.Credentials.Password.Name != "" {

		var userSecret *corev1.Secret
		userSecret, err = httpCollector.k8sClientSet.CoreV1().Secrets(config.Credentials.Namespace).Get(ctx, config.Credentials.User.Name, metav1.GetOptions{})
		if err != nil {
			httpCollector.logger.Error("can't get authorization data", "error", err)
			return nil, nil, err
		}

		var pwdSecret *corev1.Secret
		if config.Credentials.User.Name != config.Credentials.Password.Name {
			pwdSecret, err = httpCollector.k8sClientSet.CoreV1().Secrets(config.Credentials.Namespace).Get(ctx, config.Credentials.Password.Name, metav1.GetOptions{})
			if err != nil {
				httpCollector.logger.Error("can't get secret data", "error", err)
				return nil, nil, err
			}
		} else {
			pwdSecret = userSecret
		}
		name = string(pwdSecret.Data[config.Credentials.User.Key])
		pwd = string(pwdSecret.Data[config.Credentials.Password.Key])
	} else if config.Credentials.Token.Name != "" {
		var tokenSecret *corev1.Secret
		tokenSecret, err = httpCollector.k8sClientSet.CoreV1().Secrets(config.Credentials.Namespace).Get(ctx, config.Credentials.Token.Name, metav1.GetOptions{})
		if err != nil {
			httpCollector.logger.Error("can't get authorization data", "error", err)
			return nil, nil, err
		}
		token = string(tokenSecret.Data[config.Credentials.Token.Key])
	}

	if (name != "" && pwd != "") || token != "" {
		user = &User{
			name:     name,
			password: pwd,
			token:    token,
		}
	}
	var ca, certValue, pkey string
	tlsConfig := config.TlsConfig
	if tlsConfig.TLSSkip {
		tlsConf = &tls.Config{
			InsecureSkipVerify: tlsConfig.TLSSkip,
		}
	} else if tlsConfig.CA.Name != "" && tlsConfig.CA.Key != "" && tlsConfig.Namespace != "" {
		var caSecret *corev1.Secret
		caSecret, err = httpCollector.k8sClientSet.CoreV1().Secrets(tlsConfig.Namespace).Get(ctx, tlsConfig.CA.Name, metav1.GetOptions{})
		if err != nil {
			httpCollector.logger.Error("can't get secret data", "error", err)
			return nil, nil, err
		} else {
			ca = string(caSecret.Data[tlsConfig.CA.Key])
			if tlsConfig.Cert.Name != "" && tlsConfig.PKey.Name != "" {
				if tlsConfig.Cert.Name != tlsConfig.CA.Name {
					var certSecret *corev1.Secret
					certSecret, err = httpCollector.k8sClientSet.CoreV1().Secrets(tlsConfig.Namespace).Get(ctx, tlsConfig.Cert.Name, metav1.GetOptions{})
					if err != nil {
						httpCollector.logger.Error("can't get secret data", "error", err)
						return nil, nil, err
					} else {
						certValue = string(certSecret.Data[tlsConfig.Cert.Key])
					}
				} else {
					certValue = string(caSecret.Data[tlsConfig.Cert.Key])
				}
				if tlsConfig.PKey.Name != tlsConfig.CA.Name {
					var pKeySecret *corev1.Secret
					pKeySecret, err = httpCollector.k8sClientSet.CoreV1().Secrets(tlsConfig.Namespace).Get(ctx, tlsConfig.PKey.Name, metav1.GetOptions{})
					if err != nil {
						httpCollector.logger.Error("can't get secret data", "error", err)
						return nil, nil, err
					} else {
						certValue = string(pKeySecret.Data[tlsConfig.PKey.Key])
					}
				} else {
					pkey = string(caSecret.Data[tlsConfig.PKey.Key])
				}
			}
		}
		caCert := []byte(ca)
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			httpCollector.logger.Error("can't parse Certificate Authority", "error", err)
			return nil, nil, err
		}
		if pkey != "" && certValue != "" {
			clientCert, err := tls.X509KeyPair([]byte(certValue), []byte(pkey))
			if err != nil {
				httpCollector.logger.Error("can't parse certificate", "error", err)
				return nil, nil, err
			}
			tlsConf = &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{clientCert},
			}
		} else {
			tlsConf = &tls.Config{
				RootCAs: caCertPool,
			}
		}
	}

	return user, tlsConf, err
}
