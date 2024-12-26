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
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	sshModel "qubership-version-exporter/model/ssh"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// check interface
var (
	_ Collector = &SshVersionScraper{}
)

func init() {
	registerCollector(SSHType.String(), defaultEnabled, newSSHCollector)
}

func newSSHCollector(logger log.Logger) (Collector, error) {
	return &SshVersionScraper{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", SSHType.String()),
			"List of versions from ssh requests",
			nil, nil),
		ValueType: prometheus.GaugeValue,
		Logger:    logger,
	}, nil
}

type (
	SshClient struct {
		Address      string
		Network      string
		ClientConfig *ssh.ClientConfig
		Requests     []*CmdRequest
	}

	CmdRequest struct {
		Cmd         string
		MetricName  string
		Description string
		Labels      []*CmdLabel
	}

	CmdLabel struct {
		Name        *model.LabelName
		ValueRegexp *regexp.Regexp
	}

	SshVersionScraper struct {
		Desc       *prometheus.Desc
		ValueType  prometheus.ValueType
		Logger     log.Logger
		SshClients []*SshClient
	}
)

func (svc *SshVersionScraper) Name() string {
	return SSHType.String()
}

func (svc *SshVersionScraper) Type() Type {
	return SSHType
}

func (svc *SshVersionScraper) Close() {
	svc.SshClients = svc.SshClients[:0]
}

func (svc *SshVersionScraper) Initialize(ctx context.Context, config interface{}) error {
	var connOptions sshModel.Connections
	cfg := reflect.ValueOf(config)
	switch cfg.Kind() {
	case reflect.Struct:
		connOptions = config.(sshModel.Connections)
	default:
		return errors.Errorf("unsupported type: %v", cfg.Type())
	}

	for _, connOption := range connOptions.Connections {
		sshClient := svc.InitSshClient(ctx, connOption)
		if sshClient != nil {
			svc.SshClients = append(svc.SshClients, sshClient)
		}
	}

	return nil
}

func (svc *SshVersionScraper) InitSshClient(ctx context.Context, connOptions sshModel.ConnOptions) *SshClient {

	var err error
	var authMethod ssh.AuthMethod
	var hostKeyCallback = ssh.InsecureIgnoreHostKey()
	var login string
	var client *ssh.Client

	if connOptions.Credentials != nil {
		authMethod, err = publicKeyFromFile(connOptions.Credentials.PKeyPath)
		if err != nil {
			_ = level.Error(svc.Logger).Log("msg", "can't get authorization data", "err", err)
			return nil
		}

		if connOptions.Credentials.KnownHostsPath != nil {
			hostKeyCallback, err = knownhosts.New(*connOptions.Credentials.KnownHostsPath)
			if err != nil {
				_ = level.Error(svc.Logger).Log("msg", "can't get authorization data", "err", err)
				return nil
			}
		}

		login = connOptions.Credentials.Login
	}

	if connOptions.K8sCredentials != nil {
		var loginSecret *corev1.Secret
		loginSecret, err = connOptions.K8sCredentials.ClientSet.CoreV1().Secrets(connOptions.K8sCredentials.Namespace).Get(ctx, connOptions.K8sCredentials.Login.Name, metav1.GetOptions{})
		if err != nil {
			_ = level.Error(svc.Logger).Log("msg", "can't get login user data", "err", err)
			return nil
		}

		login = string(loginSecret.Data[connOptions.K8sCredentials.Login.Key])

		var pkeySecret *corev1.Secret
		if connOptions.K8sCredentials.Login.Name != connOptions.K8sCredentials.PKey.Name {
			pkeySecret, err = connOptions.K8sCredentials.ClientSet.CoreV1().Secrets(connOptions.K8sCredentials.Namespace).Get(ctx, connOptions.K8sCredentials.PKey.Name, metav1.GetOptions{})
			if err != nil {
				_ = level.Error(svc.Logger).Log("msg", "can't get pkey data", "err", err)
				return nil
			}
		} else {
			pkeySecret = loginSecret
		}

		authMethod, err = publicKey(pkeySecret.Data[connOptions.K8sCredentials.PKey.Key])
		if err != nil {
			_ = level.Error(svc.Logger).Log("msg", "can't get authorization method", "err", err)
			return nil
		}
	}

	clientConfig := &ssh.ClientConfig{
		User:            login,
		HostKeyCallback: hostKeyCallback,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		Timeout: connOptions.Timeout,
	}

	addr := net.JoinHostPort(connOptions.Host, strconv.Itoa(connOptions.Port))
	client, err = ssh.Dial(connOptions.Network, addr, clientConfig)
	if err != nil {
		_ = level.Error(svc.Logger).Log("msg", fmt.Sprintf("can't connect to the SSH server, address: %s", addr), "err", err)
		return nil
	}

	err = client.Close()
	if err != nil {
		_ = level.Error(svc.Logger).Log("msg", fmt.Sprintf("failed to close client connection to SSH server, address: %s", addr), "err", err)
		return nil
	}

	var requests []*CmdRequest
	requests, err = svc.InitCmdRequest(ctx, connOptions.Requests)
	if err != nil {
		_ = level.Error(svc.Logger).Log("msg", "failed to initialize ssh cmd request", "err", err)
		return nil
	}

	sshClient := &SshClient{
		Address:      addr,
		Network:      connOptions.Network,
		ClientConfig: clientConfig,
		Requests:     requests,
	}

	return sshClient
}

func (svc *SshVersionScraper) InitCmdRequest(ctx context.Context, requests []sshModel.Request) ([]*CmdRequest, error) {
	var cmdRequests []*CmdRequest

	for _, request := range requests {

		var labels []*CmdLabel
		for _, label := range request.Labels {

			var name *model.LabelName
			if label.Name != "" {
				if model.LabelName(label.Name).IsValid() {
					l := model.LabelName(label.Name)
					name = &l
				} else {
					return nil, errors.Errorf("Label name - %s is not a valid", label.Name)
				}
			}

			var regXp *regexp.Regexp
			if label.Regexp != "" {
				regXp = regexp.MustCompile(label.Regexp)
			}

			labels = append(labels, &CmdLabel{Name: name, ValueRegexp: regXp})
		}

		cmdRequests = append(cmdRequests, &CmdRequest{
			Cmd:         request.Cmd,
			MetricName:  request.MetricName,
			Description: request.Description,
			Labels:      labels,
		})
	}

	return cmdRequests, nil
}

func (svc *SshVersionScraper) Scrape(ctx context.Context, metrics *Metrics, ch chan<- prometheus.Metric) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, sshClient := range svc.SshClients {
		wg.Add(1)
		go func(sshClient *SshClient) {
			defer wg.Done()
			errs := sshClient.doScrape(ctx, ch)
			if errs != nil {
				label := collectorPrefix + svc.Name() + "_" + sshClient.Address
				for _, err := range errs {
					_ = level.Error(svc.Logger).Log("msg", fmt.Sprintf("Error from scraper: %s %s", svc.Name(), sshClient.Address), "err", err)
					metrics.ScrapeErrors.WithLabelValues(label).Inc()
				}
				metrics.Error.Set(1)
			}
		}(sshClient)
	}

	_ = level.Debug(svc.Logger).Log(SSHType.String(), "done")
	return nil
}

func (sshClient *SshClient) doScrape(ctx context.Context, ch chan<- prometheus.Metric) (errs []error) {
	var err error
	var client *ssh.Client

	client, err = ssh.Dial(sshClient.Network, sshClient.Address, sshClient.ClientConfig)
	if err != nil {
		errs = append(errs, err)
		return
	}

	defer client.Close()

	for _, request := range sshClient.Requests {
		var session *ssh.Session
		session, err = client.NewSession()
		if err != nil {
			errs = append(errs, err)
			_ = session.Close()
			continue
		}

		var buf []byte
		buf, err = session.CombinedOutput(request.Cmd)
		if err != nil {
			errs = append(errs, err)
			_ = session.Close()
			continue
		}

		_ = session.Close()

		metricLabels, parseErrs := sshClient.parseResponse(string(buf), request.Labels)

		if len(parseErrs) > 0 {
			errs = append(errs, parseErrs...)
		}

		request.sendMetrics(metricLabels, ch)
	}

	return
}

func (sshClient *SshClient) parseResponse(responseText string, labels []*CmdLabel) (metricLabels []Labels, errs []error) {

	var length int
	for _, label := range labels {
		if label.ValueRegexp != nil {
			var results []string
			subNames := deleteEmpty(label.ValueRegexp.SubexpNames())
			if len(subNames) == 0 {
				results = label.ValueRegexp.FindAllString(responseText, -1)
			} else {
				resSubMatch := label.ValueRegexp.FindAllStringSubmatch(responseText, -1)
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

			metricLabels = append(metricLabels, make([]Labels, resultLength)...)
			for i, str := range results {
				metricLabels[i].Name = append(metricLabels[i].Name, string(*label.Name))
				metricLabels[i].Value = append(metricLabels[i].Value, str)
			}
		} else {
			err := errors.Errorf("Invalid configuration. Regexp can't be empty for label: %s", string(*label.Name))
			errs = append(errs, err)

			metricLabels = append(metricLabels, make([]Labels, 1)...)
			length += 1
			metricLabels[length].Name = append(metricLabels[length].Name, string(*label.Name))
			metricLabels[length].Value = append(metricLabels[length].Value, "")
		}
	}

	return
}

func (request *CmdRequest) sendMetrics(metricLabels []Labels, ch chan<- prometheus.Metric) {
	help := "A metric generated by qubership-version-exporter ssh collector."
	if len(strings.TrimSpace(request.Description)) > 0 {
		help = fmt.Sprintf("%s Description: %s.", help, request.Description)
	}

	cache := make(map[string]*prometheus.CounterVec)
	for _, lPair := range metricLabels {
		lPair.Name = append(lPair.Name, commonLabel)
		lPair.Value = append(lPair.Value, commonLabelValue)

		desc := prometheus.NewDesc(
			request.MetricName,
			help,
			lPair.Name,
			map[string]string{},
		).String()

		if v, found := cache[desc]; found && v != nil {
			v.WithLabelValues(lPair.Value...).Inc()
		} else {
			resultMetric := prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: request.MetricName,
					Help: help,
				},
				lPair.Name,
			)
			resultMetric.WithLabelValues(lPair.Value...).Inc()
			cache[desc] = resultMetric
		}
	}

	for _, v := range cache {
		v.MetricVec.Collect(ch)
	}
}

func publicKeyFromFile(privateKeyFile string) (ssh.AuthMethod, error) {
	key, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(signer), nil
}

func publicKey(privateKey []byte) (ssh.AuthMethod, error) {
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(signer), nil
}
