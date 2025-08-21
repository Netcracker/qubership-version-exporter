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
	"log"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Netcracker/qubership-version-exporter/pkg/logger"
	collectorModel "github.com/Netcracker/qubership-version-exporter/pkg/model/ssh"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func init() {
	newServer(port)
}

const (
	host       = "127.0.10.10"
	port       = 2200
	network    = "tcp"
	catOsCmd   = "cat /etc/os-release"
	headSshCmd = "head /etc/ssh/ssh_config"
)

var (
	knownHostsPath = "testdata/config/ssh_collector/keys/known_hosts"
	sshColConfig   = &collectorModel.Connections{
		Connections: []collectorModel.ConnOptions{
			{
				Host:    host,
				Port:    port,
				Network: network,
				Timeout: time.Second * 5,
				Credentials: &collectorModel.Credentials{
					Login:          "centos",
					PKeyPath:       "testdata/config/ssh_collector/keys/test_private_key",
					KnownHostsPath: &knownHostsPath,
				},
				Requests: []collectorModel.Request{
					{
						Cmd:         catOsCmd,
						MetricName:  "os_versions_metric",
						Description: "Metric shows os version",
						Labels: []collectorModel.Label{
							{
								Name:   "name",
								Regexp: "NAME=\"(?P<name>[a-zA-Z0-9() ]*)\"",
							},
							{
								Name:   "os_version",
								Regexp: "VERSION=\"(?P<version>[a-zA-Z0-9. ()]*)\"",
							},
							{
								Name:   "pretty_name",
								Regexp: "PRETTY_NAME=\"(?P<version>[a-zA-Z0-9. ()]*)\"",
							},
						},
					},
					{
						Cmd:         headSshCmd,
						MetricName:  "ssh_versions_metric",
						Description: "Metric shows versions of ssh component",
						Labels: []collectorModel.Label{
							{
								Name:   "ssh_version",
								Regexp: ",v (?P<version>[a-z0-9. ]*) ",
							},
						},
					},
				},
			},
		},
	}

	sshK8sColConfig = &collectorModel.Connections{
		Connections: []collectorModel.ConnOptions{
			{
				Host:    host,
				Port:    port,
				Network: network,
				Timeout: time.Second * 5,
				K8sCredentials: &collectorModel.K8sCredentials{
					Namespace: "monitoring",
					Login: collectorModel.SecretKey{
						Key:  "login",
						Name: "version-exporter-extra-vars-secret",
					},
					PKey: collectorModel.SecretKey{
						Key:  "pkey",
						Name: "version-exporter-secret",
					},
				},
				Requests: []collectorModel.Request{
					{
						Cmd:         catOsCmd,
						MetricName:  "os_versions_metric",
						Description: "Metric shows os version",
						Labels: []collectorModel.Label{
							{
								Name:   "name",
								Regexp: "NAME=\"(?P<name>[a-zA-Z0-9() ]*)\"",
							},
							{
								Name:   "os_version",
								Regexp: "VERSION=\"(?P<version>[a-zA-Z0-9. ()]*)\"",
							},
							{
								Name:   "pretty_name",
								Regexp: "PRETTY_NAME=\"(?P<version>[a-zA-Z0-9. ()]*)\"",
							},
						},
					},
					{
						Cmd:         headSshCmd,
						MetricName:  "ssh_versions_metric",
						Description: "Metric shows versions of ssh component",
						Labels: []collectorModel.Label{
							{
								Name:   "ssh_version",
								Regexp: ",v (?P<version>[a-z0-9. ]*) ",
							},
						},
					},
				},
			},
		},
	}

	sshVersions = map[string]struct{}{
		"CentOS Linux 7 (Core)": {},
		"CentOS Linux 7":        {},
		"CentOS Linux":          {},
		"7 (Core)":              {},
		"1.30":                  {},
	}
)

func TestSshCollector_Scrape(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotEqual(t, nil, ctx)

	col, err := newSSHCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on ssh_collector creating") {
		return
	}

	assert.NotNil(t, col)
	assert.Equal(t, SSHType.String(), col.Name())
	assert.Equal(t, SSHType, col.Type())

	err = col.Initialize(ctx, *sshColConfig)
	if !assert.NoError(t, err, "no error expected on ssh_collector initializing") {
		return
	}
	sshCollector := col.(*SshVersionScraper)

	assert.NotNil(t, sshCollector.SshClients)
	assert.Equal(t, 1, len(sshCollector.SshClients))

	metrics := scrape(t, ctx, sshCollector.SshClients[0])

	assert.Equal(t, 4, len(metrics))
	var check1, check2, check3, check4, check5 int
	for _, metric := range metrics {
		for _, pair := range metric.Label {

			if *pair.Name == "name" {
				assert.NotNil(t, pair.Value)
				_, found := sshVersions[*pair.Value]
				assert.True(t, found)
				assert.True(t, metric.Counter.GetValue() == 1)
				check1++
			}

			if *pair.Name == "os_version" {
				assert.NotNil(t, pair.Value)
				_, found := sshVersions[*pair.Value]
				assert.True(t, found)
				assert.True(t, metric.Counter.GetValue() == 1)
				check2++
			}

			if *pair.Name == "pretty_name" {
				assert.NotNil(t, pair.Value)
				_, found := sshVersions[*pair.Value]
				assert.True(t, found)
				assert.True(t, metric.Counter.GetValue() == 1)
				check3++
			}

			if *pair.Name == "ssh_version" {
				assert.NotNil(t, pair.Value)
				_, found := sshVersions[*pair.Value]
				assert.True(t, found)
				assert.True(t, metric.Counter.GetValue() == 2)
				check4++
			}

			if *pair.Name == commonLabel {
				assert.NotNil(t, pair.Value)
				assert.Equal(t, commonLabelValue, *pair.Value)
				check5++
			}
		}
	}

	assert.True(t, check1 == 3 && check2 == 1 && check3 == 2 && check4 == 1 && check5 == 4)
}

func TestK8SSshCollector_Scrape(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotEqual(t, nil, ctx)
	privateKey, err := os.ReadFile("testdata/config/ssh_collector/keys/test_private_key")
	if err != nil {
		log.Fatal("Failed to read file with private key: ", err)
	}
	clientSet, err := initK8sClient(ctx, privateKey)
	if !assert.NoError(t, err, "no error expected on k8s client init") {
		return
	}

	collConfig := sshK8sColConfig
	for i := range collConfig.Connections {
		collConfig.Connections[i].K8sCredentials.ClientSet = clientSet
	}
	col, err := newSSHCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on ssh_collector creating") {
		return
	}

	assert.NotNil(t, col)
	assert.Equal(t, SSHType.String(), col.Name())
	assert.Equal(t, SSHType, col.Type())

	err = col.Initialize(ctx, *collConfig)
	if !assert.NoError(t, err, "no error expected on ssh_collector initializing") {
		return
	}
	sshCollector := col.(*SshVersionScraper)

	assert.NotNil(t, sshCollector.SshClients)
	assert.Equal(t, 1, len(sshCollector.SshClients))

	metrics := scrape(t, ctx, sshCollector.SshClients[0])

	assert.Equal(t, 4, len(metrics))
	var check1, check2, check3, check4, check5 int
	for _, metric := range metrics {
		for _, pair := range metric.Label {

			if *pair.Name == "name" {
				assert.NotNil(t, pair.Value)
				_, found := sshVersions[*pair.Value]
				assert.True(t, found)
				assert.True(t, metric.Counter.GetValue() == 1)
				check1++
			}

			if *pair.Name == "os_version" {
				assert.NotNil(t, pair.Value)
				_, found := sshVersions[*pair.Value]
				assert.True(t, found)
				assert.True(t, metric.Counter.GetValue() == 1)
				check2++
			}

			if *pair.Name == "pretty_name" {
				assert.NotNil(t, pair.Value)
				_, found := sshVersions[*pair.Value]
				assert.True(t, found)
				assert.True(t, metric.Counter.GetValue() == 1)
				check3++
			}

			if *pair.Name == "ssh_version" {
				assert.NotNil(t, pair.Value)
				_, found := sshVersions[*pair.Value]
				assert.True(t, found)
				assert.True(t, metric.Counter.GetValue() == 2)
				check4++
			}

			if *pair.Name == commonLabel {
				assert.NotNil(t, pair.Value)
				assert.Equal(t, commonLabelValue, *pair.Value)
				check5++
			}
		}
	}

	assert.True(t, check1 == 3 && check2 == 1 && check3 == 2 && check4 == 1 && check5 == 4)
}

func scrape(t *testing.T, ctx context.Context, sshClient *SshClient) (metrics []*dto.Metric) {
	metricCh := make(chan prometheus.Metric)

	go func() {
		err := sshClient.doScrape(ctx, metricCh)
		assert.Empty(t, err)
		close(metricCh)
	}()

	for mt := range metricCh {
		metric := &dto.Metric{}
		err := mt.Write(metric)
		assert.Empty(t, err)
		assert.True(t, len(metric.Label) > 1) // more than collector.commonLabel
		assert.NotNil(t, metric.Counter)
		assert.True(t, metric.Counter.GetValue() >= 1)
		metrics = append(metrics, metric)
	}

	return
}

func newServer(port int) {

	privateKey, err := os.ReadFile("testdata/config/ssh_collector/keys/test_private_key")
	if err != nil {
		log.Fatal("Failed to read file with private key: ", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	pubKey := signer.PublicKey()
	authorizedKeysMap := map[string]bool{}
	authorizedKeysMap[string(pubKey.Marshal())] = true

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	config.AddHostKey(signer)

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen(network, addr)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	go func() {

		log.Printf("Listening on %s...", strconv.Itoa(port))
		for {
			nConn, err := listener.Accept()
			if err != nil {
				log.Fatal("failed to accept incoming connection: ", err)
			}

			// Before use, a handshake must be performed on the incoming net.Conn
			_, channels, requests, err := ssh.NewServerConn(nConn, config)
			if err != nil {
				log.Fatal("failed to handshake: ", err)
			}

			// The incoming Request channel must be serviced.
			go ssh.DiscardRequests(requests)

			// Service the incoming channel.
			for channel := range channels {
				go handleChannel(channel)
			}
		}
	}()
}

func handleChannel(newChannel ssh.NewChannel) {
	if t := newChannel.ChannelType(); t != "session" {
		err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		if err != nil {
			log.Fatalf("Could not reject the channel creation request: %v", err)
		}
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Fatalf("Could not accept channel: %v", err)
	}
	defer func() {
		if err := channel.Close(); err != nil {
			log.Fatalf("Could not close channel: %v", err)
		}
	}()

	req := <-requests
	if req.Type != "exec" {
		log.Print(fmt.Errorf("unsupported request type: %s", req.Type))
		return
	}

	if !req.WantReply {
		log.Print(fmt.Errorf("it is expected that want reply is always set"))
	}

	// first 4 bytes is length, ignore it
	cmd := string(req.Payload[4:])

	var reply []byte
	switch cmd {
	case catOsCmd:
		reply, err = os.ReadFile("testdata/config/ssh_collector/replies/os_release")
		if err != nil {
			log.Print(fmt.Errorf("failed to read os_release file: %v", err))
		}
	case headSshCmd:
		reply, err = os.ReadFile("testdata/config/ssh_collector/replies/ssh_config")
		if err != nil {
			log.Print(fmt.Errorf("failed to read ssh_config file: %v", err))
		}
	default:
		log.Print(fmt.Errorf("unsupported cmd: %s", cmd))
	}

	err = req.Reply(true, nil)
	if err != nil {
		log.Print(fmt.Errorf("handler reply error: %v", err))
	}

	_, err = channel.Write(reply)
	if err != nil {
		log.Print(fmt.Errorf("write reply error: %v", err))
	}
	_, err = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
	if err != nil {
		log.Print(fmt.Errorf("unable to send exit status: %v", err))
	}
}

func initK8sClient(ctx context.Context, privateKey []byte) (*fake.Clientset, error) {
	clientSet := fake.NewSimpleClientset()
	clientSet.PrependReactor("create", "secrets", SecretDataReactor)

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "monitoring",
			Name:      "version-exporter-extra-vars-secret",
		},
		StringData: map[string]string{
			"login": "centos",
		},
		Type: v1.SecretTypeOpaque,
	}

	pkeySecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "monitoring",
			Name:      "version-exporter-secret",
		},
		Data: map[string][]byte{
			"pkey": privateKey,
		},
		Type: v1.SecretTypeOpaque,
	}

	_, err := clientSet.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	_, err = clientSet.CoreV1().Secrets(pkeySecret.Namespace).Create(ctx, pkeySecret, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return clientSet, err
}
