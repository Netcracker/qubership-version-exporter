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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"runtime"

	"github.com/Netcracker/qubership-version-exporter/pkg/logger"
	collectorModel "github.com/Netcracker/qubership-version-exporter/pkg/model/http"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

var httpColConfig = &collectorModel.Collectors{
	Connections: []collectorModel.Connector{
		{
			Host: "https://www.example.com",
			Credentials: collectorModel.Credentials{
				Namespace: "monitoring",
				User: collectorModel.SecretKey{
					Key:  "user",
					Name: "version-exporter-extra-vars-secret",
				},
				Password: collectorModel.SecretKey{
					Key:  "password",
					Name: "version-exporter-extra-vars-secret",
				},
			},
			TlsConfig: collectorModel.TLSConfig{
				TLSSkip:   false,
				Namespace: "monitoring",
				CA: collectorModel.SecretKey{
					Key:  "cert-ca.pem",
					Name: "secret-certificate-authority",
				},
			},
			Requests: []collectorModel.RequestConfig{
				{
					Path:       "/version",
					Method:     "get",
					MetricName: "versions_ci_metric",
					Metrics: []collectorModel.Metric{
						{
							JsonPath: "{.plugins[*]['.name','.version']}",
							Labels: []collectorModel.Label{
								{
									Name:   "name",
									Regexp: "[a-zA-Z0-9. ]*",
								},
								{
									Name:   "version",
									Regexp: "[a-z0-9.+-]*",
								},
							},
						},
						{
							JsonPath: "{..required_version}",
							Labels: []collectorModel.Label{
								{
									Name:   "requiredVersion",
									Regexp: "[a-zA-Z0-9.+-]*",
								},
							},
						},
					},
				},
			},
		},
		{
			Host: "https://255.255.255.255:6300",
			Credentials: collectorModel.Credentials{
				Namespace: "monitoring",
				Token: collectorModel.SecretKey{
					Key:  "token",
					Name: "version-exporter-extra-vars-secret",
				},
			},
			TlsConfig: collectorModel.TLSConfig{
				TLSSkip: true,
			},
			Requests: []collectorModel.RequestConfig{
				{
					Path:       "/version_text",
					Method:     "GET",
					MetricName: "versions_ci_metric_text",
					Metrics: []collectorModel.Metric{
						{
							Labels: []collectorModel.Label{
								{
									Name:   "federate_version",
									Regexp: "\\,version=\"(?P<version>[\\d\\w\\.]+)\"",
								},
								{
									Name:   "container_name",
									Regexp: "container=\"([\\-\\d\\w\\.]+)\"",
								},
							},
						},
						{
							Labels: []collectorModel.Label{
								{
									Name:   "plugin_id",
									Regexp: "plugin_id=\"(?P<id>[\\-\\d\\w\\.]+)\"",
								},
							},
						},
					},
				},
			},
		},
	},
}

// editorconfig-checker-disable
var testResponseJson = []byte(`
{
  "plugins": [
    {
      "name": "ArchivingPlugin",
      "author": "Qubership",
      "url": "https://github.com/graylog-archiving-plugin",
      "version": "0.0.7",
      "description": "Plugin for archiving messages",
      "unique_id": "org.qubership.graylog2.plugin.ArchivingPlugin",
      "required_version": "2.0.0-alpha.3",
      "required_capabilities": []
    },
    {
      "name": "Elasticsearch 7 Support",
      "author": "Graylog, Inc.",
      "url": "https://www.graylog.org",
      "version": "4.1.5+01c9198",
      "description": "Support for Elasticsearch 7",
      "unique_id": "org.graylog.storage.elasticsearch7.Elasticsearch7Plugin",
      "required_version": "4.1.5+01c9198",
      "required_capabilities": []
    },
    {
      "name": "ArcSightSyslogOutputPluginEnh NC",
      "author": "Qubership",
      "url": "https://qubership.org",
      "version": "1.0.0",
      "description": "Enables sending messages to ArcSite via TCP, UDP and TCP over SSL.",
      "unique_id": "org.qubership.graylog2.plugin.ArcSightSyslogOutput",
      "required_version": "2.1.1",
      "required_capabilities": []
    },
    {
      "name": "Internal Metrics Prometheus Reporter",
      "author": "Graylog, Inc.",
      "url": "https://www.graylog.org/",
      "version": "1.4.0",
      "description": "A plugin for reporting internal Graylog metrics to Prometheus.",
      "unique_id": "org.graylog.plugins.metrics.prometheus.MetricsPrometheusReporterMetaData",
      "required_version": "2.0.0",
      "required_capabilities": []
    },
    {
      "name": "Threat Intelligence Plugin",
      "author": "Graylog, Inc.",
      "url": "https://github.com/Graylog2/graylog-plugin-threatintel",
      "version": "4.1.5",
      "description": "Threat intelligence database lookup functions for the Graylog Pipeline Processor",
      "unique_id": "org.graylog.plugins.threatintel.ThreatIntelPlugin",
      "required_version": "4.1.5",
      "required_capabilities": []
    },
    {
      "name": "SyslogOutputPlugin",
      "author": "Qubership",
      "url": "https://qubership.org",
      "version": "1.0.0",
      "description": "Enables sending messages to syslog via TCP, UDP and TCP over SSL.",
      "unique_id": "org.qubership.graylog2.plugin.SyslogOutput",
      "required_version": "2.1.1",
      "required_capabilities": []
    },
    {
      "name": "SyslogOutputPlugin",
      "author": "Wizecore. Based on work by Intelie.",
      "url": "https://github.com/wizecore/graylog2-output-syslog",
      "version": "1.0.0",
      "description": "Enables sending messages to syslog via TCP, UDP and TCP over SSL.",
      "unique_id": "com.wizecore.graylog2.plugin.SyslogOutput",
      "required_version": "2.1.1",
      "required_capabilities": []
    },
    {
      "name": "Integrations",
      "author": "Graylog, Inc. <hello@graylog.com>",
      "url": "https://github.com/Graylog2/graylog-plugin-integrations.git",
      "version": "4.1.5",
      "description": "A collection of plugins that integrate external systems with Graylog.",
      "unique_id": "org.graylog.integrations.IntegrationsPlugin",
      "required_version": "4.1.5",
      "required_capabilities": []
    },
    {
      "name": "Collector",
      "author": "Graylog, Inc.",
      "url": "http://docs.graylog.org/en/latest/pages/collector_sidecar.html",
      "version": "4.1.5",
      "description": "Collectors plugin",
      "unique_id": "org.graylog.plugins.collector.CollectorPlugin",
      "required_version": "4.1.5",
      "required_capabilities": []
    },
    {
      "name": "ObfuscationPlugin",
      "author": "Qubership",
      "url": "https://github.com/PROD.Platform.Logging/graylog-obfuscation-plugin",
      "version": "1.1.0",
      "description": "Plugin for obfuscation input messages",
      "unique_id": "org.qubership.graylog2.plugin.ObfuscationPlugin",
      "required_version": "3.3.0",
      "required_capabilities": []
    },
    {
      "name": "AWS plugins",
      "author": "Graylog, Inc.",
      "url": "https://github.com/Graylog2/graylog-plugin-aws/",
      "version": "4.1.5",
      "description": "Collection of plugins to read data from or interact with the Amazon Web Services (AWS).",
      "unique_id": "org.graylog.aws.AWSPlugin",
      "required_version": "4.1.5",
      "required_capabilities": []
    },
    {
      "name": "Elasticsearch 6 Support",
      "author": "Graylog, Inc.",
      "url": "https://www.graylog.org",
      "version": "4.1.5+01c9198",
      "description": "Support for Elasticsearch 6",
      "unique_id": "org.graylog.storage.elasticsearch6.Elasticsearch6Plugin",
      "required_version": "4.1.5+01c9198",
      "required_capabilities": []
    }
  ]
}`)

var responseJsonNoName = []byte(`
{
  "plugins": [
    {
      "name": "ArchivingPlugin",
      "author": "Qubership",
      "url": "https://github.com/PROD.Platform.Logging/graylog-archiving-plugin",
      "version": "0.0.7",
      "description": "Plugin for archiving messages",
      "unique_id": "org.qubership.graylog2.plugin.ArchivingPlugin",
      "required_version": "2.0.0-alpha.3",
      "required_capabilities": []
    },
    {
      "author": "Graylog, Inc.",
      "url": "https://www.graylog.org",
      "version": "4.1.5+01c9198",
      "description": "Support for Elasticsearch 7",
      "unique_id": "org.graylog.storage.elasticsearch7.Elasticsearch7Plugin",
      "required_version": "4.1.5+01c9198",
      "required_capabilities": []
    },
    {
      "name": "ArcSightSyslogOutputPluginEnh NC",
      "author": "Qubership",
      "url": "https://qubership.org",
      "version": "1.0.0",
      "description": "Enables sending messages to ArcSite via TCP, UDP and TCP over SSL.",
      "unique_id": "org.qubership.graylog2.plugin.ArcSightSyslogOutput",
      "required_version": "2.1.1",
      "required_capabilities": []
    },
    {
      "name": "Internal Metrics Prometheus Reporter",
      "author": "Graylog, Inc.",
      "url": "https://www.graylog.org/",
      "version": "1.4.0",
      "description": "A plugin for reporting internal Graylog metrics to Prometheus.",
      "unique_id": "org.graylog.plugins.metrics.prometheus.MetricsPrometheusReporterMetaData",
      "required_version": "2.0.0",
      "required_capabilities": []
    },
    {
      "name": "Threat Intelligence Plugin",
      "author": "Graylog, Inc.",
      "url": "https://github.com/Graylog2/graylog-plugin-threatintel",
      "version": "4.1.5",
      "description": "Threat intelligence database lookup functions for the Graylog Pipeline Processor",
      "unique_id": "org.graylog.plugins.threatintel.ThreatIntelPlugin",
      "required_version": "4.1.5",
      "required_capabilities": []
    },
    {
      "name": "SyslogOutputPlugin",
      "author": "Qubership",
      "url": "https://qubership.org",
      "version": "1.0.0",
      "description": "Enables sending messages to syslog via TCP, UDP and TCP over SSL.",
      "unique_id": "org.qubership.graylog2.plugin.SyslogOutput",
      "required_version": "2.1.1",
      "required_capabilities": []
    },
    {
      "name": "SyslogOutputPlugin",
      "author": "Wizecore. Based on work by Intelie.",
      "url": "https://github.com/wizecore/graylog2-output-syslog",
      "version": "1.0.0",
      "description": "Enables sending messages to syslog via TCP, UDP and TCP over SSL.",
      "unique_id": "com.wizecore.graylog2.plugin.SyslogOutput",
      "required_version": "2.1.1",
      "required_capabilities": []
    },
    {
      "name": "Integrations",
      "author": "Graylog, Inc. <hello@graylog.com>",
      "url": "https://github.com/Graylog2/graylog-plugin-integrations.git",
      "version": "4.1.5",
      "description": "A collection of plugins that integrate external systems with Graylog.",
      "unique_id": "org.graylog.integrations.IntegrationsPlugin",
      "required_version": "4.1.5",
      "required_capabilities": []
    },
    {
      "name": "Collector",
      "author": "Graylog, Inc.",
      "url": "http://docs.graylog.org/en/latest/pages/collector_sidecar.html",
      "version": "4.1.5",
      "description": "Collectors plugin",
      "unique_id": "org.graylog.plugins.collector.CollectorPlugin",
      "required_version": "4.1.5",
      "required_capabilities": []
    },
    {
      "name": "ObfuscationPlugin",
      "author": "Qubership",
      "url": "https://github.com/PROD.Platform.Logging/graylog-obfuscation-plugin",
      "version": "1.1.0",
      "description": "Plugin for obfuscation input messages",
      "unique_id": "org.qubership.graylog2.plugin.ObfuscationPlugin",
      "required_version": "3.3.0",
      "required_capabilities": []
    },
    {
      "name": "AWS plugins",
      "author": "Graylog, Inc.",
      "url": "https://github.com/Graylog2/graylog-plugin-aws/",
      "version": "4.1.5",
      "description": "Collection of plugins to read data from or interact with the Amazon Web Services (AWS).",
      "unique_id": "org.graylog.aws.AWSPlugin",
      "required_version": "4.1.5",
      "required_capabilities": []
    },
    {
      "name": "Elasticsearch 6 Support",
      "author": "Graylog, Inc.",
      "url": "https://www.graylog.org",
      "version": "4.1.5+01c9198",
      "description": "Support for Elasticsearch 6",
      "unique_id": "org.graylog.storage.elasticsearch6.Elasticsearch6Plugin",
      "required_version": "4.1.5+01c9198",
      "required_capabilities": []
    }
  ]
}`)

var responseJson = []byte(`
{
  "firstName": "John",
  "lastName" : "Doe",
  "age"      : 26,
  "address"  : {
    "streetAddress": "naist street",
    "city"         : "Nara",
    "postalCode"   : "630-0192"
  },
  "phoneNumbers": [
    {
      "type"  : "iPhone",
      "number": "0123-4567-8888"
    },
    {
      "type"  : "home",
      "number": "0123-4567-8910"
    }
  ]
}
`)

var testResponseText = []byte(`
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="blackmirror1-singlestat-math-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="1.1.8",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="agenty-flowcharting-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="0.9.1",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="briangann-gauge-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="0.0.8",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="cloudspout-button-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="7.0.23",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="digiapulssi-breadcrumb-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="1.1.7",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="flant-statusmap-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="0.4.1",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="grafana-piechart-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="1.6.1",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="input",plugin_type="datasource",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="1.0.0",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="jdbranham-diagram-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="1.7.3",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="marcuscalidus-svg-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="0.3.4",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="michaeldmoore-multistat-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="1.7.2",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="natel-discrete-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="0.1.1",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="neocat-cal-heatmap-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="0.0.4",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="novatec-sdg-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="2.3.1",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="simpod-json-datasource",plugin_type="datasource",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="0.2.5",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="vertamedia-clickhouse-datasource",plugin_type="datasource",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="2.3.1",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
grafana_plugin_build_info{container="grafana",endpoint="grafana-http",instance="x.x.x.x:3000",job="prometheus-operator/prometheus-operator-grafana-pod-monitor",namespace="prometheus-operator",plugin_id="vonage-status-panel",plugin_type="panel",pod="grafana-deployment-5948bc84f7-7fxwr",signature_status="valid",version="1.0.11",prometheus="prometheus-operator/k8s",prometheus_replica="prometheus-k8s-0"} 1 1641988802742
`)

var names = map[string]struct{}{
	"ArchivingPlugin":                      {},
	"Elasticsearch 7 Support":              {},
	"ArcSightSyslogOutputPluginEnh NC":     {},
	"Internal Metrics Prometheus Reporter": {},
	"Threat Intelligence Plugin":           {},
	"SyslogOutputPlugin":                   {},
	"Integrations":                         {},
	"Collector":                            {},
	"ObfuscationPlugin":                    {},
	"AWS plugins":                          {},
	"Elasticsearch 6 Support":              {},
}
var versions = map[string]struct{}{
	"0.0.7":         {},
	"4.1.5+01c9198": {},
	"1.0.0":         {},
	"1.4.0":         {},
	"4.1.5":         {},
	"1.1.0":         {},
}
var requiredVersion = map[string]float64{
	"2.0.0-alpha.3": 1,
	"4.1.5+01c9198": 2,
	"2.1.1":         3,
	"2.0.0":         1,
	"4.1.5":         4,
	"3.3.0":         1,
}

var federateVersion = map[string]float64{
	"1.1.8":  1,
	"0.9.1":  1,
	"0.0.8":  1,
	"7.0.23": 1,
	"1.1.7":  1,
	"0.4.1":  1,
	"1.6.1":  1,
	"1.0.0":  1,
	"1.7.3":  1,
	"0.3.4":  1,
	"1.7.2":  1,
	"0.1.1":  1,
	"0.0.4":  1,
	"2.3.1":  2,
	"0.2.5":  1,
	"1.0.11": 1,
}

var pluginId = map[string]struct{}{
	"blackmirror1-singlestat-math-panel": {},
	"agenty-flowcharting-panel":          {},
	"briangann-gauge-panel":              {},
	"cloudspout-button-panel":            {},
	"digiapulssi-breadcrumb-panel":       {},
	"flant-statusmap-panel":              {},
	"grafana-piechart-panel":             {},
	"input":                              {},
	"jdbranham-diagram-panel":            {},
	"marcuscalidus-svg-panel":            {},
	"michaeldmoore-multistat-panel":      {},
	"natel-discrete-panel":               {},
	"neocat-cal-heatmap-panel":           {},
	"novatec-sdg-panel":                  {},
	"simpod-json-datasource":             {},
	"vertamedia-clickhouse-datasource":   {},
	"vonage-status-panel":                {},
}
// editorconfig-checker-enable

// SecretDataReactor sets the secret.Data field based on the values from secret.StringData
func SecretDataReactor(action ktesting.Action) (bool, runtime.Object, error) {
	secret, ok := action.(ktesting.CreateAction).GetObject().(*v1.Secret)
	if !ok {
		return false, nil, fmt.Errorf("SecretDataReactor can only be applied on secrets")
	}

	if len(secret.StringData) > 0 {
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}

		for k, v := range secret.StringData {
			secret.Data[k] = []byte(v)
		}
	}

	return false, nil, nil
}

func initMockK8sClient(ctx context.Context, caCert []byte) (*fake.Clientset, error) {
	clientSet := fake.NewSimpleClientset()
	clientSet.PrependReactor("create", "secrets", SecretDataReactor)

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "monitoring",
			Name:      "version-exporter-extra-vars-secret",
		},
		StringData: map[string]string{
			"user":     "user",
			"password": "password",
			"token":    "tokEn",
		},
		Type: v1.SecretTypeOpaque,
	}

	certSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "monitoring",
			Name:      "secret-certificate-authority",
		},
		Data: map[string][]byte{
			"cert-ca.pem": caCert,
		},
		Type: v1.SecretTypeOpaque,
	}

	_, err := clientSet.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	_, err = clientSet.CoreV1().Secrets(certSecret.Namespace).Create(ctx, certSecret, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return clientSet, err
}

func initMockServerHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if r.URL.Path == "/version" {
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write(testResponseJson)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			} else if r.URL.Path == "/version_text" {
				_, err := w.Write(testResponseText)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			}
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestHttpCollector_Initialize(t *testing.T) {
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotNil(t, ctx)
	caCert, err := os.ReadFile("testdata/config/http_collector/certificate/test-server.crt")
	if !assert.NoError(t, err) {
		return
	}
	clientSet, err := initMockK8sClient(ctx, caCert)
	if !assert.NoError(t, err, "no error expected on k8s client init") {
		return
	}

	serverString := "https://www.example.com"
	collConfig := httpColConfig
	collConfig.ClientSet = clientSet
	for i := range collConfig.Connections {
		collConfig.Connections[i].Host = serverString
	}

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}

	assert.NotNil(t, col)
	assert.Equal(t, HttpType.String(), col.Name())
	assert.Equal(t, HttpType, col.Type())

	err = col.Initialize(ctx, *collConfig)
	if !assert.NoError(t, err, "no error expected on http_collector initializing") {
		return
	}
	httpCol := col.(*HttpCollector)

	assert.NotNil(t, httpCol.requests)
	assert.Equal(t, 2, len(httpCol.requests))

	assert.Equal(t, serverString+"/version", httpCol.requests[0].path)
	assert.Equal(t, http.MethodGet, httpCol.requests[0].method)
	assert.NotNil(t, httpCol.requests[0].transport)
	assert.NotNil(t, httpCol.requests[0].transport.TLSClientConfig)
	assert.False(t, httpCol.requests[0].transport.TLSClientConfig.InsecureSkipVerify)
	assert.NotEmpty(t, httpCol.requests[0].transport.TLSClientConfig.RootCAs)

	assert.NotNil(t, httpCol.requests[0].auth)
	assert.Equal(t, "user", httpCol.requests[0].auth.name)
	assert.Equal(t, "password", httpCol.requests[0].auth.password)
	assert.Empty(t, httpCol.requests[0].auth.token)

	assert.Equal(t, "versions_ci_metric", httpCol.requests[0].metricName)
	assert.Empty(t, httpCol.requests[0].description)

	assert.NotEmpty(t, httpCol.requests[0].metrics)
	assert.Equal(t, 2, len(httpCol.requests[0].metrics))

	assert.NotNil(t, httpCol.requests[0].metrics[0].jsonPath)
	assert.Equal(t, "{.plugins[*]['.name','.version']}", httpCol.requests[0].metrics[0].jsonPathStr)
	assert.NotEmpty(t, httpCol.requests[0].metrics[0].labels)
	assert.Equal(t, 2, len(httpCol.requests[0].metrics[0].labels))
	assert.Equal(t, model.LabelName("name"), *httpCol.requests[0].metrics[0].labels[0].name)
	assert.NotNil(t, httpCol.requests[0].metrics[0].labels[0].valueRegexp)
	assert.Equal(t, model.LabelName("version"), *httpCol.requests[0].metrics[0].labels[1].name)
	assert.NotNil(t, httpCol.requests[0].metrics[0].labels[1].valueRegexp)

	assert.NotNil(t, httpCol.requests[0].metrics[1].jsonPath)
	assert.Equal(t, "{..required_version}", httpCol.requests[0].metrics[1].jsonPathStr)
	assert.NotEmpty(t, httpCol.requests[0].metrics[1].labels)
	assert.Equal(t, 1, len(httpCol.requests[0].metrics[1].labels))
	assert.Equal(t, model.LabelName("requiredVersion"), *httpCol.requests[0].metrics[1].labels[0].name)
	assert.NotNil(t, httpCol.requests[0].metrics[1].labels[0].valueRegexp)

	assert.Equal(t, serverString+"/version_text", httpCol.requests[1].path)
	assert.Equal(t, http.MethodGet, httpCol.requests[1].method)
	assert.NotEqual(t, nil, httpCol.requests[1].transport)
	assert.NotEqual(t, nil, httpCol.requests[1].transport.TLSClientConfig)
	assert.True(t, httpCol.requests[1].transport.TLSClientConfig.InsecureSkipVerify)
	assert.Empty(t, httpCol.requests[1].transport.TLSClientConfig.RootCAs)
	assert.Empty(t, httpCol.requests[1].transport.TLSClientConfig.Certificates)

	assert.NotNil(t, httpCol.requests[1].auth)
	assert.Empty(t, httpCol.requests[1].auth.name)
	assert.Empty(t, httpCol.requests[1].auth.password)
	assert.Equal(t, "tokEn", httpCol.requests[1].auth.token)

	assert.Equal(t, "versions_ci_metric_text", httpCol.requests[1].metricName)
	assert.Empty(t, httpCol.requests[1].description)

	assert.NotEmpty(t, httpCol.requests[1].metrics)
	assert.Equal(t, 2, len(httpCol.requests[1].metrics))
	assert.Nil(t, httpCol.requests[1].metrics[0].jsonPath)
	assert.Empty(t, httpCol.requests[1].metrics[0].jsonPathStr)
	assert.NotEmpty(t, httpCol.requests[1].metrics[0].labels)
	assert.Equal(t, 2, len(httpCol.requests[1].metrics[0].labels))
	assert.Equal(t, model.LabelName("federate_version"), *httpCol.requests[1].metrics[0].labels[0].name)
	assert.NotNil(t, httpCol.requests[1].metrics[0].labels[0].valueRegexp)
	assert.Equal(t, model.LabelName("container_name"), *httpCol.requests[1].metrics[0].labels[1].name)
	assert.NotNil(t, httpCol.requests[1].metrics[0].labels[1].valueRegexp)

	assert.Nil(t, httpCol.requests[1].metrics[1].jsonPath)
	assert.Empty(t, httpCol.requests[1].metrics[1].jsonPathStr)
	assert.NotEmpty(t, httpCol.requests[1].metrics[1].labels)
	assert.Equal(t, 1, len(httpCol.requests[1].metrics[1].labels))
	assert.Equal(t, model.LabelName("plugin_id"), *httpCol.requests[1].metrics[1].labels[0].name)
	assert.NotNil(t, httpCol.requests[1].metrics[1].labels[0].valueRegexp)

}

func TestHttpCollector_Scrape(t *testing.T) {
	t.Skip("Skip this test, because mocked Http server is not working with TLS")

	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotEqual(t, nil, ctx)
	handler := initMockServerHandler()
	server := httptest.NewTLSServer(handler)
	defer server.Close()

	caCert, err := os.ReadFile("testdata/config/http_collector/certificate/test-server.crt")
	if !assert.NoError(t, err) {
		return
	}
	clientSet, err := initMockK8sClient(ctx, caCert)
	if !assert.NoError(t, err, "no error expected on k8s client init") {
		return
	}

	collConfig := httpColConfig
	collConfig.ClientSet = clientSet
	for i := range collConfig.Connections {
		collConfig.Connections[i].Host = server.URL
	}

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}

	err = col.Initialize(ctx, *collConfig)
	if !assert.NoError(t, err, "no error expected on http_collector initializing") {
		return
	}

	metricCh := make(chan prometheus.Metric)
	endCh := make(chan struct{})
	var metrics []*dto.Metric
	defer close(metricCh)
	go func() {
		errScrape := col.Scrape(ctx, nil, metricCh)
		if !assert.NoError(t, errScrape, "no error expected on http_collector scraping") {
			return
		}
		close(endCh)
	}()
	for {
		select {
		case mt := <-metricCh:
			metric := &dto.Metric{}
			errWrite := mt.Write(metric)
			assert.Empty(t, errWrite)
			assert.True(t, len(metric.Label) > 1) // more than collector.commonLabel
			assert.NotNil(t, metric.Counter)
			assert.True(t, metric.Counter.GetValue() >= 1)
			metrics = append(metrics, metric)
			continue
		case <-endCh:
			break
		}
		break
	}

	assert.Equal(t, 50, len(metrics))
	//pairs of labels/values can be stored in different order
	var check1, check2, check3, check4, check5, check6, check7 int
	for _, metric := range metrics {
		for _, pair := range metric.Label {

			if *pair.Name == "container_name" {
				assert.NotNil(t, pair.Value)
				assert.Equal(t, "container=\"grafana\"", *pair.Value)
				check1++
			}

			if *pair.Name == "federate_version" {
				assert.NotNil(t, pair.Value)
				val, found := federateVersion[*pair.Value]
				assert.True(t, found)
				assert.True(t, metric.Counter.GetValue() == val)
				check2++
			}

			if *pair.Name == "plugin_id" {
				assert.NotNil(t, pair.Value)
				_, found := pluginId[*pair.Value]
				assert.True(t, found)
				check3++
			}

			if *pair.Name == "name" {
				assert.NotNil(t, pair.Value)
				_, found := names[*pair.Value]
				assert.True(t, found)
				check4++
			}

			if *pair.Name == "version" {
				assert.NotNil(t, pair.Value)
				_, found := versions[*pair.Value]
				assert.True(t, found)
				check5++
			}

			if *pair.Name == "requiredVersion" {
				assert.NotNil(t, pair.Value)
				val, found := requiredVersion[*pair.Value]
				assert.True(t, found)
				assert.True(t, metric.Counter.GetValue() == val)
				check6++
			}

			if *pair.Name == commonLabel {
				assert.NotNil(t, pair.Value)
				assert.Equal(t, commonLabelValue, *pair.Value)
				check7++
			}

		}

	}

	assert.True(t, check1 == 16 && check2 == 16 && check3 == 17 && check4 == 11 && check5 == 11 && check6 == 6 && check7 == 50)
}

func TestHttpCollector_jsonpathFilterUnion_parseJsonResponse(t *testing.T) {

	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotNil(t, ctx)

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}

	res := &http.Response{
		Body: io.NopCloser(bytes.NewBuffer(testResponseJson)),
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		StatusCode: 200,
	}
	httpCol := col.(*HttpCollector)

	labs := []collectorModel.Metric{
		{
			JsonPath: "{.plugins[?(@.version)]['name','version']}",
			Labels: []collectorModel.Label{
				{
					Name:   "pluginName",
					Regexp: "[a-zA-Z0-9. ]*",
				},
				{
					Name:   "pluginVersion",
					Regexp: "[a-zA-Z0-9.+]*",
				},
			},
		},
	}

	var metrics []HttpMetric
	metrics, err = httpCol.InitializeConfig(labs)
	assert.NoError(t, err, "no error expected on http_collector config initializing")
	metricLabels := httpCol.parseResponse(res, metrics)

	assert.Equal(t, 1, len(metricLabels))
	assert.Equal(t, 12, len(metricLabels[0]))
	var check1, check2 int
	for _, label := range metricLabels[0] {
		for i, name := range label.Name {
			if name == "pluginName" {
				_, found := names[label.Value[i]]
				assert.True(t, found)
				check1++
			}

			if name == "pluginVersion" {
				_, found := versions[label.Value[i]]
				assert.True(t, found)
				check2++
			}
		}
	}

	assert.True(t, check1 == 12 && check2 == 12)
}

func TestHttpCollector_jsonpathWildcardUnion_parseJsonResponse(t *testing.T) {

	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotNil(t, ctx)

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}

	res := &http.Response{
		Body: io.NopCloser(bytes.NewBuffer(testResponseJson)),
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		StatusCode: 200,
	}
	httpCol := col.(*HttpCollector)

	labs := []collectorModel.Metric{
		{
			JsonPath: "{.plugins[*]['name','version']}",
			Labels: []collectorModel.Label{
				{
					Name:   "pluginName",
					Regexp: "[a-zA-Z0-9. ]*",
				},
				{
					Name:   "pluginVersion",
					Regexp: "[a-zA-Z0-9.+]*",
				},
			},
		},
	}

	var metrics []HttpMetric
	metrics, err = httpCol.InitializeConfig(labs)
	assert.NoError(t, err, "no error expected on http_collector config initializing")
	metricLabels := httpCol.parseResponse(res, metrics)

	assert.Equal(t, 1, len(metricLabels))
	assert.Equal(t, 12, len(metricLabels[0]))
	var check1, check2 int
	for _, label := range metricLabels[0] {
		for i, name := range label.Name {
			if name == "pluginName" {
				_, found := names[label.Value[i]]
				assert.True(t, found)
				check1++
			}

			if name == "pluginVersion" {
				_, found := versions[label.Value[i]]
				assert.True(t, found)
				check2++
			}
		}
	}

	assert.True(t, check1 == 12 && check2 == 12)
}

func TestHttpCollector_jsonpathWildcardUnion_parseJsonNoOneNameResponse(t *testing.T) {

	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotNil(t, ctx)

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}

	res := &http.Response{
		Body: io.NopCloser(bytes.NewBuffer(responseJsonNoName)),
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		StatusCode: 200,
	}
	httpCol := col.(*HttpCollector)

	labs := []collectorModel.Metric{
		{
			JsonPath: "{.plugins[*]['name','version']}",
			Labels: []collectorModel.Label{
				{
					Name:   "pluginName",
					Regexp: "[a-zA-Z0-9. ]*",
				},
				{
					Name:   "pluginVersion",
					Regexp: "[a-zA-Z0-9.+]*",
				},
			},
		},
	}

	var metrics []HttpMetric
	metrics, err = httpCol.InitializeConfig(labs)
	assert.NoError(t, err, "no error expected on http_collector config initializing")
	metricLabels := httpCol.parseResponse(res, metrics)

	assert.Equal(t, 1, len(metricLabels))
	assert.Nil(t, metricLabels[0])
}

func TestHttpCollector_jsonpathWildcardRange_parseJsonNoOneNameResponse(t *testing.T) {

	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotNil(t, ctx)

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}

	res := &http.Response{
		Body: io.NopCloser(bytes.NewBuffer(responseJsonNoName)),
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		StatusCode: 200,
	}
	httpCol := col.(*HttpCollector)

	labs := []collectorModel.Metric{
		{
			JsonPath: "{range .plugins[*]}{.name}{.version}{end}",
			Labels: []collectorModel.Label{
				{
					Name: "pluginName",
				},
				{
					Name: "pluginVersion",
				},
			},
		},
		{
			JsonPath: "{ range .plugins[*]}{.name}{.version}{end}",
			Labels: []collectorModel.Label{
				{
					Name: "pluginName",
				},
				{
					Name: "pluginVersion",
				},
			},
		},
	}

	var metrics []HttpMetric
	metrics, err = httpCol.InitializeConfig(labs)
	assert.NoError(t, err, "no error expected on http_collector config initializing")
	metricLabels := httpCol.parseResponse(res, metrics)

	assert.Equal(t, 2, len(metricLabels))
	assert.Equal(t, 12, len(metricLabels[0]))
	assert.Equal(t, 12, len(metricLabels[1]))

	for k := range metricLabels {
		for i := range metricLabels[k] {
			for j := range metricLabels[k][i].Value {
				if i == 1 && j == 0 {
					assert.Empty(t, metricLabels[k][i].Value[j])
				} else {
					assert.NotEmpty(t, metricLabels[k][i].Value[j])
				}
			}
		}
	}
}

func TestHttpCollector_jsonpathFailWildcardRange_parseJsonNoOneNameResponse(t *testing.T) {

	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotNil(t, ctx)

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}

	res := &http.Response{
		Body: io.NopCloser(bytes.NewBuffer(responseJsonNoName)),
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		StatusCode: 200,
	}
	httpCol := col.(*HttpCollector)

	labs := []collectorModel.Metric{
		{
			JsonPath: "{range .plugins[*]}[{.name}, {.version}] {end}",
			Labels: []collectorModel.Label{
				{
					Name: "pluginName",
				},
				{
					Name: "pluginVersion",
				},
			},
		},
	}

	var metrics []HttpMetric
	metrics, err = httpCol.InitializeConfig(labs)
	assert.NoError(t, err, "no error expected on http_collector config initializing")
	metricLabels := httpCol.parseResponse(res, metrics)

	assert.Equal(t, 1, len(metricLabels))
	assert.Nil(t, metricLabels[0])
}

func TestHttpCollector_jsonpath_parseJsonArrayResp(t *testing.T) {

	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotNil(t, ctx)

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}

	res := &http.Response{
		Body: io.NopCloser(bytes.NewBuffer(responseJson)),
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		StatusCode: 200,
	}
	httpCol := col.(*HttpCollector)

	labs := []collectorModel.Metric{
		{
			JsonPath: "{.phoneNumbers}",
			Labels: []collectorModel.Label{
				{
					Name:   "firstName",
					Regexp: "[a-zA-Z0-9.+]*",
				},
			},
		},
	}

	var metrics []HttpMetric
	metrics, err = httpCol.InitializeConfig(labs)
	assert.NoError(t, err, "no error expected on http_collector config initializing")
	metricLabels := httpCol.parseResponse(res, metrics)

	assert.Equal(t, 1, len(metricLabels))
	assert.Nil(t, metricLabels[0])
}

func TestHttpCollector_jsonpath_parseJsonListResp(t *testing.T) {

	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotNil(t, ctx)

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}

	res := &http.Response{
		Body: io.NopCloser(bytes.NewBuffer(responseJson)),
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		StatusCode: 200,
	}
	httpCol := col.(*HttpCollector)

	labs := []collectorModel.Metric{
		{
			JsonPath: "{['firstName','lastName']}",
			Labels: []collectorModel.Label{
				{
					Name:   "firstName",
					Regexp: "[a-zA-Z0-9. ]*",
				},
				{
					Name:   "lastName",
					Regexp: "[a-zA-Z0-9. ]*",
				},
			},
		},
	}

	var metrics []HttpMetric
	metrics, err = httpCol.InitializeConfig(labs)
	assert.NoError(t, err, "no error expected on http_collector config initializing")
	metricLabels := httpCol.parseResponse(res, metrics)

	assert.Equal(t, 1, len(metricLabels))
	assert.Equal(t, 1, len(metricLabels[0]))
	assert.Equal(t, "firstName", metricLabels[0][0].Name[0])
	assert.Equal(t, "lastName", metricLabels[0][0].Name[1])
	assert.Equal(t, "John", metricLabels[0][0].Value[0])
	assert.Equal(t, "Doe", metricLabels[0][0].Value[1])
}

func TestHttpCollector_jsonpath_parseJsonResp(t *testing.T) {

	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotNil(t, ctx)

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}

	res := &http.Response{
		Body: io.NopCloser(bytes.NewBuffer(responseJson)),
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		StatusCode: 200,
	}
	httpCol := col.(*HttpCollector)

	labs := []collectorModel.Metric{
		{
			JsonPath: "$.firstName,lastName",
			Labels: []collectorModel.Label{
				{
					Name:   "firstName",
					Regexp: "[a-zA-Z0-9. ]*",
				},
				{
					Name:   "lastName",
					Regexp: "[a-zA-Z0-9. ]*",
				},
			},
		},
	}

	var metrics []HttpMetric
	metrics, err = httpCol.InitializeConfig(labs)
	assert.NoError(t, err, "no error expected on http_collector config initializing")
	metricLabels := httpCol.parseResponse(res, metrics)

	assert.Equal(t, 1, len(metricLabels))
	assert.Nil(t, metricLabels[0])
}

func TestHttpCollector_recursiveDescent_parseJsonResponse(t *testing.T) {

	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotNil(t, ctx)

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}

	res := &http.Response{
		Body: io.NopCloser(bytes.NewBuffer(testResponseJson)),
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		StatusCode: 200,
	}
	httpCol := col.(*HttpCollector)

	labs := []collectorModel.Metric{
		{
			JsonPath: "{..name}",
			Labels: []collectorModel.Label{
				{
					Name:   "pluginName",
					Regexp: "[a-zA-Z0-9. ]*",
				},
			},
		},
	}

	var metrics []HttpMetric
	metrics, err = httpCol.InitializeConfig(labs)
	assert.NoError(t, err, "no error expected on http_collector config initializing")
	metricLabels := httpCol.parseResponse(res, metrics)

	assert.Equal(t, 1, len(metricLabels))
	assert.Equal(t, 12, len(metricLabels[0]))
	var check int
	for _, label := range metricLabels[0] {
		for i := range label.Name {
			_, found := names[label.Value[i]]
			assert.True(t, found)
			check++
		}
	}

	assert.True(t, check == 12)
}

func TestHttpCollector_parseTextResponse(t *testing.T) {
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())
	assert.NotEqual(t, nil, ctx)

	col, err := newHttpCollector(*logger.New(&logger.Config{Writer: os.Stderr}))
	if !assert.NoError(t, err, "no error expected on http_collector creating") {
		return
	}
	testResponse := []byte(fmt.Sprintf("go1.13.15 linux/%s", runtime.GOARCH))
	res := &http.Response{
		Body: io.NopCloser(bytes.NewBuffer(testResponse)),
		Header: http.Header{
			"Content-Type": {"text/plain"},
		},
		StatusCode: 200,
	}
	httpCol := col.(*HttpCollector)

	labs := []collectorModel.Metric{
		{
			Labels: []collectorModel.Label{
				{
					Name:   "go",
					Regexp: "[0-9.].[0-9.].[0-9.]+",
				},
				{
					Name:   "os",
					Regexp: "[a-z]+\\/.*",
				},
			},
		},
	}

	var metrics []HttpMetric
	metrics, err = httpCol.InitializeConfig(labs)
	assert.NoError(t, err, "no error expected on http_collector config initializing")
	metricLabels := httpCol.parseResponse(res, metrics)

	assert.Equal(t, 1, len(metricLabels))
	assert.Equal(t, 1, len(metricLabels[0]))
	assert.Equal(t, "go", metricLabels[0][0].Name[0])
	assert.Equal(t, "os", metricLabels[0][0].Name[1])
	assert.Equal(t, "1.13.15", metricLabels[0][0].Value[0])
	assert.Equal(t, fmt.Sprintf("linux/%s", runtime.GOARCH), metricLabels[0][0].Value[1])
}
