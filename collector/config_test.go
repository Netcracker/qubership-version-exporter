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
	"errors"
	"path/filepath"
	"regexp"
	"testing"

	configmapModel "qubership-version-exporter/model/configmap"
	httpModel "qubership-version-exporter/model/http"
	"qubership-version-exporter/model/postgres"
	sshModel "qubership-version-exporter/model/ssh"
	"github.com/go-kit/log"
	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	pgCollectorConfigPath                   = "postgres_collector"
	collectorNegativeConfigPath             = "/negative"
	clusterMetricFieldName                  = "version"
	metricServerFieldName                   = "server_version"
	pgNamespace                             = "monitoring"
	pgSecretName                            = "version-exporter-extra-vars-secret"
	pgUsernameKey                           = "pgUsername"
	pgPasswordKey                           = "pgPassword"
	pgDbName                                = "postgres"
	pgClusterPort                           = 5432
	pgClusterUri                            = "pg-patroni.postgres12.svc"
	pgPort                                  = 30063
	pgUri                                   = "x.x.x.x"
	pgTimeout                               = "10s"
	clusterRegexp                           = "\\s((?P<major>\\d+).(?P<minor>\\d+))\\son\\s(?P<platform>.*?),"
	regex                                   = "((?P<major>\\d+).(?P<minor>\\d+))"
	pgVersionClusterSql                     = "select version()"
	pgVersionSql                            = "show server_version"
	pgExtensionVersionClusterSql            = "select extname, extversion, extnamespace from pg_extension"
	pgExtensionVersionSql                   = "select * from pg_extension"
	pgMetricName                            = "postgres_build_info"
	pgDescription                           = "Information about postgres version"
	httpCollectorConfigPath                 = "http_collector"
	extName                                 = "extname"
	extensionName                           = "extension_name"
	extensionVersion                        = "extension_version"
	extNamespace                            = "extnamespace"
	extVersion                              = "extversion"
	testContextKey               contextKey = "testCtxKey"
	configmapCollectorConfigPath            = "configmap_collector"
	sshCollectorConfigPath                  = "ssh_collector"
	metricsRegexp                           = "^[a-zA-Z_]*{namespace=\"[a-zA-Z-]*\",application_name=\"[a-zA-Z0-9_@.#&+-]*\",date=\"[-0-9]*\",username=\"[a-zA-Z_]*\",version=\"[A-Za-z0-9_.#&+-]*\"} [0-9]*"
)

func TestLoadingValidPgConfig(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	cfg, err := loadTestConfig(ctx, "validExporterConfig.yaml", pgCollectorConfigPath)
	if !assert.NoError(t, err, "no error expected on config loading") {
		return
	}
	assert.Equal(t, 1, len(cfg.CollectorConfigs))
	assert.Contains(t, cfg.CollectorConfigs, Postgres)
	pgConnections, ok := cfg.CollectorConfigs[Postgres].(postgres.PgConnections)
	assert.True(t, ok)
	assert.Equal(t, 2, len(pgConnections.Connections))

	assert.Equal(t, pgClusterUri, pgConnections.Connections[0].Host)
	assert.Equal(t, pgClusterPort, pgConnections.Connections[0].Port)
	assert.NotEmpty(t, pgConnections.Connections[0].Credentials.ClientSet)
	assert.Equal(t, pgNamespace, pgConnections.Connections[0].Credentials.Namespace)
	assert.Equal(t, pgSecretName, pgConnections.Connections[0].Credentials.User.Name)
	assert.Equal(t, pgUsernameKey, pgConnections.Connections[0].Credentials.User.Key)
	assert.Equal(t, pgSecretName, pgConnections.Connections[0].Credentials.Password.Name)
	assert.Equal(t, pgPasswordKey, pgConnections.Connections[0].Credentials.Password.Key)
	assert.Equal(t, pgDbName, pgConnections.Connections[0].DbName)
	assert.Equal(t, pgTimeout, pgConnections.Connections[0].Timeout.String())

	assert.Equal(t, 3, len(pgConnections.Connections[0].Requests))

	assert.Equal(t, pgVersionClusterSql, pgConnections.Connections[0].Requests[0].Sql)
	assert.Equal(t, pgMetricName, pgConnections.Connections[0].Requests[0].MetricName)
	assert.Equal(t, pgDescription, pgConnections.Connections[0].Requests[0].Description)
	assert.Equal(t, 1, len(pgConnections.Connections[0].Requests[0].Metrics))
	assert.Equal(t, clusterMetricFieldName, pgConnections.Connections[0].Requests[0].Metrics[0].FieldName)
	assert.Empty(t, pgConnections.Connections[0].Requests[0].Metrics[0].Label)
	assert.Equal(t, clusterRegexp, pgConnections.Connections[0].Requests[0].Metrics[0].Regexp)

	assert.Equal(t, pgExtensionVersionClusterSql, pgConnections.Connections[0].Requests[1].Sql)
	assert.Equal(t, pgMetricName, pgConnections.Connections[0].Requests[1].MetricName)
	assert.Empty(t, pgConnections.Connections[0].Requests[1].Description)
	assert.Equal(t, 3, len(pgConnections.Connections[0].Requests[1].Metrics))
	assert.Equal(t, extName, pgConnections.Connections[0].Requests[1].Metrics[0].FieldName)
	assert.Equal(t, extensionName, pgConnections.Connections[0].Requests[1].Metrics[0].Label)
	assert.Empty(t, pgConnections.Connections[0].Requests[1].Metrics[0].Regexp)
	assert.Equal(t, extVersion, pgConnections.Connections[0].Requests[1].Metrics[1].FieldName)
	assert.Equal(t, extensionVersion, pgConnections.Connections[0].Requests[1].Metrics[1].Label)
	assert.Empty(t, pgConnections.Connections[0].Requests[1].Metrics[1].Regexp)
	assert.Equal(t, extNamespace, pgConnections.Connections[0].Requests[1].Metrics[2].FieldName)
	assert.Empty(t, pgConnections.Connections[0].Requests[1].Metrics[2].Label)
	assert.Empty(t, pgConnections.Connections[0].Requests[1].Metrics[2].Regexp)

	assert.Equal(t, pgVersionSql, pgConnections.Connections[0].Requests[2].Sql)
	assert.Equal(t, pgMetricName, pgConnections.Connections[0].Requests[2].MetricName)
	assert.Empty(t, pgConnections.Connections[0].Requests[2].Description)
	assert.Equal(t, 1, len(pgConnections.Connections[0].Requests[2].Metrics))
	assert.Equal(t, metricServerFieldName, pgConnections.Connections[0].Requests[2].Metrics[0].FieldName)
	assert.Equal(t, "pg_server_version", pgConnections.Connections[0].Requests[2].Metrics[0].Label)
	assert.Equal(t, "((\\d+).(\\d+))", pgConnections.Connections[0].Requests[2].Metrics[0].Regexp)

	assert.Equal(t, pgUri, pgConnections.Connections[1].Host)
	assert.Equal(t, pgPort, pgConnections.Connections[1].Port)
	assert.NotEmpty(t, pgConnections.Connections[1].Credentials.ClientSet)
	assert.Equal(t, pgNamespace, pgConnections.Connections[1].Credentials.Namespace)
	assert.Equal(t, pgSecretName, pgConnections.Connections[1].Credentials.User.Name)
	assert.Equal(t, pgUsernameKey, pgConnections.Connections[1].Credentials.User.Key)
	assert.Equal(t, pgSecretName, pgConnections.Connections[1].Credentials.Password.Name)
	assert.Equal(t, pgPasswordKey, pgConnections.Connections[1].Credentials.Password.Key)
	assert.Equal(t, pgDbName, pgConnections.Connections[1].DbName)
	assert.Equal(t, pgTimeout, pgConnections.Connections[1].Timeout.String())

	assert.Equal(t, 4, len(pgConnections.Connections[1].Requests))

	assert.Equal(t, pgVersionClusterSql, pgConnections.Connections[1].Requests[0].Sql)
	assert.Equal(t, pgMetricName, pgConnections.Connections[1].Requests[0].MetricName)
	assert.Empty(t, pgConnections.Connections[1].Requests[0].Description)
	assert.Equal(t, 1, len(pgConnections.Connections[1].Requests[0].Metrics))
	assert.Equal(t, clusterMetricFieldName, pgConnections.Connections[1].Requests[0].Metrics[0].FieldName)
	assert.Empty(t, pgConnections.Connections[1].Requests[0].Metrics[0].Label)
	assert.Equal(t, clusterRegexp, pgConnections.Connections[1].Requests[0].Metrics[0].Regexp)

	assert.Equal(t, pgExtensionVersionClusterSql, pgConnections.Connections[1].Requests[1].Sql)
	assert.Equal(t, pgMetricName, pgConnections.Connections[1].Requests[1].MetricName)
	assert.Empty(t, pgConnections.Connections[1].Requests[1].Description)
	assert.NotEmpty(t, pgConnections.Connections[1].Requests[1].Metrics)
	assert.Equal(t, 1, len(pgConnections.Connections[1].Requests[1].Metrics))
	assert.Equal(t, extVersion, pgConnections.Connections[1].Requests[1].Metrics[0].FieldName)

	assert.Equal(t, pgVersionSql, pgConnections.Connections[1].Requests[2].Sql)
	assert.Equal(t, pgMetricName, pgConnections.Connections[1].Requests[2].MetricName)
	assert.Empty(t, pgConnections.Connections[1].Requests[2].Description)
	assert.Equal(t, 1, len(pgConnections.Connections[1].Requests[2].Metrics))
	assert.Equal(t, metricServerFieldName, pgConnections.Connections[1].Requests[2].Metrics[0].FieldName)
	assert.Empty(t, pgConnections.Connections[1].Requests[2].Metrics[0].Label)
	assert.Equal(t, regex, pgConnections.Connections[1].Requests[2].Metrics[0].Regexp)

	assert.Equal(t, pgExtensionVersionSql, pgConnections.Connections[1].Requests[3].Sql)
	assert.NotEmpty(t, pgConnections.Connections[1].Requests[3].Metrics)
	assert.Equal(t, 3, len(pgConnections.Connections[1].Requests[3].Metrics))
	assert.Equal(t, extName, pgConnections.Connections[1].Requests[3].Metrics[0].FieldName)
	assert.Equal(t, extensionName, pgConnections.Connections[1].Requests[3].Metrics[0].Label)
	assert.Empty(t, pgConnections.Connections[1].Requests[3].Metrics[0].Regexp)
	assert.Equal(t, extVersion, pgConnections.Connections[1].Requests[3].Metrics[1].FieldName)
	assert.Equal(t, extensionVersion, pgConnections.Connections[1].Requests[3].Metrics[1].Label)
	assert.Empty(t, pgConnections.Connections[1].Requests[3].Metrics[1].Regexp)
	assert.Equal(t, extNamespace, pgConnections.Connections[1].Requests[3].Metrics[2].FieldName)
	assert.Empty(t, pgConnections.Connections[1].Requests[3].Metrics[2].Label)
	assert.Empty(t, pgConnections.Connections[1].Requests[3].Metrics[2].Regexp)
}

func TestLoadingEmptyConfig(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	cfg, err := loadTestConfig(ctx, "emptyConfig.yaml", pgCollectorConfigPath)
	assert.Error(t, err, "error expected on empty config loading")
	assert.Equal(t, "config is empty!", err.Error())
	assert.Equal(t, 0, len(cfg.CollectorConfigs))
}

func TestLoadingEmptyModuleConfig(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	cfg, err := loadTestConfig(ctx, "emptyModule.yaml", pgCollectorConfigPath)
	assert.Error(t, err)
	assert.Equal(t, "postgres_collector config cannot be unmarshalled", err.Error())
	assert.Equal(t, 0, len(cfg.CollectorConfigs))

	cfg, err = loadTestConfig(ctx, "emptyModule.yaml", httpCollectorConfigPath)
	assert.Error(t, err)
	assert.Equal(t, "http_collector config cannot be unmarshalled", err.Error())
	assert.Equal(t, 0, len(cfg.CollectorConfigs))

	cfg, err = loadTestConfig(ctx, "emptyModule.yaml", configmapCollectorConfigPath)
	assert.Error(t, err)
	assert.Equal(t, "configmap_collector config cannot be unmarshalled", err.Error())
	assert.Equal(t, 0, len(cfg.CollectorConfigs))

}

func TestLoadingInvalidConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		testConfig string
		expected   string
	}{
		{"EmptyConnections", "invalidEmptyConnectionsConfig.yaml", "Key: 'PgConnections.connections' Error:Field validation for 'connections' failed on the 'min' tag"},
		{"InvalidConnections", "invalidConnectionsConfig.yaml", "Key: 'ConnOptions.host' Error:Field validation for 'host' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.port' Error:Field validation for 'port' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.credentials.username.key' Error:Field validation for 'key' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.credentials.username.name' Error:Field validation for 'name' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.credentials.password.key' Error:Field validation for 'key' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.credentials.password.name' Error:Field validation for 'name' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.db' Error:Field validation for 'db' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.timeout' Error:Field validation for 'timeout' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.requests' Error:Field validation for 'requests' failed on the 'required' tag"},
		{"InvalidHostName", "invalidHostNameConfig.yaml", "Key: 'ConnOptions.host' Error:Field validation for 'host' failed on the 'hostname|ip' tag"},
		{"InvalidHostIp", "invalidHostIPConfig.yaml", "Key: 'ConnOptions.host' Error:Field validation for 'host' failed on the 'hostname|ip' tag"},
		{"HostNameNotUnique", "invalidHostNameNotUniqueConfig.yaml", "Key: 'PgConnections.connections' Error:Field validation for 'connections' failed on the 'unique' tag"},
		{"InvalidHostMinPort", "invalidHostMinPortConfig.yaml", "Key: 'ConnOptions.port' Error:Field validation for 'port' failed on the 'min' tag"},
		{"InvalidHostMaxPort", "invalidHostMaxPortConfig.yaml", "Key: 'ConnOptions.port' Error:Field validation for 'port' failed on the 'max' tag"},
		{"EmptyCredentials", "invalidEmptyCredentialsConfig.yaml", "Key: 'ConnOptions.credentials.username.key' Error:Field validation for 'key' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.credentials.username.name' Error:Field validation for 'name' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.credentials.password.key' Error:Field validation for 'key' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.credentials.password.name' Error:Field validation for 'name' failed on the 'required' tag"},
		{"InvalidEmptyDBName", "invalidEmptyDbNameConfig.yaml", "Key: 'ConnOptions.db' Error:Field validation for 'db' failed on the 'required' tag"},
		{"InvalidTimeout", "invalidTimeoutConfig.yaml", "postgres_collector config cannot be parsed: unknown unit \"ss\" in duration \"10ss\""},
		{"EmptyTimeout", "invalidEmptyTimeoutConfig.yaml", "Key: 'ConnOptions.timeout' Error:Field validation for 'timeout' failed on the 'required' tag"},
		{"EmptyRequests", "invalidEmptyRequests.yaml", "Key: 'ConnOptions.requests' Error:Field validation for 'requests' failed on the 'required' tag"},
		{"InvalidRequests", "invalidRequests.yaml", "Key: 'ConnOptions.requests[0].sql' Error:Field validation for 'sql' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.requests[0].metricName' Error:Field validation for 'metricName' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.requests[0].metrics' Error:Field validation for 'metrics' failed on the 'required' tag"},
		{"InvalidDuplicateSqlRequest", "invalidDuplicateSqlRequest.yaml", "Key: 'ConnOptions.requests' Error:Field validation for 'requests' failed on the 'unique' tag"},
		{"InvalidRequestNoMetricName", "invalidRequestNoMetricNameConfig.yaml", "Key: 'ConnOptions.requests[0].metricName' Error:Field validation for 'metricName' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.requests[0].metrics' Error:Field validation for 'metrics' failed on the 'required' tag"},
		{"InvalidRequestRegexp", "invalidRequestRegexpConfig.yaml", "Key: 'ConnOptions.requests[0].metrics[0].valueRegexp' Error:Field validation for 'valueRegexp' failed on the 'property_regexp' tag"},
		{"InvalidRequestFieldName", "invalidRequestFieldNameConfig.yaml", "Key: 'ConnOptions.requests[0].metrics[0].fieldName' Error:Field validation for 'fieldName' failed on the 'prometheus_label_name' tag"},
		{"InvalidRequestLabel", "invalidRequestLabelConfig.yaml", "Key: 'ConnOptions.requests[1].metrics[0].label' Error:Field validation for 'label' failed on the 'prometheus_label_name' tag"},
		{"InvalidRequestNotUniqueLabel", "invalidRequestNotUniqueLabelConfig.yaml", "Key: 'ConnOptions.requests[1].metrics' Error:Field validation for 'metrics' failed on the 'unique_labels' tag"},
		{"invalidRequestNoMetrics", "invalidRequestNoMetrics.yaml", "Key: 'ConnOptions.requests[0].metrics' Error:Field validation for 'metrics' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.requests[1].metrics' Error:Field validation for 'metrics' failed on the 'required' tag"},
		{"invalidRequestMetricFieldNameNotUnique", "invalidRequestMetricFieldNameNotUniqueConfig.yaml", "Key: 'ConnOptions.requests[0].metrics' Error:Field validation for 'metrics' failed on the 'unique' tag"},
	}

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.WithValue(context.Background(), testContextKey, t.Name())
			cfg, err := loadTestConfig(ctx, tc.testConfig, pgCollectorConfigPath+collectorNegativeConfigPath)
			assert.Error(t, err)
			assert.Equal(t, tc.expected, err.Error())
			assert.Equal(t, 0, len(cfg.CollectorConfigs))
		})
	}
}

func loadTestConfig(ctx context.Context, path string, configDirectory string) (*Container, error) {
	configPath := filepath.Join("..", "testdata", "config")
	clientSet := fake.NewSimpleClientset()
	cc := NewConfigContainer(filepath.Join(configPath, configDirectory, path), "monitoring", clientSet, log.NewNopLogger())
	err := cc.ReadConfig(ctx)
	return cc, err
}

func TestHttpCollectorConfig(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	cfg, err := loadTestConfig(ctx, "validExporterConfig.yaml", httpCollectorConfigPath)
	if !assert.NoError(t, err, "no error expected on config loading") {
		return
	}
	httpConnections, ok := cfg.CollectorConfigs[HttpType].(httpModel.Collectors)
	assert.True(t, ok)
	assert.Equal(t, 2, len(httpConnections.Connections))
	httpUrls := httpConnections.Connections
	assert.Equal(t, "https://www.example.com", httpUrls[0].Host)

	assert.NotEqual(t, nil, httpUrls[0].TlsConfig)
	assert.False(t, httpUrls[0].TlsConfig.TLSSkip)
	assert.Equal(t, "monitoring", httpUrls[0].TlsConfig.Namespace)
	assert.Equal(t, "cert-ca.pem", httpUrls[0].TlsConfig.CA.Key)
	assert.Equal(t, "secret-certificate-authority", httpUrls[0].TlsConfig.CA.Name)

	assert.NotEqual(t, nil, httpUrls[0].Credentials)
	assert.Equal(t, "monitoring", httpUrls[0].Credentials.Namespace)
	assert.NotEqual(t, nil, httpUrls[0].Credentials.User)
	assert.Equal(t, "user", httpUrls[0].Credentials.User.Key)
	assert.Equal(t, "secret-name", httpUrls[0].Credentials.User.Name)
	assert.NotEqual(t, nil, httpUrls[0].Credentials.Password)
	assert.Equal(t, "password", httpUrls[0].Credentials.Password.Key)
	assert.Equal(t, "secret-name", httpUrls[0].Credentials.Password.Name)
	assert.Empty(t, httpUrls[0].Credentials.Token)

	assert.NotNil(t, httpUrls[0].Requests)
	assert.Equal(t, 2, len(httpUrls[0].Requests))

	assert.Equal(t, "/version", httpUrls[0].Requests[0].Path)
	assert.Equal(t, "versions_ci_metric", httpUrls[0].Requests[0].MetricName)
	assert.Empty(t, httpUrls[0].Requests[0].Description)
	assert.Equal(t, "get", httpUrls[0].Requests[0].Method)
	assert.NotNil(t, httpUrls[0].Requests[0].Metrics)

	assert.Equal(t, 2, len(httpUrls[0].Requests[0].Metrics))

	assert.Equal(t, ".[buildDate,gitCommit]", httpUrls[0].Requests[0].Metrics[0].JsonPath)
	assert.NotNil(t, httpUrls[0].Requests[0].Metrics[0].Labels)
	assert.Equal(t, 2, len(httpUrls[0].Requests[0].Metrics[0].Labels))
	assert.Equal(t, "buildDate", httpUrls[0].Requests[0].Metrics[0].Labels[0].Name)
	assert.Equal(t, "[a-z0-9.]*", httpUrls[0].Requests[0].Metrics[0].Labels[0].Regexp)
	assert.Equal(t, "gitCommit", httpUrls[0].Requests[0].Metrics[0].Labels[1].Name)

	assert.Equal(t, "{.plugins[*]['name','required_version']}", httpUrls[0].Requests[0].Metrics[1].JsonPath)
	assert.NotNil(t, httpUrls[0].Requests[0].Metrics[1].Labels)
	assert.Equal(t, 2, len(httpUrls[0].Requests[0].Metrics[1].Labels))
	assert.Equal(t, "name", httpUrls[0].Requests[0].Metrics[1].Labels[0].Name)
	assert.Equal(t, "[^a-zA-Z0-9]", httpUrls[0].Requests[0].Metrics[1].Labels[0].Regexp)
	assert.Equal(t, "requiredVersion", httpUrls[0].Requests[0].Metrics[1].Labels[1].Name)

	assert.Equal(t, "/api/system/plugins", httpUrls[0].Requests[1].Path)
	assert.Equal(t, "versions_ci_product_metric", httpUrls[0].Requests[1].MetricName)
	assert.Equal(t, "Metric shows versions of product components", httpUrls[0].Requests[1].Description)
	assert.Equal(t, "post", httpUrls[0].Requests[1].Method)
	assert.NotNil(t, httpUrls[0].Requests[1].Metrics)

	assert.Equal(t, 1, len(httpUrls[0].Requests[1].Metrics))
	assert.Equal(t, "{['name','required_version']}", httpUrls[0].Requests[1].Metrics[0].JsonPath)
	assert.NotNil(t, httpUrls[0].Requests[1].Metrics[0].Labels)
	assert.Equal(t, 2, len(httpUrls[0].Requests[1].Metrics[0].Labels))
	assert.Equal(t, "name", httpUrls[0].Requests[1].Metrics[0].Labels[0].Name)
	assert.Equal(t, "[^a-zA-Z0-9]", httpUrls[0].Requests[1].Metrics[0].Labels[0].Regexp)
	assert.Equal(t, "requiredVersion", httpUrls[0].Requests[1].Metrics[0].Labels[1].Name)

	assert.Equal(t, "https://255.255.255.255:6300", httpUrls[1].Host)

	assert.NotEqual(t, nil, httpUrls[1].TlsConfig)
	assert.True(t, httpUrls[1].TlsConfig.TLSSkip)

	assert.NotEqual(t, nil, httpUrls[1].Credentials)
	assert.Equal(t, "monitoring", httpUrls[1].Credentials.Namespace)
	assert.Empty(t, httpUrls[1].Credentials.User)
	assert.Empty(t, httpUrls[1].Credentials.Password)
	assert.NotEqual(t, nil, httpUrls[1].Credentials.Token)
	assert.Equal(t, "token", httpUrls[1].Credentials.Token.Key)
	assert.Equal(t, "secret-name", httpUrls[1].Credentials.Token.Name)

	assert.NotNil(t, httpUrls[1].Requests)
	assert.Equal(t, 2, len(httpUrls[1].Requests))

	assert.Equal(t, "/version", httpUrls[1].Requests[0].Path)
	assert.Equal(t, "versions_ci_text_metric", httpUrls[1].Requests[0].MetricName)
	assert.Empty(t, httpUrls[1].Requests[0].Description)
	assert.Equal(t, "get", httpUrls[1].Requests[0].Method)
	assert.NotNil(t, httpUrls[1].Requests[0].Metrics)

	assert.NotNil(t, httpUrls[1].Requests[0].Metrics)
	assert.Equal(t, 1, len(httpUrls[1].Requests[0].Metrics))

	assert.Equal(t, "$.platform", httpUrls[1].Requests[0].Metrics[0].JsonPath)
	assert.NotNil(t, httpUrls[1].Requests[0].Metrics[0].Labels)
	assert.Equal(t, 1, len(httpUrls[1].Requests[0].Metrics[0].Labels))
	assert.Equal(t, "platform", httpUrls[1].Requests[0].Metrics[0].Labels[0].Name)
	assert.Equal(t, "[a-z0-9.]*", httpUrls[1].Requests[0].Metrics[0].Labels[0].Regexp)

	assert.Equal(t, "/product_versions", httpUrls[1].Requests[1].Path)
	assert.Equal(t, "product_versions_ci_metric", httpUrls[1].Requests[1].MetricName)
	assert.Equal(t, "Shows versions of application product components", httpUrls[1].Requests[1].Description)
	assert.Equal(t, "get", httpUrls[1].Requests[1].Method)
	assert.NotNil(t, httpUrls[1].Requests[1].Metrics)

	assert.NotNil(t, httpUrls[1].Requests[1].Metrics)
	assert.Equal(t, 1, len(httpUrls[1].Requests[1].Metrics))

	assert.Equal(t, "{range @[*]}{.component}{.version}{end}", httpUrls[1].Requests[1].Metrics[0].JsonPath)
	assert.NotNil(t, httpUrls[1].Requests[1].Metrics[0].Labels)
	assert.Equal(t, 2, len(httpUrls[1].Requests[1].Metrics[0].Labels))
	assert.Equal(t, "component", httpUrls[1].Requests[1].Metrics[0].Labels[0].Name)
	assert.Equal(t, "version", httpUrls[1].Requests[1].Metrics[0].Labels[1].Name)
}

func TestHttpCollectorConfig_failedValidations(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	_, err := loadTestConfig(ctx, "blankRequestsConfig.yaml", httpCollectorConfigPath)
	assert.NotEqual(t, nil, err)

	var errs validator.ValidationErrors
	errors.As(err, &errs)
	assert.Equal(t, 3, len(errs))
	assert.Equal(t, "required", errs[0].Tag())
	assert.Equal(t, "url", errs[0].Field())

	assert.Equal(t, "required", errs[1].Tag())
	assert.Equal(t, "requests", errs[1].Field())

	assert.Equal(t, "tlsConfig", errs[2].Tag())
	assert.Equal(t, "tlsConfig", errs[2].Field())
}

func TestHttpCollectorCredentialsConfig_failedValidations(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	_, err := loadTestConfig(ctx, "invalidCredentialConfig.yaml", httpCollectorConfigPath)
	assert.NotEqual(t, nil, err)

	var errs validator.ValidationErrors
	errors.As(err, &errs)
	assert.Equal(t, 1, len(errs))
	assert.Equal(t, "credentials", errs[0].Tag())
	assert.Equal(t, "credentials", errs[0].Field())
}

func TestHttpCollectorConfig_Labels(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	_, err := loadTestConfig(ctx, "invalidMetricsConfig.yaml", httpCollectorConfigPath)
	assert.NotEqual(t, nil, err)

	var errs validator.ValidationErrors
	errors.As(err, &errs)
	assert.Equal(t, 10, len(errs))

	assert.Equal(t, "required", errs[0].Tag())
	assert.Equal(t, "metricName", errs[0].Field())

	assert.Equal(t, "unique_json_paths", errs[1].Tag())
	assert.Equal(t, "metrics", errs[1].Field())

	assert.Equal(t, "jsonPathProperty", errs[2].Tag())
	assert.Equal(t, "jsonPath", errs[2].Field())

	assert.Equal(t, "required", errs[3].Tag())
	assert.Equal(t, "metrics", errs[3].Field())

	assert.Equal(t, "required", errs[4].Tag())
	assert.Equal(t, "metrics", errs[4].Field())

	assert.Equal(t, "prometheus_label_name", errs[5].Tag())
	assert.Equal(t, "name", errs[5].Field())

	assert.Equal(t, "property_regexp", errs[6].Tag())
	assert.Equal(t, "valueRegexp", errs[6].Field())

	assert.Equal(t, "labels_amount", errs[7].Tag())
	assert.Equal(t, "metrics", errs[7].Field())

	assert.Equal(t, "labels_amount", errs[8].Tag())
	assert.Equal(t, "metrics", errs[8].Field())

	assert.Equal(t, "labels_amount", errs[9].Tag())
	assert.Equal(t, "metrics", errs[9].Field())

}

func TestHttpCollectorConfig_duplicatedUrl(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	_, err := loadTestConfig(ctx, "invalidConnectionsConfig.yaml", httpCollectorConfigPath)
	assert.NotEqual(t, nil, err)

	var errs validator.ValidationErrors
	errors.As(err, &errs)
	assert.Equal(t, 1, len(errs))
	assert.Equal(t, "unique", errs[0].Tag())
	assert.Equal(t, "connections", errs[0].Field())

}

func TestHttpCollectorConfig_duplicatedPath(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	_, err := loadTestConfig(ctx, "invalidRequestsConfig.yaml", httpCollectorConfigPath)
	assert.NotEqual(t, nil, err)

	var errs validator.ValidationErrors
	errors.As(err, &errs)
	assert.Equal(t, 1, len(errs))
	assert.Equal(t, "unique", errs[0].Tag())
	assert.Equal(t, "requests", errs[0].Field())

}

func TestHttpCollectorConfig_Request(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	_, err := loadTestConfig(ctx, "invalidRequestConfig.yaml", httpCollectorConfigPath)
	assert.NotEqual(t, nil, err)

	var errs validator.ValidationErrors
	errors.As(err, &errs)
	assert.Equal(t, 6, len(errs))

	assert.Equal(t, "required", errs[0].Tag())
	assert.Equal(t, "method", errs[0].Field())

	assert.Equal(t, "prometheus_metric_name", errs[1].Tag())
	assert.Equal(t, "metricName", errs[1].Field())

	assert.Equal(t, "required", errs[2].Tag())
	assert.Equal(t, "metrics", errs[2].Field())

	assert.Equal(t, "oneof", errs[3].Tag())
	assert.Equal(t, "method", errs[3].Field())

	assert.Equal(t, "required", errs[4].Tag())
	assert.Equal(t, "metricName", errs[4].Field())

	assert.Equal(t, "tlsConfig", errs[5].Tag())
	assert.Equal(t, "tlsConfig", errs[5].Field())
}

func TestConfigmapCollectorConfig(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	cfg, err := loadTestConfig(ctx, "validExporterConfig.yaml", configmapCollectorConfigPath)
	if !assert.NoError(t, err, "no error expected on config loading") {
		return
	}
	configmapCollector, ok := cfg.CollectorConfigs[ConfigMapType].(configmapModel.CmCollector)
	assert.True(t, ok)
	configmapDefaults := configmapCollector.Defaults
	assert.Equal(t, "configmap", configmapDefaults.Type)
	assert.Equal(t, 1, len(configmapDefaults.Namespaces))
	assert.Equal(t, "monitoring", configmapDefaults.Namespaces[0])
	assert.Equal(t, 0, len(configmapDefaults.ResourceLabels))
	assert.Equal(t, "configmap_collected_versions", configmapDefaults.MetricName)
	assert.Equal(t, "Metric shows version collected from configmaps", configmapDefaults.Description)
	defaultLabels := configmapDefaults.Labels
	assert.Equal(t, 4, len(defaultLabels))
	assert.Equal(t, "application_name", defaultLabels[0].Name)
	assert.Equal(t, "^([^\\.]+)\\.[^\\.]+\\.[^\\.]+", defaultLabels[0].KeyRegexp)
	assert.Equal(t, "date", defaultLabels[1].Name)
	assert.Equal(t, "^[^\\.]+\\.([^\\.]+)\\.[^\\.]+", defaultLabels[1].KeyRegexp)
	assert.Equal(t, "username", defaultLabels[2].Name)
	assert.Equal(t, "^[^\\.]+\\.[^\\.]+\\.([^\\.]+)", defaultLabels[2].KeyRegexp)
	assert.Equal(t, "application_version", defaultLabels[3].Name)
	assert.Equal(t, ".*", defaultLabels[3].ValueRegexp)

	resources := configmapCollector.Resources
	assert.Equal(t, 3, len(resources))

	assert.Equal(t, "version-configmap-test", resources[0].Name)
	assert.Empty(t, resources[0].Type)
	assert.Equal(t, 0, len(resources[0].Namespaces))
	assert.NotEqual(t, 0, len(resources[0].ResourceLabels))
	assert.Equal(t, "label-value", resources[0].ResourceLabels["label-key"])
	assert.Equal(t, "configmap_versions", resources[0].MetricName)
	assert.Equal(t, "Help", resources[0].Description)
	assert.Equal(t, 1, len(resources[0].Labels))
	assert.Equal(t, "label", resources[0].Labels[0].Name)
	assert.Equal(t, ".*", resources[0].Labels[0].KeyRegexp)
	assert.Empty(t, resources[0].Labels[0].ValueRegexp)

	assert.Equal(t, "version-secret-test", resources[1].Name)
	assert.Equal(t, "secret", resources[1].Type)
	assert.Empty(t, resources[1].Namespaces)
	assert.Empty(t, resources[1].ResourceLabels)
	assert.Empty(t, resources[1].MetricName)
	assert.Empty(t, resources[1].Description)
	assert.Empty(t, resources[1].Labels)

	assert.Equal(t, "version-default-configmap", resources[2].Name)
}

func TestLoadingValidSshConfig(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	cfg, err := loadTestConfig(ctx, "validExporterConfig.yaml", sshCollectorConfigPath)
	if !assert.NoError(t, err, "no error expected on config loading") {
		return
	}
	assert.Equal(t, 1, len(cfg.CollectorConfigs))
	assert.Contains(t, cfg.CollectorConfigs, SSHType)
	sshConnections, ok := cfg.CollectorConfigs[SSHType].(sshModel.Connections)
	assert.True(t, ok)
	assert.Equal(t, 2, len(sshConnections.Connections))

	assert.Equal(t, "x.x.x.x", sshConnections.Connections[0].Host)
	assert.Equal(t, 22, sshConnections.Connections[0].Port)
	assert.Equal(t, "tcp", sshConnections.Connections[0].Network)
	assert.Equal(t, "5s", sshConnections.Connections[0].Timeout.String())
	assert.Nil(t, sshConnections.Connections[0].Credentials)
	assert.NotNil(t, sshConnections.Connections[0].K8sCredentials)
	assert.Equal(t, "sshLogin", sshConnections.Connections[0].K8sCredentials.Login.Key)
	assert.Equal(t, "version-exporter-extra-vars-secret", sshConnections.Connections[0].K8sCredentials.Login.Name)
	assert.Equal(t, "privKey", sshConnections.Connections[0].K8sCredentials.PKey.Key)
	assert.Equal(t, "version-exporter-extra-vars-secret", sshConnections.Connections[0].K8sCredentials.PKey.Name)

	assert.Equal(t, 3, len(sshConnections.Connections[0].Requests))

	assert.Equal(t, "head /etc/os-release", sshConnections.Connections[0].Requests[0].Cmd)
	assert.Equal(t, "os_versions_metric", sshConnections.Connections[0].Requests[0].MetricName)
	assert.Equal(t, "", sshConnections.Connections[0].Requests[0].Description)
	assert.Equal(t, 2, len(sshConnections.Connections[0].Requests[0].Labels))
	assert.Equal(t, "os_version", sshConnections.Connections[0].Requests[0].Labels[0].Name)
	assert.Equal(t, "[a-z0-9.]*", sshConnections.Connections[0].Requests[0].Labels[0].Regexp)
	assert.Equal(t, "name", sshConnections.Connections[0].Requests[0].Labels[1].Name)
	assert.Equal(t, "[^a-zA-Z0-9]", sshConnections.Connections[0].Requests[0].Labels[1].Regexp)

	assert.Equal(t, "tail /etc/ssh/ssh_config", sshConnections.Connections[0].Requests[1].Cmd)
	assert.Equal(t, "ssh_versions_metric", sshConnections.Connections[0].Requests[1].MetricName)
	assert.Equal(t, "Metric shows versions of ssh component", sshConnections.Connections[0].Requests[1].Description)
	assert.Equal(t, 1, len(sshConnections.Connections[0].Requests[1].Labels))
	assert.Equal(t, "ssh_version", sshConnections.Connections[0].Requests[1].Labels[0].Name)
	assert.Equal(t, "[^a-zA-Z0-9]", sshConnections.Connections[0].Requests[1].Labels[0].Regexp)

	assert.Equal(t, "cat /etc/ssh/ssh_config", sshConnections.Connections[0].Requests[2].Cmd)
	assert.Equal(t, "ssh_ver_metric", sshConnections.Connections[0].Requests[2].MetricName)
	assert.Equal(t, "Metric shows versions of ssh component", sshConnections.Connections[0].Requests[2].Description)
	assert.Equal(t, 1, len(sshConnections.Connections[0].Requests[2].Labels))
	assert.Equal(t, "version", sshConnections.Connections[0].Requests[2].Labels[0].Name)
	assert.Equal(t, "[^a-zA-Z0-9]", sshConnections.Connections[0].Requests[2].Labels[0].Regexp)

	assert.Equal(t, "x.x.x.x", sshConnections.Connections[1].Host)
	assert.Equal(t, 22, sshConnections.Connections[1].Port)
	assert.Equal(t, "tcp", sshConnections.Connections[1].Network)
	assert.Equal(t, "5s", sshConnections.Connections[1].Timeout.String())
	assert.NotNil(t, sshConnections.Connections[1].Credentials)
	assert.Nil(t, sshConnections.Connections[1].K8sCredentials)
	assert.Equal(t, "centos", sshConnections.Connections[1].Credentials.Login)
	assert.Equal(t, "../testdata/config/ssh_collector/keys/test_private_key", sshConnections.Connections[1].Credentials.PKeyPath)
	assert.Equal(t, "../testdata/config/ssh_collector/keys/known_hosts", *sshConnections.Connections[1].Credentials.KnownHostsPath)

	assert.Equal(t, 3, len(sshConnections.Connections[1].Requests))

	assert.Equal(t, "echo `ssh -V`", sshConnections.Connections[1].Requests[0].Cmd)
	assert.Equal(t, "os_versions_metric", sshConnections.Connections[1].Requests[0].MetricName)
	assert.Equal(t, "", sshConnections.Connections[1].Requests[0].Description)
	assert.Equal(t, 2, len(sshConnections.Connections[1].Requests[0].Labels))
	assert.Equal(t, "os_version", sshConnections.Connections[1].Requests[0].Labels[0].Name)
	assert.Equal(t, "(?P<version>[a-z0-9.]*)", sshConnections.Connections[1].Requests[0].Labels[0].Regexp)
	assert.Equal(t, "name", sshConnections.Connections[1].Requests[0].Labels[1].Name)
	assert.Equal(t, "(?P<name>[^a-zA-Z0-9])", sshConnections.Connections[1].Requests[0].Labels[1].Regexp)

	assert.Equal(t, "nl /etc/ssh/ssh_config", sshConnections.Connections[1].Requests[1].Cmd)
	assert.Equal(t, "ssh_versions_metric", sshConnections.Connections[1].Requests[1].MetricName)
	assert.Equal(t, "Metric shows versions of ssh component", sshConnections.Connections[1].Requests[1].Description)
	assert.Equal(t, 1, len(sshConnections.Connections[1].Requests[1].Labels))
	assert.Equal(t, "ssh_version", sshConnections.Connections[1].Requests[1].Labels[0].Name)
	assert.Equal(t, "[^a-zA-Z0-9]", sshConnections.Connections[1].Requests[1].Labels[0].Regexp)

	assert.Equal(t, "hostname --fqdn", sshConnections.Connections[1].Requests[2].Cmd)
	assert.Equal(t, "hostname_metric", sshConnections.Connections[1].Requests[2].MetricName)
	assert.Equal(t, "", sshConnections.Connections[1].Requests[2].Description)
	assert.Equal(t, 1, len(sshConnections.Connections[1].Requests[2].Labels))
	assert.Equal(t, "version", sshConnections.Connections[1].Requests[2].Labels[0].Name)
	assert.Equal(t, "[^a-zA-Z0-9]", sshConnections.Connections[1].Requests[2].Labels[0].Regexp)
}

func TestMetricsValidFormat(t *testing.T) {
	t.Parallel()
	metrics := "configmap_collected_versions{namespace=\"monitoring\",application_name=\"qubership-version-exporter\",date=\"2025-01-01-00-00-00-000\",username=\"UserName\",version=\"0.0.0-qubership-version-exporter\"} 1"
	assert.Regexp(t, regexp.MustCompile(metricsRegexp), metrics)
}

func TestMetricsMissingApplicationName(t *testing.T) {
	t.Parallel()
	metrics := "configmap_collected_versions{namespace=\"monitoring\",date=\"2025-01-01-00-00-00-000\",username=\"UserName\",version=\"0.0.0-qubership-version-exporter\"} 1"
	assert.NotRegexp(t, regexp.MustCompile(metricsRegexp), metrics)
}

func TestMetricsMissingDate(t *testing.T) {
	t.Parallel()
	metrics := "configmap_collected_versions{namespace=\"monitoring\",application_name=\"qubership-version-exporter\",username=\"UserName\",version=\"0.0.0-qubership-version-exporter\"} 1"
	assert.NotRegexp(t, regexp.MustCompile(metricsRegexp), metrics)
}

func TestMetricsMissingUsername(t *testing.T) {
	t.Parallel()
	metrics := "configmap_collected_versions{namespace=\"monitoring\",application_name=\"qubership-version-exporter\",date=\"2025-01-01-00-00-00-000\",version=\"0.0.0-qubership-version-exporter\"} 1"
	assert.NotRegexp(t, regexp.MustCompile(metricsRegexp), metrics)
}

func TestMetricsMissingVersion(t *testing.T) {
	t.Parallel()
	metrics := "configmap_collected_versions{namespace=\"monitoring\",application_name=\"qubership-version-exporter\",date=\"2025-01-01-00-00-00-000\",username=\"UserName\"} 1"
	assert.NotRegexp(t, regexp.MustCompile(metricsRegexp), metrics)
}

func TestLoadingEmptySshConfig(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	cfg, err := loadTestConfig(ctx, "emptyConfig.yaml", sshCollectorConfigPath)
	assert.Error(t, err, "error expected on empty config loading")
	assert.Equal(t, "config is empty!", err.Error())
	assert.Equal(t, 0, len(cfg.CollectorConfigs))
}

func TestLoadingEmptySshModuleConfig(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey, t.Name())

	cfg, err := loadTestConfig(ctx, "emptyModule.yaml", sshCollectorConfigPath)
	assert.Error(t, err)
	assert.Equal(t, "ssh_collector config cannot be unmarshalled", err.Error())
	assert.Equal(t, 0, len(cfg.CollectorConfigs))
}

func TestLoadingInvalidSshConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		testConfig string
		expected   string
	}{
		{"EmptyConnections", "invalidEmptyConnectionsConfig.yaml", "Key: 'Connections.connections' Error:Field validation for 'connections' failed on the 'min' tag"},
		{"InvalidConnections", "invalidConnectionsConfig.yaml", "Key: 'ConnOptions.host' Error:Field validation for 'host' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.port' Error:Field validation for 'port' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.network' Error:Field validation for 'network' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.timeout' Error:Field validation for 'timeout' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.requests' Error:Field validation for 'requests' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.connections' Error:Field validation for 'connections' failed on the 'connections' tag"},
		{"InvalidHostName", "invalidHostNameConfig.yaml", "Key: 'ConnOptions.host' Error:Field validation for 'host' failed on the 'hostname|ip' tag"},
		{"InvalidHostIp", "invalidHostIPConfig.yaml", "Key: 'ConnOptions.host' Error:Field validation for 'host' failed on the 'hostname|ip' tag"},
		{"HostNameNotUnique", "invalidHostNameNotUniqueConfig.yaml", "Key: 'Connections.connections' Error:Field validation for 'connections' failed on the 'unique' tag"},
		{"InvalidHostMaxPort", "invalidHostMaxPortConfig.yaml", "Key: 'ConnOptions.port' Error:Field validation for 'port' failed on the 'max' tag"},
		{"EmptyCredentials", "invalidEmptyCredentialsConfig.yaml", "Key: 'ConnOptions.connections' Error:Field validation for 'connections' failed on the 'connections' tag"},
		{"InvalidTimeout", "invalidTimeoutConfig.yaml", "ssh_collector config cannot be parsed: yaml: unmarshal errors:\n  line 7: cannot unmarshal !!str `5ss` into time.Duration"},
		{"EmptyTimeout", "invalidEmptyTimeoutConfig.yaml", "Key: 'ConnOptions.timeout' Error:Field validation for 'timeout' failed on the 'required' tag"},
		{"EmptyRequests", "invalidEmptyRequests.yaml", "Key: 'ConnOptions.requests' Error:Field validation for 'requests' failed on the 'required' tag"},
		{"EmptyLogin", "invalidEmptyLogin.yaml", "Key: 'ConnOptions.credentials.login' Error:Field validation for 'login' failed on the 'required' tag"},
		{"IdentityFileNotExists", "invalidIdentityFilePath.yaml", "Key: 'ConnOptions.credentials.identityFile' Error:Field validation for 'identityFile' failed on the 'file' tag"},
		{"InvalidRequests", "invalidRequests.yaml", "Key: 'ConnOptions.requests[0].cmd' Error:Field validation for 'cmd' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.requests[0].metricName' Error:Field validation for 'metricName' failed on the 'required' tag\n" +
			"Key: 'ConnOptions.requests[0].labels' Error:Field validation for 'labels' failed on the 'required' tag"},
		{"InvalidCmdRequest", "invalidCmdRequest.yaml", "Key: 'ConnOptions.requests[0].cmd' Error:Field validation for 'cmd' failed on the 'startswith=cat|startswith=nl|startswith=head|startswith=tail|startswith=echo|startswith=hostname|startswith=uname' tag"},
		{"InvalidRequestNoMetricName", "invalidRequestNoMetricNameConfig.yaml", "Key: 'ConnOptions.requests[0].metricName' Error:Field validation for 'metricName' failed on the 'required' tag"},
		{"InvalidRequestRegexp", "invalidRequestRegexpConfig.yaml", "Key: 'ConnOptions.requests[0].labels[1].valueRegexp' Error:Field validation for 'valueRegexp' failed on the 'property_regexp' tag"},
		{"InvalidRequestLabel", "invalidRequestLabelConfig.yaml", "Key: 'ConnOptions.requests[0].labels[0].name' Error:Field validation for 'name' failed on the 'prometheus_label_name' tag"},
		{"InvalidRequestNotUniqueLabel", "invalidRequestNotUniqueLabelConfig.yaml", "Key: 'ConnOptions.requests[0].labels' Error:Field validation for 'labels' failed on the 'unique' tag"},
	}

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.WithValue(context.Background(), testContextKey, t.Name())
			cfg, err := loadTestConfig(ctx, tc.testConfig, sshCollectorConfigPath+collectorNegativeConfigPath)
			assert.Error(t, err)
			assert.Equal(t, tc.expected, err.Error())
			assert.Equal(t, 0, len(cfg.CollectorConfigs))
		})
	}
}
