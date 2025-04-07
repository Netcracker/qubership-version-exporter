# Installation Notes

This document provides information about the requirements, configuration, and steps to install Qubership-version-exporter to an
environment.

## Table of Contents

* [Table of Contents](#table-of-contents)
* [Inventory](#inventory)
  * [Configuration](#configuration)
    * [General Flags](#general-flags)
    * [Postgres collector parameters](#postgres-collector-parameters)
    * [HTTP requests collector parameters](#http-requests-collector-parameters)
    * [ConfigMap collector parameters](#configmap-collector-parameters)
    * [SSH collector parameters](#ssh-collector-parameters)
* [Deploy](#deploy)
  * [Manual deploy using Helm](#manual-deploy-using-helm)
    * [Installing the Chart](#installing-the-chart)

## Inventory

This section describes how to create an inventory and which parameters are used to deploy Qubership-version-exporter
and it`s collectors.

### Configuration

This section provides information about all the parameters of `qubership-version-exporter`.
The exporter provides the types of collectors:

* [Postgres collector parameters](#postgres-collector-parameters)
* [HTTP requests collector](#http-requests-collector-parameters)
* [ConfigMap collector](#configmap-collector-parameters)

#### General Flags
<!-- markdownlint-disable line-length -->
| Name               | Description                                           | Default value                    |
| ------------------ | ----------------------------------------------------- | -------------------------------- |
| log.level          | Logging verbosity                                     | info                             |
| web.listen-address | Address on which to expose metrics and web interface. | :9100                            |
| web.telemetry-path | Path under which to expose metrics.                   | /metrics                         |
| web.max-requests   | Maximum number of parallel scrape requests.           | 40 (0 means no limit is applied) |
| config.file        | Path to a exporter configuration file.                | /config/exporterConfig.yaml      |

<!-- markdownlint-enable line-length -->

#### Postgres collector parameters

Postgres collector is able to collect data from pg with sql requests provided in configuration and
exposes it as prometheus metrics.

The parameters of `Postgres collector` should be provided under the section:

```yaml
version_exporter:
  #...
  exporterConfig:
    #...
    postgres_collector:
      connections:
      # list of connections
```

<!-- markdownlint-disable line-length -->
| Field                        | Description                                                                                                                                                | Scheme | Required |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------- |
| host                         | Postgres hostname or ip to connect to. A part of postgres URL. Must be unique.                                                                             | string | true     |
| port                         | Postgres port number to connect to at the server host.                                                                                                     | string | true     |
| credentials.username.key     | Credentials for basic authentication. Secret key                                                                                                           | string | true     |
| credentials.username.name    | Credentials for basic authentication. Secret name                                                                                                          | string | true     |
| credentials.password.key     | Credentials for basic authentication. Secret key                                                                                                           | string | true     |
| credentials.password.name    | Credentials for basic authentication. Secret name                                                                                                          | string | true     |
| db                           | The database name.                                                                                                                                         | string | true     |
| timeout                      | Max connection life time is the duration since creation after which a connection will be automatically closed.                                             | string | true     |
| requests.sql                 | Postgres sql request                                                                                                                                       | string | true     |
| requests.metricName          | Name of new Prometheus metric.                                                                                                                             | string | true     |
| requests.metrics.fieldName   | Name of the field returned by sql request. It is to be unique. Either requests.metrics.label or requests.metrics.valueRegexp is to be used with this field | string | false    |
| requests.description         | Description of new Prometheus metric. Limit 100 symbols.                                                                                                   | string | false    |
| requests.metrics.label       | Name of new Prometheus metric label. It is to be unique if defined.                                                                                        | string | false    |
| requests.metrics.valueRegexp | Regular expression applied to results of sql request                                                                                                       | string | false    |
<!-- markdownlint-enable line-length -->

If requests.metrics.label is not defined, use as labels:

1. Named group of regular expression
2. Column name of sql request results

Example of configuration:

```yaml
postgres_collector:
  connections:
    # Form postgres url, like
    # postgres://postgres:password@pg-patroni.postgres12.svc:5432/postgres?sslmode=disable
    - host: pg-patroni.postgres12.svc
      port: 5432
      credentials:
        username:
          key: pgUsername
          name: version-exporter-extra-vars-secret
        password:
          key: pgPassword
          name: version-exporter-extra-vars-secret
      db: postgres
      # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
      timeout: 10s
      requests:
        - sql: select version()
          metricName: postgres_build_info
          description: "Information about postgres version"
          metrics:
            # If metric exists, 'fieldName' must be present and either 'label' or 'valueRegexp' field must not be empty
            - fieldName: version
              label:
              valueRegexp: \s((?P<major>\d+).(?P<minor>\d+))\son\s(?P<platform>.*?),
        - sql: select extname, extversion from pg_extension
          metricName: postgres_build_info
          metrics:
            - fieldName: extname
              label: extension_name
              valueRegexp:
            - fieldName: extversion
              label: extension_version
        - sql: show server_version
          metricName: postgres_build_info
          metrics:
            - fieldName: server_version
              label: pg_server_version
              valueRegexp: ((\d+).(\d+))
    - host: x.x.x.x
      port: 12345
      credentials:
        username:
          key: pgUsername
          name: version-exporter-extra-vars-secret
        password:
          key: pgPassword
          name: version-exporter-extra-vars-secret
      db: postgres
      # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
      timeout: 10s
      requests:
        - sql: select version()
          metricName: postgres_build_info
          metrics:
            - fieldName: version
              valueRegexp: \s((?P<major>\d+).(?P<minor>\d+))\son\s(?P<platform>.*?),
        - sql: select extname, extversion from pg_extension
          metricName: postgres_build_info
        - sql: show server_version
          metricName: postgres_build_info
          metrics:
            - fieldName: server_version
              valueRegexp: ((?P<major>\d+).(?P<minor>\d+))
        - sql: select * from pg_extension
          metricName: postgres_build_info
          metrics:
```

#### HTTP requests collector parameters

HTTP requests collector can send `GET` and `POST` requests and parse responses with `Content-Type` of `application/json`
and `text/plain`.

To one endpoint (`url`) can be sent one or more requests. A Prometheus metric can be different for different requests.
If `metricName` is not filled, the results will be stored in metric with default name `http_collected_versions` with
configured `labels`. `labels` section is required and `label.name` must be unique.

If `Content-Type` of response is `application/json`, `label.jsonPath` value applied to this json and regular expression
`label.valueRegexp` applied to result of jsonpath search.
If `Content-Type` of response is `text/plain`, `label.valueRegexp` applied to result.

The parameters of `HTTP collector` should be provided under the section:

```yaml
version_exporter:
  #...
  exporterConfig:
    #...
    http_collector:
      connections:
      # list of connections
```

<!-- markdownlint-disable line-length -->

| Field                         | Description                                                                                                          | Scheme | Required |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------ | -------- |
| `url`                         | A part of REST request (protocol, domain ant port). Must be unique.                                                  | string | true     |
| `tlsConfig.tlsSkip`           | Allow to disable certificates verification. Default: `false`.                                                        | bool   | false    |
| `tlsConfig.ca`                | Secret name and key where Certificate Authority is stored. Ignored if `tlsConfig.tlsSkip=true`.                      | object | true     |
| `tlsConfig.cert`              | Secret name and key where Certificate signing request is stored. Ignored if `tlsConfig.tlsSkip=true`.                | object | false    |
| `tlsConfig.pkey`              | Secret name and key where private key is stored. Ignored if `tlsConfig.tlsSkip=true`.                                | object | false    |
| `credentials.username`        | Credentials for basic authentication. Basic auth or token data should be provided if necessary.                      | object | false    |
| `credentials.password`        | Credentials for basic authentication.                                                                                | object | false    |
| `credentials.token`           | Credentials for token-based authentication.                                                                          | object | false    |
| `requests.path`               | Path and parameters of REST request (without protocol, domain ant port). Must be unique.                             | string | true     |
| `requests.method`             | Method of REST request. Possible values: `get/post`                                                                  | string | true     |
| `requests.metricName`         | Name of new Prometheus metric.                                                                                       | string | true     |
| `requests.description`        | Description of new Prometheus metric. Limit 100 symbols.                                                             | string | false    |
| `requests.metrics.jsonPath`   | JsonPath expressions applied to response of Content-Type "application/json". Must be unique.                         | string | false    |
| `requests.labels.name`        | Name of label of new Prometheus metric. Must be unique.                                                              | string | true     |
| `requests.labels.valueRegexp` | Regular expression applied to results of JsonPath search or to response of Content-Type "text/plain". Default: `.*`. | string | false    |

<!-- markdownlint-enable line-length -->

Example of configuration:

```yaml
http_collector:
  connections:
    - url: https://www.example.com
      tlsConfig:
        tlsSkip: false
        ca:
          key: cert-ca.pem
          name: secret-certificate-authority
      credentials:
        username:
          key: user
          name: version-exporter-extra-vars-secret
        password:
          key: password
          name: version-exporter-extra-vars-secret
      requests:
        - path: /version
          method: get
          metricName: "versions_ci_metric"
          metrics:
            - jsonPath: $.buildDate
              labels:
                - name: buildDate
                  valueRegexp: "[a-z0-9.]*"
            - jsonPath: $.gitCommit
              labels:
                - name: gitCommit
        - path: /product_versions
          method: get
          metricName: "versions_ci_product_metric"
          description: "Metric shows versions of product components"
          metrics:
            - jsonPath: $.go.goVersion
              labels:
                - name: goVersion
    - url: https://255.255.255.255:6300
      tlsConfig:
        tlsSkip: true
      credentials:
        token:
          key: token
          name: version-exporter-extra-vars-secret
      requests:
        - path: /version
          method: get
          metricName: "versions_ci_product_metric"
          metrics:
            - jsonPath: $.platform
              labels:
                - name: platform
                  valueRegexp: "[a-z0-9.]*"
        - path: /thirdparty_versions
          method: get
          metricName: "thirdparty_versions_ci_metric"
          metrics:
            - jsonPath: "{range .plugins[*]}{.name}{.version}{end}"
              labels:
                - name: component_name
                  valueRegexp: "[a-z0-9.]*"
                - name: version
```

The jsonpath library used here is <https://kubernetes.io/docs/reference/kubectl/jsonpath>

If you need to collect metrics with some empty values, use "{range ...} ... {end}" function.
Some examples of range-end jsonpath function: ```{range .plugins[*]}{.unique_id}{.name}{.version}{end}```,
```{range @[*]}{.name}{.version}{end}```.
Be careful, jsonpath with range function should not have plain text symbols, because qubership-version-exporter can not parse it.
Example of unsupported case: ```{range .items[*]}[{.metadata.name}, {.status.capacity}] {end}```.

#### ConfigMap collector parameters

ConfigMap collector is able to collect data from K8s resources such ConfigMaps and Secrets and
exposes it as prometheus metrics.

The parameters of `ConfigMap collector` should be provided under the section:

```yaml
version_exporter:
  #...
  exporterConfig:
    #...
    configmap_collector:
      defaults:
        # Default values to search k8s resources and take data from them
      resources:
        - name: # Unique name of searching resource (or group of resources)
          # Values that overrides the default section
        - #...
```

<!-- markdownlint-disable line-length -->
| Field                              | Description                                                                                                                                                                                                                                   | Scheme            | Required |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | -------- |
| defaults                           | Default values for configuration. Can be overrided in the resources section for each resource. Most of fields in this section are mandatory.                                                                                                  | object            | true     |
| defaults.type                      | Type of k8s resource. Allowed values: configmap, secret.                                                                                                                                                                                      | string            | true     |
| defaults.namespaces                | Namespaces in which to search for resources. Use empty list to search in all namespaces.                                                                                                                                                      | list[string]      | true     |
| defaults.resourceLabels            | Allows to search resources by k8s labels instead of names. If resourceLabels is not empty, the search is carried out by labels, and not by the name of the resource.                                                                          | map[string]string | true     |
| defaults.metricName                | Name of new Prometheus metric.                                                                                                                                                                                                                | string            | true     |
| defaults.description               | Description of new Prometheus metric. Limit 100 symbols.                                                                                                                                                                                      | string            | true     |
| defaults.labels                    | Labels of new Prometheus metric.                                                                                                                                                                                                              | list[object]      | true     |
| defaults.labels[N].name            | Name of label of new Prometheus metric. Value for this label will be taken with keyRegexp or valueRegexp. Must be unique.                                                                                                                     | string            | true     |
| defaults.labels[N].keyRegexp       | Regular expression that will be used to find version information in keys of fields in Data from found ConfigMap or Secret. Each labels item must contain either the keyRegexp or the valueRegexp, but not both.                               | string            | false    |
| defaults.labels[N].valueRegexp     | Regular expression that will be used to find version information in values of fields in Data from found ConfigMap or Secret. Each labels item must contain either the keyRegexp or the valueRegexp, but not both.                             | string            | false    |
| resources                          | Each resource must contain the name parameter. Other fields are optional and override values from defaults section. If resourceLabels is empty, resource will be searched by name. Configuration must contain at least one item in this list. | list[object]      | true     |
| resources[N].name                  | Name of resource. If resourceLabels is NOT empty, name parameter will not be used to find resources.                                                                                                                                          | string            | true     |
| resources[N].type                  | Override value from defaults section. Allowed values: configmap, secret.                                                                                                                                                                      | string            | false    |
| resources[N].namespaces            | Override value from defaults section.                                                                                                                                                                                                         | list[string]      | false    |
| resources[N].resourceLabels        | Override value from defaults section.                                                                                                                                                                                                         | map[string]string | false    |
| resources[N].metricName            | Override value from defaults section.                                                                                                                                                                                                         | string            | false    |
| resources[N].description           | Override value from defaults section.                                                                                                                                                                                                         | string            | false    |
| resources[N].labels                | Override value from defaults section.                                                                                                                                                                                                         | list[object]      | false    |
| resources[N].labels[N].name        | Override value from defaults section.                                                                                                                                                                                                         | string            | false    |
| resources[N].labels[N].keyRegexp   | Override value from defaults section.                                                                                                                                                                                                         | string            | false    |
| resources[N].labels[N].valueRegexp | Override value from defaults section.                                                                                                                                                                                                         | string            | false    |
<!-- markdownlint-enable line-length -->

**NOTE:** Almost all the default parameters are required fields.

You can use `name` or `labels` to find ConfigMaps or Secrets you are looking for.
If you declare the empty `resourceLabels` parameter, collector will search resources with the same name as in the
`resources[N].name` field in each of the specified namespaces.

If the `resourceLabels` is not empty, collector will search resources that contain labels from this parameter.
You should declare labels as `map[string]string`. Each label is AND connected.
In this case the `resources[N].name` will NOT be used for searching resources (if `resourceLabels` is not empty,
you can use no real `resources[N].name`), but every item of the `resources`
list must contain this field, and it should be unique anyway.

Parameter `namespaces` allows to specify namespaces for searching resources. Empty list means that resources will be
searched in all namespaces.

Collector parses and processes data from ConfigMaps and Secrets with regular expressions from the `labels` sections.
Configuration must contain at least one item in the `labels` list. Each item must contain unique `name` that will be
used as label name for Prometheus metrics, and must contain either `keyRegexp` or `valueRegexp`.

The data in ConfigMaps and Secrets is a `map[string]string` where each field has a key and a value.
When you specify parameter `keyRegexp` for label item, it means that collector will parse *keys* from the data with
regular expression from the parameter.
If you specify `valueRegexp`, collector will parse *values* with this regular expression.

Version exporter expects the ConfigMap data to be in the following format:

```yaml
...
data:
  {
    "application_name.date.username": "version",
    ...
  }
  ...
```

For example, collector found ConfigMap with follow content:

```yaml
...
data:
  example-app: v0.0.1
  ...
```

Configuration of the collector contains follow statements:

```yaml
...
  metricName: configmap_collected_versions
  labels:
    - name: application_name
      keyRegexp: ^([^\.]+)\.[^\.]+\.[^\.]+
    - name: date
      keyRegexp: ^[^\.]+\.([^\.]+)\.[^\.]+
    - name: username
      keyRegexp: ^[^\.]+\.[^\.]+\.([^\.]+)
    - name: application_version
      valueRegexp: .*
```

Then exposed metrics will contain the follow one:

```bash
configmap_collected_versions{...app_name="example-app",app_version="v0.0.1"}
```

Example of configuration:

```yaml
configmap_collector:
  defaults:
    type: configmap
    namespaces: ["monitoring"]
    resourceLabels: {}
    metricName: "configmap_collected_versions"
    description: "Metric shows version collected from configmaps"
    labels:
      - name: application_name
        keyRegexp: ^([^\.]+)\.[^\.]+\.[^\.]+
      - name: date
        keyRegexp: ^[^\.]+\.([^\.]+)\.[^\.]+
      - name: username
        keyRegexp: ^[^\.]+\.[^\.]+\.([^\.]+)
      - name: application_version
        valueRegexp: .*
  resources:
    # Collector will search configmaps with label "label-key: label-value" in all namespaces
    - name: version-configmap-test
      namespaces: []
      resourceLabels:
        label-key: label-value
      metricName: "configmap_versions"
      description: "Help for Prometheus metric"
      labels:
        - name: version_from_key
          keyRegexp: "version-app-*"
    # Collector will search secret with name "version-secret-test" in the "monitoring" namespace
    - name: version-secret-test
      type: secret
    # Collector will search configmap with name "version-default-configmap" in the "monitoring" namespace
    - name: version-default-configmap
```

#### SSH collector parameters

SSH collector is able to collect data over SSH by requests provided in configuration and
exposes it as prometheus metrics.

The parameters of `SSH collector` should be provided under the section:

```yaml
version_exporter:
  #...
  exporterConfig:
    #...
    ssh_collector:
      connections:
      # list of connections
```

<!-- markdownlint-disable line-length -->
| Field                       | Description                                                                                                    | Scheme | Required |
| --------------------------- | -------------------------------------------------------------------------------------------------------------- | ------ | -------- |
| host                        | SSH server hostname or ip to connect to. Must be unique.                                                      | string | true     |
| port                        | Port number to connect to the server host.                                                                     | string | true     |
| network                     | Network type to connect to the server host. ("tcp" is only supported)                                          | string | true     |
| k8sCredentials.login.key    | Credentials for basic authentication. Secret key                                                               | string | true     |
| k8sCredentials.login.name   | Credentials for basic authentication. Secret name                                                              | string | true     |
| k8sCredentials.pkey.key     | Credentials for basic authentication. Secret key                                                               | string | true     |
| k8sCredentials.pkey.name    | Credentials for basic authentication. Secret name                                                              | string | true     |
| timeout                     | Max connection life time is the duration since creation after which a connection will be automatically closed. | string | true     |
| requests.cmd                | cmd command request. Supported ones: cat, nl, head, tail, echo, hostname, uname                                | string | true     |
| requests.metricName         | Name of new Prometheus metric.                                                                                 | string | true     |
| requests.description        | Description of new Prometheus metric. Limit 100 symbols.                                                       | string | false    |
| requests.labels.name        | Name of new Prometheus metric label. It is to be unique if defined.                                            | string | true     |
| requests.labels.valueRegexp | Regular expression applied to results of cmd request                                                           | string | true     |
<!-- markdownlint-enable line-length -->

Example of configuration:

```yaml
ssh_collector:
  connections:
    - host: x.x.x.x
      port: 22
      network: tcp
      # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
      timeout: 5s
      k8sCredentials:
        login:
          key: sshLogin
          name: version-exporter-extra-vars-secret
        pkey:
          key: privKey
          name: version-exporter-extra-vars-secret
      requests:
        - cmd: "head /etc/os-release"
          metricName: "os_versions_metric"
          labels:
            - name: os_version
              valueRegexp: "[a-z0-9.]*"
            - name: name
              valueRegexp: "[^a-zA-Z0-9]"
        - cmd: 'tail /etc/ssh/ssh_config'
          metricName: "ssh_versions_metric"
          description: "Metric shows versions of ssh component"
          labels:
            - name: ssh_version
              valueRegexp: "[^a-zA-Z0-9]"
        - cmd: 'cat /etc/ssh/ssh_config'
          metricName: "ssh_ver_metric"
          description: "Metric shows versions of ssh component"
          labels:
            - name: version
              valueRegexp: "[^a-zA-Z0-9]"
    - host: x.x.x.x
      port: 22
      network: tcp
      # Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
      timeout: 5s
      k8sCredentials:
        login:
          key: sshLogin
          name: version-exporter-extra-vars-secret
        pkey:
          key: privKey
          name: version-exporter-extra-vars-secret
      requests:
        - cmd: 'echo `ssh -V`'
          metricName: "ssh_version_metric"
          labels:
            - name: ssh_version
              valueRegexp: ".*[^\n]"
        - cmd: 'hostname --fqdn'
          metricName: "hostname_metric"
          labels:
            - name: version
              valueRegexp: "[^a-zA-Z0-9]"

```

## Deploy

### Manual deploy using Helm

This chart installs deployment of Qubership-version-exporter.

#### Installing the Chart

To install the chart with the release name `qubership-version-exporter`:

```bash
helm install qubership-version-exporter charts/qubership-version-exporter
```
