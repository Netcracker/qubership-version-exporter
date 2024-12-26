# qubership-version-exporter

`Qubership-version-exporter` is a useful tool that allows you to get product, project, third-party versions of an application and
store the results in custom Prometheus metrics. The exporter supports the following types of collectors:

* Postgres collector which collects versions from Postgres database using sql queries,
* HTTP collector which collects versions by performing REST requests.
* ConfigMap collector which collects versions from ConfigMaps and Secrets in Kubernetes.

The results of versions collectors are processed, filtered and exposed as Prometheus metrics.
z
## Public documents

This section contains documents of directories that describe `qubership-version-exporter`.

* [Installation](documents/public/installation.md)
