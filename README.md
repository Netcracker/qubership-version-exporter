# qubership-version-exporter
[![Super-Linter](https://github.com/Netcracker/qubership-version-exporter/actions/workflows/super-linter.yaml/badge.svg)](https://github.com/marketplace/actions/super-linter)

`Qubership-version-exporter` is a useful tool that allows you to get product, project, third-party versions of an application and
store the results in custom Prometheus metrics. The exporter supports the following types of collectors:

* Postgres collector which collects versions from Postgres database using SQL queries,
* HTTP collector which collects versions by performing REST requests.
* ConfigMap collector which collects versions from ConfigMaps and Secrets in Kubernetes.

The results of versions collectors are processed, filtered and exposed as Prometheus metrics.

## Public documents

This section contains documents of directories that describe `qubership-version-exporter`.

* [Installation](docs/installation.md)

## Development
Before push your commits and create PR run linters and test.
* SuperLinter
```shell
docker run \
  -e RUN_LOCAL=true \
  -e DEFAULT_BRANCH=$(git rev-parse --abbrev-ref HEAD) \
  --env-file .github/super-linter.env \
  -v ${PWD}:/tmp/lint \
  --rm \
  ghcr.io/super-linter/super-linter:slim-$(sed -nE 's#.*uses:\s+super-linter/super-linter/slim@([^\s]+).*#\1#p' .github/workflows/super-linter.yaml)
```

