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

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
)

type contextKey string

const (
	defaultEnabled              = true
	ContextKey       contextKey = "ctxKey"
	commonLabel                 = "dashboard"
	commonLabelValue            = "qubership-version-exporter"
	versionNamespace			= "version_namespace"
)

var (
	factories      = make(map[string]func(logger log.Logger) (Collector, error))
	collectorState = make(map[string]bool)
)

//Collector is minimal interface that let you add new prometheus metrics to version_exporter.
type Collector interface {
	// Name of the Scraper. Should be unique.
	Name() string

	Type() Type

	Initialize(ctx context.Context, config interface{}) error

	Close()

	// Scrape collects data from database connection and sends it over channel as prometheus metric.
	Scrape(ctx context.Context, metrics *Metrics, ch chan<- prometheus.Metric) error
}

func GetCollectorStates() map[string]bool {
	return collectorState
}

func GetCollector(name string, logger log.Logger) (Collector, error) {
	return factories[name](log.With(logger, "depth_caller", log.Caller(4)))
}
