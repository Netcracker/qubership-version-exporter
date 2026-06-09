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
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace       = "version"
	subsystem       = "scrape"
	collectorPrefix = "collector."

	Postgres      Type = "postgres_collector"
	HttpType      Type = "http_collector"
	ConfigMapType Type = "configmap_collector"
	SSHType       Type = "ssh_collector"

	prometheusTimeoutHeader = "X-Prometheus-Scrape-Timeout-Seconds"
)

type Type string

func (ct Type) String() string {
	types := [...]string{"postgres_collector", "http_collector", "configmap_collector", "ssh_collector"}

	x := string(ct)
	for _, v := range types {
		if v == x {
			return x
		}
	}

	return ""
}

func AsType(str string) Type {
	switch strings.ToLower(str) {
	case Postgres.String(), HttpType.String(), ConfigMapType.String(), SSHType.String():
		return Type(str)
	default:
		return ""
	}
}

func (ct *Type) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type collectorTypeDef Type
	ctDef := (*collectorTypeDef)(ct)
	if err := unmarshal(&ctDef); err != nil {
		return err
	}
	ctVal := Type(*ctDef)
	switch ctVal {
	case Postgres, HttpType, ConfigMapType, SSHType:
		*ct = ctVal
	default:
		return errors.Errorf("unknown collection type: %s", ctVal)
	}
	return nil
}

var (
	scrapeDurationDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "collector_duration_seconds"),
		"version_exporter: Duration of a collector scrape.",
		[]string{"collector"},
		nil,
	)
)

// Verify if Exporter implements prometheus.Collector
var _ prometheus.Collector = (*Exporter)(nil)

// Exporter collects version metrics. It implements prometheus.Collector.
type Exporter struct {
	ctx        context.Context
	logger     slog.Logger
	Collectors []Collector
	metrics    Metrics
	Mutex      sync.RWMutex
}

// New returns a new exporter.
func New(ctx context.Context, metrics Metrics, collectors []Collector, logger slog.Logger) *Exporter {
	return &Exporter{
		ctx:        ctx,
		logger:     logger,
		Collectors: collectors,
		metrics:    metrics,
	}
}

func MetricHandler(exporter *Exporter, maxRequests int, logger slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Use request context for cancellation when connection gets closed.
		ctx := r.Context()
		// If a timeout is configured via the Prometheus header, add it to the context.
		if v := r.Header.Get(prometheusTimeoutHeader); v != "" {
			timeoutSeconds, err := strconv.ParseFloat(v, 64)
			if err != nil {
				logger.Error("Failed to parse timeout from Prometheus header", "error", err)
			} else {
				// Create new timeout context with request context as parent.
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds*float64(time.Second)))
				defer cancel()
				// Overwrite request with timeout context.
				r = r.WithContext(ctx)
			}
		}

		exporter.Mutex.RLock()
		defer exporter.Mutex.RUnlock()

		err := prometheus.Register(exporter)
		if err != nil {
			if !prometheus.Unregister(exporter) {
				logger.Error("Exporter can't be unregistered")
				return
			}
			prometheus.MustRegister(exporter)
		}

		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		handler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
			ErrorHandling:       promhttp.ContinueOnError,
			MaxRequestsInFlight: maxRequests,
		})
		handler.ServeHTTP(w, r)
	}
}

// Describe implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- scrapeDurationDesc
	ch <- e.metrics.TotalScrapes.Desc()
	ch <- e.metrics.Error.Desc()
	e.metrics.ScrapeErrors.Describe(ch)
}

// Collect implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.scrape(e.ctx, ch)
	ch <- e.metrics.TotalScrapes
	ch <- e.metrics.Error
	e.metrics.ScrapeErrors.Collect(ch)
}

func (e *Exporter) scrape(ctx context.Context, ch chan<- prometheus.Metric) {
	e.metrics.TotalScrapes.Inc()
	e.metrics.Error.Set(0)

	var err error
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, scraper := range e.Collectors {
		wg.Add(1)
		go func(scraper Collector) {
			defer wg.Done()
			label := collectorPrefix + scraper.Name()
			sTime := time.Now()
			if err = scraper.Scrape(ctx, &e.metrics, ch); err != nil {
				e.logger.Error(fmt.Sprintf("Error from: %s", scraper.Name()), "error", err)
				e.metrics.ScrapeErrors.WithLabelValues(label).Inc()
				e.metrics.Error.Set(1)
			}
			ch <- prometheus.MustNewConstMetric(scrapeDurationDesc, prometheus.GaugeValue, time.Since(sTime).Seconds(), label)
		}(scraper)
	}
}

// Metrics represents exporter metrics which values can be carried between http requests.
type Metrics struct {
	TotalScrapes prometheus.Counter
	ScrapeErrors *prometheus.CounterVec
	Error        prometheus.Gauge
}

// NewMetrics creates new Metrics instance.
func NewMetrics() Metrics {
	return Metrics{
		TotalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "scrapes_total",
			Help:      "Total number of times metrics were scraped.",
		}),
		ScrapeErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "scrape_errors_total",
			Help:      "Total number of times an error occurred while scraping metrics.",
		}, []string{"collector"}),
		Error: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "last_scrape_error",
			Help:      "Whether the last scrape of metrics resulted in an error (1 for error, 0 for success).",
		}),
	}
}

func registerCollector(collector string, isDefaultEnabled bool, factory func(logger slog.Logger) (Collector, error)) {
	collectorState[collector] = isDefaultEnabled
	factories[collector] = factory
}
