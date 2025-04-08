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

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Netcracker/qubership-version-exporter/pkg/collector"
	"github.com/Netcracker/qubership-version-exporter/pkg/logger"

	"github.com/alecthomas/kingpin/v2"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	versionCollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	webConfig  = webflag.AddFlags(kingpin.CommandLine, ":9100")
	metricPath = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Default("/metrics").String()
	maxRequests = kingpin.Flag(
		"web.max-requests",
		"Maximum number of parallel scrape requests. Use 0 to disable.",
	).Default("40").Int()
	configPath = kingpin.Flag(
		"config.file",
		"Version exporter configuration file.",
	).Default("/config/exporterConfig.yaml").String()
	watchPath = kingpin.Flag(
		"config.watch",
		"Directory for watching change config map events.",
	).Default("").String()
)

func init() {
	prometheus.MustRegister(versionCollector.NewCollector("qubership_version_exporter"))
}

func main() {
	// Initialize logger
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	loggerConfig := &logger.Config{}
	logger := logger.New(loggerConfig)

	err := loggerConfig.Level.Set(logLevel)
	if err != nil {
		logger.Error("Failed to set log level", "error", err)
	}

	logger.Info("Starting qubership_version_exporter", "version", version.Info())
	logger.Info("Build context", "context", version.BuildContext())

	baseCtx, cancel := context.WithCancel(context.Background())
	ctx := context.WithValue(baseCtx, collector.ContextKey, "main")

	namespace, found := os.LookupEnv("POD_NAMESPACE")
	if !found {
		namespace = "monitoring"
	}

	rCfg, _ := ctrl.GetConfig()
	var clientSet *kubernetes.Clientset
	if rCfg != nil {
		clientSet = kubernetes.NewForConfigOrDie(rCfg)
	}

	cfgCont := collector.NewConfigContainer(*configPath, namespace, clientSet, *logger)

	if err := cfgCont.Initialize(ctx); err != nil {
		logger.Error("Initialization failed", "error", err)
		os.Exit(1)
	}

	var enabledCollectors []collector.Collector
	for collectorName, enabled := range collector.GetCollectorStates() {
		if _, found = cfgCont.CollectorConfigs[collector.AsType(collectorName)]; found && enabled {
			logger.Info("Collector enabled", "collector", collectorName)
			c, err := collector.GetCollector(collectorName, *logger)
			if err != nil {
				logger.Error("Couldn't get collector", "collector", collectorName, "error", err)
				continue
			}
			enabledCollectors = append(enabledCollectors, c)
		}
	}

	for _, coll := range enabledCollectors {
		if cfg := cfgCont.GetConfig(ctx, coll.Type()); cfg != nil {
			err := coll.Initialize(ctx, cfg)
			if err != nil {
				logger.Error("Can't initialize collector", "collector", coll.Name(), "error", err)
			}
		}
	}

	exporter := collector.New(ctx, collector.NewMetrics(), enabledCollectors, *logger)
	cfgCont.Exporter = exporter

	if *watchPath != "" {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			logger.Error("Couldn't create a new file system watcher", "error", err)
		}
		defer func(watcher *fsnotify.Watcher) {
			err = watcher.Close()
			if err != nil {
				logger.Error("Unexpected error", "error", err)
			}
		}(watcher)

		err = watcher.Add(*watchPath)
		if err != nil {
			logger.Error("Unexpected error", "error", err)
		}
		logger.Debug("Watching directory", "directory", *watchPath)

		fw := &fsWatcher{
			ctx:    ctx,
			logger: *logger,
		}

		go fw.watch(watcher, cfgCont)
	}

	metricHandlerFunc := collector.MetricHandler(exporter, *maxRequests, *logger)
	http.Handle(*metricPath, promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, metricHandlerFunc))
	http.Handle("/-/ready", readinessChecker())
	http.Handle("/-/healthy", healthChecker())

	srvBaseCtx := context.WithValue(context.Background(), collector.ContextKey, "http")
	srv := &http.Server{
		BaseContext: func(_ net.Listener) context.Context {
			return srvBaseCtx
		},
	}

	sd := &shutdown{
		srv:     srv,
		logger:  *logger,
		ctx:     context.WithValue(context.Background(), collector.ContextKey, "shutdown"),
		timeout: 30 * time.Second,
	}
	go sd.listen()
	logger.Info(fmt.Sprintf("Starting server on address %s", srv.Addr))
	exit := web.ListenAndServe(srv, webConfig, logger)

	cancel()
	for _, coll := range enabledCollectors {
		coll.Close()
	}
	logger.Info("All collectors are closed")

	if !errors.Is(exit, http.ErrServerClosed) {
		logger.Error("Failed to start application", "error", exit)
	}
	logger.Info("Server is shut down")
}

func healthChecker() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		},
	)
}

func readinessChecker() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})
}
