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
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"qubership-version-exporter/collector"

	"github.com/alecthomas/kingpin/v2"
	"github.com/fsnotify/fsnotify"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	versionCollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

func init() {
	prometheus.MustRegister(versionCollector.NewCollector("version_exporter"))
}

func main() {
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

	promLogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promLogConfig)
	kingpin.Version(version.Print("version_exporter"))
	kingpin.CommandLine.UsageWriter(os.Stdout)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promLogConfig)

	_ = os.Setenv("LOG_LEVEL", promLogConfig.Level.String())

	_ = level.Info(logger).Log("msg", fmt.Sprintf("Starting version_exporter: %s", version.Info()))
	_ = level.Info(logger).Log("msg", fmt.Sprintf("Build context: %s", version.BuildContext()))

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

	cfgCont := collector.NewConfigContainer(*configPath, namespace, clientSet, logger)

	if err := cfgCont.Initialize(ctx); err != nil {
		_ = level.Error(logger).Log("msg", "initialization failed", "err", err)
		os.Exit(1)
	}

	var enabledCollectors []collector.Collector
	for collectorName, enabled := range collector.GetCollectorStates() {
		if _, found = cfgCont.CollectorConfigs[collector.AsType(collectorName)]; found && enabled {
			_ = level.Info(logger).Log("msg", fmt.Sprintf("Collector enabled: %s", collectorName))
			c, err := collector.GetCollector(collectorName, logger)
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("couldn't get collector: %s", collectorName), "err", err)
				continue
			}
			enabledCollectors = append(enabledCollectors, c)
		}
	}

	for _, coll := range enabledCollectors {
		if cfg := cfgCont.GetConfig(ctx, coll.Type()); cfg != nil {
			err := coll.Initialize(ctx, cfg)
			if err != nil {
				_ = level.Error(logger).Log("msg", fmt.Sprintf("can't initialize collector: %s", coll.Name()), "err", err)
			}
		}
	}

	exporter := collector.New(ctx, collector.NewMetrics(), enabledCollectors, logger)
	cfgCont.Exporter = exporter

	if *watchPath != "" {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
		}
		defer func(watcher *fsnotify.Watcher) {
			err = watcher.Close()
			if err != nil {
				log.Fatal(err)
			}
		}(watcher)

		err = watcher.Add(*watchPath)
		if err != nil {
			log.Fatal(err)
		}
		_ = level.Debug(logger).Log("msg", fmt.Sprintf("Watching directory: %s", *watchPath))

		fw := &fsWatcher{
			ctx:    ctx,
			logger: logger,
		}

		go fw.watch(watcher, cfgCont)
	}

	metricHandlerFunc := collector.MetricHandler(exporter, *maxRequests, logger)
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
		logger:  logger,
		ctx:     context.WithValue(context.Background(), collector.ContextKey, "shutdown"),
		timeout: 30 * time.Second,
	}
	go sd.listen()
	_ = level.Info(logger).Log("msg", fmt.Sprintf("starting server on address %s", srv.Addr))
	exit := web.ListenAndServe(srv, webConfig, logger)

	cancel()
	for _, coll := range enabledCollectors {
		coll.Close()
	}
	_ = level.Info(logger).Log("msg", "All collectors are closed")

	if !errors.Is(exit, http.ErrServerClosed) {
		_ = level.Error(logger).Log("msg", "failed to start application", "err", exit)
	}
	_ = level.Info(logger).Log("msg", "server is shut down")
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
