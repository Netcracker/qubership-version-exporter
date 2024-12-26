// Copyright 2024-2025 NetCracker Technology Corporation

// Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
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
	"fmt"
	"os"
	"path/filepath"

	"qubership-version-exporter/collector"
	"github.com/fsnotify/fsnotify"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

type fsWatcher struct {
	ctx    context.Context
	logger log.Logger
}

func (fw *fsWatcher) watch(watcher *fsnotify.Watcher, container *collector.Container) {
	for {
		select {
		case event := <-watcher.Events:
			if !fw.isValidEvent(event) {
				continue
			}
			_ = level.Info(fw.logger).Log("msg", "config map updated")

			if err := container.ReadConfig(fw.ctx); err != nil {
				_ = level.Error(fw.logger).Log("msg", "initialization failed", "err", err)
				os.Exit(1)
			}

			container.Exporter.Mutex.RLock()
			var enabledCollectors []collector.Collector
			for collectorName, enabled := range collector.GetCollectorStates() {
				if _, found := container.CollectorConfigs[collector.AsType(collectorName)]; found && enabled {
					_ = level.Info(fw.logger).Log("msg", fmt.Sprintf("Collector enabled: %s", collectorName))
					c, err := collector.GetCollector(collectorName, fw.logger)
					if err != nil {
						_ = level.Error(fw.logger).Log("msg", fmt.Sprintf("couldn't get collector: %s", collectorName), "err", err)
						continue
					}
					enabledCollectors = append(enabledCollectors, c)
				}
			}

			for _, coll := range enabledCollectors {
				coll.Close()
				if cfg := container.GetConfig(fw.ctx, coll.Type()); cfg != nil {
					err := coll.Initialize(fw.ctx, cfg)
					if err != nil {
						_ = level.Error(fw.logger).Log("msg", fmt.Sprintf("can't initialize collector: %s", coll.Name()), "err", err)
					}
				}
			}
			container.Exporter.Collectors = enabledCollectors
			container.Exporter.Mutex.RUnlock()

		case err := <-watcher.Errors:
			_ = level.Error(fw.logger).Log("msg", "initialization failed", "err", err)
		}
	}
}

func (fw *fsWatcher) isValidEvent(event fsnotify.Event) bool {
	_ = level.Debug(fw.logger).Log("msg", event.String())
	if event.Op&fsnotify.Create != fsnotify.Create {
		return false
	}

	if filepath.Base(event.Name) != "..data" {
		return false
	}
	return true
}
