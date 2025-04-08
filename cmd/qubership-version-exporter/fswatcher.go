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
	"log/slog"
	"os"
	"path/filepath"

	"github.com/Netcracker/qubership-version-exporter/pkg/collector"

	"github.com/fsnotify/fsnotify"
)

type fsWatcher struct {
	ctx    context.Context
	logger slog.Logger
}

func (fw *fsWatcher) watch(watcher *fsnotify.Watcher, container *collector.Container) {
	for {
		select {
		case event := <-watcher.Events:
			if !fw.isValidEvent(event) {
				continue
			}
			fw.logger.Info("config map updated")

			if err := container.ReadConfig(fw.ctx); err != nil {
				fw.logger.Error("initialization failed", "error", err)
				os.Exit(1)
			}

			container.Exporter.Mutex.RLock()
			var enabledCollectors []collector.Collector
			for collectorName, enabled := range collector.GetCollectorStates() {
				if _, found := container.CollectorConfigs[collector.AsType(collectorName)]; found && enabled {
					fw.logger.Info("Collector enabled", "collector", collectorName)
					c, err := collector.GetCollector(collectorName, fw.logger)
					if err != nil {
						fw.logger.Error("couldn't get collector", "collector", collectorName, "error", err)
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
						fw.logger.Error("can't initialize collector", "collector", coll.Name(), "error", err)
					}
				}
			}
			container.Exporter.Collectors = enabledCollectors
			container.Exporter.Mutex.RUnlock()

		case err := <-watcher.Errors:
			fw.logger.Error("initialization failed", "error", err)
		}
	}
}

func (fw *fsWatcher) isValidEvent(event fsnotify.Event) bool {
	fw.logger.Debug(event.String())
	if event.Op&fsnotify.Create != fsnotify.Create {
		return false
	}

	if filepath.Base(event.Name) != "..data" {
		return false
	}
	return true
}
