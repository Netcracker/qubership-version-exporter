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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type shutdown struct {
	srv     *http.Server
	logger  slog.Logger
	ctx     context.Context
	timeout time.Duration
}

func (s *shutdown) listen() {
	s.logger.Debug("start listening for interruption signal")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	<-stop
	s.do()
}

func (s *shutdown) do() {
	s.logger.Info("try to shut down server gracefully", "timeout", s.timeout)
	shtdwnCtx, cancel := context.WithTimeout(s.ctx, s.timeout)
	defer cancel()
	if err := s.srv.Shutdown(shtdwnCtx); err != nil {
		s.logger.Info("failed to shut down server gracefully", "timeout", s.timeout, "error", err)
		s.logger.Info("force closing server", "error", s.srv.Close())
	}
}
