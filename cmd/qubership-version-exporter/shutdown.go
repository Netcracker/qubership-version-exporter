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
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

type shutdown struct {
	srv     *http.Server
	logger  log.Logger
	ctx     context.Context
	timeout time.Duration
}

func (s *shutdown) listen() {
	_ = level.Debug(s.logger).Log("msg", "start listening for interruption signal")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	<-stop
	s.do()
}

func (s *shutdown) do() {
	_ = level.Info(s.logger).Log("msg", "try to shut down server gracefully", "timeout", s.timeout)
	shtdwnCtx, cancel := context.WithTimeout(s.ctx, s.timeout)
	defer cancel()
	if err := s.srv.Shutdown(shtdwnCtx); err != nil {
		_ = level.Info(s.logger).Log("msg", "failed to shut down server gracefully", "timeout", s.timeout, "err", err)
		_ = level.Info(s.logger).Log("msg", "force closing server", "err", s.srv.Close())
	}
}
