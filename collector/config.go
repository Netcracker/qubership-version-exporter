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
	"errors"
	"fmt"
	"os"
	"sync"

	configMapModel "qubership-version-exporter/model/configmap"
	httpModel "qubership-version-exporter/model/http"
	"qubership-version-exporter/model/postgres"
	"qubership-version-exporter/model/ssh"
	"qubership-version-exporter/validation"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-playground/validator/v10"
	errs "github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"
)

type rawMessage struct {
	unmarshal func(interface{}) error
}

func (msg *rawMessage) UnmarshalYAML(unmarshal func(interface{}) error) error {
	msg.unmarshal = unmarshal
	return nil
}

func (msg *rawMessage) Unmarshal(v interface{}) error {
	return msg.unmarshal(v)
}

type ExporterConfig struct {
	ConfigPath string
	ClientSet  kubernetes.Interface
	Namespace  string
	Mutex      sync.RWMutex
}

type Container struct {
	*ExporterConfig
	Exporter         *Exporter
	CollectorConfigs map[Type]interface{}

	once   sync.Once
	logger log.Logger
}

func NewConfigContainer(configPath, namespace string, clientSet kubernetes.Interface, logger log.Logger) *Container {
	configHolder := &Container{
		ExporterConfig: &ExporterConfig{
			ConfigPath: configPath,
			ClientSet:  clientSet,
			Namespace:  namespace,
		},
		CollectorConfigs: make(map[Type]interface{}),
		logger:           logger,
	}

	return configHolder
}

func (c *Container) Initialize(ctx context.Context) (err error) {
	c.once.Do(func() {
		err = c.ReadConfig(ctx)
	})
	return
}

func (c *Container) ReadConfig(ctx context.Context) error {
	_ = level.Debug(c.logger).Log("msg", fmt.Sprintf("trying to read config: %s", c.ConfigPath))

	c.Mutex.RLock()
	defer c.Mutex.RUnlock()

	configMap := make(map[Type]rawMessage)

	yamlFile, err := os.ReadFile(c.ConfigPath)
	if err != nil {
		_ = level.Error(c.logger).Log("msg", "failed to read config file", "err", err)
		return err
	}
	if err = yaml.UnmarshalStrict(yamlFile, &configMap); err != nil {
		_ = level.Error(c.logger).Log("msg", "failed to decode config", "err", err)
		return err
	}

	if configMap == nil {
		return errors.New("config is empty!")
	}

	if len(c.CollectorConfigs) != 0 {
		c.CollectorConfigs = make(map[Type]interface{})
	}
	for cType, rawConfig := range configMap {
		if rawConfig.unmarshal == nil {
			return errs.Errorf("%s config cannot be unmarshalled", cType.String())
		} else {
			switch cType {
			case Postgres:
				var postgresConfig postgres.PgConnections
				if err = rawConfig.Unmarshal(&postgresConfig); err == nil {
					if err = c.validateConfig(ctx, postgresConfig, cType.String()); err != nil {
						return err
					}
					for i, pgCfg := range postgresConfig.Connections {
						if err = c.validateConfig(ctx, pgCfg, cType.String()); err != nil {
							return err
						}
						postgresConfig.Connections[i].Credentials.ClientSet = c.ClientSet
						postgresConfig.Connections[i].Credentials.Namespace = c.Namespace
					}
					c.CollectorConfigs[cType] = postgresConfig
				} else {
					return errs.Errorf("%s config cannot be parsed: %v", cType.String(), err)
				}
			case HttpType:
				var httpConfig httpModel.Collectors
				if err = rawConfig.Unmarshal(&httpConfig); err == nil {
					if err = c.validateConfig(ctx, httpConfig, cType.String()); err != nil {
						return err
					}
					httpConfig.ClientSet = c.ClientSet
					for i, cfg := range httpConfig.Connections {
						if err = c.validateConfig(ctx, cfg, cType.String()); err != nil {
							return err
						}
						httpConfig.Connections[i].Credentials.Namespace = c.Namespace
						httpConfig.Connections[i].TlsConfig.Namespace = c.Namespace
					}
					c.CollectorConfigs[cType] = httpConfig
				} else {
					return errs.Errorf("%s config cannot be parsed: %v", cType.String(), err)
				}
			case ConfigMapType:
				var cmConfig configMapModel.CmCollector
				if err = rawConfig.Unmarshal(&cmConfig); err == nil {
					if err = c.validateConfig(ctx, cmConfig, cType.String()); err != nil {
						return err
					}
					cmConfig.ClientSet = c.ClientSet
					c.CollectorConfigs[cType] = cmConfig
				} else {
					return errs.Errorf("%s config cannot be parsed: %v", cType.String(), err)
				}
			case SSHType:
				var sshConfig ssh.Connections
				if err = rawConfig.Unmarshal(&sshConfig); err == nil {
					if err = c.validateConfig(ctx, sshConfig, cType.String()); err != nil {
						return err
					}
					for i, sshCfg := range sshConfig.Connections {
						if err = c.validateConfig(ctx, sshCfg, cType.String()); err != nil {
							return err
						}
						if sshConfig.Connections[i].K8sCredentials != nil {
							sshConfig.Connections[i].K8sCredentials.ClientSet = c.ClientSet
							sshConfig.Connections[i].K8sCredentials.Namespace = c.Namespace
						}
					}
					c.CollectorConfigs[cType] = sshConfig
				} else {
					return errs.Errorf("%s config cannot be parsed: %v", cType.String(), err)
				}
			default:
				return errs.Errorf("unknown collector type: %s", cType)
			}
		}
	}

	return nil
}

func (c *Container) GetConfig(ctx context.Context, configType Type) interface{} {
	if cfg, found := c.CollectorConfigs[configType]; found {
		return cfg
	}

	return nil
}

func (c *Container) validateConfig(ctx context.Context, config interface{}, configType string) error {
	if err := validation.Validator().Struct(config); err != nil {
		var validationErrors validator.ValidationErrors
		ok := errors.As(err, &validationErrors)
		if ok {
			_ = level.Error(c.logger).Log("msg", fmt.Sprintf("config %s isn't valid. Error: %s", configType, validationErrors.Translate(validation.Translator())))
		} else {
			_ = level.Error(c.logger).Log("msg", fmt.Sprintf("config %s isn't valid", configType))
		}

		return err
	}

	return nil
}
