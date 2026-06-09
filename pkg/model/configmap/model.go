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

package configmap

import (
	"k8s.io/client-go/kubernetes"
)

func init() {}

type CmCollector struct {
	Defaults  Defaults   `yaml:"defaults" validate:"required"`
	Resources []Resource `yaml:"resources" validate:"required,min=1,unique=Name"`
	ClientSet kubernetes.Interface
}

type Defaults struct {
	Type           string            `yaml:"type" validate:"required"`
	Namespaces     []string          `yaml:"namespaces" validate:"required"`
	ResourceLabels map[string]string `yaml:"resourceLabels" validate:"required"`
	MetricName     string            `yaml:"metricName" validate:"required,prometheus_metric_name"`
	Description    string            `yaml:"description,omitempty" validate:"omitempty,lte=100"`
	Labels         []Label           `yaml:"labels" validate:"required,unique=Name,min=1,dive"`
}

type Resource struct {
	Name           string            `yaml:"name" validate:"required"`
	Type           string            `yaml:"type,omitempty" validate:"omitempty"`
	Namespaces     []string          `yaml:"namespaces,omitempty" validate:"omitempty"`
	ResourceLabels map[string]string `yaml:"resourceLabels,omitempty" validate:"omitempty"`
	MetricName     string            `yaml:"metricName,omitempty" validate:"omitempty,prometheus_metric_name"`
	Description    string            `yaml:"description,omitempty"`
	Labels         []Label           `yaml:"labels,omitempty" validate:"omitempty,unique=Name,min=1,dive"`
}

type Label struct {
	Name        string `yaml:"name" validate:"required,prometheus_label_name"`
	KeyRegexp   string `yaml:"keyRegexp,omitempty" validate:"omitempty,property_regexp"`
	ValueRegexp string `yaml:"valueRegexp,omitempty" validate:"omitempty,property_regexp"`
}
