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

package postgres

import (
	"qubership-version-exporter/validation"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	"github.com/prometheus/common/model"
	"k8s.io/client-go/kubernetes"
)

func init() {
	tag, vfunc, cn, rtrfunc, trfunc := validateLabels()
	validation.MustRegisterValidation(tag, vfunc, cn)
	validation.MustRegisterTranslation(tag, rtrfunc, trfunc)
}

type (
	PgConnections struct {
		Connections []ConnOptions `yaml:"connections" validate:"min=1,unique=Host"`
	}

	// ConnOptions postgres://username:password@host:port/db?sslmode=disable
	ConnOptions struct {
		Host        string         `yaml:"host" validate:"required,hostname|ip"`
		Port        int            `yaml:"port" validate:"required,min=1024,max=65535"`
		Credentials Credentials    `yaml:"credentials" validate:"required"`
		DbName      string         `yaml:"db" validate:"required"`
		Timeout     model.Duration `yaml:"timeout" validate:"required"`
		Requests    []Request      `yaml:"requests" validate:"required,gt=0,unique=Sql,dive,required"`
	}

	Request struct {
		Sql         string   `yaml:"sql" validate:"required"`
		MetricName  string   `yaml:"metricName" validate:"required,prometheus_metric_name"`
		Metrics     []Metric `yaml:"metrics" validate:"required,gt=0,unique=FieldName,unique_labels,dive,required"`
		Description string   `yaml:"description,omitempty" validate:"omitempty,lte=100"`
	}

	Metric struct {
		FieldName string `yaml:"fieldName" validate:"required,prometheus_label_name"`
		Label     string `yaml:"label,omitempty" validate:"omitempty,prometheus_label_name"`
		Regexp    string `yaml:"valueRegexp,omitempty" validate:"omitempty,notblank,property_regexp"`
	}

	Credentials struct {
		ClientSet kubernetes.Interface
		Namespace string
		User      SecretKey `yaml:"username" validate:"required"`
		Password  SecretKey `yaml:"password" validate:"required"`
	}

	SecretKey struct {
		Key  string `yaml:"key" validate:"required"`
		Name string `yaml:"name" validate:"required"`
	}
)

func validateLabels() (t string, v validator.Func, cn bool, rtr validator.RegisterTranslationsFunc, tr validator.TranslationFunc) {
	t = "unique_labels"
	v = func(fl validator.FieldLevel) bool {
		length := fl.Field().Len()
		if length > 1 {
			labelSet := make(map[string]struct{})
			metrics := fl.Field().Interface().([]Metric)
			for _, metric := range metrics {
				if metric.Label != "" {
					if _, ok := labelSet[metric.Label]; ok {
						return false
					} else {
						labelSet[metric.Label] = struct{}{}
					}
				}
			}
		}
		return true
	}
	rtr = func(ut ut.Translator) error {
		return ut.Add(t, "labels are to be unique within metric", false)
	}
	tr = func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T(t, fe.Field())
		return t
	}

	return
}
