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

package ssh

import (
	"time"

	"github.com/Netcracker/qubership-version-exporter/pkg/validation"

	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	"k8s.io/client-go/kubernetes"
)

func init() {
	sTag, svfunc, srtrfunc, strfunc := propertyCredentials()
	validation.RegisterStructValidation(svfunc, ConnOptions{})
	validation.MustRegisterTranslation(sTag, srtrfunc, strfunc)
}

type (
	Connections struct {
		Connections []ConnOptions `yaml:"connections" validate:"min=1,unique=Host"`
	}

	ConnOptions struct {
		Host           string          `yaml:"host" validate:"required,hostname|ip"`
		Port           int             `yaml:"port" validate:"required,max=65535"`
		Network        string          `yaml:"network" validate:"required,eq=tcp"`
		Timeout        time.Duration   `yaml:"timeout" validate:"required"`
		Credentials    *Credentials    `yaml:"credentials,omitempty"`
		K8sCredentials *K8sCredentials `yaml:"k8sCredentials,omitempty"`
		Requests       []Request       `yaml:"requests" validate:"required,gt=0,dive,required"`
	}

	Credentials struct {
		Login          string  `yaml:"login" validate:"required"`
		PKeyPath       string  `yaml:"identityFile" validate:"required,file"`
		KnownHostsPath *string `yaml:"knownHostsPath,omitempty" validate:"omitempty,file"`
	}

	K8sCredentials struct {
		ClientSet kubernetes.Interface
		Namespace string
		Login     SecretKey `yaml:"login" validate:"required"`
		PKey      SecretKey `yaml:"pkey" validate:"required"`
	}

	SecretKey struct {
		Key  string `yaml:"key" validate:"required"`
		Name string `yaml:"name" validate:"required"`
	}

	Request struct {
		Cmd         string  `yaml:"cmd" validate:"required,startswith=cat|startswith=nl|startswith=head|startswith=tail|startswith=echo|startswith=hostname|startswith=uname"`
		MetricName  string  `yaml:"metricName" validate:"required,prometheus_metric_name"`
		Description string  `yaml:"description,omitempty" validate:"omitempty,lte=100"`
		Labels      []Label `yaml:"labels" validate:"required,unique=Name,min=1,dive"`
	}

	Label struct {
		Name   string `yaml:"name" validate:"required,prometheus_label_name"`
		Regexp string `yaml:"valueRegexp" validate:"required,property_regexp"`
	}
)

func propertyCredentials() (t string, v validator.StructLevelFunc, rtr validator.RegisterTranslationsFunc, tr validator.TranslationFunc) {
	t = "connections"
	v = func(sl validator.StructLevel) {
		connOptions := sl.Current().Interface().(ConnOptions)
		if (connOptions.Credentials != nil && connOptions.K8sCredentials != nil) ||
			(connOptions.Credentials == nil && connOptions.K8sCredentials == nil) {
			sl.ReportError(connOptions, "connections", "Connections", t, "Only one parameter: credentials or k8sCredentials is to be defined")
		}
	}
	rtr = func(ut ut.Translator) error {
		return ut.Add(t, "Only one parameter: credentials or k8sCredentials is to be defined", false)
	}
	tr = func(ut ut.Translator, fe validator.FieldError) string {
		trans, _ := ut.T(t, fe.Field(), fe.Param())
		return trans
	}

	return
}
