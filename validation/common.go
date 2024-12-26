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

package validation

import (
	"regexp"

	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	"github.com/prometheus/common/model"
)

func propertyValueRegexp() (t string, v validator.Func, cn bool, rtr validator.RegisterTranslationsFunc, tr validator.TranslationFunc) {
	t = "property_regexp"
	v = func(fl validator.FieldLevel) bool {
		_, err := regexp.Compile(fl.Field().String())
		return err == nil
	}
	rtr = func(ut ut.Translator) error {
		return ut.Add(t, "{0} shall be a valid regexp", false)
	}
	tr = func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T(t, fe.Field())
		return t
	}

	return
}

func PropertyPrometheusLabelName() (t string, v validator.Func, cn bool, rtr validator.RegisterTranslationsFunc, tr validator.TranslationFunc) {
	t = "prometheus_label_name"
	v = func(fl validator.FieldLevel) bool {
		valid := model.LabelName(fl.Field().String()).IsValid()
		return valid
	}
	rtr = func(ut ut.Translator) error {
		return ut.Add(t, "{0} shall be a valid postgres sql query", false)
	}
	tr = func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T(t, fe.Field())
		return t
	}

	return
}

func PropertyPrometheusMetricName() (t string, v validator.Func, cn bool, rtr validator.RegisterTranslationsFunc, tr validator.TranslationFunc) {
	t = "prometheus_metric_name"
	v = func(fl validator.FieldLevel) bool {
		valid := model.MetricNameRE.MatchString(fl.Field().String())
		return valid
	}
	rtr = func(ut ut.Translator) error {
		return ut.Add(t, "{0} shall be a valid prometheus metric name", false)
	}
	tr = func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T(t, fe.Field())
		return t
	}

	return
}
