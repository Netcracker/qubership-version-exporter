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
	"reflect"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	"github.com/go-playground/validator/v10/non-standard/validators"
	tr "github.com/go-playground/validator/v10/translations/en"
)

var (
	validate   *validator.Validate
	translator ut.Translator
)

func init() {
	validate = validator.New()
	lang := en.New()
	translator, _ = ut.New(lang, lang).GetTranslator(lang.Locale())
	_ = tr.RegisterDefaultTranslations(validate, translator)
	validate.RegisterTagNameFunc(yamlName)

	_ = tr.RegisterDefaultTranslations(validate, translator)

	validate.RegisterTagNameFunc(yamlName)

	MustRegisterValidation("notblank", validators.NotBlank)
	MustRegisterTranslation("notblank",
		func(ut ut.Translator) error {
			return ut.Add("notblank", "{0} can't be blank", false)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("notblank", fe.Field())
			return t
		})

	tag, vfunc, cn, rtrfunc, trfunc := propertyValueRegexp()
	MustRegisterValidation(tag, vfunc, cn)
	MustRegisterTranslation(tag, rtrfunc, trfunc)

	tag, vfunc, cn, rtrfunc, trfunc = PropertyPrometheusLabelName()
	MustRegisterValidation(tag, vfunc, cn)
	MustRegisterTranslation(tag, rtrfunc, trfunc)

	tag, vfunc, cn, rtrfunc, trfunc = PropertyPrometheusMetricName()
	MustRegisterValidation(tag, vfunc, cn)
	MustRegisterTranslation(tag, rtrfunc, trfunc)
}

func yamlName(fl reflect.StructField) string {
	yamlTag := strings.SplitN(fl.Tag.Get("yaml"), ",", 2)
	if len(yamlTag) == 0 {
		return strings.ToLower(fl.Name)
	}
	name := yamlTag[0]
	if name == "-" {
		return ""
	}
	if name == "" {
		for i := 1; i < len(yamlTag); i++ {
			if yamlTag[i] == "inline" {
				return "<" + fl.Name + ">"
			}
		}
	}
	return name
}

func Validator() *validator.Validate {
	return validate
}

func Translator() ut.Translator {
	return translator
}

// Functions to register custom validations/translations during initialization

func MustRegisterValidation(tag string, vfunc validator.Func, callIfNull ...bool) {
	_ = validate.RegisterValidation(tag, vfunc, callIfNull...)
}

func RegisterStructValidation(vfunc validator.StructLevelFunc, types ...interface{}) {
	validate.RegisterStructValidation(vfunc, types...)
}

func MustRegisterTranslation(tag string, rtfunc validator.RegisterTranslationsFunc, tfunc validator.TranslationFunc) {
	_ = validate.RegisterTranslation(tag, translator, rtfunc, tfunc)
}
