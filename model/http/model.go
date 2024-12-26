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

package http

import (
	"regexp"
	"strings"

	"qubership-version-exporter/validation"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/jsonpath"
)

func init() {
	sTag, svfunc, srtrfunc, strfunc := propertyTLSConfig()
	validation.RegisterStructValidation(svfunc, TLSConfig{})
	validation.MustRegisterTranslation(sTag, srtrfunc, strfunc)

	sTag, svfunc, srtrfunc, strfunc = propertyCredentials()
	validation.RegisterStructValidation(svfunc, Credentials{})
	validation.MustRegisterTranslation(sTag, srtrfunc, strfunc)

	tag, vfunc, cn, rtrfunc, trfunc := propertyJsonPath()
	validation.MustRegisterValidation(tag, vfunc, cn)
	validation.MustRegisterTranslation(tag, rtrfunc, trfunc)

	tag, vfunc, cn, rtrfunc, trfunc = validateUniquenessJsonPaths()
	validation.MustRegisterValidation(tag, vfunc, cn)
	validation.MustRegisterTranslation(tag, rtrfunc, trfunc)

	tag, vfunc, cn, rtrfunc, trfunc = validateLabelsAmount()
	validation.MustRegisterValidation(tag, vfunc, cn)
	validation.MustRegisterTranslation(tag, rtrfunc, trfunc)
}

var (
	rangeRegexp = regexp.MustCompile("^{ *range.*{end}$")
)

type Collectors struct {
	Connections []Connector `yaml:"connections" validate:"required,min=1,unique=Host"`
	ClientSet   kubernetes.Interface
}

type Connector struct {
	Host        string          `yaml:"url" validate:"required,url"`
	Credentials Credentials     `yaml:"credentials,omitempty"`
	Requests    []RequestConfig `yaml:"requests" validate:"required,unique=Path,min=1,dive"`
	TlsConfig   TLSConfig       `yaml:"tlsConfig" validate:"required"`
}

type TLSConfig struct {
	TLSSkip   bool `yaml:"tlsSkip,omitempty" default:"false"`
	Namespace string
	CA        SecretKey `yaml:"ca"`
	Cert      SecretKey `yaml:"cert"`
	PKey      SecretKey `yaml:"pkey"`
}

type Credentials struct {
	Namespace string
	Token     SecretKey `yaml:"token,omitempty"`
	User      SecretKey `yaml:"username"`
	Password  SecretKey `yaml:"password"`
}

type SecretKey struct {
	Key  string `yaml:"key"`
	Name string `yaml:"name"`
}

type RequestConfig struct {
	Path        string   `yaml:"path" validate:"required"`
	Method      string   `yaml:"method" validate:"required,oneof=get post"`
	MetricName  string   `yaml:"metricName" validate:"required,prometheus_metric_name"`
	Metrics     []Metric `yaml:"metrics" validate:"required,labels_amount,unique_json_paths,min=1,dive"`
	Description string   `yaml:"description,omitempty" validate:"omitempty,lte=100"`
}

type Metric struct {
	JsonPath string  `yaml:"jsonPath,omitempty" validate:"omitempty,jsonPathProperty"`
	Labels   []Label `yaml:"labels" validate:"required,unique=Name,min=1,dive"`
}

type Label struct {
	Name   string `yaml:"name" validate:"required,prometheus_label_name"`
	Regexp string `yaml:"valueRegexp,omitempty" validate:"omitempty,property_regexp"`
}

func propertyTLSConfig() (t string, v validator.StructLevelFunc, rtr validator.RegisterTranslationsFunc, tr validator.TranslationFunc) {
	t = "tlsConfig"
	v = func(sl validator.StructLevel) {
		selector := sl.Current().Interface().(TLSConfig)
		if !selector.TLSSkip {
			if selector.CA.Key == "" || selector.CA.Name == "" {
				sl.ReportError(selector, "tlsConfig", "TLSConfig", t, "parameters 'ca.key' or 'ca.name' must not be empty")
			}
			if !(selector.Cert.Key != "" && selector.Cert.Name != "" && selector.PKey.Key != "" && selector.PKey.Name != "") &&
				!(selector.Cert.Key == "" && selector.Cert.Name == "" && selector.PKey.Key == "" && selector.PKey.Name == "") {
				sl.ReportError(selector, "tlsConfig", "TLSConfig", t, "parameters 'cert' and 'pkey' are not full")
			}
		}
	}
	rtr = func(ut ut.Translator) error {
		return ut.Add(t, "parameters 'CertName' or 'CertKey' must not be empty", false)
	}
	tr = func(ut ut.Translator, fe validator.FieldError) string {
		trans, _ := ut.T(t, fe.Field(), fe.Param())
		return trans
	}

	return
}

func propertyCredentials() (t string, v validator.StructLevelFunc, rtr validator.RegisterTranslationsFunc, tr validator.TranslationFunc) {
	t = "credentials"
	v = func(sl validator.StructLevel) {
		selector := sl.Current().Interface().(Credentials)
		if (selector.User.Name != "" && (selector.User.Key == "" || selector.Password.Name == "" || selector.Password.Key == "")) ||
			(selector.User.Key != "" && (selector.User.Name == "" || selector.Password.Name == "" || selector.Password.Key == "")) ||
			(selector.Password.Name != "" && (selector.Password.Key == "" || selector.User.Key == "" || selector.User.Name == "")) ||
			(selector.Password.Key != "" && (selector.Password.Name == "" || selector.User.Key == "" || selector.User.Name == "")) ||
			(selector.Token.Name != "" && selector.Token.Key == "") ||
			(selector.Token.Key != "" && selector.Token.Name == "") {
			sl.ReportError(selector, "credentials", "Credentials", t, "credential parameters not fully defined")
		}
	}
	rtr = func(ut ut.Translator) error {
		return ut.Add(t, "credential parameters not fully defined", false)
	}
	tr = func(ut ut.Translator, fe validator.FieldError) string {
		trans, _ := ut.T(t, fe.Field(), fe.Param())
		return trans
	}

	return
}

func propertyJsonPath() (t string, v validator.Func, cn bool, rtr validator.RegisterTranslationsFunc, tr validator.TranslationFunc) {
	t = "jsonPathProperty"
	v = func(fl validator.FieldLevel) bool {
		field := fl.Field()
		if field.String() != "" {
			parserObj := jsonpath.New("validationParser")
			if err := parserObj.Parse(field.String()); err != nil {
				return false
			}
		}
		return true
	}
	rtr = func(ut ut.Translator) error {
		return ut.Add(t, "jsonPath is not valid", false)
	}
	tr = func(ut ut.Translator, fe validator.FieldError) string {
		trans, _ := ut.T(t, fe.Field(), fe.Param())
		return trans
	}

	return
}

func validateUniquenessJsonPaths() (t string, v validator.Func, cn bool, rtr validator.RegisterTranslationsFunc, tr validator.TranslationFunc) {
	t = "unique_json_paths"
	v = func(fl validator.FieldLevel) bool {
		length := fl.Field().Len()
		if length > 1 {
			pathSet := make(map[string]struct{})
			metrics := fl.Field().Interface().([]Metric)
			for _, metric := range metrics {
				if metric.JsonPath != "" {
					if _, ok := pathSet[metric.JsonPath]; ok {
						return false
					} else {
						pathSet[metric.JsonPath] = struct{}{}
					}
				}
			}
		}
		return true
	}
	rtr = func(ut ut.Translator) error {
		return ut.Add(t, "jsonpaths are to be unique within metrics", false)
	}
	tr = func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T(t, fe.Field())
		return t
	}

	return
}

func validateLabelsAmount() (t string, v validator.Func, cn bool, rtr validator.RegisterTranslationsFunc, tr validator.TranslationFunc) {
	t = "labels_amount"
	v = func(fl validator.FieldLevel) bool {
		metrics := fl.Field().Interface().([]Metric)
		for _, metric := range metrics {
			if metric.JsonPath != "" {
				parser1 := jsonpath.NewParser("validationParser")
				if err := parser1.Parse(metric.JsonPath); err != nil {
					return false
				}
				if rangeRegexp.MatchString(metric.JsonPath) {
					re := regexp.MustCompile("[{}]")

					split := re.Split(metric.JsonPath, -1)
					if len(split) > 0 {
						labelsActual := 0
						for i := 1; i < len(split); i = i + 2 {
							if !strings.HasPrefix(split[i], "range") && split[i] != "end" {
								labelsActual++
							}
						}
						if labelsActual != len(metric.Labels) {
							return false
						}
					}
				}

				unionNode := findUnionNode(parser1.Root)
				if unionNode != nil {
					if len(unionNode.Nodes) != len(metric.Labels) {
						return false
					}
				}
				return true
			}
		}
		return true
	}
	rtr = func(ut ut.Translator) error {
		return ut.Add(t, "the number of labels must match the number of return jsonpath values", false)
	}
	tr = func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T(t, fe.Field())
		return t
	}

	return
}

func findUnionNode(listNode jsonpath.Node) (unionNode *jsonpath.UnionNode) {
	if jsonpath.NodeList == listNode.Type() {
		for _, node := range listNode.(*jsonpath.ListNode).Nodes {
			if node.Type() == jsonpath.NodeUnion {
				unionNode = node.(*jsonpath.UnionNode)
				return unionNode
			} else if node.Type() == jsonpath.NodeList {
				listNode = node.(*jsonpath.ListNode)
				if unionNode = findUnionNode(listNode); unionNode != nil {
					return unionNode
				}
			}
		}
	}
	return unionNode
}
