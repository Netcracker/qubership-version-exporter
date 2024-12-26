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
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"

	collectorModel "qubership-version-exporter/model/configmap"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

func init() {
	registerCollector(ConfigMapType.String(), defaultEnabled, newCmCollector)
}

func (cmCollector *CmCollector) Close() {
	cmCollector.Resources = cmCollector.Resources[:0]
}

func newCmCollector(logger log.Logger) (Collector, error) {
	return &CmCollector{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", ConfigMapType.String()),
			"List of versions from http requests",
			nil, nil),
		ValueType: prometheus.GaugeValue,
		Logger:    logger,
	}, nil
}

const (
	ConfigMapResourceType ResourceType = "configmap"
	SecretResourceType    ResourceType = "secret"
)

type (
	CmCollector struct {
		Desc         *prometheus.Desc
		ValueType    prometheus.ValueType
		Logger       log.Logger
		Resources    []*Resource
		K8sClientSet kubernetes.Interface
	}

	Resource struct {
		Name           string
		Type           ResourceType
		Namespaces     []string
		ResourceLabels map[string]string
		MetricName     string
		Description    string
		Labels         []collectorModel.Label
	}

	ResourceType string
)

func (rt ResourceType) String() string {
	types := [...]string{"configmap", "secret"}

	x := string(rt)
	for _, v := range types {
		if v == x {
			return x
		}
	}

	return ""
}

func AsResourceType(str string) (ResourceType, error) {
	switch strings.ToLower(str) {
	case ConfigMapResourceType.String(), SecretResourceType.String():
		return ResourceType(str), nil
	default:
		return "", errors.Errorf("Unknown resource type: %s", str)
	}
}

func (cmCollector *CmCollector) Initialize(ctx context.Context, config interface{}) error {
	var cmConfig collectorModel.CmCollector
	cfg := reflect.ValueOf(config)
	switch cfg.Kind() {
	case reflect.Struct:
		cmConfig = config.(collectorModel.CmCollector)
	default:
		return errors.Errorf("Unsupported type: %v", cfg.Type())
	}
	cmCollector.K8sClientSet = cmConfig.ClientSet

	for _, rawResource := range cmConfig.Resources {
		r := &Resource{
			Name: rawResource.Name,
		}

		// Fill defaults
		var rawType string
		if rawResource.Type != "" {
			rawType = rawResource.Type
		} else {
			rawType = cmConfig.Defaults.Type
		}
		resourceType, err := AsResourceType(rawType)
		if err != nil {
			return err
		}
		r.Type = resourceType

		if rawResource.Namespaces != nil {
			r.Namespaces = rawResource.Namespaces
		} else {
			r.Namespaces = cmConfig.Defaults.Namespaces
		}

		if rawResource.ResourceLabels != nil {
			r.ResourceLabels = rawResource.ResourceLabels
		} else {
			r.ResourceLabels = cmConfig.Defaults.ResourceLabels
		}

		if rawResource.MetricName != "" {
			r.MetricName = rawResource.MetricName
		} else {
			r.MetricName = cmConfig.Defaults.MetricName
		}

		if rawResource.Description != "" {
			r.Description = rawResource.Description
		} else {
			r.Description = cmConfig.Defaults.Description
		}

		if rawResource.Labels != nil {
			r.Labels = rawResource.Labels
		} else {
			r.Labels = cmConfig.Defaults.Labels
		}

		cmCollector.Resources = append(cmCollector.Resources, r)
	}

	return nil
}

func (cmCollector *CmCollector) Scrape(ctx context.Context, metrics *Metrics, ch chan<- prometheus.Metric) error {
	namespaces, err := cmCollector.K8sClientSet.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		_ = level.Error(cmCollector.Logger).Log("msg", "Failed to get namespaces", "err", err)
		errorLabel := collectorPrefix + cmCollector.Name()
		metrics.ScrapeErrors.WithLabelValues(errorLabel).Inc()
		metrics.Error.Set(1)
		return nil
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	for _, r := range cmCollector.Resources {
		var checkAllNamespaces bool
		if r.Namespaces == nil || len(r.Namespaces) == 0 {
			checkAllNamespaces = true
		} else {
			checkAllNamespaces = false
		}

		for _, ns := range namespaces.Items {
			_ = level.Debug(cmCollector.Logger).Log("msg", "Inspect namespace", "namespace", ns.Name)
			if !checkAllNamespaces {
				isCorrectNamespace := false
				for _, resourceNs := range r.Namespaces {
					if ns.Name == resourceNs {
						isCorrectNamespace = true
						break
					}
				}
				if !isCorrectNamespace {
					continue
				}
			}
			_ = level.Debug(cmCollector.Logger).Log("msg", "Namespace matched")

			// Filtration by Name
			if len(r.ResourceLabels) == 0 {
				_ = level.Debug(cmCollector.Logger).Log("msg", "ResourceLabels is nil. Search for matches by resource name", "resource_name", r.Name)
				switch r.Type {
				case ConfigMapResourceType:
					cm, err := cmCollector.K8sClientSet.CoreV1().ConfigMaps(ns.Name).Get(context.TODO(), r.Name, metav1.GetOptions{})
					if err != nil {
						if k8sErrors.IsNotFound(err) {
							continue
						}
						_ = level.Error(cmCollector.Logger).Log("msg", "Failed to get ConfigMap", "err", err)
						errorLabel := collectorPrefix + cmCollector.Name() + "_" + r.Name
						metrics.ScrapeErrors.WithLabelValues(errorLabel).Inc()
						metrics.Error.Set(1)
						return nil
					}
					_ = level.Info(cmCollector.Logger).Log("msg", "ConfigMap found", "name", r.Name, "namespace", ns.Name)
					if len(cm.Data) > 0 {
						for k, v := range cm.Data {
							wg.Add(1)
							go func(r *Resource, ns v1.Namespace, k string, v string) {
								defer wg.Done()
								promLabels, promValues := cmCollector.parseResourceData(k, v, r.Labels)
								if len(promLabels) > 0 && len(promValues) > 0 && len(promLabels) == len(promValues) {
									_ = level.Debug(cmCollector.Logger).Log("msg", "Send metric", "metric_name", r.MetricName, "labels", strings.Join(promLabels, ","), "label_values", strings.Join(promValues, ","))
									sendMetrics(promLabels, promValues, r, ns, ch)
								}
							}(r, ns, k, v)
						}
					} else {
						_ = level.Debug(cmCollector.Logger).Log("msg", "ConfigMap data is empty", "name", r.Name, "namespace", ns.Name)
					}
				case SecretResourceType:
					s, err := cmCollector.K8sClientSet.CoreV1().Secrets(ns.Name).Get(context.TODO(), r.Name, metav1.GetOptions{})
					if err != nil {
						if k8sErrors.IsNotFound(err) {
							continue
						}
						_ = level.Error(cmCollector.Logger).Log("msg", "Failed to get ConfigMap", "err", err)
						errorLabel := collectorPrefix + cmCollector.Name() + "_" + r.Name
						metrics.ScrapeErrors.WithLabelValues(errorLabel).Inc()
						metrics.Error.Set(1)
						return nil
					}
					_ = level.Info(cmCollector.Logger).Log("msg", "Secret found", "name", r.Name, "namespace", ns.Name)
					if len(s.Data) > 0 {
						for k, v := range s.Data {
							stringV := string(v)
							wg.Add(1)
							go func(r *Resource, ns v1.Namespace, k string, stringV string) {
								defer wg.Done()
								promLabels, promValues := cmCollector.parseResourceData(k, stringV, r.Labels)
								if len(promLabels) > 0 && len(promValues) > 0 && len(promLabels) == len(promValues) {
									_ = level.Debug(cmCollector.Logger).Log("msg", "Send metric", "metric_name", r.MetricName, "labels", strings.Join(promLabels, ","), "label_values", strings.Join(promValues, ","))
									sendMetrics(promLabels, promValues, r, ns, ch)
								}
							}(r, ns, k, stringV)
						}
					} else {
						_ = level.Debug(cmCollector.Logger).Log("msg", "Secret data is empty", "name", r.Name, "namespace", ns.Name)
					}
				default:
					_ = level.Error(cmCollector.Logger).Log("msg", "Unknown resource type", "type", r.Type.String())
					errorLabel := collectorPrefix + cmCollector.Name() + "_" + r.Name
					metrics.ScrapeErrors.WithLabelValues(errorLabel).Inc()
					metrics.Error.Set(1)
					return nil
				}
				// Filtration by Resource labels
			} else {
				listOptions := metav1.ListOptions{
					LabelSelector: labels.SelectorFromSet(r.ResourceLabels).String(),
				}

				_ = level.Debug(cmCollector.Logger).Log("msg", "Search for matches by resource labels", "resource_labels", labels.SelectorFromSet(r.ResourceLabels).String())
				switch r.Type {
				case ConfigMapResourceType:
					cmList, err := cmCollector.K8sClientSet.CoreV1().ConfigMaps(ns.Name).List(context.TODO(), listOptions)
					if err != nil {
						_ = level.Error(cmCollector.Logger).Log("msg", "Failed to get list of ConfigMaps", "err", err)
						errorLabel := collectorPrefix + cmCollector.Name() + "_" + r.Name
						metrics.ScrapeErrors.WithLabelValues(errorLabel).Inc()
						metrics.Error.Set(1)
						return nil
					}
					if len(cmList.Items) == 0 {
						continue
					}
					var resourceLabelsStr []string
					for k, v := range r.ResourceLabels {
						resourceLabelsStr = append(resourceLabelsStr, fmt.Sprintf("%s:%s", k, v))
					}
					_ = level.Info(cmCollector.Logger).Log("msg", "ConfigMaps found by resource labels", "resource_labels", strings.Join(resourceLabelsStr, ","), "namespace", ns.Name)
					for _, cm := range cmList.Items {
						if len(cm.Data) > 0 {
							for k, v := range cm.Data {
								wg.Add(1)
								go func(r *Resource, ns v1.Namespace, k string, v string) {
									defer wg.Done()
									promLabels, promValues := cmCollector.parseResourceData(k, v, r.Labels)
									if len(promLabels) > 0 && len(promValues) > 0 && len(promLabels) == len(promValues) {
										_ = level.Debug(cmCollector.Logger).Log("msg", "Send metric", "metric_name", r.MetricName, "labels", strings.Join(promLabels, ","), "label_values", strings.Join(promValues, ","))
										sendMetrics(promLabels, promValues, r, ns, ch)
									}
								}(r, ns, k, v)
							}
						} else {
							_ = level.Debug(cmCollector.Logger).Log("msg", "ConfigMap data is empty", "name", r.Name, "namespace", ns.Name)
						}
					}
				case SecretResourceType:
					sList, err := cmCollector.K8sClientSet.CoreV1().Secrets(ns.Name).List(context.TODO(), listOptions)
					if err != nil {
						_ = level.Error(cmCollector.Logger).Log("msg", "Failed to get list of Secrets", "err", err)
						errorLabel := collectorPrefix + cmCollector.Name() + "_" + r.Name
						metrics.ScrapeErrors.WithLabelValues(errorLabel).Inc()
						metrics.Error.Set(1)
						return nil
					}
					if len(sList.Items) == 0 {
						continue
					}
					var resourceLabelsStr []string
					for k, v := range r.ResourceLabels {
						resourceLabelsStr = append(resourceLabelsStr, fmt.Sprintf("%s:%s", k, v))
					}
					_ = level.Info(cmCollector.Logger).Log("msg", "Secrets found by resource labels", "resource_labels", strings.Join(resourceLabelsStr, ","), "namespace", ns.Name)
					for _, s := range sList.Items {
						if len(s.Data) > 0 {
							for k, v := range s.Data {
								stringV := string(v)
								wg.Add(1)
								go func(r *Resource, ns v1.Namespace, k string, stringV string) {
									defer wg.Done()
									promLabels, promValues := cmCollector.parseResourceData(k, stringV, r.Labels)
									if len(promLabels) > 0 && len(promValues) > 0 && len(promLabels) == len(promValues) {
										_ = level.Debug(cmCollector.Logger).Log("msg", "Send metric", "metric_name", r.MetricName, "labels", strings.Join(promLabels, ","), "label_values", strings.Join(promValues, ","))
										sendMetrics(promLabels, promValues, r, ns, ch)
									}
								}(r, ns, k, stringV)
							}
						} else {
							_ = level.Debug(cmCollector.Logger).Log("msg", "Secret data is empty", "name", r.Name, "namespace", ns.Name)
						}
					}
				default:
					_ = level.Error(cmCollector.Logger).Log("msg", "Unknown resource type", "type", r.Type.String())
					errorLabel := collectorPrefix + cmCollector.Name() + "_" + r.Name
					metrics.ScrapeErrors.WithLabelValues(errorLabel).Inc()
					metrics.Error.Set(1)
					return nil
				}
			}
		}
	}

	return nil
}

func (cmCollector *CmCollector) parseResourceData(key string, value string, labels []collectorModel.Label) (resultLabels, resultValues []string) {
	_ = level.Debug(cmCollector.Logger).Log("msg", "Processing key-value pair", "key", key, "value", value)
	for _, l := range labels {
		_ = level.Debug(cmCollector.Logger).Log("msg", "Processing label", "label_name", l.Name)
		if l.KeyRegexp != "" {
			_ = level.Debug(cmCollector.Logger).Log("msg", "Searching version in key by regexp", "key", key, "regexp", l.KeyRegexp)
			foundStr := cmCollector.parseKeyString(key, l.KeyRegexp)
			if foundStr != "" {
				_ = level.Debug(cmCollector.Logger).Log("msg", "Found version in key by regexp", "version", foundStr, "regexp", l.KeyRegexp)
				resultLabels = append(resultLabels, l.Name)
				resultValues = append(resultValues, foundStr)
			}
		} else if l.ValueRegexp != "" {
			_ = level.Debug(cmCollector.Logger).Log("msg", "Searching version in value by regexp", "value", value, "regexp", l.ValueRegexp)
			foundStr := cmCollector.parseString(value, l.ValueRegexp)
			if foundStr != "" {
				_ = level.Debug(cmCollector.Logger).Log("msg", "Found version in value by regexp", "version", foundStr, "regexp", l.ValueRegexp)
				resultLabels = append(resultLabels, l.Name)
				resultValues = append(resultValues, foundStr)
			}
		} else {
			_ = level.Warn(cmCollector.Logger).Log("msg", "Label has no fields keyRegexp or valueRegexp", "label_name", l.Name)
		}
	}

	return
}

func (cmCollector *CmCollector) parseString(str string, regex string) string {
	regexpCompiled := regexp.MustCompile(regex)
	return regexpCompiled.FindString(str)
}

func (cmCollector *CmCollector) parseKeyString(str string, regex string) string {
	regexpCompiled := regexp.MustCompile(regex)
	if matches := regexpCompiled.FindStringSubmatch(str); len(matches) > 1 {
		return matches[1]
	} else {
		_ = level.Debug(cmCollector.Logger).Log("msg", "Cannot match string", "version", str, "regexp", regex)
		return ""
	}
}

func sendMetrics(labels, labelValues []string, r *Resource, ns v1.Namespace, ch chan<- prometheus.Metric) {
	labels = append(labels, commonLabel)
	labelValues = append(labelValues, commonLabelValue)

	labels = append(labels, versionNamespace)
	labelValues = append(labelValues, ns.Name)

	help := "A metric generated by qubership-version-exporter configmap collector."
	if len(strings.TrimSpace(r.Description)) > 0 {
		help = fmt.Sprintf("%s Description: %s.", help, r.Description)
	}
	buildInfo := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: r.MetricName,
			Help: help,
		},
		labels,
	)
	buildInfo.WithLabelValues(labelValues...).Set(1)
	buildInfo.MetricVec.Collect(ch)
}

func (cmCollector *CmCollector) Type() Type {
	return ConfigMapType
}

// Name of the Scraper. Should be unique.
func (cmCollector *CmCollector) Name() string {
	return ConfigMapType.String()
}
