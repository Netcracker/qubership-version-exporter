{{/*
Expand the name of the chart.
*/}}
{{- define "qubership-version-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "qubership-version-exporter.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "qubership-version-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "qubership-version-exporter.labels" -}}
helm.sh/chart: {{ include "qubership-version-exporter.chart" . }}
{{ include "qubership-version-exporter.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "qubership-version-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qubership-version-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "qubership-version-exporter.serviceAccountName" -}}
{{- if .Values.versionExporter.serviceAccount.create }}
{{- default (include "qubership-version-exporter.fullname" .) .Values.versionExporter.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.versionExporter.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Find an image in various places.
Image can be found from:
* specified by user from .Values.versionExporter.image
* default value
*/}}
{{- define "version-exporter.image" -}}
  {{- if .Values.versionExporter.image -}}
    {{- printf "%s" .Values.versionExporter.image -}}
  {{- else -}}
    {{- printf "ghcr.io/netcracker/version-exporter:main" -}}
  {{- end -}}
{{- end -}}
