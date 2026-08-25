{{/*
Expand the name of the chart.
*/}}
{{- define "uncrowned-king.name" -}}
{{- default .Chart.Name .Values.global.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "uncrowned-king.fullname" -}}
{{- if .Values.global.fullnameOverride }}
{{- .Values.global.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.global.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Server fullname
*/}}
{{- define "uncrowned-king.server.fullname" -}}
{{- printf "%s-server" (include "uncrowned-king.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Client fullname
*/}}
{{- define "uncrowned-king.client.fullname" -}}
{{- printf "%s-client" (include "uncrowned-king.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "uncrowned-king.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "uncrowned-king.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Server selector labels
*/}}
{{- define "uncrowned-king.server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "uncrowned-king.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end }}

{{/*
Client selector labels
*/}}
{{- define "uncrowned-king.client.selectorLabels" -}}
app.kubernetes.io/name: {{ include "uncrowned-king.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: client
{{- end }}
