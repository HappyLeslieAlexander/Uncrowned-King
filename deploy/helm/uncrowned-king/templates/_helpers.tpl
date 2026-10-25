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

{{/*
Validates one credential secret and fails closed at render time. Call with a
dict holding `secret` and `where` (the values path named in the error).

Rejects: empty/whitespace-only values, anything under 32 characters after
trimming, placeholder text (case-insensitive, trimmed), and any character
outside [A-Za-z0-9+/=._~-]. The charset bound is what keeps the value safe to
interpolate into the rendered credentials.toml: quotes, backslashes,
newlines and other TOML-breaking or log-forging characters can never reach
it, so a bad value fails `helm template` instead of CrashLooping the pod on
a config parse error.
*/}}
{{- define "uncrowned-king.validate_credential_secret" -}}
{{- $secret := toString .secret -}}
{{- $trimmed := trim $secret -}}
{{- $where := .where -}}
{{- if or (not $trimmed) (lt (len $trimmed) 32) (hasPrefix "replace-with" (lower $trimmed)) (hasPrefix "changeme" (lower $trimmed)) (hasPrefix "placeholder" (lower $trimmed)) (hasPrefix "dummy" (lower $trimmed)) (hasPrefix "example" (lower $trimmed)) }}
{{- fail (printf "Security error: placeholder or empty credential secret found in %s. You must configure a secure secret of at least 32 characters (64-character hex recommended) before deployment." $where) }}
{{- end }}
{{- if ne $secret $trimmed }}
{{- fail (printf "Security error: credential secret in %s must not be surrounded by whitespace." $where) }}
{{- end }}
{{- if not (mustRegexMatch "^[A-Za-z0-9+/=._~-]+$" $trimmed) }}
{{- fail (printf "Security error: credential secret in %s contains characters outside [A-Za-z0-9+/=._~-]. Quotes, backslashes, whitespace and control characters would break the rendered TOML configuration." $where) }}
{{- end }}
{{- end }}

{{/*
Validates a credential key id for the same TOML-safety reason as
`uncrowned-king.validate_credential_secret`; key ids are shorter and not
secret, but they are interpolated into the same quoted TOML string.
*/}}
{{- define "uncrowned-king.validate_credential_key_id" -}}
{{- $keyId := toString .key_id -}}
{{- $where := .where -}}
{{- if or (not (trim $keyId)) (not (mustRegexMatch "^[A-Za-z0-9._-]+$" (trim $keyId))) (ne $keyId (trim $keyId)) }}
{{- fail (printf "Security error: key_id in %s is required and must contain only [A-Za-z0-9._-] without surrounding whitespace." $where) }}
{{- end }}
{{- end }}
