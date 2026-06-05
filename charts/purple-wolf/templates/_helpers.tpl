{{- define "purple-wolf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "purple-wolf.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "purple-wolf.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/name: {{ include "purple-wolf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "purple-wolf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "purple-wolf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "purple-wolf.serviceAccountName" -}}
{{- if .Values.relay.serviceAccount.create -}}
{{- default (include "purple-wolf.fullname" .) .Values.relay.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.relay.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "purple-wolf.image" -}}
{{- $image := .image -}}
{{- $tag := default .appVersion $image.tag -}}
{{- if $image.digest -}}
{{- printf "%s@%s" $image.repository $image.digest -}}
{{- else -}}
{{- printf "%s:%s" $image.repository $tag -}}
{{- end -}}
{{- end -}}
