{{/*
Expand the name of the chart.
*/}}
{{- define "custom-metrics.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "custom-metrics.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cert_info" -}}
{{- $altNames := list ( printf "%s.%s" (include "custom-metrics.name" .) .Release.Namespace ) ( printf "%s.%s.svc" (include "custom-metrics.name" .) .Release.Namespace ) -}}
{{- $ca := genCA "custom-metrics-ca" 365 -}}
{{- $cert := genSignedCert ( include "custom-metrics.name" . ) nil $altNames 365 $ca -}}
tls.crt: {{ $cert.Cert | b64enc }}
tls.key: {{ $cert.Key | b64enc }}
ca.crt: {{ $ca.Cert | b64enc }}
{{- end -}}