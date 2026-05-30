{{/*
Common labels applied to every resource.
*/}}
{{- define "tsm.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/*
Selector labels (immutable — used in Deployment.spec.selector).
*/}}
{{- define "tsm.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Full image reference for a given component, e.g. "proxy" or "detector".
Usage: {{ include "tsm.image" (dict "root" . "comp" "proxy") }}
*/}}
{{- define "tsm.image" -}}
{{- $img := index .root.Values.image .comp -}}
{{ $img.repository }}:{{ $img.tag }}
{{- end }}
