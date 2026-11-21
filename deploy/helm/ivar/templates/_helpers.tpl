{{- define "ivar.labels" -}}
app.kubernetes.io/part-of: ivar
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "ivar.image" -}}
{{ .root.Values.image.registry }}/{{ .name }}:{{ .root.Values.image.tag }}
{{- end }}

{{- define "ivar.coreUrl" -}}
http://ivar-core.{{ .Release.Namespace }}.svc:8080
{{- end }}

{{- define "ivar.controlUrl" -}}
http://ivar-control.{{ .Release.Namespace }}.svc:8090
{{- end }}

{{- define "ivar.restricted" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities: { drop: [ALL] }
seccompProfile: { type: RuntimeDefault }
{{- end }}
