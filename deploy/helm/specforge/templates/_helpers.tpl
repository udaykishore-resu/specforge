{{/*
Shared template helpers.

The validation block is the interesting part: the chart refuses to render when
a control the platform depends on has been switched off without an explicit
decision. Failing at `helm template` time is far better than discovering in an
audit that evidence was written to a bucket with no object lock.
*/}}

{{- define "specforge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "specforge.fullname" -}}
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

{{- define "specforge.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "specforge.labels" -}}
helm.sh/chart: {{ include "specforge.chart" . }}
{{ include "specforge.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: specforge
{{- with .Values.extraLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "specforge.selectorLabels" -}}
app.kubernetes.io/name: {{ include "specforge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "specforge.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "specforge.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "specforge.image" -}}
{{- $registry := .root.Values.image.registry -}}
{{- $repository := .root.Values.image.repository -}}
{{- printf "%s/%s/%s:%s" $registry $repository .component .tag -}}
{{- end -}}

{{/*
Environment shared by the API and the worker.

Every value that is a secret is referenced from a Secret rather than inlined,
so a values file committed to Git never carries one.
*/}}
{{- define "specforge.commonEnv" -}}
- name: SF_ENV
  value: {{ .Values.environment | quote }}
- name: SF_LOG_LEVEL
  value: {{ .Values.observability.logLevel | quote }}
- name: SF_LOG_FORMAT
  value: {{ .Values.observability.logFormat | quote }}
- name: SF_METRICS_ADDR
  value: ":9090"
- name: SF_DB_DSN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret }}
      key: {{ .Values.database.dsnKey }}
- name: SF_DB_MAX_OPEN_CONNS
  value: {{ .Values.database.maxOpenConns | quote }}
- name: SF_DB_STATEMENT_TIMEOUT
  value: {{ .Values.database.statementTimeout | quote }}
- name: SF_OBJSTORE_PROVIDER
  value: {{ .Values.objstore.provider | quote }}
- name: SF_OBJSTORE_REGION
  value: {{ .Values.objstore.region | quote }}
{{- if .Values.objstore.endpoint }}
- name: SF_OBJSTORE_ENDPOINT
  value: {{ .Values.objstore.endpoint | quote }}
{{- end }}
- name: SF_OBJSTORE_CONTENT_BUCKET
  value: {{ .Values.objstore.contentBucket | quote }}
- name: SF_OBJSTORE_EVIDENCE_BUCKET
  value: {{ .Values.objstore.evidenceBucket | quote }}
- name: SF_OBJSTORE_OBJECT_LOCK
  value: {{ .Values.objstore.objectLock | quote }}
{{- if .Values.objstore.existingSecret }}
- name: SF_OBJSTORE_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.objstore.existingSecret }}
      key: {{ .Values.objstore.accessKeyKey }}
- name: SF_OBJSTORE_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.objstore.existingSecret }}
      key: {{ .Values.objstore.secretKeyKey }}
{{- end }}
- name: SF_EVENTS_PROVIDER
  value: {{ .Values.events.provider | quote }}
- name: SF_EVENTS_BROKERS
  value: {{ join "," .Values.events.brokers | quote }}
- name: SF_EVENTS_TOPIC_PREFIX
  value: {{ .Values.events.topicPrefix | quote }}
{{- if .Values.cache.addr }}
- name: SF_CACHE_PROVIDER
  value: {{ .Values.cache.provider | quote }}
- name: SF_CACHE_ADDR
  value: {{ .Values.cache.addr | quote }}
- name: SF_CACHE_TLS
  value: {{ .Values.cache.tls | quote }}
{{- if .Values.cache.existingSecret }}
- name: SF_CACHE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.cache.existingSecret }}
      key: {{ .Values.cache.passwordKey }}
{{- end }}
{{- end }}
{{- if .Values.observability.otlpEndpoint }}
- name: SF_OTEL_ENDPOINT
  value: {{ .Values.observability.otlpEndpoint | quote }}
- name: SF_OTEL_SAMPLE_RATIO
  value: {{ .Values.observability.sampleRatio | quote }}
{{- end }}
- name: SF_GOV_FOUR_EYES
  value: {{ .Values.governance.fourEyes | quote }}
- name: SF_GOV_MAX_EXCEPTION_DAYS
  value: {{ .Values.governance.maxExceptionDays | quote }}
- name: POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
Refuse to render a configuration that would quietly weaken a guarantee.
*/}}
{{- define "specforge.validate" -}}
{{- if and (eq .Values.environment "production") .Values.auth.devIdP -}}
{{- fail "auth.devIdP must be false in production: the development identity provider issues tokens for seeded users." -}}
{{- end -}}
{{- if and (eq .Values.environment "production") (not .Values.governance.fourEyes) -}}
{{- fail "governance.fourEyes is disabled in production. If this is a deliberate, documented exception, set environment to something other than production for that cluster." -}}
{{- end -}}
{{- if not .Values.objstore.objectLock -}}
{{- fail "objstore.objectLock is disabled. Approval evidence and audit anchors are written once and depend on it; without object lock they are ordinary, overwritable objects." -}}
{{- end -}}
{{- if not .Values.database.existingSecret -}}
{{- fail "database.existingSecret is required. The chart does not accept a database password as a value." -}}
{{- end -}}
{{- if not .Values.objstore.evidenceBucket -}}
{{- fail "objstore.evidenceBucket is required: approvals cannot be sealed without somewhere to write their evidence." -}}
{{- end -}}
{{- if and .Values.web.enabled (not .Values.web.publicUrl) -}}
{{- fail "web.publicUrl is required. The console builds post-authentication redirects from it, and the pod cannot infer the origin a browser uses." -}}
{{- end -}}
{{- if and (ne .Values.environment "development") (not .Values.auth.issuer) -}}
{{- fail "auth.issuer is required outside development." -}}
{{- end -}}
{{- end -}}
