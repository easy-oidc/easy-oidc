# Easy OIDC <https://easy-oidc.dev>
# Copyright The Easy OIDC Authors
# SPDX-License-Identifier: Apache-2.0

{{- define "easy-oidc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "easy-oidc.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{ else }}{{ printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}{{ end }}
{{- end }}
{{- end }}

{{- define "easy-oidc.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "easy-oidc.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end }}

{{- define "easy-oidc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "easy-oidc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "easy-oidc.labels" -}}
helm.sh/chart: {{ include "easy-oidc.chart" . }}
{{ include "easy-oidc.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "easy-oidc.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}{{ default (include "easy-oidc.fullname" .) .Values.serviceAccount.name }}{{ else }}{{ default "default" .Values.serviceAccount.name }}{{ end }}
{{- end }}

{{- define "easy-oidc.configMapName" -}}
{{- default (printf "%s-config" (include "easy-oidc.fullname" .)) .Values.config.existingConfigMap }}
{{- end }}

{{- define "easy-oidc.claimName" -}}
{{- default (include "easy-oidc.fullname" .) .Values.config.state_database.persistence.existingClaim }}
{{- end }}

{{- define "easy-oidc.serverTLSSecretName" -}}
{{- default (printf "%s-tls" (include "easy-oidc.fullname" .)) .Values.server.tls.secretName }}
{{- end }}

{{- define "easy-oidc.generatedConfig" -}}
{{- $config := deepCopy .Values.config -}}
{{- $_ := unset $config "rawOverride" -}}
{{- $_ := unset $config "existingConfigMap" -}}
{{- $_ := unset $config "existingConfigMapKey" -}}
{{- $stateDatabase := deepCopy $config.state_database -}}
{{- $_ := unset $stateDatabase "persistence" -}}
{{- if and (eq $stateDatabase.driver "sqlite") (empty (default "" $stateDatabase.path)) -}}
{{- $_ := set $stateDatabase "path" "/var/lib/easy-oidc/easy-oidc-state.db" -}}
{{- end -}}
{{- $_ := set $config "state_database" $stateDatabase -}}
{{- if .Values.server.tls.enabled -}}
{{- $_ := set $config "serving_certificate" (dict "certificate_file" "/var/run/easy-oidc/tls/tls.crt" "private_key_file" "/var/run/easy-oidc/tls/tls.key") -}}
{{- end -}}
{{- $config | toPrettyJson -}}
{{- end }}

{{- define "easy-oidc.validateConfig" -}}
{{- $raw := not (empty (trim .Values.config.rawOverride)) -}}
{{- $existing := not (empty (trim .Values.config.existingConfigMap)) -}}
{{- if and $raw $existing -}}
{{- fail "config.rawOverride and config.existingConfigMap are mutually exclusive" -}}
{{- end -}}
{{- if and $existing (empty (trim .Values.config.existingConfigMapKey)) -}}
{{- fail "config.existingConfigMapKey is required when config.existingConfigMap is set" -}}
{{- end -}}
{{- if hasKey .Values.config "serving_certificate" -}}
{{- fail "configure native HTTPS with server.tls values, not config.serving_certificate" -}}
{{- end -}}
{{- if and (not $raw) (not $existing) (empty (trim .Values.config.issuer_url)) -}}
{{- fail "config.issuer_url is required when generating config.jsonc" -}}
{{- end -}}
{{- if and (not $raw) (not $existing) (eq (len .Values.config.user_login_connectors) 0) -}}
{{- fail "config.user_login_connectors must contain at least one connector when generating config.jsonc" -}}
{{- end -}}
{{- if and (not $raw) (not $existing) (eq (len .Values.config.static_policy.clients) 0) (empty (default dict .Values.config.policy_database)) -}}
{{- fail "generated configuration requires config.static_policy.clients or config.policy_database" -}}
{{- end -}}
{{- if not (has .Values.config.state_database.driver (list "sqlite" "postgresql")) -}}
{{- fail "config.state_database.driver must be sqlite or postgresql" -}}
{{- end -}}
{{- if and (not $raw) (not $existing) (eq .Values.config.state_database.driver "postgresql") (empty (default "" .Values.config.state_database.connection_string_secret)) -}}
{{- fail "config.state_database.connection_string_secret is required for generated PostgreSQL configuration" -}}
{{- end -}}
{{- if and (not $raw) (not $existing) (eq .Values.config.state_database.driver "sqlite") (not (hasPrefix "/var/lib/easy-oidc/" (clean (default "/var/lib/easy-oidc/easy-oidc-state.db" .Values.config.state_database.path)))) -}}
{{- fail "generated SQLite config.state_database.path must be beneath /var/lib/easy-oidc so the selected persistence is effective" -}}
{{- end -}}
{{- if and .Values.secretFiles.enabled (empty (trim .Values.secretFiles.csi.secretProviderClass)) -}}
{{- fail "secretFiles.csi.secretProviderClass is required when secretFiles.enabled is true" -}}
{{- end -}}
{{- if and .Values.secretFiles.enabled (not $raw) (not $existing) (ne .Values.config.secrets.provider "file") -}}
{{- fail "config.secrets.provider must be file when secretFiles.enabled is true" -}}
{{- end -}}
{{- if and (not $raw) (not $existing) (eq .Values.config.secrets.provider "file") (not .Values.secretFiles.enabled) -}}
{{- fail "secretFiles.enabled must be true when generated configuration uses the file secrets provider" -}}
{{- end -}}
{{- if and .Values.secretFiles.enabled (not $raw) (not $existing) (ne .Values.config.secrets.file_directory .Values.secretFiles.mountPath) -}}
{{- fail "config.secrets.file_directory must match secretFiles.mountPath" -}}
{{- end -}}
{{- if and .Values.migrations.secretFiles.enabled (not .Values.migrations.enabled) -}}
{{- fail "migrations.secretFiles.enabled requires migrations.enabled" -}}
{{- end -}}
{{- if and .Values.migrations.secretFiles.enabled (empty (trim .Values.migrations.secretFiles.csi.secretProviderClass)) -}}
{{- fail "migrations.secretFiles.csi.secretProviderClass is required when migrations.secretFiles.enabled is true" -}}
{{- end -}}
{{- if and .Values.migrations.secretFiles.enabled (not $raw) (not $existing) (ne .Values.config.secrets.provider "file") -}}
{{- fail "config.secrets.provider must be file when migrations.secretFiles.enabled is true" -}}
{{- end -}}
{{- if and .Values.server.tls.certManager.enabled (not .Values.server.tls.enabled) -}}
{{- fail "server.tls.certManager.enabled requires server.tls.enabled" -}}
{{- end -}}
{{- if and .Values.server.tls.certManager.enabled (empty (trim .Values.server.tls.certManager.issuerRef.name)) -}}
{{- fail "server.tls.certManager.issuerRef.name is required when creating a Certificate" -}}
{{- end -}}
{{- if and .Values.server.tls.certManager.enabled (empty (trim .Values.server.tls.certManager.issuerRef.kind)) -}}
{{- fail "server.tls.certManager.issuerRef.kind is required when creating a Certificate" -}}
{{- end -}}
{{- if and .Values.server.tls.certManager.enabled (empty (trim .Values.server.tls.certManager.issuerRef.group)) -}}
{{- fail "server.tls.certManager.issuerRef.group is required when creating a Certificate" -}}
{{- end -}}
{{- if and .Values.server.tls.certManager.enabled (eq (len .Values.server.tls.certManager.dnsNames) 0) -}}
{{- fail "server.tls.certManager.dnsNames must contain at least one name when creating a Certificate" -}}
{{- end -}}
{{- if .Values.server.tls.certManager.enabled -}}
{{- range .Values.server.tls.certManager.dnsNames -}}
{{- if empty (trim .) -}}
{{- fail "server.tls.certManager.dnsNames must not contain empty names" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and (eq .Values.config.state_database.driver "sqlite") (ne (int .Values.replicaCount) 1) -}}
{{- fail "config.state_database.driver sqlite requires replicaCount: 1 because replicas cannot share protocol state" -}}
{{- end -}}
{{- if and (eq .Values.config.state_database.driver "sqlite") (ne .Values.deploymentStrategy.type "Recreate") -}}
{{- fail "config.state_database.driver sqlite requires deploymentStrategy.type: Recreate to prevent overlapping protocol-state databases during upgrades" -}}
{{- end -}}
{{- end }}
