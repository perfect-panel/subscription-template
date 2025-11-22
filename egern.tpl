{{- $GiB := 1073741824.0 -}}
{{- $used := printf "%.2f" (divf (add (.UserInfo.Download | default 0 | float64) (.UserInfo.Upload | default 0 | float64)) $GiB) -}}
{{- $traffic := (.UserInfo.Traffic | default 0 | float64) -}}
{{- $total := printf "%.2f" (divf $traffic $GiB) -}}

{{- $ExpiredAt := "" -}}
{{- $expStr := printf "%v" .UserInfo.ExpiredAt -}}
{{- if regexMatch `^[0-9]+$` $expStr -}}
  {{- $ts := $expStr | float64 -}}
  {{- $sec := ternary (divf $ts 1000.0) $ts (ge (len $expStr) 13) -}}
  {{- $ExpiredAt = (date "2006-01-02 15:04:05" (unixEpoch ($sec | int64))) -}}
{{- else -}}
  {{- $ExpiredAt = $expStr -}}
{{- end -}}

{{- $sortFields := list "Sort" "Port" "Name" -}}
{{- $sortConfig := dict "Sort" "asc" "Port" "asc" "Name" "asc" -}}
{{- $byKey := dict -}}
{{- range $p := .Proxies -}}
  {{- $keyParts := list -}}
  {{- range $field := $sortFields -}}
    {{- $order := index $sortConfig $field -}}
    {{- $val := default "" (printf "%v" (index $p $field)) -}}
    {{- if or (eq $field "Sort") (eq $field "Port") -}}
      {{- $val = printf "%08d" (int (default 0 (index $p $field))) -}}
    {{- end -}}
    {{- if eq $order "desc" -}}
      {{- $val = printf "~%s" $val -}}
    {{- end -}}
    {{- $keyParts = append $keyParts $val -}}
  {{- end -}}
  {{- $_ := set $byKey (join "|" $keyParts) $p -}}
{{- end -}}
{{- $sorted := list -}}
{{- range $k := sortAlpha (keys $byKey) -}}
  {{- $sorted = append $sorted (index $byKey $k) -}}
{{- end -}}

{{- $supportSet := dict "shadowsocks" true "vmess" true "vless" true "trojan" true "hysteria2" true "hysteria" true "tuic" true "anytls" true -}}
{{- $supportedProxies := list -}}
{{- range $proxy := $sorted -}}
  {{- if hasKey $supportSet $proxy.Type -}}
    {{- $supportedProxies = append $supportedProxies $proxy -}}
  {{- end -}}
{{- end -}}

{{- $proxyNames := "" -}}
{{- range $proxy := $supportedProxies -}}
  {{- if eq $proxyNames "" -}}
    {{- $proxyNames = printf "%q" $proxy.Name -}}
  {{- else -}}
    {{- $proxyNames = printf "%s, %q" $proxyNames $proxy.Name -}}
  {{- end -}}
{{- end -}}

# {{ .SiteName }}-{{ .SubscribeName }}
# Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $ExpiredAt }}
# Generated at: {{ now | date "2006-01-02 15:04:05" }}

ipv6: true
http_port: 6088
socks_port: 6089
allow_external_connections: true
hijack_dns:
- 8.8.8.8:53
- 1.1.1.1:53
dns:
  bootstrap:
    - system
    - 223.5.5.5
  upstreams:
    proxy:
      - 8.8.8.8
      - 1.1.1.1
  forward:
  - proxy_rule_set:
      match: https://github.com/ACL4SSR/ACL4SSR/raw/master/Clash/ChinaDomain.list
      value: system
  - wildcard:
      match: '*'
      value: proxy

proxies:
{{- range $proxy := $supportedProxies }}
  {{- $common := "udp: true, tfo: true" -}}

  {{- $server := $proxy.Server -}}
  {{- if and (contains $server ":") (not (hasPrefix "[" $server)) -}}
    {{- $server = printf "[%s]" $server -}}
  {{- end -}}

  {{- $password := $.UserInfo.Password -}}
  {{- if and (eq $proxy.Type "shadowsocks") (ne (default "" $proxy.ServerKey) "") -}}
    {{- $method := $proxy.Method -}}
    {{- if or (hasPrefix "2022-blake3-" $method) (eq $method "2022-blake3-aes-128-gcm") (eq $method "2022-blake3-aes-256-gcm") -}}
      {{- $userKeyLen := ternary 16 32 (hasSuffix "128-gcm" $method) -}}
      {{- $pwdStr := printf "%s" $password -}}
      {{- $userKey := ternary $pwdStr (trunc $userKeyLen $pwdStr) (le (len $pwdStr) $userKeyLen) -}}
      {{- $serverB64 := b64enc $proxy.ServerKey -}}
      {{- $userB64 := b64enc $userKey -}}
      {{- $password = printf "%s:%s" $serverB64 $userB64 -}}
    {{- end -}}
  {{- end -}}

  {{- $SkipVerify := $proxy.AllowInsecure -}}

  {{- if eq $proxy.Type "shadowsocks" }}
  - { name: {{ $proxy.Name | quote }}, type: ss, server: {{ $server }}, port: {{ $proxy.Port }}, cipher: {{ default "aes-128-gcm" $proxy.Method }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.Obfs) "" }}, plugin: obfs, plugin-opts: { mode: {{ $proxy.Obfs }}, host: {{ default "" $proxy.ObfsHost }} }{{- end }} }
  {{- else if eq $proxy.Type "vmess" }}
  - { name: {{ $proxy.Name | quote }}, type: vmess, server: {{ $server }}, port: {{ $proxy.Port }}, uuid: {{ $password }}, alterId: 0, cipher: auto, {{ $common }}{{- if or (eq $proxy.Transport "websocket") (eq $proxy.Transport "ws") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName }} }{{- end }}{{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") }}, tls: true{{- end }}{{- if ne (default "" $proxy.SNI) "" }}, servername: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, fingerprint: {{ $proxy.Fingerprint }}{{- end }} }
  {{- else if eq $proxy.Type "vless" }}
  - { name: {{ $proxy.Name | quote }}, type: vless, server: {{ $server }}, port: {{ $proxy.Port }}, uuid: {{ $password }}, {{ $common }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "httpupgrade" }}, network: httpupgrade, httpupgrade-opts: { path: {{ default "/" $proxy.Path }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName }} }{{- end }}{{- if ne (default "" $proxy.SNI) "" }}, servername: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, client-fingerprint: {{ $proxy.Fingerprint }}{{- end }}{{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") }}, tls: true, reality-opts: { public-key: {{ $proxy.RealityPublicKey }}{{- if ne (default "" $proxy.RealityShortId) "" }}, short-id: {{ $proxy.RealityShortId }}{{- end }} }{{- end }}{{- if ne (default "none" $proxy.Flow) "none" }}, flow: {{ $proxy.Flow }}{{- end }} }
  {{- else if eq $proxy.Type "trojan" }}
  - { name: {{ $proxy.Name | quote }}, type: trojan, server: {{ $server }}, port: {{ $proxy.Port }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, fingerprint: {{ $proxy.Fingerprint }}{{- end }}{{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") }}, reality-opts: { public-key: {{ $proxy.RealityPublicKey }}{{- if ne (default "" $proxy.RealityShortId) "" }}, short-id: {{ $proxy.RealityShortId }}{{- end }} }{{- end }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName }} }{{- end }} }
  {{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hysteria") }}
  - { name: {{ $proxy.Name | quote }}, type: hysteria2, server: {{ $server }}, port: {{ $proxy.Port }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.ObfsPassword) "" }}, obfs: salamander, obfs-password: {{ $proxy.ObfsPassword }}{{- end }}{{- if ne (default "" $proxy.HopPorts) "" }}, ports: {{ $proxy.HopPorts }}{{- end }}{{- if ne (default 0 $proxy.HopInterval) 0 }}, hop-interval: {{ $proxy.HopInterval }}{{- end }} }
  {{- else if eq $proxy.Type "tuic" }}
  - { name: {{ $proxy.Name | quote }}, type: tuic, server: {{ $server }}, port: {{ $proxy.Port }}, private-key: {{ default "" $proxy.ServerKey }}, public-key: {{ default "" $proxy.RealityPublicKey }}, {{ $common }}{{- if ne (default "" $proxy.Path) "" }}, preshared-key: {{ $proxy.Path }}{{- end }}{{- if ne (default "" $proxy.RealityServerAddr) "" }}, ip: {{ $proxy.RealityServerAddr }}{{- end }}{{- if ne (default 0 $proxy.RealityServerPort) 0 }}, ipv6: {{ $proxy.RealityServerPort }}{{- end }} }
  {{- else if eq $proxy.Type "anytls" }}
  - { name: {{ $proxy.Name | quote }}, type: anytls, server: {{ $server }}, port: {{ $proxy.Port }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, fingerprint: {{ $proxy.Fingerprint }}{{- end }} }
  {{- else }}
  - { name: {{ $proxy.Name | quote }}, type: {{ $proxy.Type }}, server: {{ $server }}, port: {{ $proxy.Port }}, {{ $common }} }
  {{- end }}
{{- end }}

policy_groups:
  - select: { name: Proxy, policies: [{{ $proxyNames }}] }

rules:
- geoip:
    match: CN
    policy: DIRECT
- default:
    policy: Proxy

mitm:
  enabled: true
