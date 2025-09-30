{{- $GiB := 1073741824.0 -}}
{{- $used := printf "%.2f" (divf (add (.UserInfo.Download | default 0 | float64) (.UserInfo.Upload | default 0 | float64)) $GiB) -}}
{{- $traffic := (.UserInfo.Traffic | default 0 | float64) -}}
{{- $total := printf "%.2f" (divf $traffic $GiB) -}}

{{- $exp := "" -}}
{{- $expStr := printf "%v" .UserInfo.ExpiredAt -}}
{{- if regexMatch `^[0-9]+$` $expStr -}}
  {{- $ts := $expStr | float64 -}}
  {{- $sec := ternary (divf $ts 1000.0) $ts (ge (len $expStr) 13) -}}
  {{- $exp = (date "2006-01-02 15:04:05" (unixEpoch ($sec | int64))) -}}
{{- else -}}
  {{- $exp = $expStr -}}
{{- end -}}

{{- $supportedProxies := list -}}
{{- range $proxy := .Proxies -}}
  {{- if or (eq $proxy.Type "shadowsocks") (eq $proxy.Type "vmess") (eq $proxy.Type "vless") (eq $proxy.Type "trojan") (eq $proxy.Type "hysteria2") (eq $proxy.Type "http") (eq $proxy.Type "socks5") -}}
    {{- $supportedProxies = append $supportedProxies $proxy -}}
  {{- end -}}
{{- end -}}

{{- $proxyNames := "" -}}
{{- range $proxy := $supportedProxies -}}
  {{- if eq $proxyNames "" -}}
    {{- $proxyNames = $proxy.Name -}}
  {{- else -}}
    {{- $proxyNames = printf "%s, %s" $proxyNames $proxy.Name -}}
  {{- end -}}
{{- end -}}

# {{ .SiteName }}-{{ .SubscribeName }}
# Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $exp }}

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
  {{- $server := $proxy.Server -}}
  {{- if and (contains $proxy.Server ":") (not (hasPrefix "[" $proxy.Server)) -}}
    {{- $server = printf "[%s]" $proxy.Server -}}
  {{- end -}}

  {{- $sni := default "" $proxy.SNI -}}
  {{- if eq $sni "" -}}
    {{- $sni = default "" $proxy.Host -}}
  {{- end -}}
  {{- if and (eq $sni "") (not (or (regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$" $proxy.Server) (contains $proxy.Server ":"))) -}}
    {{- $sni = $proxy.Server -}}
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

  {{- $common := "udp: true" -}}

  {{- if eq $proxy.Type "shadowsocks" }}
  - shadowsocks: { name: {{ $proxy.Name | quote }}, method: {{ default "aes-128-gcm" $proxy.Method }}, password: {{ $password }}, server: {{ $server }}, port: {{ $proxy.Port }}, tfo: true, udp_relay: true }
  {{- end }}
{{- end }}

{{- range $proxy := .Proxies }}
  {{- if not (or (eq $proxy.Type "shadowsocks") ) }}
  {{- end }}
{{- end }}

policy_groups:
  - select: { name: Proxy,  policies: [{{- range $i, $p := .Proxies -}}{{- if gt $i 0 }}, {{ end }}'{{ $p.Name }}'{{- end -}}] }

rules:
- geoip:
    match: CN
    policy: DIRECT
- default:
    policy: Proxy

mitm:
  enabled: true
