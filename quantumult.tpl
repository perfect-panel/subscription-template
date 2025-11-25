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

{{- $supportSet := dict "shadowsocks" true "vmess" true "trojan" true "anytls" true "http" true "https" true "socks5" true "socks5-tls" true -}}
{{- $supportedProxies := list -}}
{{- range $proxy := $sorted -}}
  {{- if hasKey $supportSet $proxy.Type -}}
    {{- $supportedProxies = append $supportedProxies $proxy -}}
  {{- end -}}
{{- end -}}

# {{ .SiteName }}-{{ .SubscribeName }}
# Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $ExpiredAt }}
# Generated at: {{ now | date "2006-01-02 15:04:05" }}

{{- range $proxy := $supportedProxies }}
  {{- $common := "fast-open=false, udp-relay=true" -}}

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
    {{- $method := default "aes-128-gcm" $proxy.Method }}
shadowsocks={{ $server }}:{{ $proxy.Port }}, method={{ $method }}, password={{ $password }}{{- if ne (default "" $proxy.Obfs) "" }}, obfs={{ $proxy.Obfs }}{{- if ne (default "" $proxy.ObfsHost) "" }}, obfs-host={{ $proxy.ObfsHost }}{{- end }}{{- if ne (default "" $proxy.ObfsPath) "" }}, obfs-uri={{ $proxy.ObfsPath }}{{- end }}{{- end }}, {{ $common }}, tag={{ $proxy.Name }}
  {{- else if eq $proxy.Type "vmess" }}
vmess={{ $server }}:{{ $proxy.Port }}, method=none, password={{ $password }}{{- if or (eq (default "" $proxy.Security) "tls") (eq $proxy.Transport "over-tls") }}, obfs=over-tls{{- end }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, obfs=ws{{- if ne (default "" $proxy.Path) "" }}, obfs-uri={{ $proxy.Path }}{{- end }}{{- end }}{{- if eq $proxy.Transport "wss" }}, obfs=wss{{- if ne (default "" $proxy.Path) "" }}, obfs-uri={{ $proxy.Path }}{{- end }}{{- end }}{{- if ne (default "" $proxy.Host) "" }}, obfs-host={{ $proxy.Host }}{{- end }}, udp-relay=false, tag={{ $proxy.Name }}
  {{- else if eq $proxy.Type "trojan" }}
trojan={{ $server }}:{{ $proxy.Port }}, password={{ $password }}, over-tls=true{{- if ne (default "" $proxy.SNI) "" }}, tls-host={{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, tls-verification=false{{- else }}, tls-verification=true{{- end }}, udp-relay=false, tag={{ $proxy.Name }}
  {{- else if eq $proxy.Type "anytls" }}
anytls={{ $server }}:{{ $proxy.Port }}, password={{ $password }}{{- if ne (default "" $proxy.SNI) "" }}, tls-host={{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, tls-verification=false{{- else }}, tls-verification=true{{- end }}, udp-relay=false, tag={{ $proxy.Name }}
  {{- else if or (eq $proxy.Type "http") (eq $proxy.Type "https") }}
http={{ $server }}:{{ $proxy.Port }}{{- if or (ne (default "" $proxy.Username) "") (ne $password "") }}, username={{ default $password $proxy.Username }}, password={{ $password }}{{- end }}{{- if eq $proxy.Type "https" }}, over-tls=true{{- if ne (default "" $proxy.SNI) "" }}, tls-host={{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, tls-verification=false{{- else }}, tls-verification=true{{- end }}{{- end }}, udp-relay=false, tag={{ $proxy.Name }}
  {{- else if or (eq $proxy.Type "socks5") (eq $proxy.Type "socks5-tls") }}
socks5={{ $server }}:{{ $proxy.Port }}{{- if or (ne (default "" $proxy.Username) "") (ne $password "") }}, username={{ default $password $proxy.Username }}, password={{ $password }}{{- end }}{{- if eq $proxy.Type "socks5-tls" }}, over-tls=true{{- if ne (default "" $proxy.SNI) "" }}, tls-host={{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, tls-verification=false{{- else }}, tls-verification=true{{- end }}{{- end }}, udp-relay=false, tag={{ $proxy.Name }}
  {{- end }}
{{- end }}