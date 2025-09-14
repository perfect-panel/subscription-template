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

REMARKS={{ .SiteName }}-{{ .SubscribeName }}
STATUS=Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $exp }}

{{- range $proxy := .Proxies }}
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

  {{- $common := "udp=1&tfo=1" -}}

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

  {{- if eq $proxy.Type "shadowsocks" }}
ss://{{ printf "%s:%s" $proxy.Method $password | b64enc }}@{{ $server }}:{{ $proxy.Port }}?{{ $common }}#{{ $proxy.Name }}
  {{- else if eq $proxy.Type "vmess" }}
vmess://{{ (dict "v" "2" "ps" $proxy.Name "add" $proxy.Server "port" (printf "%d" $proxy.Port) "id" $password "aid" "0" "net" (default "tcp" $proxy.Transport) "type" "none" "host" (default "" $proxy.Host) "path" (default "" $proxy.Path) "tls" (ternary "tls" "" (or (eq $proxy.Security "tls") (eq $proxy.Security "reality"))) "sni" $sni) | toJson | b64enc }}
  {{- else if eq $proxy.Type "vless" }}
vless://{{ $password }}@{{ $server }}:{{ $proxy.Port }}?encryption=none{{- if ne (default "" $proxy.Flow) "" }}&flow={{ $proxy.Flow }}{{- end }}{{- if ne $proxy.Transport "" }}&type={{ $proxy.Transport }}{{- end }}{{- if and (or (eq $proxy.Transport "ws") (eq $proxy.Transport "xhttp") (eq $proxy.Transport "httpupgrade")) (ne (default "" $proxy.Host) "") }}&host={{ $proxy.Host }}{{- end }}{{- if and (or (eq $proxy.Transport "ws") (eq $proxy.Transport "xhttp") (eq $proxy.Transport "httpupgrade")) (ne (default "" $proxy.Path) "") }}&path={{ $proxy.Path | urlquery }}{{- end }}{{- if and (eq $proxy.Transport "grpc") (ne (default "" $proxy.ServiceName) "") }}&serviceName={{ $proxy.ServiceName }}{{- end }}{{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") }}&security={{ $proxy.Security }}{{- end }}{{- if ne $sni "" }}&sni={{ $sni }}{{- end }}{{- if $proxy.AllowInsecure }}&allowInsecure=1{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}&fp={{ $proxy.Fingerprint }}{{- end }}{{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") }}&pbk={{ $proxy.RealityPublicKey }}{{- end }}{{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityShortId) "") }}&sid={{ $proxy.RealityShortId }}{{- end }}&{{ $common }}#{{ $proxy.Name }}
  {{- else if eq $proxy.Type "trojan" }}
trojan://{{ $password }}@{{ $server }}:{{ $proxy.Port }}{{- if or (and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) (ne $sni "")) (and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) $proxy.AllowInsecure) (ne $proxy.Transport "") }}?{{- end }}{{- if and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) (ne $sni "") }}sni={{ $sni }}{{- end }}{{- if and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) $proxy.AllowInsecure }}{{- if and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) (ne $sni "") }}&{{- end }}allowInsecure=1{{- end }}{{- if ne $proxy.Transport "" }}{{- if or (and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) (ne $sni "")) (and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) $proxy.AllowInsecure) }}&{{- end }}type={{ $proxy.Transport }}{{- end }}{{- if and (eq $proxy.Transport "ws") (ne (default "" $proxy.Host) "") }}{{- if or (and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) (ne $sni "")) (and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) $proxy.AllowInsecure) (ne $proxy.Transport "") }}&{{- end }}host={{ $proxy.Host }}{{- end }}{{- if and (eq $proxy.Transport "ws") (ne (default "" $proxy.Path) "") }}{{- if or (and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) (ne $sni "")) (and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) $proxy.AllowInsecure) (ne $proxy.Transport "") (and (eq $proxy.Transport "ws") (ne (default "" $proxy.Host) "")) }}&{{- end }}path={{ $proxy.Path | urlquery }}{{- end }}{{- if or (and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) (ne $sni "")) (and (or (eq $proxy.Security "tls") (eq $proxy.Security "reality")) $proxy.AllowInsecure) (ne $proxy.Transport "") }}&{{ $common }}{{- else }}?{{ $common }}{{- end }}#{{ $proxy.Name }}
  {{- else if eq $proxy.Type "hysteria2" }}
hysteria2://{{- if ne $password "" -}}{{ $password }}@{{- end -}}{{ $server }}:{{ $proxy.Port }}?{{- $hasQ := false -}}{{- if ne $sni "" -}}{{- $hasQ = true -}}sni={{ $sni }}{{- end -}}{{- if $proxy.AllowInsecure -}}{{- if $hasQ }}&{{- end -}}{{- $hasQ = true -}}insecure=1{{- end -}}{{- if ne (default "" $proxy.ObfsPassword) "" -}}{{- if $hasQ }}&{{- end -}}{{- $hasQ = true -}}obfs=salamander&obfs-password={{ $proxy.ObfsPassword }}{{- end -}}{{- if ne (default "" $proxy.HopPorts) "" -}}{{- if $hasQ }}&{{- end -}}{{- $hasQ = true -}}mport={{ $proxy.HopPorts }}{{- end -}}{{- if $hasQ }}&{{- end -}}udp=1&tfo=1#{{ $proxy.Name | urlquery }}
  {{- else if eq $proxy.Type "tuic" }}
tuic://{{ $password }}:{{ $password }}@{{ $server }}:{{ $proxy.Port }}{{- if or (ne (default "" $proxy.CongestionController) "") (ne (default "" $proxy.UDPRelayMode) "") $proxy.ReduceRtt $proxy.DisableSNI (ne $sni "") $proxy.AllowInsecure }}?{{- end }}{{- if ne (default "" $proxy.CongestionController) "" }}congestion_controller={{ $proxy.CongestionController }}{{- end }}{{- if ne (default "" $proxy.UDPRelayMode) "" }}{{- if ne (default "" $proxy.CongestionController) "" }}&{{- end }}udp_relay_mode={{ $proxy.UDPRelayMode }}{{- end }}{{- if $proxy.ReduceRtt }}{{- if or (ne (default "" $proxy.CongestionController) "") (ne (default "" $proxy.UDPRelayMode) "") }}&{{- end }}reduce_rtt=1{{- end }}{{- if $proxy.DisableSNI }}{{- if or (ne (default "" $proxy.CongestionController) "") (ne (default "" $proxy.UDPRelayMode) "") $proxy.ReduceRtt }}&{{- end }}disable_sni=1{{- end }}{{- if ne $sni "" }}{{- if or (ne (default "" $proxy.CongestionController) "") (ne (default "" $proxy.UDPRelayMode) "") $proxy.ReduceRtt $proxy.DisableSNI }}&{{- end }}sni={{ $sni }}{{- end }}{{- if $proxy.AllowInsecure }}{{- if or (ne (default "" $proxy.CongestionController) "") (ne (default "" $proxy.UDPRelayMode) "") $proxy.ReduceRtt $proxy.DisableSNI (ne $sni "") }}&{{- end }}allow_insecure=1{{- end }}{{- if or (ne (default "" $proxy.CongestionController) "") (ne (default "" $proxy.UDPRelayMode) "") $proxy.ReduceRtt $proxy.DisableSNI (ne $sni "") $proxy.AllowInsecure }}&{{ $common }}{{- else }}?{{ $common }}{{- end }}#{{ $proxy.Name }}
  {{- else if eq $proxy.Type "anytls" }}
anytls://{{ $password }}@{{ $server }}:{{ $proxy.Port }}{{- if ne $sni "" }}?sni={{ $sni }}&{{ $common }}{{- else }}?{{ $common }}{{- end }}#{{ $proxy.Name }}
  {{- end }}
{{- end }}

{{- range $proxy := .Proxies }}
  {{- if not (or (eq $proxy.Type "shadowsocks") (eq $proxy.Type "vmess") (eq $proxy.Type "vless") (eq $proxy.Type "trojan") (eq $proxy.Type "hysteria2") (eq $proxy.Type "tuic") (eq $proxy.Type "anytls")) }}
# Skipped (unsupported protocol): {{ $proxy.Name }} ({{ $proxy.Type }})
  {{- end }}
{{- end }}