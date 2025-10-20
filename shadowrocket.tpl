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

{{- $sortConfig := dict "Sort" "asc" -}}
{{- $byKey := dict -}}
{{- range $p := .Proxies -}}
  {{- $keyParts := list -}}
  {{- range $field, $order := $sortConfig -}}
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

REMARKS={{ .SiteName }}-{{ .SubscribeName }}
STATUS=Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $ExpiredAt }}
# Generated at: {{ now | date "2006-01-02 15:04:05\n" }}

{{- range $proxy := $supportedProxies }}
  {{- $common := "udp=1&tfo=1" -}}

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
  {{- $params := list -}}
  {{- if ne (default "" $proxy.Obfs) "" -}}
    {{- $params = append $params (printf "obfs=%s" $proxy.Obfs) -}}
  {{- end -}}
  {{- if ne (default "" $proxy.ObfsHost) "" -}}
    {{- $params = append $params (printf "obfs-host=%s" $proxy.ObfsHost) -}}
  {{- end -}}
  {{- if ne (default "" $proxy.ObfsPath) "" -}}
    {{- $params = append $params (printf "obfs-uri=%s" ($proxy.ObfsPath | urlquery)) -}}
  {{- end -}}
ss://{{ printf "%s:%s" (default "aes-128-gcm" $proxy.Method) $password | b64enc }}@{{ $server }}:{{ $proxy.Port }}{{- if gt (len $params) 0 -}}?{{ $common }}&{{ join "&" $params }}{{- else -}}?{{ $common }}{{- end }}#{{ $proxy.Name }}
  {{ else if eq $proxy.Type "vmess" }}
vmess://{{ (dict "v" "2" "ps" $proxy.Name "add" $proxy.Server "port" (printf "%d" $proxy.Port) "id" $password "aid" "0" "net" (ternary "ws" $proxy.Transport (eq $proxy.Transport "websocket")) "type" "none" "host" (default "" $proxy.Host) "path" (default "" $proxy.Path) "tls" (ternary "tls" "" (or (eq $proxy.Security "tls") (eq $proxy.Security "reality"))) "sni" $proxy.SNI) | toJson | b64enc }}
  {{ else if eq $proxy.Type "vless" }}
  {{- $params := list (printf "encryption=none") -}}
  {{- if ne (default "" $proxy.Flow) "none" -}}
    {{- $params = append $params (printf "flow=%s" $proxy.Flow) -}}
  {{- end -}}
  {{- if ne (default "" $proxy.Transport) "" -}}
    {{- $params = append $params (printf "type=%s" (ternary "ws" $proxy.Transport (eq $proxy.Transport "websocket"))) -}}
  {{- end -}}
  {{- if and (or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") (eq $proxy.Transport "xhttp") (eq $proxy.Transport "httpupgrade")) (ne (default "" $proxy.Host) "") -}}
    {{- $params = append $params (printf "host=%s" $proxy.Host) -}}
  {{- end -}}
  {{- if and (or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") (eq $proxy.Transport "xhttp") (eq $proxy.Transport "httpupgrade")) (ne (default "" $proxy.Path) "") -}}
    {{- $params = append $params (printf "path=%s" ($proxy.Path | urlquery)) -}}
  {{- end -}}
  {{- if and (eq $proxy.Transport "grpc") (ne (default "" $proxy.ServiceName) "") -}}
    {{- $params = append $params (printf "serviceName=%s" $proxy.ServiceName) -}}
  {{- end -}}
  {{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") -}}
    {{- $params = append $params (printf "security=%s" $proxy.Security) -}}
  {{- end -}}
  {{- if ne (default "" $proxy.SNI) "" -}}
    {{- $params = append $params (printf "sni=%s" $proxy.SNI) -}}
  {{- end -}}
  {{- if $SkipVerify -}}
    {{- $params = append $params "allowInsecure=1" -}}
  {{- end -}}
  {{- if ne (default "" $proxy.Fingerprint) "" -}}
    {{- $params = append $params (printf "fp=%s" $proxy.Fingerprint) -}}
  {{- end -}}
  {{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") -}}
    {{- $params = append $params (printf "pbk=%s" $proxy.RealityPublicKey) -}}
  {{- end -}}
  {{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityShortId) "") -}}
    {{- $params = append $params (printf "sid=%s" $proxy.RealityShortId) -}}
  {{- end -}}
  {{- $params = append $params $common -}}
vless://{{ $password }}@{{ $server }}:{{ $proxy.Port }}?{{ join "&" $params }}#{{ $proxy.Name }}
  {{ else if eq $proxy.Type "trojan" }}
  {{- $params := list -}}
  {{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") -}}
    {{- if ne (default "" $proxy.SNI) "" -}}
      {{- $params = append $params (printf "sni=%s" $proxy.SNI) -}}
    {{- end -}}
    {{- if $SkipVerify -}}
      {{- $params = append $params "allowInsecure=1" -}}
    {{- end -}}
  {{- end -}}
  {{- if ne (default "" $proxy.Transport) "" -}}
    {{- $params = append $params (printf "type=%s" $proxy.Transport) -}}
    {{- if and (eq $proxy.Transport "ws") (ne (default "" $proxy.Host) "") -}}
      {{- $params = append $params (printf "host=%s" $proxy.Host) -}}
    {{- end -}}
    {{- if and (eq $proxy.Transport "ws") (ne (default "" $proxy.Path) "") -}}
      {{- $params = append $params (printf "path=%s" ($proxy.Path | urlquery)) -}}
    {{- end -}}
  {{- end -}}
  {{- $params = append $params $common -}}
trojan://{{ $password }}@{{ $server }}:{{ $proxy.Port }}?{{ join "&" $params }}#{{ $proxy.Name }}
  {{ else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hysteria") }}
  {{- $params := list -}}
  {{- if ne (default "" $proxy.SNI) "" -}}
    {{- $params = append $params (printf "sni=%s" $proxy.SNI) -}}
  {{- end -}}
  {{- if $proxy.AllowInsecure -}}
    {{- $params = append $params "insecure=1" -}}
  {{- end -}}
  {{- if ne (default "" $proxy.ObfsPassword) "" -}}
    {{- $params = append $params (printf "obfs=salamander&obfs-password=%s" $proxy.ObfsPassword) -}}
  {{- end -}}
  {{- if ne (default "" $proxy.HopPorts) "" -}}
    {{- $params = append $params (printf "mport=%s" $proxy.HopPorts) -}}
  {{- end -}}
hysteria2://{{- if ne $password "" -}}{{ $password }}@{{- end -}}{{ $server }}:{{ $proxy.Port }}?{{ join "&" (append $params $common) }}#{{ $proxy.Name | urlquery }}
  {{ else if eq $proxy.Type "tuic" }}
  {{- $params := list -}}
  {{- if ne (default "" $proxy.CongestionController) "" -}}
    {{- $params = append $params (printf "congestion_controller=%s" $proxy.CongestionController) -}}
  {{- end -}}
  {{- if ne (default "" $proxy.UDPRelayMode) "" -}}
    {{- $params = append $params (printf "udp_relay_mode=%s" $proxy.UDPRelayMode) -}}
  {{- end -}}
  {{- if $proxy.ReduceRtt -}}
    {{- $params = append $params "reduce_rtt=1" -}}
  {{- end -}}
  {{- if $proxy.DisableSNI -}}
    {{- $params = append $params "disable_sni=1" -}}
  {{- end -}}
  {{- if ne (default "" $proxy.SNI) "" -}}
    {{- $params = append $params (printf "sni=%s" $proxy.SNI) -}}
  {{- end -}}
  {{- if $proxy.AllowInsecure -}}
    {{- $params = append $params "allow_insecure=1" -}}
  {{- end -}}
  {{- $params = append $params $common -}}
tuic://{{ default "" $proxy.ServerKey }}:{{ $password }}@{{ $server }}:{{ $proxy.Port }}?{{ join "&" $params }}#{{ $proxy.Name }}
  {{ else if eq $proxy.Type "anytls" }}
  {{- $params := list -}}
  {{- if ne (default "" $proxy.SNI) "" -}}
    {{- $params = append $params (printf "sni=%s" $proxy.SNI) -}}
  {{- end -}}
  {{- $params = append $params $common -}}
anytls://{{ $password }}@{{ $server }}:{{ $proxy.Port }}?{{ join "&" $params }}#{{ $proxy.Name }}
  {{ else if or (eq $proxy.Type "http") (eq $proxy.Type "https") }}
  {{- $user := default $password $proxy.Username -}}
http{{- if eq $proxy.Type "https" -}}s{{- end -}}://{{- if or (ne (default "" $user) "") (ne (default "" $password) "") -}}{{ $user }}:{{ $password }}@{{- end -}}{{ $server }}:{{ $proxy.Port }}#{{ $proxy.Name }}
  {{ else if or (eq $proxy.Type "socks") (eq $proxy.Type "socks5") (eq $proxy.Type "socks5-tls") }}
  {{- $user := default $password $proxy.Username -}}
socks5://{{- if or (ne (default "" $user) "") (ne (default "" $password) "") -}}{{ $user }}:{{ $password }}@{{- end -}}{{ $server }}:{{ $proxy.Port }}{{- if eq $proxy.Type "socks5-tls" }}?tls=1{{- end }}#{{ $proxy.Name }}
  {{- end }}
{{- end }}
