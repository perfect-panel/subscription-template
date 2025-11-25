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

  {{- /* 公共传输层配置函数 */ -}}
  {{- $buildTransportParams := dict -}}
  {{- $transport := default "tcp" $proxy.Transport -}}
  {{- if ne $transport "" -}}
    {{- $_ := set $buildTransportParams "type" (ternary "ws" $transport (eq $transport "websocket")) -}}
  {{- end -}}
  {{- /* TCP 传输类型配置 */ -}}
  {{- if eq $transport "tcp" -}}
    {{- $headerType := default "none" $proxy.HeaderType -}}
    {{- if ne $headerType "none" -}}
      {{- $_ := set $buildTransportParams "headerType" $headerType -}}
    {{- end -}}
    {{- if and (eq $headerType "http") (ne (default "" $proxy.Host) "") -}}
      {{- $_ := set $buildTransportParams "host" $proxy.Host -}}
    {{- end -}}
    {{- if and (eq $headerType "http") (ne (default "" $proxy.Path) "") -}}
      {{- $_ := set $buildTransportParams "path" ($proxy.Path | urlquery) -}}
    {{- end -}}
  {{- end -}}
  {{- /* WebSocket/xhttp/httpupgrade 传输类型配置 */ -}}
  {{- if and (or (eq $transport "ws") (eq $transport "websocket") (eq $transport "xhttp") (eq $transport "httpupgrade")) (ne (default "" $proxy.Host) "") -}}
    {{- $_ := set $buildTransportParams "host" $proxy.Host -}}
  {{- end -}}
  {{- if and (or (eq $transport "ws") (eq $transport "websocket") (eq $transport "xhttp") (eq $transport "httpupgrade")) (ne (default "" $proxy.Path) "") -}}
    {{- $_ := set $buildTransportParams "path" ($proxy.Path | urlquery) -}}
  {{- end -}}
  {{- /* gRPC 传输类型配置 */ -}}
  {{- if and (eq $transport "grpc") (ne (default "" $proxy.ServiceName) "") -}}
    {{- $_ := set $buildTransportParams "serviceName" $proxy.ServiceName -}}
  {{- end -}}
  {{- /* xhttp 特有配置 */ -}}
  {{- if and (eq $transport "xhttp") (ne (default "" $proxy.XhttpMode) "") -}}
    {{- $_ := set $buildTransportParams "mode" $proxy.XhttpMode -}}
  {{- end -}}
  {{- if and (eq $transport "xhttp") (ne (default "" $proxy.XhttpExtra) "") -}}
    {{- $_ := set $buildTransportParams "extra" (urlquery $proxy.XhttpExtra) -}}
  {{- end -}}

  {{- /* 公共安全层配置 */ -}}
  {{- $buildSecurityParams := dict -}}
  {{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") -}}
    {{- $_ := set $buildSecurityParams "security" $proxy.Security -}}
  {{- end -}}
  {{- if ne (default "" $proxy.SNI) "" -}}
    {{- $_ := set $buildSecurityParams "sni" $proxy.SNI -}}
  {{- end -}}
  {{- if $SkipVerify -}}
    {{- $_ := set $buildSecurityParams "allowInsecure" "1" -}}
  {{- end -}}
  {{- if ne (default "" $proxy.Fingerprint) "" -}}
    {{- $_ := set $buildSecurityParams "fp" $proxy.Fingerprint -}}
  {{- end -}}
  {{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") -}}
    {{- $_ := set $buildSecurityParams "pbk" $proxy.RealityPublicKey -}}
  {{- end -}}
  {{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityShortId) "") -}}
    {{- $_ := set $buildSecurityParams "sid" $proxy.RealityShortId -}}
  {{- end -}}

  {{- if eq $proxy.Type "shadowsocks" }}
  {{- $params := list -}}
  {{- /* Shadowsocks 特有的 obfs 插件参数 */ -}}
  {{- if ne (default "" $proxy.Obfs) "" -}}
    {{- $params = append $params (printf "obfs=%s" $proxy.Obfs) -}}
  {{- end -}}
  {{- if ne (default "" $proxy.ObfsHost) "" -}}
    {{- $params = append $params (printf "obfs-host=%s" $proxy.ObfsHost) -}}
  {{- end -}}
  {{- if ne (default "" $proxy.ObfsPath) "" -}}
    {{- $params = append $params (printf "obfs-uri=%s" ($proxy.ObfsPath | urlquery)) -}}
  {{- end -}}
  {{- /* 使用公共传输层配置 */ -}}
  {{- range $key, $val := $buildTransportParams -}}
    {{- $params = append $params (printf "%s=%s" $key $val) -}}
  {{- end -}}
  {{- /* 使用公共安全层配置 */ -}}
  {{- range $key, $val := $buildSecurityParams -}}
    {{- $params = append $params (printf "%s=%s" $key $val) -}}
  {{- end -}}
  {{- /* 添加公共参数 */ -}}
  {{- $params = append $params $common }}
ss://{{ printf "%s:%s" (default "aes-128-gcm" $proxy.Method) $password | b64enc }}@{{ $server }}:{{ $proxy.Port }}?{{ join "&" $params }}#{{ $proxy.Name }}
  {{- else if eq $proxy.Type "vmess" }}
  {{- $vmessDict := dict "v" "2" "ps" $proxy.Name "add" $proxy.Server "port" (printf "%d" $proxy.Port) "id" $password "aid" "0" "net" "tcp" "type" "none" -}}
  {{- if hasKey $buildTransportParams "type" -}}
    {{- $_ := set $vmessDict "net" (index $buildTransportParams "type") -}}
  {{- end -}}
  {{- if hasKey $buildTransportParams "host" -}}
    {{- $_ := set $vmessDict "host" (index $buildTransportParams "host") -}}
  {{- end -}}
  {{- if hasKey $buildTransportParams "path" -}}
    {{- $_ := set $vmessDict "path" (index $buildTransportParams "path") -}}
  {{- end -}}
  {{- if and (eq $transport "grpc") (hasKey $buildTransportParams "serviceName") -}}
    {{- $_ := set $vmessDict "path" (index $buildTransportParams "serviceName") -}}
  {{- end -}}
  {{- if hasKey $buildTransportParams "mode" -}}
    {{- $_ := set $vmessDict "xhttpMode" (index $buildTransportParams "mode") -}}
  {{- end -}}
  {{- if hasKey $buildTransportParams "extra" -}}
    {{- $_ := set $vmessDict "xhttpExtra" (index $buildTransportParams "extra") -}}
  {{- end -}}
  {{- if hasKey $buildSecurityParams "security" -}}
    {{- $_ := set $vmessDict "tls" (index $buildSecurityParams "security") -}}
  {{- end -}}
  {{- if hasKey $buildSecurityParams "sni" -}}
    {{- $_ := set $vmessDict "sni" (index $buildSecurityParams "sni") -}}
  {{- end -}}
  {{- if hasKey $buildSecurityParams "fp" -}}
    {{- $_ := set $vmessDict "fp" (index $buildSecurityParams "fp") -}}
  {{- end -}}
  {{- if hasKey $buildSecurityParams "allowInsecure" -}}
    {{- $_ := set $vmessDict "skip-cert-verify" true -}}
  {{- end }}
vmess://{{ $vmessDict | toJson | b64enc }}
  {{- else if eq $proxy.Type "vless" }}
  {{- $params := list -}}
  {{- /* 1. Encryption 加密参数 */ -}}
  {{- $encryption := default "none" $proxy.Encryption -}}
  {{- if eq $encryption "none" -}}
    {{- $params = append $params "encryption=none" -}}
  {{- else -}}
    {{- $encParts := list -}}
    {{- $encParts = append $encParts $encryption -}}
    {{- if ne (default "" $proxy.Encryption_Mode) "" -}}
      {{- $encParts = append $encParts $proxy.Encryption_Mode -}}
    {{- end -}}
    {{- if ne (default "" $proxy.EncryptionRtt) "" -}}
      {{- $encParts = append $encParts $proxy.EncryptionRtt -}}
    {{- end -}}
    {{- if ne (default "" $proxy.EncryptionClientPadding) "" -}}
      {{- $encParts = append $encParts $proxy.EncryptionClientPadding -}}
    {{- end -}}
    {{- if ne (default "" $proxy.EncryptionPassword) "" -}}
      {{- $encParts = append $encParts $proxy.EncryptionPassword -}}
    {{- end -}}
    {{- $params = append $params (printf "encryption=%s" (join "." $encParts)) -}}
  {{- end -}}
  {{- /* 2. Flow 流控参数 */ -}}
  {{- if ne (default "" $proxy.Flow) "none" -}}
    {{- $params = append $params (printf "flow=%s" $proxy.Flow) -}}
  {{- end -}}
  {{- /* 3. Security 安全参数 */ -}}
  {{- if hasKey $buildSecurityParams "security" -}}
    {{- $params = append $params (printf "security=%s" (index $buildSecurityParams "security")) -}}
  {{- end -}}
  {{- if hasKey $buildSecurityParams "sni" -}}
    {{- $params = append $params (printf "sni=%s" (index $buildSecurityParams "sni")) -}}
  {{- end -}}
  {{- if hasKey $buildSecurityParams "fp" -}}
    {{- $params = append $params (printf "fp=%s" (index $buildSecurityParams "fp")) -}}
  {{- end -}}
  {{- if hasKey $buildSecurityParams "allowInsecure" -}}
    {{- $params = append $params "allowInsecure=1" -}}
  {{- end -}}
  {{- if hasKey $buildSecurityParams "pbk" -}}
    {{- $params = append $params (printf "pbk=%s" (index $buildSecurityParams "pbk")) -}}
  {{- end -}}
  {{- if hasKey $buildSecurityParams "sid" -}}
    {{- $params = append $params (printf "sid=%s" (index $buildSecurityParams "sid")) -}}
  {{- end -}}
  {{- /* 4. Transport 传输层参数 */ -}}
  {{- if hasKey $buildTransportParams "type" -}}
    {{- $params = append $params (printf "type=%s" (index $buildTransportParams "type")) -}}
  {{- end -}}
  {{- if hasKey $buildTransportParams "host" -}}
    {{- $params = append $params (printf "host=%s" (index $buildTransportParams "host")) -}}
  {{- end -}}
  {{- if hasKey $buildTransportParams "path" -}}
    {{- $params = append $params (printf "path=%s" (index $buildTransportParams "path")) -}}
  {{- end -}}
  {{- if hasKey $buildTransportParams "serviceName" -}}
    {{- $params = append $params (printf "serviceName=%s" (index $buildTransportParams "serviceName")) -}}
  {{- end -}}
  {{- if hasKey $buildTransportParams "mode" -}}
    {{- $params = append $params (printf "mode=%s" (index $buildTransportParams "mode")) -}}
  {{- end -}}
  {{- if hasKey $buildTransportParams "extra" -}}
    {{- $params = append $params (printf "extra=%s" (index $buildTransportParams "extra")) -}}
  {{- end -}}
  {{- /* 5. Common 通用参数 */ -}}
  {{- $params = append $params $common }}
vless://{{ $password }}@{{ $server }}:{{ $proxy.Port }}?{{ join "&" $params }}#{{ $proxy.Name }}
  {{- else if eq $proxy.Type "trojan" }}
  {{- $params := list -}}
  {{- range $key, $val := $buildTransportParams -}}
    {{- $params = append $params (printf "%s=%s" $key $val) -}}
  {{- end -}}
  {{- range $key, $val := $buildSecurityParams -}}
    {{- $params = append $params (printf "%s=%s" $key $val) -}}
  {{- end -}}
  {{- $params = append $params $common }}
trojan://{{ $password }}@{{ $server }}:{{ $proxy.Port }}?{{ join "&" $params }}#{{ $proxy.Name }}
  {{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hysteria") }}
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
  {{- end }}
hysteria2://{{- if ne $password "" -}}{{ $password }}@{{- end -}}{{ $server }}:{{ $proxy.Port }}?{{ join "&" (append $params $common) }}#{{ $proxy.Name | urlquery }}
  {{- else if eq $proxy.Type "tuic" }}
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
  {{- $params = append $params $common }}
tuic://{{ default "" $proxy.ServerKey }}:{{ $password }}@{{ $server }}:{{ $proxy.Port }}?{{ join "&" $params }}#{{ $proxy.Name }}
  {{- else if eq $proxy.Type "anytls" }}
  {{- $params := list -}}
  {{- /* 使用公共传输层配置 */ -}}
  {{- range $key, $val := $buildTransportParams -}}
    {{- $params = append $params (printf "%s=%s" $key $val) -}}
  {{- end -}}
  {{- /* 使用公共安全层配置 */ -}}
  {{- range $key, $val := $buildSecurityParams -}}
    {{- $params = append $params (printf "%s=%s" $key $val) -}}
  {{- end -}}
  {{- $params = append $params $common }}
anytls://{{ $password }}@{{ $server }}:{{ $proxy.Port }}?{{ join "&" $params }}#{{ $proxy.Name }}
  {{- else if or (eq $proxy.Type "http") (eq $proxy.Type "https") }}
  {{- $user := default $password $proxy.Username }}
http{{- if eq $proxy.Type "https" -}}s{{- end -}}://{{- if or (ne (default "" $user) "") (ne (default "" $password) "") -}}{{ $user }}:{{ $password }}@{{- end -}}{{ $server }}:{{ $proxy.Port }}#{{ $proxy.Name }}
  {{- else if or (eq $proxy.Type "socks") (eq $proxy.Type "socks5") (eq $proxy.Type "socks5-tls") }}
  {{- $user := default $password $proxy.Username }}
socks5://{{- if or (ne (default "" $user) "") (ne (default "" $password) "") -}}{{ $user }}:{{ $password }}@{{- end -}}{{ $server }}:{{ $proxy.Port }}{{- if eq $proxy.Type "socks5-tls" }}?tls=1{{- end }}#{{ $proxy.Name }}
  {{- end }}
{{- end }}