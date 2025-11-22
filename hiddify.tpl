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

{{- $supportSet := dict "shadowsocks" true "vmess" true "vless" true "trojan" true "hysteria2" true "hysteria" true "tuic" true "wireguard" true "anytls" true -}}
{{- $supportedProxies := list -}}
{{- range $proxy := $sorted -}}
  {{- if hasKey $supportSet $proxy.Type -}}
    {{- $supportedProxies = append $supportedProxies $proxy -}}
  {{- end -}}
{{- end -}}

{{- $proxyNames := "" -}}
{{- if gt (len $supportedProxies) 0 -}}
  {{- range $proxy := $supportedProxies -}}
    {{- if eq $proxyNames "" -}}
      {{- $proxyNames = printf "\"%s\"" $proxy.Name -}}
    {{- else -}}
      {{- $proxyNames = printf "%s, \"%s\"" $proxyNames $proxy.Name -}}
    {{- end -}}
  {{- end -}}
  {{- $proxyNames = printf ", %s" $proxyNames -}}
{{- end -}}

{
  "log": {"level": "info", "timestamp": true},
  "experimental": {
    "cache_file": {"enabled": true, "path": "hiddify_cache.db", "cache_id": "{{ .SiteName | default "hiddify" }}", "store_fakeip": true},
    "clash_api": {"external_controller": "127.0.0.1:9090", "external_ui": "ui", "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/gh-pages.zip", "external_ui_download_detour": "direct", "default_mode": "rule"}
  },
  "dns": {
    "servers": [
      {"tag": "dns_proxy","address": "https://8.8.8.8/dns-query","detour": "Proxy"},
      {"tag": "dns_direct","address": "https://223.5.5.5/dns-query","detour": "direct"},
      {"tag": "dns_local","address": "local","detour": "direct"}
    ],
    "rules": [
      {"outbound": "any", "server": "dns_local"},
      {"rule_set": "geosite-cn", "server": "dns_direct"},
      {"clash_mode": "direct", "server": "dns_direct"},
      {"clash_mode": "global", "server": "dns_proxy"},
      {"rule_set": "geosite-geolocation-!cn", "server": "dns_proxy"}
    ],
    "final": "dns_direct", "strategy": "ipv4_only"
  },
  "inbounds": [
    {"tag": "tun-in", "type": "tun", "inet4_address": "172.19.0.1/30", "auto_route": true, "strict_route": true, "stack": "system", "sniff": true,
      "platform": {"http_proxy": {"enabled": true, "server": "127.0.0.1", "server_port": 7890}}},
    {"tag": "mixed-in", "type": "mixed", "listen": "127.0.0.1", "listen_port": 7890, "sniff": true}
  ],
  "outbounds": [
    {"tag": "Proxy", "type": "selector", "outbounds": ["Auto - UrlTest", "direct"{{ $proxyNames }}]},
    {"tag": "Domestic", "type": "selector", "outbounds": ["direct", "Proxy"{{ $proxyNames }}]},
    {"tag": "Others", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "AI Suite", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Netflix", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Disney Plus", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "YouTube", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Spotify", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Apple", "type": "selector", "outbounds": ["direct", "Proxy"{{ $proxyNames }}]},
    {"tag": "Telegram", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "Microsoft", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "TikTok", "type": "selector", "outbounds": ["Proxy", "direct"{{ $proxyNames }}]},
    {"tag": "AdBlock", "type": "selector", "outbounds": ["block", "direct", "Proxy"]},
    {{- if gt (len $supportedProxies) 0 }}
    {"tag": "Auto - UrlTest", "type": "urltest", "outbounds": [{{ $proxyNames | trimPrefix ", " }}], "url": "http://cp.cloudflare.com/", "interval": "10m", "tolerance": 50}
    {{- range $proxy := $supportedProxies }},

      {{- $common := `"tcp_fast_open": false, "udp_over_tcp": true` -}}

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

{{- if eq $proxy.Type "shadowsocks" -}}
    { "type": "shadowsocks", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "method": {{ $proxy.Method | quote }}, "password": {{ $password | quote }}, {{ $common }} }
{{- else if eq $proxy.Type "vmess" -}}
    { "type": "vmess", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "uuid": {{ $.UserInfo.Password | quote }}, "security": "auto", {{ $common }}{{ if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, "transport": {"type": "ws", "path": {{ $proxy.Path | default "/" | quote }}{{- if $proxy.Host }}, "headers": {"Host": {{ $proxy.Host | quote }} }{{- end }}}{{ else if eq $proxy.Transport "grpc" }}, "transport": {"type": "grpc", "service_name": {{ $proxy.ServiceName | quote }}}{{ end }}{{ if or $proxy.SNI $SkipVerify $proxy.Fingerprint }}, "tls": {"enabled": true{{ if $proxy.SNI }}, "server_name": {{ $proxy.SNI | quote }}{{ end }}{{ if $SkipVerify }}, "insecure": true{{ end }}{{ if $proxy.Fingerprint }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{ end }}}{{ end }} }
{{- else if eq $proxy.Type "vless" -}}
    { "type": "vless", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "uuid": {{ $.UserInfo.Password | quote }}, {{ $common }}{{ if and $proxy.Flow (ne $proxy.Flow "none") }}, "flow": {{ $proxy.Flow | quote }}{{ end }}{{ if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, "transport": {"type": "ws", "path": {{ $proxy.Path | default "/" | quote }}{{- if $proxy.Host }}, "headers": {"Host": {{ $proxy.Host | quote }} }{{- end }}}{{ else if eq $proxy.Transport "grpc" }}, "transport": {"type": "grpc", "service_name": {{ $proxy.ServiceName | quote }}}{{ end }}{{ if $proxy.RealityPublicKey }}, "reality": { "enabled": true, "public_key": {{ $proxy.RealityPublicKey | quote }}{{ if $proxy.RealityShortId }}, "short_id": {{ $proxy.RealityShortId | quote }}{{ end }}{{ if $proxy.SNI }}, "server_name": {{ $proxy.SNI | quote }}{{ end }} }{{ else if or $proxy.SNI $SkipVerify $proxy.Fingerprint }}, "tls": {"enabled": true{{ if $proxy.SNI }}, "server_name": {{ $proxy.SNI | quote }}{{ end }}{{ if $SkipVerify }}, "insecure": true{{ end }}{{ if $proxy.Fingerprint }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{ end }}}{{ end }} }
{{- else if eq $proxy.Type "trojan" -}}
    { "type": "trojan", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "password": {{ $password | quote }}{{ if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, "transport": {"type": "ws", "path": {{ $proxy.Path | default "/" | quote }}{{- if $proxy.Host }}, "headers": {"Host": {{ $proxy.Host | quote }} }{{- end }}}{{ else if eq $proxy.Transport "grpc" }}, "transport": {"type": "grpc", "service_name": {{ $proxy.ServiceName | quote }}}{{ end }}, {{ $common }}, "tls": {"enabled": true{{ if $proxy.SNI }}, "server_name": {{ $proxy.SNI | quote }}{{ end }}{{ if $SkipVerify }}, "insecure": true{{ end }}{{ if $proxy.Fingerprint }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{ end }}} }
{{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hysteria") -}}
    { "type": "hysteria2", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "password": {{ $password | quote }}{{ if $proxy.ObfsPassword }}, "obfs": { "type": "salamander", "password": {{ $proxy.ObfsPassword | quote }} }{{ end }}{{ if $proxy.HopPorts }}, "ports": {{ $proxy.HopPorts | quote }}{{ end }}{{ if $proxy.HopInterval }}, "hop_interval": {{ $proxy.HopInterval }}{{ end }}, {{ $common }}, "tls": {"enabled": true{{ if $proxy.SNI }}, "server_name": {{ $proxy.SNI | quote }}{{ end }}{{ if $SkipVerify }}, "insecure": true{{ end }}{{ if $proxy.Fingerprint }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{ end }}} }
{{- else if eq $proxy.Type "tuic" -}}
    { "type": "tuic", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "uuid": {{ $.UserInfo.Password | quote }}, "password": {{ $password | quote }}{{ if $proxy.DisableSNI }}, "disable_sni": {{ $proxy.DisableSNI }}{{ end }}{{ if $proxy.ReduceRtt }}, "reduce_rtt": {{ $proxy.ReduceRtt }}{{ end }}{{ if $proxy.UDPRelayMode }}, "udp_relay_mode": {{ $proxy.UDPRelayMode | quote }}{{ end }}{{ if $proxy.CongestionController }}, "congestion_control": {{ $proxy.CongestionController | quote }}{{ end }}, {{ $common }}, "alpn": ["h3"], "tls": {"enabled": true{{ if $proxy.SNI }}, "server_name": {{ $proxy.SNI | quote }}{{ end }}{{ if $SkipVerify }}, "insecure": true{{ end }}{{ if $proxy.Fingerprint }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{ end }}} }
{{- else if eq $proxy.Type "wireguard" -}}
    { "type": "wireguard", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "private_key": {{ $proxy.ServerKey | quote }}, "peer_public_key": {{ $proxy.RealityPublicKey | quote }}{{ if $proxy.Path }}, "pre_shared_key": {{ $proxy.Path | quote }}{{ end }}{{ if $proxy.RealityServerAddr }}, "local_address": [{{ $proxy.RealityServerAddr | quote }}]{{ end }}, {{ $common }} }
{{- else if eq $proxy.Type "anytls" -}}
    { "type": "anytls", "tag": {{ $proxy.Name | quote }}, "server": {{ $server | quote }}, "server_port": {{ $proxy.Port }}, "password": {{ $password | quote }}, {{ $common }}, "tls": {"enabled": true{{ if $proxy.SNI }}, "server_name": {{ $proxy.SNI | quote }}{{ end }}{{ if $SkipVerify }}, "insecure": true{{ end }}{{ if $proxy.Fingerprint }}, "utls": {"enabled": true, "fingerprint": {{ $proxy.Fingerprint | quote }} }{{ end }}} }
{{- else -}}
    { "type": "direct", "tag": {{ $proxy.Name | quote }}, {{ $common }} }
{{- end }}
    {{- end }},
    {{- end }}
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ],
  "route": {
    "auto_detect_interface": true, "final": "Proxy",
    "rules": [
      {"type": "logical", "mode": "or", "rules": [{"port": 53},{"protocol": "dns"}], "action": "hijack-dns"},
      {"rule_set": "geosite-category-ads-all", "outbound": "AdBlock"},
      {"clash_mode": "direct", "outbound": "direct"},
      {"clash_mode": "global", "outbound": "Proxy"},
      {"domain": ["clash.razord.top","yacd.metacubex.one","yacd.haishan.me","d.metacubex.one"], "outbound": "direct"},
      {"ip_is_private": true, "outbound": "direct"},
      {"rule_set": ["geoip-netflix","geosite-netflix"], "outbound": "Netflix"},
      {"rule_set": "geosite-disney", "outbound": "Disney Plus"},
      {"rule_set": "geosite-youtube", "outbound": "YouTube"},
      {"rule_set": "geosite-spotify", "outbound": "Spotify"},
      {"rule_set": ["geoip-apple","geosite-apple"], "outbound": "Apple"},
      {"rule_set": ["geoip-telegram","geosite-telegram"], "outbound": "Telegram"},
      {"rule_set": "geosite-openai", "outbound": "AI Suite"},
      {"rule_set": "geosite-microsoft", "outbound": "Microsoft"},
      {"rule_set": "geosite-tiktok", "outbound": "TikTok"},
      {"rule_set": "geosite-private", "outbound": "direct"},
      {"rule_set": ["geoip-cn","geosite-cn"], "outbound": "Domestic"},
      {"rule_set": "geosite-geolocation-!cn", "outbound": "Others"}
    ],
    "rule_set": [
      {"tag": "geoip-cn","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geoip/cn.srs","download_detour": "direct"},
      {"tag": "geosite-cn","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/cn.srs","download_detour": "direct"},
      {"tag": "geosite-private","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/private.srs","download_detour": "direct"},
      {"tag": "geosite-geolocation-!cn","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/geolocation-!cn.srs","download_detour": "direct"},
      {"tag": "geosite-category-ads-all","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/category-ads-all.srs","download_detour": "direct"},
      {"tag": "geoip-netflix","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geoip/netflix.srs","download_detour": "direct"},
      {"tag": "geosite-netflix","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/netflix.srs","download_detour": "direct"},
      {"tag": "geosite-disney","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/disney.srs","download_detour": "direct"},
      {"tag": "geosite-youtube","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/youtube.srs","download_detour": "direct"},
      {"tag": "geosite-spotify","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/spotify.srs","download_detour": "direct"},
      {"tag": "geoip-apple","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo-lite/geoip/apple.srs","download_detour": "direct"},
      {"tag": "geosite-apple","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/apple.srs","download_detour": "direct"},
      {"tag": "geoip-telegram","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geoip/telegram.srs","download_detour": "direct"},
      {"tag": "geosite-telegram","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/telegram.srs","download_detour": "direct"},
      {"tag": "geosite-openai","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/openai.srs","download_detour": "direct"},
      {"tag": "geosite-microsoft","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/microsoft.srs","download_detour": "direct"},
      {"tag": "geosite-tiktok","type": "remote","format": "binary","url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/tiktok.srs","download_detour": "direct"}
    ]
  }
}

<!--
{{ .SiteName }}-{{ .SubscribeName }}
Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $ExpiredAt }}
Generated at: {{ now | date "2006-01-02 15:04:05" }}
-->
