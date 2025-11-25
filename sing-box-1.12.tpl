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

{{- $supportedProxies := list -}}
{{- range $proxy := $sorted -}}
  {{- $isSupported := false -}}
  {{- if or (eq $proxy.Type "shadowsocks") (eq $proxy.Type "vmess") (eq $proxy.Type "trojan") (eq $proxy.Type "hysteria2") (eq $proxy.Type "hy2") (eq $proxy.Type "tuic") (eq $proxy.Type "anytls") -}}
    {{- $isSupported = true -}}
  {{- else if eq $proxy.Type "vless" -}}
    {{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") (eq $proxy.Transport "grpc") (eq $proxy.Transport "tcp") (not $proxy.Transport) -}}
      {{- $isSupported = true -}}
    {{- end -}}
  {{- end -}}
  {{- if $isSupported -}}
    {{- $supportedProxies = append $supportedProxies $proxy -}}
  {{- end -}}
{{- end -}}

{{- define "AllNodeNames" -}}
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
{{- $supportedProxies := list -}}
{{- range $proxy := $sorted -}}
  {{- $isSupported := false -}}
  {{- if or (eq .Type "shadowsocks") (eq .Type "vmess") (eq .Type "trojan") (eq .Type "hysteria2") (eq .Type "hy2") (eq .Type "tuic") (eq .Type "anytls") -}}
    {{- $isSupported = true -}}
  {{- else if eq .Type "vless" -}}
    {{- if or (eq .Transport "ws") (eq .Transport "websocket") (eq .Transport "grpc") (eq .Transport "tcp") (not .Transport) -}}
      {{- $isSupported = true -}}
    {{- end -}}
  {{- end -}}
  {{- if $isSupported -}}
    {{- $supportedProxies = append $supportedProxies . -}}
  {{- end -}}
{{- end -}}
{{- $first := true -}}
{{- range $supportedProxies -}}
  {{- if $first -}}
    "{{ .Name }}"
    {{- $first = false -}}
  {{- else -}}
    , "{{ .Name }}"
  {{- end -}}
{{- end -}}
{{- end -}}

{{- define "NodeOutbound" -}}
{{- $proxy := .proxy -}}
{{- $server := $proxy.Server -}}
{{- if and (contains $server ":") (not (hasPrefix "[" $server)) -}}
  {{- $server = printf "[%s]" $server -}}
{{- end -}}
{{- $port := $proxy.Port -}}
{{- $name := $proxy.Name -}}
{{- $pwd := $.UserInfo.Password -}}
{{- $sni := or $proxy.SNI $server }}
{{- $svc := $proxy.ServiceName }}

{{- $tlsOpts := "" -}}
{{- if or $sni $proxy.AllowInsecure $proxy.Fingerprint -}}
  {{- $tlsOpts = "\"tls\": {\"enabled\": true" -}}
  {{- if $sni -}}
    {{- $tlsOpts = printf "%s, \"server_name\": \"%s\"" $tlsOpts $sni -}}
  {{- end -}}
  {{- if $proxy.AllowInsecure -}}
    {{- $tlsOpts = printf "%s, \"insecure\": true" $tlsOpts -}}
  {{- end -}}
  {{- if $proxy.Fingerprint -}}
    {{- $tlsOpts = printf "%s, \"utls\": {\"enabled\": true, \"fingerprint\": \"%s\"}" $tlsOpts ($proxy.Fingerprint) -}}
  {{- end -}}
  {{- $tlsOpts = printf "%s}" $tlsOpts -}}
{{- end -}}

{{- $transportOpts := "" -}}
{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") -}}
  {{- $wsPath := default "/" $proxy.Path -}}
  {{- $transportOpts = printf "\"transport\": {\"type\": \"ws\", \"path\": \"%s\"" $wsPath -}}
  {{- if $proxy.Host -}}
    {{- $transportOpts = printf "%s, \"headers\": {\"Host\": \"%s\"}" $transportOpts ($proxy.Host) -}}
  {{- end -}}
  {{- $transportOpts = printf "%s}" $transportOpts -}}
{{- else if eq $proxy.Transport "grpc" -}}
  {{- $grpcService := default "grpc" $svc -}}
  {{- $transportOpts = printf "\"transport\": {\"type\": \"grpc\", \"service_name\": \"%s\"}" $grpcService -}}
{{- end -}}

{{- if eq $proxy.Type "shadowsocks" -}}
  {{- $method := default "aes-128-gcm" $proxy.Method -}}
  {{- $password := $pwd -}}
  {{- if $proxy.ServerKey -}}
    {{- $needBytes := ternary 16 32 (eq $proxy.Method "2022-blake3-aes-128-gcm") -}}
    {{- $cutLen := min $needBytes (len $pwd) | int -}}
    {{- $userCut := $pwd | trunc $cutLen -}}
    {{- $serverB64 := b64enc $proxy.ServerKey -}}
    {{- $userB64 := b64enc $userCut -}}
    {{- $password = printf "%s:%s" $serverB64 $userB64 -}}
  {{- end -}}
{ "type": "shadowsocks", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "method": "{{ $method }}", "password": "{{ $password }}" }

{{- else if eq $proxy.Type "trojan" -}}
{ "type": "trojan", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "password": "{{ $pwd }}"{{ if $transportOpts }}, {{ $transportOpts }}{{ end }}, {{ $tlsOpts }} }

{{- else if eq $proxy.Type "vless" -}}
{{- $realityOpts := "" -}}
{{- if $proxy.RealityPublicKey -}}
  {{- $realityOpts = printf "\"reality\": { \"enabled\": true, \"public_key\": \"%s\"" ($proxy.RealityPublicKey) -}}
  {{- if $proxy.RealityShortId -}}
    {{- $realityOpts = printf "%s, \"short_id\": \"%s\"" $realityOpts ($proxy.RealityShortId) -}}
  {{- end -}}
  {{- if $svc -}}
    {{- $realityOpts = printf "%s, \"server_name\": \"%s\"" $realityOpts ($svc) -}}
  {{- end -}}
  {{- $realityOpts = printf "%s }" $realityOpts -}}
{{- end -}}
{{- $flowOpts := "" -}}
{{- if $proxy.Flow -}}
  {{- $flowOpts = printf ", \"flow\": \"%s\"" ($proxy.Flow) -}}
{{- end -}}
{ "type": "vless", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "uuid": "{{ $pwd }}"{{ $flowOpts }}{{ if $transportOpts }}, {{ $transportOpts }}{{ end }}{{ if $realityOpts }}, {{ $realityOpts }}{{ else if $tlsOpts }}, {{ $tlsOpts }}{{ end }} }

{{- else if eq $proxy.Type "vmess" -}}
{ "type": "vmess", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "uuid": "{{ $pwd }}", "security": "auto"{{ if $transportOpts }}, {{ $transportOpts }}{{ end }}{{ if $tlsOpts }}, {{ $tlsOpts }}{{ end }} }

{{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hy2") -}}
{{- $obfsOpts := "" -}}
{{- if $proxy.ObfsPassword -}}
  {{- $obfsOpts = printf "\"obfs\": { \"type\": \"salamander\", \"password\": \"%s\" }" ($proxy.ObfsPassword) -}}
{{- end -}}
{{- $hopPortsOpts := "" -}}
{{- if $proxy.HopPorts -}}
  {{- $hopPortsOpts = printf ", \"ports\": \"%s\"" ($proxy.HopPorts) -}}
{{- end -}}
{{- $hopIntervalOpts := "" -}}
{{- if $proxy.HopInterval -}}
  {{- $hopIntervalOpts = printf ", \"hop_interval\": %v" $proxy.HopInterval -}}
{{- end -}}
{ "type": "hysteria2", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "password": "{{ $pwd }}"{{ if $obfsOpts }}, {{ $obfsOpts }}{{ end }}{{ $hopPortsOpts }}{{ $hopIntervalOpts }}, {{ $tlsOpts }} }

{{- else if eq $proxy.Type "tuic" -}}
{{- $tuicServerKey := $proxy.ServerKey -}}
{{- $tuicOpts := "" -}}
{{- if $proxy.DisableSNI -}}
  {{- $tuicOpts = printf "%s, \"disable_sni\": %v" $tuicOpts $proxy.DisableSNI -}}
{{- end -}}
{{- if $proxy.ReduceRtt -}}
  {{- $tuicOpts = printf "%s, \"reduce_rtt\": %v" $tuicOpts $proxy.ReduceRtt -}}
{{- end -}}
{{- if $proxy.UDPRelayMode -}}
  {{- $tuicOpts = printf "%s, \"udp_relay_mode\": \"%s\"" $tuicOpts ($proxy.UDPRelayMode) -}}
{{- end -}}
{{- if $proxy.CongestionController -}}
  {{- $tuicOpts = printf "%s, \"congestion_control\": \"%s\"" $tuicOpts ($proxy.CongestionController) -}}
{{- end -}}
{ "type": "tuic", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "uuid": "{{ $tuicServerKey }}", "password": "{{ $pwd }}"{{ $tuicOpts }}, "alpn": ["h3"], {{ $tlsOpts }} }

{{- else if eq $proxy.Type "anytls" -}}
{{- $anytlsOpts := "" -}}
{{- if $proxy.Method -}}
  {{- $anytlsOpts = printf "%s, \"method\": \"%s\"" $anytlsOpts ($proxy.Method) -}}
{{- end -}}
{{- if $proxy.ObfsPassword -}}
  {{- $anytlsOpts = printf "%s, \"obfs\": \"%s\"" $anytlsOpts ($proxy.ObfsPassword) -}}
{{- end -}}
{{- if $proxy.Path -}}
  {{- $anytlsOpts = printf "%s, \"path\": \"%s\"" $anytlsOpts ($proxy.Path) -}}
{{- end -}}
{{- if $proxy.Host -}}
  {{- $anytlsOpts = printf "%s, \"host\": \"%s\"" $anytlsOpts ($proxy.Host) -}}
{{- end -}}
{ "type": "anytls", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "password": "{{ $pwd }}"{{ $anytlsOpts }}{{ if $tlsOpts }}, {{ $tlsOpts }}{{ end }} }

{{- else if eq $proxy.Type "wireguard" -}}
{{- $wgPrivateKey := $proxy.ServerKey -}}
{{- $wgPublicKey := $proxy.RealityPublicKey -}}
{{- $wgPreSharedOpts := "" -}}
{{- if $proxy.Path -}}
  {{- $wgPreSharedOpts = printf ", \"pre_shared_key\": \"%s\"" ($proxy.Path) -}}
{{- end -}}
{{- $wgLocalAddressOpts := "" -}}
{{- if $proxy.RealityServerAddr -}}
  {{- $wgLocalAddressOpts = printf ", \"local_address\": [\"%s\"]" ($proxy.RealityServerAddr) -}}
{{- end -}}
{ "type": "wireguard", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "private_key": "{{ $wgPrivateKey }}", "peer_public_key": "{{ $wgPublicKey }}"{{ $wgPreSharedOpts }}{{ $wgLocalAddressOpts }} }

{{- else if or (eq $proxy.Type "http") (eq $proxy.Type "https") -}}
{{- $httpsTLSOpts := "" -}}
{{- if and (eq $proxy.Type "https") $tlsOpts -}}
  {{- $httpsTLSOpts = printf ", %s" $tlsOpts -}}
{{- end -}}
{ "type": "http", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "username": "{{ $pwd }}", "password": "{{ $pwd }}"{{ $httpsTLSOpts }} }

{{- else if or (eq $proxy.Type "socks") (eq $proxy.Type "socks5") -}}
{ "type": "socks", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "version": "5", "username": "{{ $pwd }}", "password": "{{ $pwd }}" }

{{- else -}}
{ "type": "direct", "tag": "{{ $name }}" }
{{- end -}}
{{- end -}}

// 用户信息: 已用流量 {{ $used }}GB / 总流量 {{ $total }}GB, 过期时间: {{ $ExpiredAt }}
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "store_fakeip": true,
      "store_rdrc": true
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "access_control_allow_origin": [
        "http://127.0.0.1",
        "https://yacd.metacubex.one",
        "https://metacubex.github.io",
        "https://metacubexd.pages.dev",
        "https://board.zash.run.place"
      ]
    }
  },
  "dns": {
    "independent_cache": true,
    "servers": [
      {
        "tag": "google",
        "type": "https",
        "server": "8.8.8.8",
        "detour": "节点选择"
      },
      {
        "tag": "ali",
        "type": "https",
        "server": "223.5.5.5"
      },
      {
        "tag": "fakeip",
        "type": "fakeip",
        "inet4_range": "198.18.0.0/15",
        "inet6_range": "fc00::/18"
      }
    ],
    "rules": [
      {
        "clash_mode": "Direct",
        "server": "ali"
      },
      {
        "clash_mode": "Global",
        "server": "google"
      },
      {
        "query_type": [
          "A",
          "AAAA"
        ],
        "server": "fakeip"
      },
      {
        "rule_set": "geosite-cn",
        "server": "ali"
      }
    ]
  },
  "inbounds": [
    {
      "type": "tun",
      "address": [
        "172.18.0.1/30",
        "fdfe:dcba:9876::1/126"
      ],
      "auto_route": true,
      "strict_route": true
    },
    {
      "type": "mixed",
      "listen": "::",
      "listen_port": 7890
    }
  ],
  "outbounds": [
    {
      "tag": "节点选择",
      "type": "selector",
      "outbounds": [{{ template "AllNodeNames" . }}, "直连"]
    },
    {
      "tag": "Github",
      "type": "selector",
      "outbounds": [
        "节点选择",
        "直连",
        {{ template "AllNodeNames" . }}
      ]
    },
    {
      "tag": "Google",
      "type": "selector",
      "outbounds": [
        "节点选择",
        "直连",
        {{ template "AllNodeNames" . }}
      ]
    },
    {
      "tag": "Microsoft",
      "type": "selector",
      "outbounds": [
        "节点选择",
        "直连",
        {{ template "AllNodeNames" . }}
      ]
    },
    {
      "tag": "OpenAI",
      "type": "selector",
      "outbounds": [
        "节点选择",
        "直连",
        {{ template "AllNodeNames" . }}
      ]
    },
    {
      "tag": "Telegram",
      "type": "selector",
      "outbounds": [
        "节点选择",
        "直连",
        {{ template "AllNodeNames" . }}
      ]
    },
    {
      "tag": "Twitter",
      "type": "selector",
      "outbounds": [
        "节点选择",
        "直连",
        {{ template "AllNodeNames" . }}
      ]
    },
    {
      "tag": "Youtube",
      "type": "selector",
      "outbounds": [
        "节点选择",
        "直连",
        {{ template "AllNodeNames" . }}
      ]
    },
    {
      "tag": "国内",
      "type": "selector",
      "outbounds": [
        "直连",
        "节点选择",
        {{ template "AllNodeNames" . }}
      ]
    },
    {{- range $i, $proxy := $supportedProxies }}
    {{ if $i }},{{ end }}
    {{ template "NodeOutbound" (dict "proxy" $proxy "UserInfo" $.UserInfo) }}
    {{- end }}
    {{- if gt (len $supportedProxies) 0 }},{{ end }}
    {
      "tag": "直连",
      "type": "direct"
    }
  ],
  "route": {
    "default_domain_resolver": {
      "server": "ali"
    },
    "auto_detect_interface": true,
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "ip_is_private": true,
        "outbound": "直连"
      },
      {
        "rule_set": "anti-ad",
        "clash_mode": "Rule",
        "action": "reject"
      },
      {
        "clash_mode": "Direct",
        "outbound": "直连"
      },
      {
        "clash_mode": "Global",
        "outbound": "节点选择"
      },
      {
        "rule_set": "geosite-github",
        "outbound": "Github"
      },
      {
        "rule_set": [
          "geoip-google",
          "geosite-google"
        ],
        "outbound": "Google"
      },
      {
        "rule_set": "geosite-microsoft",
        "outbound": "Microsoft"
      },
      {
        "rule_set": "geosite-openai",
        "outbound": "OpenAI"
      },
      {
        "rule_set": [
          "geoip-telegram",
          "geosite-telegram"
        ],
        "outbound": "Telegram"
      },
      {
        "rule_set": [
          "geoip-twitter",
          "geosite-twitter"
        ],
        "outbound": "Twitter"
      },
      {
        "rule_set": "geosite-youtube",
        "outbound": "Youtube"
      },
      {
        "rule_set": [
          "geoip-cn",
          "geosite-cn"
        ],
        "outbound": "国内"
      }
    ],
    "rule_set": [
      {
        "tag": "anti-ad",
        "type": "remote",
        "format": "binary",
        "url": "https://anti-ad.net/anti-ad-sing-box.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-github",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/github.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geoip-google",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geoip/google.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-google",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/google.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-microsoft",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/microsoft.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-openai",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/openai.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geoip-telegram",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geoip/telegram.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-telegram",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/telegram.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geoip-twitter",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geoip/twitter.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-twitter",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/twitter.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-youtube",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/youtube.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geosite/cn.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/perfect-panel/rules/geo/geoip/cn.srs",
        "download_detour": "直连"
      }
    ]
  }
}