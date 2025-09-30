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

{{- $proxyNames := "" -}}
{{- range $proxy := $supportedProxies -}}
  {{- if eq $proxyNames "" -}}
    {{- $proxyNames = printf "%q" $proxy.Name -}}
  {{- else -}}
    {{- $proxyNames = printf "%s, %q" $proxyNames $proxy.Name -}}
  {{- end -}}
{{- end -}}

{{- define "NodeOutbound" -}}
{{- $proxy := .proxy -}}
{{- $server := $proxy.Server -}}
{{- if and (contains ":" $proxy.Server) (not (hasPrefix "[" $proxy.Server)) -}}
  {{- $server = printf "[%s]" $proxy.Server -}}
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
{{- else if eq $proxy.Transport "httpupgrade" -}}
  {{- $wsPath := default "/" $proxy.Path -}}
  {{- $transportOpts = printf "\"transport\": {\"type\": \"httpupgrade\", \"path\": \"%s\"" $wsPath -}}
  {{- if $proxy.Host -}}
    {{- $transportOpts = printf "%s, \"headers\": {\"Host\": \"%s\"}" $transportOpts ($proxy.Host) -}}
  {{- end -}}
  {{- $transportOpts = printf "%s}" $transportOpts -}}
{{- else if eq $proxy.Transport "grpc" -}}
  {{- $grpcService := default "grpc" $svc -}}
  {{- $transportOpts = printf "\"transport\": {\"type\": \"grpc\", \"service_name\": \"%s\"}" $grpcService -}}
{{- end -}}

{{- if eq $proxy.Type "shadowsocks" -}}
{ "type": "shadowsocks", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "method": "{{ default "aes-128-gcm" $proxy.Method }}", "password": "{{ $pwd }}" }

{{- else if eq $proxy.Type "trojan" -}}
{ "type": "trojan", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "password": "{{ $pwd }}"{{ if $transportOpts }}, {{ $transportOpts }}{{ end }}, {{ $tlsOpts }} }

{{- else if eq $proxy.Type "vless" -}}
{ "type": "vless", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "uuid": "{{ $pwd }}"{{ if $transportOpts }}, {{ $transportOpts }}{{ end }}{{ if $tlsOpts }}, {{ $tlsOpts }}{{ end }} }

{{- else if eq $proxy.Type "vmess" -}}
{ "type": "vmess", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "uuid": "{{ $pwd }}", "security": "auto"{{ if $transportOpts }}, {{ $transportOpts }}{{ end }}{{ if $tlsOpts }}, {{ $tlsOpts }}{{ end }} }

{{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hy2") -}}
{ "type": "hysteria2", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "password": "{{ $pwd }}", {{ $tlsOpts }} }

{{- else if eq $proxy.Type "tuic" -}}
{ "type": "tuic", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "uuid": "{{ $proxy.ServerKey }}", "password": "{{ $pwd }}", "alpn": ["h3"], {{ $tlsOpts }} }

{{- else if eq $proxy.Type "wireguard" -}}
{ "type": "wireguard", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "private_key": "{{ $proxy.ServerKey }}", "peer_public_key": "{{ $proxy.RealityPublicKey }}" }

{{- else if or (eq $proxy.Type "http") (eq $proxy.Type "https") -}}
{ "type": "http", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "username": "{{ $pwd }}", "password": "{{ $pwd }}"{{ if eq $proxy.Type "https" }}, {{ $tlsOpts }}{{ end }} }

{{- else if or (eq $proxy.Type "socks") (eq $proxy.Type "socks5") -}}
{ "type": "socks", "tag": "{{ $name }}", "server": "{{ $server }}", "server_port": {{ $port }}, "version": "5", "username": "{{ $pwd }}", "password": "{{ $pwd }}" }

{{- else -}}
{ "type": "direct", "tag": "{{ $name }}" }
{{- end -}}
{{- end -}}

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
        "address": "https://8.8.8.8/dns-query",
        "detour": "节点选择"
      },
      {
        "tag": "ali",
        "address": "https://223.5.5.5/dns-query",
        "detour": "直连"
      },
      {
        "tag": "fakeip",
        "address": "fakeip"
      }
    ],
    "rules": [
      {
        "outbound": "any",
        "server": "ali"
      },
      {
        "clash_mode": "Direct",
        "server": "ali"
      },
      {
        "clash_mode": "Global",
        "server": "google"
      },
      {
        "rule_set": "geosite-cn",
        "server": "ali"
      },
      {
        "query_type": [
          "A",
          "AAAA"
        ],
        "server": "fakeip"
      }
    ],
    "fakeip": {
      "enabled": true,
      "inet4_range": "198.18.0.0/15",
      "inet6_range": "fc00::/18"
    }
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
      "outbounds": [{{ $proxyNames }}, "直连"]
    },
    {
      "tag": "Github",
      "type": "selector",
      "outbounds": ["节点选择","直连", {{ $proxyNames }}]
    },
    {
      "tag": "Google",
      "type": "selector",
      "outbounds": ["节点选择","直连", {{ $proxyNames }}]
    },
    {
      "tag": "Microsoft",
      "type": "selector",
      "outbounds": ["节点选择","直连", {{ $proxyNames }}]
    },
    {
      "tag": "OpenAI",
      "type": "selector",
      "outbounds": ["节点选择","直连", {{ $proxyNames }}]
    },
    {
      "tag": "Telegram",
      "type": "selector",
      "outbounds": ["节点选择","直连", {{ $proxyNames }}]
    },
    {
      "tag": "Twitter",
      "type": "selector",
      "outbounds": ["节点选择","直连", {{ $proxyNames }}]
    },
    {
      "tag": "Youtube",
      "type": "selector",
      "outbounds": ["节点选择","直连", {{ $proxyNames }}]
    },
    {
      "tag": "国内",
      "type": "selector",
      "outbounds": ["直连","节点选择", {{ $proxyNames }}]
    },
    {{- $supportedProxies := list -}}
    {{- $usedNames := dict -}}
    {{- range $proxy := .Proxies -}}
      {{- $isSupported := false -}}
      {{- if or (eq $proxy.Type "shadowsocks") (eq $proxy.Type "vmess") (eq $proxy.Type "trojan") (eq $proxy.Type "hysteria2") (eq $proxy.Type "hy2") (eq $proxy.Type "tuic") (eq $proxy.Type "anytls") -}}
        {{- $isSupported = true -}}
      {{- else if eq $proxy.Type "vless" -}}
        {{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") (eq $proxy.Transport "grpc") (eq $proxy.Transport "tcp") (not $proxy.Transport) -}}
          {{- $isSupported = true -}}
        {{- end -}}
      {{- end -}}
      {{- if and $isSupported (not (hasKey $usedNames $proxy.Name)) -}}
        {{- $supportedProxies = append $supportedProxies $proxy -}}
        {{- $_ := set $usedNames $proxy.Name true -}}
      {{- end -}}
    {{- end -}}
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
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geosite/geosite-github.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geoip-google",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geoip/geoip-google.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-google",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geosite/geosite-google.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-microsoft",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geosite/geosite-microsoft.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-openai",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geosite/geosite-openai.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geoip-telegram",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geoip/geoip-telegram.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-telegram",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geosite/geosite-telegram.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geoip-twitter",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geoip/geoip-twitter.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-twitter",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geosite/geosite-twitter.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-youtube",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geosite/geosite-youtube.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geosite/geosite-cn.srs",
        "download_detour": "直连"
      },
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://cdn.jsdmirror.com/gh/lyc8503/sing-box-rules@rule-set-geoip/geoip-cn.srs",
        "download_detour": "直连"
      }
    ]
  }
}