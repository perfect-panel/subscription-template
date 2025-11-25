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

{{- $supportSet := dict "shadowsocks" true "vmess" true "vless" true "trojan" true "hysteria2" true "hysteria" true "tuic" true "wireguard" true -}}
{{- $supportedProxies := list -}}
{{- range $proxy := $sorted -}}
  {{- if hasKey $supportSet $proxy.Type -}}
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
# Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $ExpiredAt }}
# Generated at: {{ now | date "2006-01-02 15:04:05" }}

mode: rule
log-level: info
dns:
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - system
    - https://dns.alidns.com/dns-query

proxies:
{{- range $proxy := $supportedProxies }}
  {{- $common := "udp: true" -}}

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
  - { name: {{ $proxy.Name | quote }}, type: vmess, server: {{ $server }}, port: {{ $proxy.Port }}, uuid: {{ $password }}, alterId: 0, cipher: auto, {{ $common }}{{- if or (eq $proxy.Transport "websocket") (eq $proxy.Transport "ws") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName }} }{{- end }}{{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") }}, tls: true{{- end }}{{- if ne (default "" $proxy.SNI) "" }}, servername: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, client-fingerprint: {{ $proxy.Fingerprint }}{{- end }} }
  {{- else if eq $proxy.Type "vless" }}
  - { name: {{ $proxy.Name | quote }}, type: vless, server: {{ $server }}, port: {{ $proxy.Port }}, uuid: {{ $password }}, {{ $common }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName }} }{{- end }}{{- if ne (default "" $proxy.SNI) "" }}, servername: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, client-fingerprint: {{ $proxy.Fingerprint }}{{- end }}{{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") }}, reality-opts: { public-key: {{ $proxy.RealityPublicKey }}{{- if ne (default "" $proxy.RealityShortId) "" }}, short-id: {{ $proxy.RealityShortId }}{{- end }} }{{- end }}{{- if ne (default "" $proxy.Flow) "none" }}, flow: {{ $proxy.Flow }}{{- end }} }
  {{- else if eq $proxy.Type "trojan" }}
  - { name: {{ $proxy.Name | quote }}, type: trojan, server: {{ $server }}, port: {{ $proxy.Port }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, client-fingerprint: {{ $proxy.Fingerprint }}{{- end }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName }} }{{- end }} }
  {{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hysteria") }}
  - { name: {{ $proxy.Name | quote }}, type: hysteria2, server: {{ $server }}, port: {{ $proxy.Port }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.ObfsPassword) "" }}, obfs: salamander, obfs-password: {{ $proxy.ObfsPassword }}{{- end }}{{- if ne (default "" $proxy.HopPorts) "" }}, ports: {{ $proxy.HopPorts }}{{- end }}{{- if ne (default 0 $proxy.HopInterval) 0 }}, hop-interval: {{ $proxy.HopInterval }}{{- end }} }
  {{- else if eq $proxy.Type "tuic" }}
  - { name: {{ $proxy.Name | quote }}, type: tuic, server: {{ $server }}, port: {{ $proxy.Port }}, uuid: {{ default "" $proxy.ServerKey }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if $proxy.DisableSNI }}, disable-sni: true{{- end }}{{- if $proxy.ReduceRtt }}, reduce-rtt: true{{- end }}{{- if ne (default "" $proxy.UDPRelayMode) "" }}, udp-relay-mode: {{ $proxy.UDPRelayMode }}{{- end }}{{- if ne (default "" $proxy.CongestionController) "" }}, congestion-controller: {{ $proxy.CongestionController }}{{- end }} }
  {{- else if eq $proxy.Type "wireguard" }}
  - { name: {{ $proxy.Name | quote }}, type: wireguard, server: {{ $server }}, port: {{ $proxy.Port }}, private-key: {{ default "" $proxy.ServerKey }}, public-key: {{ default "" $proxy.RealityPublicKey }}, {{ $common }}{{- if ne (default "" $proxy.Path) "" }}, preshared-key: {{ $proxy.Path }}{{- end }}{{- if ne (default "" $proxy.RealityServerAddr) "" }}, ip: {{ $proxy.RealityServerAddr }}{{- end }}{{- if ne (default 0 $proxy.RealityServerPort) 0 }}, ipv6: {{ $proxy.RealityServerPort }}{{- end }} }
  {{- else }}
  - { name: {{ $proxy.Name | quote }}, type: {{ $proxy.Type }}, server: {{ $server }}, port: {{ $proxy.Port }}, {{ $common }} }
  {{- end }}
{{- end }}

proxy-groups:
  - { name: 🚀 Proxy, type: select, proxies: [🌏 Auto, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🍎 Apple, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🔍 Google, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🪟 Microsoft, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 📺 GlobalMedia, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 📟 Telegram, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🤖 AI, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🪙 Crypto, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🎮 Game, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🇨🇳 China, type: select, proxies: [🎯 Direct, 🚀 Proxy, {{ $proxyNames }}] }
  - { name: 🎯 Direct, type: select, proxies: [DIRECT], hidden: true }
  - { name: 🐠 Final, type: select, proxies: [🚀 Proxy, 🎯 Direct, {{ $proxyNames }}] }
  - { name: 🌏 Auto, type: url-test, proxies: [{{ $proxyNames }}], url: 'http://www.gstatic.com/generate_204', interval: 300 }

rules:
  - RULE-SET, Apple, 🍎 Apple
  - RULE-SET, Google, 🔍 Google
  - RULE-SET, Microsoft, 🪟 Microsoft
  - RULE-SET, Github, 🪟 Microsoft
  - RULE-SET, HBO, 📺 GlobalMedia
  - RULE-SET, Disney, 📺 GlobalMedia
  - RULE-SET, TikTok, 📺 GlobalMedia
  - RULE-SET, Netflix, 📺 GlobalMedia
  - RULE-SET, GlobalMedia, 📺 GlobalMedia
  - RULE-SET, Telegram, 📟 Telegram
  - RULE-SET, OpenAI, 🤖 AI
  - RULE-SET, Gemini, 🤖 AI
  - RULE-SET, Copilot, 🤖 AI
  - RULE-SET, Claude, 🤖 AI
  - RULE-SET, Crypto, 🪙 Crypto
  - RULE-SET, Cryptocurrency, 🪙 Crypto
  - RULE-SET, Game, 🎮 Game
  - RULE-SET, Global, 🚀 Proxy
  - RULE-SET, ChinaMax, 🇨🇳 China
  - RULE-SET, Lan, 🎯 Direct
  - GEOIP, CN, 🇨🇳 China
  - MATCH, 🐠 Final

rule-providers:
  Apple:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Apple/Apple_Classical_No_Resolve.yaml
    interval: 86400
  Google:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Google/Google_No_Resolve.yaml
    interval: 86400
  Microsoft:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Microsoft/Microsoft.yaml
    interval: 86400
  Github:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/GitHub/GitHub.yaml
    interval: 86400
  HBO:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/HBO/HBO.yaml
    interval: 86400
  Disney:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Disney/Disney.yaml
    interval: 86400
  TikTok:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/TikTok/TikTok.yaml
    interval: 86400
  Netflix:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Netflix/Netflix.yaml
    interval: 86400
  GlobalMedia:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/GlobalMedia/GlobalMedia_Classical_No_Resolve.yaml
    interval: 86400
  Telegram:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Telegram/Telegram_No_Resolve.yaml
    interval: 86400
  OpenAI:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/OpenAI/OpenAI.yaml
    interval: 86400
  Gemini:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Gemini/Gemini.yaml
    interval: 86400
  Copilot:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Copilot/Copilot.yaml
    interval: 86400
  Claude:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Claude/Claude.yaml
    interval: 86400
  Crypto:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Crypto/Crypto.yaml
    interval: 86400
  Cryptocurrency:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Cryptocurrency/Cryptocurrency.yaml
    interval: 86400
  Game:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Game/Game.yaml
    interval: 86400
  Global:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Global/Global_Classical_No_Resolve.yaml
    interval: 86400
  ChinaMax:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/ChinaMax/ChinaMax_Classical_No_Resolve.yaml
    interval: 86400
  Lan:
    type: http
    behavior: classical
    format: yaml
    url: https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Clash/Lan/Lan.yaml
    interval: 86400

url-rewrite:
  - ^https?:\/\/(www.)?g\.cn https://www.google.com 302
  - ^https?:\/\/(www.)?google\.cn https://www.google.com 302
