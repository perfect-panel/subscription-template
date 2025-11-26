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

mode: rule
ipv6: true
allow-lan: true
bind-address: '*'
mixed-port: 10808
log-level: info
unified-delay: true
tcp-concurrent: true
external-controller: '0.0.0.0:9090'
global-client-fingerprint: chrome
tun:
  enable: true
  stack: system
  auto-route: true
dns:
  enable: true
  cache-algorithm: arc
  listen: '0.0.0.0:1053'
  ipv6: true
  use-hosts: true
  use-system-hosts: true
  respect-rules: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - 'localhost'
    - 'lens.l.google.com'
    - '*.srv.nintendo.net'
    - '*.stun.playstation.net'
    - 'xbox.*.*.microsoft.com'
    - '*.xboxlive.com'
    - '*.msftncsi.com'
    - '*.msftconnecttest.com'
    - 'time.*.com'
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/dns-query
  fallback:
    - tls://1.1.1.1
    - tls://8.8.8.8
  proxy-server-nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  direct-nameserver:
    - system
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  direct-nameserver-follow-policy: false
  fallback-filter:
    geoip: true
    geoip-code: CN
    geosite:
      - gfw
      - youtube
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.twitter.com'
      - '+.telegram.org'

proxies:
{{- range $proxy := $supportedProxies }}
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
- name: {{ $proxy.Name | quote }}
  type: ss
  server: {{ $server }}
  port: {{ $proxy.Port }}
  cipher: {{ default "aes-128-gcm" $proxy.Method }}
  password: {{ $password }}
  udp: true
  tfo: true
  {{- if ne (default "" $proxy.Obfs) "" }}
  plugin: obfs
  plugin-opts:
    mode: {{ $proxy.Obfs }}
    host: {{ default "" $proxy.ObfsHost }}
  {{- end }}
{{- else if eq $proxy.Type "vmess" }}
- name: {{ $proxy.Name | quote }}
  type: vmess
  server: {{ $server }}
  port: {{ $proxy.Port }}
  uuid: {{ $password }}
  alterId: 0
  cipher: auto
  udp: true
  tfo: true
  {{- if or (eq $proxy.Transport "websocket") (eq $proxy.Transport "ws") }}
  network: ws
  ws-opts:
    path: {{ default "/" $proxy.Path }}
    {{- if ne (default "" $proxy.Host) "" }}
    headers:
      Host: {{ $proxy.Host }}
    {{- end }}
  {{- else if eq $proxy.Transport "http" }}
  network: http
  http-opts:
    method: GET
    path: [{{ default "/" $proxy.Path | quote }}]
    {{- if ne (default "" $proxy.Host) "" }}
    headers:
      Host: [{{ $proxy.Host | quote }}]
    {{- end }}
  {{- else if eq $proxy.Transport "grpc" }}
  network: grpc
  grpc-opts:
    grpc-service-name: {{ default "grpc" $proxy.ServiceName }}
  {{- end }}
  {{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") }}
  tls: true
  {{- end }}
  {{- if ne (default "" $proxy.SNI) "" }}
  servername: {{ $proxy.SNI }}
  {{- end }}
  {{- if $SkipVerify }}
  skip-cert-verify: true
  {{- end }}
  {{- if ne (default "" $proxy.Fingerprint) "" }}
  client-fingerprint: {{ $proxy.Fingerprint }}
  {{- end }}
{{- else if eq $proxy.Type "vless" }}
  {{- $encryptionStr := "" -}}
  {{- $encryption := default "none" $proxy.Encryption -}}
  {{- if eq $encryption "none" -}}
    {{- $encryptionStr = "none" -}}
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
    {{- $encryptionStr = join "." $encParts -}}
  {{- end }}
- name: {{ $proxy.Name | quote }}
  type: vless
  server: {{ $server }}
  port: {{ $proxy.Port }}
  uuid: {{ $password }}
  udp: true
  tfo: true
  encryption: {{ $encryptionStr }}
  {{- if ne (default "" $proxy.Flow) "" }}
  flow: {{ $proxy.Flow }}
  {{- end }}
  {{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}
  network: ws
  ws-opts:
    path: {{ default "/" $proxy.Path }}
    {{- if ne (default "" $proxy.Host) "" }}
    headers:
      Host: {{ $proxy.Host }}
    {{- end }}
  {{- else if eq $proxy.Transport "http" }}
  network: http
  http-opts:
    method: GET
    path: [{{ default "/" $proxy.Path | quote }}]
    {{- if ne (default "" $proxy.Host) "" }}
    headers:
      Host: [{{ $proxy.Host | quote }}]
    {{- end }}
  {{- else if eq $proxy.Transport "httpupgrade" }}
  network: httpupgrade
  httpupgrade-opts:
    path: {{ default "/" $proxy.Path }}
    {{- if ne (default "" $proxy.Host) "" }}
    headers:
      Host: {{ $proxy.Host }}
    {{- end }}
  {{- else if eq $proxy.Transport "xhttp" }}
  network: xhttp
  xhttp-opts:
    path: {{ default "/" $proxy.Path }}
    {{- if ne (default "" $proxy.Host) "" }}
    headers:
      Host: {{ $proxy.Host }}
    {{- end }}
  {{- else if eq $proxy.Transport "grpc" }}
  network: grpc
  grpc-opts:
    grpc-service-name: {{ default "grpc" $proxy.ServiceName }}
  {{- end }}
  {{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") }}
  tls: true
  {{- end }}
  {{- if ne (default "" $proxy.SNI) "" }}
  servername: {{ $proxy.SNI }}
  {{- end }}
  {{- if $proxy.AllowInsecure }}
  skip-cert-verify: true
  {{- end }}
  {{- if ne (default "" $proxy.Fingerprint) "" }}
  client-fingerprint: {{ $proxy.Fingerprint }}
  {{- end }}
  {{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") }}
  reality-opts:
    public-key: {{ $proxy.RealityPublicKey }}
    {{- if ne (default "" $proxy.RealityShortId) "" }}
    short-id: {{ $proxy.RealityShortId }}
    {{- end }}
  {{- end }}
{{- else if eq $proxy.Type "trojan" }}
- name: {{ $proxy.Name | quote }}
  type: trojan
  server: {{ $server }}
  port: {{ $proxy.Port }}
  password: {{ $password }}
  udp: true
  tfo: true
  {{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") }}
  tls: true
  {{- end }}
  {{- if ne (default "" $proxy.SNI) "" }}
  sni: {{ $proxy.SNI }}
  {{- end }}
  {{- if $SkipVerify }}
  skip-cert-verify: true
  {{- end }}
  {{- if ne (default "" $proxy.Fingerprint) "" }}
  client-fingerprint: {{ $proxy.Fingerprint }}
  {{- end }}
  {{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") }}
  reality-opts:
    public-key: {{ $proxy.RealityPublicKey }}
    {{- if ne (default "" $proxy.RealityShortId) "" }}
    short-id: {{ $proxy.RealityShortId }}
    {{- end }}
  {{- end }}
  {{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}
  network: ws
  ws-opts:
    path: {{ default "/" $proxy.Path }}
    {{- if ne (default "" $proxy.Host) "" }}
    headers:
      Host: {{ $proxy.Host }}
    {{- end }}
  {{- else if eq $proxy.Transport "http" }}
  network: http
  http-opts:
    method: GET
    path: [{{ default "/" $proxy.Path | quote }}]
    {{- if ne (default "" $proxy.Host) "" }}
    headers:
      Host: [{{ $proxy.Host | quote }}]
    {{- end }}
  {{- else if eq $proxy.Transport "grpc" }}
  network: grpc
  grpc-opts:
    grpc-service-name: {{ default "grpc" $proxy.ServiceName }}
  {{- end }}
{{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hysteria") }}
- name: {{ $proxy.Name | quote }}
  type: hysteria2
  server: {{ $server }}
  port: {{ $proxy.Port }}
  password: {{ $password }}
  udp: true
  tfo: true
  {{- if ne (default "" $proxy.SNI) "" }}
  sni: {{ $proxy.SNI }}
  {{- end }}
  {{- if $proxy.AllowInsecure }}
  skip-cert-verify: true
  {{- end }}
  {{- if ne (default "" $proxy.ObfsPassword) "" }}
  obfs: salamander
  obfs-password: {{ $proxy.ObfsPassword }}
  {{- end }}
  {{- if ne (default "" $proxy.HopPorts) "" }}
  ports: {{ $proxy.HopPorts }}
  {{- end }}
  {{- if ne (default 0 $proxy.HopInterval) 0 }}
  hop-interval: {{ $proxy.HopInterval }}
  {{- end }}
  {{- if ne (default "" (printf "%v" $proxy.UpMbps)) "" }}
  up: "{{ $proxy.UpMbps }} Mbps"
  {{- end }}
  {{- if ne (default "" (printf "%v" $proxy.DownMbps)) "" }}
  down: "{{ $proxy.DownMbps }} Mbps"
  {{- end }}
{{- else if eq $proxy.Type "tuic" }}
- name: {{ $proxy.Name | quote }}
  type: tuic
  server: {{ $server }}
  port: {{ $proxy.Port }}
  uuid: {{ default "" $proxy.ServerKey }}
  password: {{ $password }}
  udp: true
  tfo: true
  {{- if ne (default "" $proxy.SNI) "" }}
  sni: {{ $proxy.SNI }}
  {{- end }}
  {{- if $proxy.AllowInsecure }}
  skip-cert-verify: true
  {{- end }}
  {{- if $proxy.DisableSNI }}
  disable-sni: true
  {{- end }}
  {{- if $proxy.ReduceRtt }}
  reduce-rtt: true
  {{- end }}
  {{- if ne (default "" $proxy.UDPRelayMode) "" }}
  udp-relay-mode: {{ $proxy.UDPRelayMode }}
  {{- end }}
  {{- if ne (default "" $proxy.CongestionController) "" }}
  congestion-controller: {{ $proxy.CongestionController }}
  {{- end }}
{{- else if eq $proxy.Type "wireguard" }}
- name: {{ $proxy.Name | quote }}
  type: wireguard
  server: {{ $server }}
  port: {{ $proxy.Port }}
  private-key: {{ default "" $proxy.ServerKey }}
  public-key: {{ default "" $proxy.RealityPublicKey }}
  udp: true
  tfo: true
  {{- if ne (default "" $proxy.Path) "" }}
  preshared-key: {{ $proxy.Path }}
  {{- end }}
  {{- if ne (default "" $proxy.RealityServerAddr) "" }}
  ip: {{ $proxy.RealityServerAddr }}
  {{- end }}
  {{- if ne (default 0 $proxy.RealityServerPort) 0 }}
  ipv6: {{ $proxy.RealityServerPort }}
  {{- end }}
{{- else if eq $proxy.Type "anytls" }}
- name: {{ $proxy.Name | quote }}
  type: anytls
  server: {{ $server }}
  port: {{ $proxy.Port }}
  password: {{ $password }}
  udp: true
  tfo: true
  {{- if ne (default "" $proxy.SNI) "" }}
  sni: {{ $proxy.SNI }}
  {{- end }}
  {{- if $proxy.AllowInsecure }}
  skip-cert-verify: true
  {{- end }}
  {{- if ne (default "" $proxy.Fingerprint) "" }}
  client-fingerprint: {{ $proxy.Fingerprint }}
  {{- end }}
{{- else }}
- name: {{ $proxy.Name | quote }}
  type: {{ $proxy.Type }}
  server: {{ $server }}
  port: {{ $proxy.Port }}
  udp: true
  tfo: true
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
  - { name: 🌏 Auto, type: url-test, proxies: [{{ $proxyNames }}] }

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