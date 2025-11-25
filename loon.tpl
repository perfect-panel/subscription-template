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

[General]
ip-mode = v4-only
dns-server = system, 223.5.5.5
doh-server = https://dns.alidns.com/dns-query
allow-wifi-access = true
wifi-access-http-port = 6088
wifi-access-socks5-port = 6089
proxy-test-url = http://www.gstatic.com/generate_204
internet-test-url = http://connectivitycheck.platform.hicloud.com/generate_204
test-timeout = 5
interface-mode = auto
bypass-tun = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 127.0.0.0/8, localhost, *.local
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 127.0.0.0/8, localhost, *.local
real-ip = *.lan, lens.l.google.com, *.srv.nintendo.net, *.stun.playstation.net, *.xboxlive.com, xbox.*.*.microsoft.com, *.msftncsi.com, *.msftconnecttest.com
hijack-dns = 8.8.8.8:53, 1.1.1.1:53

[Proxy]
{{- range $proxy := $supportedProxies }}
  {{- $common := "udp=true,fast-open=true" -}}

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
{{ $proxy.Name }} = Shadowsocks,{{ $server }},{{ $proxy.Port }},{{ $proxy.Method }},{{ $password }}{{- if $proxy.Transport }},obfs={{ $proxy.Transport }},obfs-host={{ $proxy.SNI }}{{ end }},{{ $common }}
{{- else if eq $proxy.Type "vmess" }}
{{ $proxy.Name }} = vmess,{{ $server }},{{ $proxy.Port }},{{ $password }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }},transport=ws{{- if $proxy.Path }},path={{ $proxy.Path }}{{ end }}{{- if $proxy.Host }},host={{ $proxy.Host }}{{ end }}{{- else if eq $proxy.Transport "grpc" }},transport=grpc,servicename={{ $proxy.ServiceName | default "grpc" }}{{ end }}{{- if or $proxy.SNI $proxy.Fingerprint $proxy.AllowInsecure }},over-tls=true{{ end }}{{- if $proxy.SNI }},tls-name={{ $proxy.SNI }}{{ end }}{{- if $proxy.AllowInsecure }},skip-cert-verify={{ $proxy.AllowInsecure }}{{ end }}{{- if $proxy.Fingerprint }},tls-fingerprint={{ $proxy.Fingerprint }}{{ end }},{{ $common }}
{{- else if eq $proxy.Type "vless" }}
{{ $proxy.Name }} = VLESS,{{ $server }},{{ $proxy.Port }},{{ $password }}{{- if $proxy.Flow }},flow={{ $proxy.Flow }}{{ end }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }},transport=ws{{- if $proxy.Path }},path={{ $proxy.Path }}{{ end }}{{- if $proxy.Host }},host={{ $proxy.Host }}{{ end }}{{- else if eq $proxy.Transport "grpc" }},transport=grpc,servicename={{ $proxy.ServiceName | default "grpc" }}{{ end }}{{- if $proxy.SNI }},tls-name={{ $proxy.SNI }}{{ end }}{{- if $proxy.AllowInsecure }},skip-cert-verify={{ $proxy.AllowInsecure }}{{ end }}{{- if $proxy.RealityPublicKey }},reality-public-key={{ $proxy.RealityPublicKey }}{{- if $proxy.RealityShortId }},reality-short-id={{ $proxy.RealityShortId }}{{ end }}{{ end }},{{ $common }}
{{- else if eq $proxy.Type "trojan" }}
{{ $proxy.Name }} = trojan,{{ $server }},{{ $proxy.Port }},{{ $password }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }},transport=ws{{- if $proxy.Path }},path={{ $proxy.Path }}{{ end }}{{- if $proxy.Host }},host={{ $proxy.Host }}{{ end }}{{- else if eq $proxy.Transport "grpc" }},transport=grpc,servicename={{ $proxy.ServiceName | default "grpc" }}{{ end }}{{- if $proxy.SNI }},tls-name={{ $proxy.SNI }}{{ end }}{{- if $proxy.AllowInsecure }},skip-cert-verify={{ $proxy.AllowInsecure }}{{ end }}{{- if $proxy.Fingerprint }},tls-fingerprint={{ $proxy.Fingerprint }}{{ end }},{{ $common }}
{{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hysteria") }}
{{ $proxy.Name }} = Hysteria2,{{ $proxy.Server }},{{ $proxy.Port }},{{ $.UserInfo.Password }}{{- if $proxy.SNI }},sni={{ $proxy.SNI }}{{ end }}{{- if $proxy.AllowInsecure }},skip-cert-verify={{ $proxy.AllowInsecure }}{{ end }}{{- if $proxy.ObfsPassword }},obfs=salamander,obfs-password={{ $proxy.ObfsPassword }}{{ end }}{{- if $proxy.HopPorts }},port-hopping={{ $proxy.HopPorts }}{{ end }}{{- if $proxy.HopInterval }},hop-interval={{ $proxy.HopInterval }}{{ end }}
{{- else if eq $proxy.Type "tuic" }}
{{ $proxy.Name }} = TUIC,{{ $proxy.Server }},{{ $proxy.Port }},{{ $proxy.ServerKey }},{{ $.UserInfo.Password }}{{- if $proxy.SNI }},sni={{ $proxy.SNI }}{{ end }}{{- if $proxy.AllowInsecure }},skip-cert-verify={{ $proxy.AllowInsecure }}{{ end }}{{- if $proxy.DisableSNI }},disable-sni={{ $proxy.DisableSNI }}{{ end }}{{- if $proxy.ReduceRtt }},reduce-rtt={{ $proxy.ReduceRtt }}{{ end }}{{- if $proxy.UDPRelayMode }},udp-relay-mode={{ $proxy.UDPRelayMode }}{{ end }}{{- if $proxy.CongestionController }},congestion-control={{ $proxy.CongestionController }}{{ end }}
{{- else if eq $proxy.Type "wireguard" }}
{{ $proxy.Name }} = WireGuard,interface-ip={{ $proxy.RealityServerAddr | default "10.0.0.2" }},interface-ipv6={{ $proxy.RealityServerPort | default "::" }},private-key={{ $proxy.ServerKey }},mtu=1280,dns=8.8.8.8,keepalive=25,peers=[{public-key={{ $proxy.RealityPublicKey }},allowed-ips="0.0.0.0/0,::/0",endpoint={{ $proxy.Host }}:{{ $proxy.Port }}{{- if $proxy.Path }},preshared-key={{ $proxy.Path }}{{ end }}}]
{{- else if eq $proxy.Type "anytls" }}
{{ $proxy.Name }} = anytls,{{ $proxy.Server }},{{ $proxy.Port }},{{ $.UserInfo.Password }}{{- if $proxy.SNI }},sni={{ $proxy.SNI }}{{ end }}{{- if $proxy.AllowInsecure }},skip-cert-verify={{ $proxy.AllowInsecure }}{{ end }}
{{- end }}
{{- end }}

[Remote Filter]
🇺🇳 Nodes = NameRegex, FilterKey = ".*"

[Proxy Group]
🚀 Proxy = select, 🌏 Auto, 🎯 Direct, 🇺🇳 Nodes
🍎 Apple = select, 🚀 Proxy, 🎯 Direct, 🇺🇳 Nodes
🔍 Google = select, 🚀 Proxy, 🎯 Direct, 🇺🇳 Nodes
🪟 Microsoft = select, 🚀 Proxy, 🎯 Direct, 🇺🇳 Nodes
📺 GlobalMedia = select, 🚀 Proxy, 🎯 Direct, 🇺🇳 Nodes
🤖 AI = select, 🚀 Proxy, 🎯 Direct, 🇺🇳 Nodes
🪙 Crypto = select, 🚀 Proxy, 🎯 Direct, 🇺🇳 Nodes
🎮 Game = select, 🚀 Proxy, 🎯 Direct, 🇺🇳 Nodes
📟 Telegram = select, 🚀 Proxy, 🎯 Direct, 🇺🇳 Nodes
🇨🇳 China = select, 🎯 Direct, 🚀 Proxy, 🇺🇳 Nodes
🐠 Final = select, 🚀 Proxy, 🎯 Direct, 🇺🇳 Nodes
🌏 Auto = url-test, 🇺🇳 Nodes
🎯 Direct = select, DIRECT

[Rewrite]
^https?:\/\/(www.)?g\.cn 302 https://www.google.com
^https?:\/\/(www.)?google\.cn 302 https://www.google.com

[Remote Rule]
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Apple/Apple.list, policy = 🍎 Apple, tag = Apple, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Google/Google.list, policy = 🔍 Google, tag = Google, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/GitHub/GitHub.list, policy = 🪟 Microsoft, tag = GitHub, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Microsoft/Microsoft.list, policy = 🪟 Microsoft, tag = Microsoft, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/HBO/HBO.list, policy = 📺 GlobalMedia, tag = HBO, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Disney/Disney.list, policy = 📺 GlobalMedia, tag = Disney, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/TikTok/TikTok.list, policy = 📺 GlobalMedia, tag = TikTok, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Netflix/Netflix.list, policy = 📺 GlobalMedia, tag = Netflix, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/GlobalMedia/GlobalMedia.list, policy = 📺 GlobalMedia, tag = GlobalMedia, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/GlobalMedia/GlobalMedia_Domain.list, policy = 📺 GlobalMedia, tag = GlobalMedia, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Telegram/Telegram.list, policy = 📟 Telegram, tag = Telegram, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/OpenAI/OpenAI.list, policy = 🤖 AI, tag = OpenAI, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Gemini/Gemini.list, policy = 🤖 AI, tag = Gemini, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Copilot/Copilot.list, policy = 🤖 AI, tag = Copilot, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Claude/Claude.list, policy = 🤖 AI, tag = Claude, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Crypto/Crypto.list, policy = 🪙 Crypto, tag = Crypto, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Cryptocurrency/Cryptocurrency.list, policy = 🪙 Crypto, tag = Cryptocurrency, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Game/Game.list, policy = 🎮 Game, tag = Game, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Global/Global.list, policy = 🚀 Proxy, tag = Global, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Global/Global_Domain.list, policy = 🚀 Proxy, tag = Global, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/ChinaMax/ChinaMax.list, policy = 🇨🇳 China, tag = ChinaMax, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/ChinaMax/ChinaMax_Domain.list, policy = 🇨🇳 China, tag = ChinaMax, enabled = true
https://cdn.jsdmirror.com/gh/perfect-panel/rules/rule/Loon/Lan/Lan.list, policy = 🎯 Direct, tag = Lan, enabled = true

[Rule]
GEOIP, CN, 🇨🇳 China
FINAL, 🐠 Final
