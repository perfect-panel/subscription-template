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

{{- $supportedProxies := list -}}
{{- range $proxy := .Proxies -}}
  {{- if or (eq $proxy.Type "shadowsocks") (eq $proxy.Type "vmess") (eq $proxy.Type "trojan") (eq $proxy.Type "hysteria2") (eq $proxy.Type "tuic") -}}
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

#!MANAGED-CONFIG {{ .UserInfo.SubscribeURL }} interval=86400

[General]
loglevel = notify
external-controller-access = perlnk@0.0.0.0:6170
exclude-simple-hostnames = true
show-error-page-for-reject = true
udp-priority = true
udp-policy-not-supported-behaviour = reject
ipv6 = true
ipv6-vif = auto
proxy-test-url = http://www.gstatic.com/generate_204
internet-test-url = http://connectivitycheck.platform.hicloud.com/generate_204
test-timeout = 5
dns-server = system, 119.29.29.29, 223.5.5.5
encrypted-dns-server = https://dns.alidns.com/dns-query
hijack-dns = 8.8.8.8:53, 8.8.4.4:53, 1.1.1.1:53, 1.0.0.1:53
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 127.0.0.0/8, localhost, *.local
always-real-ip = *.lan, lens.l.google.com, *.srv.nintendo.net, *.stun.playstation.net, *.xboxlive.com, xbox.*.*.microsoft.com, *.msftncsi.com, *.msftconnecttest.com

# > Surge Mac Parameters
http-listen = 0.0.0.0:6088
socks5-listen = 0.0.0.0:6089

# > Surge iOS Parameters
allow-wifi-access = true
allow-hotspot-access = true
wifi-access-http-port = 6088
wifi-access-socks5-port = 6089

[Panel]
SubscribeInfo = title={{ .SiteName }} - {{ .SubscribeName }}, content=官方网站: perlnk.com \n已用流量: {{ $used }} GiB/{{ $total }} GiB \n到期时间: {{ $exp }}, style=info

[Proxy]
{{- range $proxy := $supportedProxies }}
  {{- $server := $proxy.Server -}}
  {{- if and (contains ":" $proxy.Server) (not (hasPrefix "[" $proxy.Server)) -}}
    {{- $server = printf "[%s]" $proxy.Server -}}
  {{- end -}}

  {{- $sni := default "" $proxy.SNI -}}
  {{- if eq $sni "" -}}
    {{- $sni = default "" $proxy.Host -}}
  {{- end -}}
  {{- if and (eq $sni "") (not (or (regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$" $proxy.Server) (contains $proxy.Server ":"))) -}}
    {{- $sni = $proxy.Server -}}
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

  {{- $common := "udp-relay=true, tfo=true" -}}

  {{- if eq $proxy.Type "shadowsocks" }}
{{ $proxy.Name }} = ss, {{ $server }}, {{ $proxy.Port }}, encrypt-method={{ default "aes-128-gcm" $proxy.Method }}, password={{ $password }}{{- if ne (default "" $proxy.Transport) "" }}, obfs={{ $proxy.Transport }}, obfs-host={{ $sni }}{{- end }}, {{ $common }}
  {{- else if eq $proxy.Type "vmess" }}
{{ $proxy.Name }} = vmess, {{ $server }}, {{ $proxy.Port }}, username={{ $password }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, ws=true{{- if ne (default "" $proxy.Path) "" }}, ws-path={{ $proxy.Path }}{{- end }}{{- if ne (default "" $proxy.Host) "" }}, ws-headers="Host:{{ $proxy.Host }}"{{- end }}{{- else if eq $proxy.Transport "grpc" }}, grpc=true{{- if ne (default "" $proxy.ServiceName) "" }}, grpc-service-name={{ $proxy.ServiceName }}{{- end }}{{- end }}{{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") }}, tls=true{{- end }}{{- if ne $sni "" }}, sni={{ $sni }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify=true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, fingerprint={{ $proxy.Fingerprint }}{{- end }}, {{ $common }}
  {{- else if eq $proxy.Type "vless" }}
{{ $proxy.Name }} = vless, {{ $server }}, {{ $proxy.Port }}, username={{ $password }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, ws=true{{- if ne (default "" $proxy.Path) "" }}, ws-path={{ $proxy.Path }}{{- end }}{{- if ne (default "" $proxy.Host) "" }}, ws-headers="Host:{{ $proxy.Host }}"{{- end }}{{- else if eq $proxy.Transport "grpc" }}, grpc=true{{- if ne (default "" $proxy.ServiceName) "" }}, grpc-service-name={{ $proxy.ServiceName }}{{- end }}{{- end }}{{- if ne $sni "" }}, sni={{ $sni }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify=true{{- end }}{{- if ne (default "" $proxy.Flow) "" }}, flow={{ $proxy.Flow }}{{- end }}, {{ $common }}
  {{- else if eq $proxy.Type "trojan" }}
{{ $proxy.Name }} = trojan, {{ $server }}, {{ $proxy.Port }}, password={{ $password }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, ws=true{{- if ne (default "" $proxy.Path) "" }}, ws-path={{ $proxy.Path }}{{- end }}{{- if ne (default "" $proxy.Host) "" }}, ws-headers="Host:{{ $proxy.Host }}"{{- end }}{{- else if eq $proxy.Transport "grpc" }}, grpc=true{{- if ne (default "" $proxy.ServiceName) "" }}, grpc-service-name={{ $proxy.ServiceName }}{{- end }}{{- end }}{{- if ne $sni "" }}, sni={{ $sni }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify=true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, fingerprint={{ $proxy.Fingerprint }}{{- end }}, {{ $common }}
  {{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hy2") }}
{{ $proxy.Name }} = hysteria2, {{ $server }}, {{ $proxy.Port }}, password={{ $password }}{{- if ne $sni "" }}, sni={{ $sni }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify=true{{- end }}{{- if ne (default "" $proxy.ObfsPassword) "" }}, obfs=salamander, obfs-password={{ $proxy.ObfsPassword }}{{- end }}{{- if ne (default "" $proxy.HopPorts) "" }}, ports={{ $proxy.HopPorts }}{{- end }}{{- if ne (default 0 $proxy.HopInterval) 0 }}, hop-interval={{ $proxy.HopInterval }}{{- end }}, {{ $common }}
  {{- else if eq $proxy.Type "tuic" }}
{{ $proxy.Name }} = tuic, {{ $server }}, {{ $proxy.Port }}, uuid={{ default "" $proxy.ServerKey }}, password={{ $password }}{{- if ne $sni "" }}, sni={{ $sni }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify=true{{- end }}{{- if $proxy.DisableSNI }}, disable-sni=true{{- end }}{{- if $proxy.ReduceRtt }}, reduce-rtt=true{{- end }}{{- if ne (default "" $proxy.UDPRelayMode) "" }}, udp-relay-mode={{ $proxy.UDPRelayMode }}{{- end }}{{- if ne (default "" $proxy.CongestionController) "" }}, congestion-controller={{ $proxy.CongestionController }}{{- end }}, {{ $common }}
  {{- else if eq $proxy.Type "wireguard" }}
{{ $proxy.Name }} = wireguard, {{ $server }}, {{ $proxy.Port }}, private-key={{ default "" $proxy.ServerKey }}, public-key={{ default "" $proxy.RealityPublicKey }}{{- if ne (default "" $proxy.Path) "" }}, preshared-key={{ $proxy.Path }}{{- end }}{{- if ne (default "" $proxy.RealityServerAddr) "" }}, ip={{ $proxy.RealityServerAddr }}{{- end }}{{- if ne (default 0 $proxy.RealityServerPort) 0 }}, ipv6={{ $proxy.RealityServerPort }}{{- end }}, {{ $common }}
  {{- else if eq $proxy.Type "anytls" }}
{{ $proxy.Name }} = anytls, {{ $server }}, {{ $proxy.Port }}, password={{ $password }}{{- if ne $sni "" }}, sni={{ $sni }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify=true{{- end }}, {{ $common }}
  {{- else }}
{{ $proxy.Name }} = {{ $proxy.Type }}, {{ $server }}, {{ $proxy.Port }}, {{ $common }}
  {{- end }}
{{- end }}

[Proxy Group]
🚀 Proxy = select, 🌏 Auto, 🎯 Direct, include-other-group=🇺🇳 Nodes
🍎 Apple = select, 🚀 Proxy, 🎯 Direct, include-other-group=🇺🇳 Nodes
🔍 Google = select, 🚀 Proxy, 🎯 Direct, include-other-group=🇺🇳 Nodes
🪟 Microsoft = select, 🚀 Proxy, 🎯 Direct, include-other-group=🇺🇳 Nodes
📺 GlobalMedia = select, 🚀 Proxy, 🎯 Direct, include-other-group=🇺🇳 Nodes
🤖 AI = select, 🚀 Proxy, 🎯 Direct, include-other-group=🇺🇳 Nodes
🪙 Crypto = select, 🚀 Proxy, 🎯 Direct, include-other-group=🇺🇳 Nodes
🎮 Game = select, 🚀 Proxy, 🎯 Direct, include-other-group=🇺🇳 Nodes
📟 Telegram = select, 🚀 Proxy, 🎯 Direct, include-other-group=🇺🇳 Nodes
🇨🇳 China = select, 🎯 Direct, 🚀 Proxy, include-other-group=🇺🇳 Nodes
🐠 Final = select, 🚀 Proxy, 🎯 Direct, include-other-group=🇺🇳 Nodes
🌏 Auto = smart, include-other-group=🇺🇳 Nodes
🎯 Direct = select, DIRECT, hidden=1
🇺🇳 Nodes = select, {{ $proxyNames }}, hidden=1

[Rule]
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Apple/Apple_All.list, 🍎 Apple
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Google/Google.list, 🔍 Google
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/GitHub/GitHub.list, 🪟 Microsoft
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Microsoft/Microsoft.list, 🪟 Microsoft
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/HBO/HBO.list, 📺 GlobalMedia
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Disney/Disney.list, 📺 GlobalMedia
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/TikTok/TikTok.list, 📺 GlobalMedia
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Netflix/Netflix.list, 📺 GlobalMedia
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/GlobalMedia/GlobalMedia_All_No_Resolve.list, 📺 GlobalMedia
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Telegram/Telegram.list, 📟 Telegram
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/OpenAI/OpenAI.list, 🤖 AI
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Gemini/Gemini.list, 🤖 AI
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Copilot/Copilot.list, 🤖 AI
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Claude/Claude.list, 🤖 AI
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Crypto/Crypto.list, 🪙 Crypto
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Cryptocurrency/Cryptocurrency.list, 🪙 Crypto
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Game/Game.list, 🎮 Game
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Global/Global_All_No_Resolve.list, 🚀 Proxy
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/ChinaMax/ChinaMax_All_No_Resolve.list, 🇨🇳 China
RULE-SET, https://cdn.jsdmirror.com/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Lan/Lan.list, 🎯 Direct

GEOIP, CN, 🇨🇳 China
FINAL, 🐠 Final, dns-failed

[URL Rewrite]
^https?:\/\/(www.)?g\.cn https://www.google.com 302
^https?:\/\/(www.)?google\.cn https://www.google.com 302

{{- range $proxy := $supportedProxies }}
  {{- if not (or (eq $proxy.Type "shadowsocks") (eq $proxy.Type "vmess") (eq $proxy.Type "trojan") (eq $proxy.Type "hysteria2") (eq $proxy.Type "tuic")) }}
# Skipped (unsupported by Surge): {{ $proxy.Name }} ({{ $proxy.Type }})
  {{- end }}
{{- end }}