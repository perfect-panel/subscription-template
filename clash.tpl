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

{{- $supportSet := dict "shadowsocks" true "vmess" true "vless" true "trojan" true "hysteria2" true "hysteria" true "tuic" true "anytls" true "wireguard" true -}}
{{- $supportedProxies := list -}}
{{- range $proxy := $sorted -}}
  {{- if hasKey $supportSet $proxy.Type -}}
    {{- $supportedProxies = append $supportedProxies $proxy -}}
  {{- end -}}
{{- end -}}
{{- /* End: Official Data Processing Logic */ -}}


# {{ .SiteName }}-{{ .SubscribeName }}
# Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $ExpiredAt }}
port: 8888
socks-port: 8889
mixed-port: 8899
allow-lan: true
mode: Rule
log-level: info
external-controller: '127.0.0.1:6170'
secret: {{ .SiteName }}
experimental:
    ignore-resolve-fail: true
cfw-latency-url: 'http://cp.cloudflare.com/generate_204'
cfw-latency-timeout: 3000
cfw-latency-type: 1
cfw-conn-break-strategy: true
clash-for-android:
    ui-subtitle-pattern: ''
url-rewrite:
    - '^https?:\/\/(www.)?(g|google)\.cn https://www.google.com 302'
    - '^https?:\/\/(ditu|maps).google\.cn https://maps.google.com 302'

# This anchor contains the dynamically generated list of proxies from your subscription.
proxies-list: &A
  proxies:
    {{- range $proxy := $supportedProxies }}
    - {{ $proxy.Name | quote }}
    {{- end }}

# This anchor is a template for creating select groups with all your proxies.
group-template: &All
  type: select
  <<: *A

# Anchor for proxy groups that should prioritize proxies over DIRECT.
proxy_groups: &proxy_groups
    type: select
    proxies:
      - 总模式
      - ⛔️ 拒绝连接
      - 延迟最低
      - 故障转移
      - 负载均衡
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 美国节点
      - 其它地区
      - 🇨🇳 大陆

# Anchor for proxy groups that should prioritize DIRECT (for CN services).
CNproxy_groups: &CNproxy_groups
    type: select
    proxies:
      - 🇨🇳 大陆
      - ⛔️ 拒绝连接
      - 总模式
      - 延迟最低
      - 故障转移
      - 负载均衡
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 美国节点
      - 其它地区

proxies:
  # Static Proxies for rules
  - {name: 🇨🇳 大陆, type: direct, udp: true}
  - {name: ⛔️ 拒绝连接, type: reject}
  - {name: 🌐 DNS_Hijack, type: dns}

  # Dynamic Proxies from Subscription - USING OFFICIAL PPANEL LOGIC
{{- range $proxy := $supportedProxies }}
  {{- $common := "udp: true, tfo: true" -}}

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
  - { name: {{ $proxy.Name | quote }}, type: vmess, server: {{ $server }}, port: {{ $proxy.Port }}, uuid: {{ $password }}, alterId: 0, cipher: auto, {{ $common }}{{- if or (eq $proxy.Transport "websocket") (eq $proxy.Transport "ws") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path | quote }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName | quote }} }{{- end }}{{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") }}, tls: true{{- end }}{{- if ne (default "" $proxy.SNI) "" }}, servername: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, fingerprint: {{ $proxy.Fingerprint }}{{- end }} }
  {{- else if eq $proxy.Type "vless" }}
  - { name: {{ $proxy.Name | quote }}, type: vless, server: {{ $server }}, port: {{ $proxy.Port }}, uuid: {{ $password }}, {{ $common }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path | quote }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "httpupgrade" }}, network: httpupgrade, httpupgrade-opts: { path: {{ default "/" $proxy.Path | quote }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName | quote }} }{{- end }}{{- if ne (default "" $proxy.SNI) "" }}, servername: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, client-fingerprint: {{ $proxy.Fingerprint }}{{- end }}{{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") }}, tls: true, reality-opts: { public-key: {{ $proxy.RealityPublicKey }}{{- if ne (default "" $proxy.RealityShortId) "" }}, short-id: {{ $proxy.RealityShortId }}{{- end }} }{{- end }}{{- if ne (default "" $proxy.Flow) "none" }}, flow: {{ $proxy.Flow }}{{- end }} }
  {{- else if eq $proxy.Type "trojan" }}
  - { name: {{ $proxy.Name | quote }}, type: trojan, server: {{ $server }}, port: {{ $proxy.Port }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, fingerprint: {{ $proxy.Fingerprint }}{{- end }}{{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") }}, reality-opts: { public-key: {{ $proxy.RealityPublicKey }}{{- if ne (default "" $proxy.RealityShortId) "" }}, short-id: {{ $proxy.RealityShortId }}{{- end }} }{{- end }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path | quote }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName | quote }} }{{- end }} }
  {{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hysteria") }}
  - { name: {{ $proxy.Name | quote }}, type: hysteria2, server: {{ $server }}, port: {{ $proxy.Port }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.ObfsPassword) "" }}, obfs: salamander, obfs-password: {{ $proxy.ObfsPassword }}{{- end }}{{- if ne (default "" $proxy.HopPorts) "" }}, ports: {{ $proxy.HopPorts }}{{- end }}{{- if ne (default 0 $proxy.HopInterval) 0 }}, hop-interval: {{ $proxy.HopInterval }}{{- end }} }
  {{- else if eq $proxy.Type "tuic" }}
  - { name: {{ $proxy.Name | quote }}, type: tuic, server: {{ $server }}, port: {{ $proxy.Port }}, uuid: {{ default "" $proxy.ServerKey }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify: true{{- end }}{{- if $proxy.DisableSNI }}, disable-sni: true{{- end }}{{- if $proxy.ReduceRtt }}, reduce-rtt: true{{- end }}{{- if ne (default "" $proxy.UDPRelayMode) "" }}, udp-relay-mode: {{ $proxy.UDPRelayMode }}{{- end }}{{- if ne (default "" $proxy.CongestionController) "" }}, congestion-controller: {{ $proxy.CongestionController }}{{- end }} }
  {{- else if eq $proxy.Type "wireguard" }}
  - { name: {{ $proxy.Name | quote }}, type: wireguard, server: {{ $server }}, port: {{ $proxy.Port }}, private-key: {{ default "" $proxy.ServerKey }}, public-key: {{ default "" $proxy.RealityPublicKey }}, {{ $common }}{{- if ne (default "" $proxy.Path) "" }}, preshared-key: {{ $proxy.Path }}{{- end }}{{- if ne (default "" $proxy.RealityServerAddr) "" }}, ip: {{ $proxy.RealityServerAddr }}{{- end }}{{- if ne (default 0 $proxy.RealityServerPort) 0 }}, ipv6: {{ $proxy.RealityServerPort }}{{- end }} }
  {{- else if eq $proxy.Type "anytls" }}
  - { name: {{ $proxy.Name | quote }}, type: anytls, server: {{ $server }}, port: {{ $proxy.Port }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, fingerprint: {{ $proxy.Fingerprint }}{{- end }} }
  {{- else }}
  - { name: {{ $proxy.Name | quote }}, type: {{ $proxy.Type }}, server: {{ $server }}, port: {{ $proxy.Port }}, {{ $common }} }
  {{- end }}
{{- end }}

proxy-groups:
  - name: 总模式
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/All.svg"
    type: select
    proxies:
      - 延迟最低
      - 故障转移
      - 负载均衡
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 美国节点
      - 其它地区
      - 🇨🇳 大陆

  - name: 订阅更新
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Update.svg"
    type: select
    proxies:
      - 🇨🇳 大陆
      - 总模式

  - name: 小红书
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/XiaoHongShu.svg"
    <<: *CNproxy_groups

  - name: 抖音
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/DouYin.svg"
    <<: *CNproxy_groups

  - name: BiliBili
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/BiliBili.svg"
    <<: *CNproxy_groups

  - name: Steam
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Steam.svg"
    <<: *CNproxy_groups

  - name: Apple
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Apple.svg"
    <<: *CNproxy_groups

  - name: Microsoft
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Microsoft.svg"
    <<: *CNproxy_groups

  - name: Telegram
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Telegram.svg"
    <<: *proxy_groups

  - name: Discord
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Discord.svg"
    <<: *proxy_groups

  - name: Spotify
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Spotify.svg"
    <<: *proxy_groups

  - name: TikTok
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/TikTok.svg"
    <<: *proxy_groups

  - name: YouTube
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/YouTube.svg"
    <<: *proxy_groups

  - name: Netflix
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Netflix.svg"
    <<: *proxy_groups

  - name: Google
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Google.svg"
    <<: *proxy_groups

  - name: GoogleFCM
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/GoogleFCM.svg"
    <<: *proxy_groups

  - name: Facebook
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Facebook.svg"
    <<: *proxy_groups

  - name: OpenAI
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/OpenAI.svg"
    <<: *proxy_groups

  - name: GitHub
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/GitHub.svg"
    <<: *proxy_groups

  - name: Twitter
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Twitter.svg"
    <<: *proxy_groups

  - name: DNS连接
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/DNS.svg"
    <<: *proxy_groups

  - name: 漏网之鱼
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/HBASE-copy.svg"
    <<: *proxy_groups

  - name: 广告拦截
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/No-ads-all.svg"
    type: select
    proxies:
      - ⛔️ 拒绝连接
      - 🌐 DNS_Hijack

  - name: WebRTC
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/WebRTC.svg"
    type: select
    proxies:
      - ⛔️ 拒绝连接
      - 🌐 DNS_Hijack

  - name: 白名单出站
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/User.svg"
    <<: *CNproxy_groups

  - name: 延迟最低
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Return.svg"
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 300
    <<: *A

  - name: 故障转移
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Return.svg"
    type: fallback
    url: https://www.gstatic.com/generate_204
    interval: 300
    <<: *A

  - name: 负载均衡
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Return.svg"
    type: load-balance
    strategy: round-robin
    url: https://www.gstatic.com/generate_204
    interval: 300
    <<: *A

  - name: 台湾节点
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/CN.svg"
    filter: "^(?=.*(台|新北|彰化|TW|Taiwan)).*$"
    <<: *All

  - name: 香港节点
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/HK.svg"
    filter: "^(?=.*(港|HK|hk|Hong Kong|HongKong|hongkong)).*$"
    <<: *All

  - name: 日本节点
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/JP.svg"
    filter: "^(?=.*(日本|川日|东京|大阪|泉日|埼玉|沪日|深日|[^-]日|JP|Japan)).*$"
    <<: *All

  - name: 美国节点
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/US.svg"
    filter: "^(?=.*(美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|US|United States)).*$"
    <<: *All

  - name: 狮城节点
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Singapore.svg"
    filter: "^(?=.*(新加坡|坡|狮城|SG|Singapore)).*$"
    <<: *All

  - name: 其它地区
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Globe.svg"
    filter: "^(?!.*(港|HK|hk|Hong Kong|HongKong|hongkong|日本|川日|东京|大阪|泉日|埼玉|沪日|深日|[^-]日|JP|Japan|美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|US|United States|台|新北|彰化|TW|Taiwan|新加坡|坡|狮城|SG|Singapore|灾|网易|Netease|套餐|重置|剩余|到期|订阅|群|账户|流量|有效期|时间|官网)).*$"
    <<: *All

rule-anchor:
  Local: &Local
    {type: file, behavior: classical, format: text}
  Classical: &Classical
    {type: http, behavior: classical, format: text, interval: 86400}
  IPCIDR: &IPCIDR
    {type: http, behavior: ipcidr, format: mrs, interval: 86400}
  Domain: &Domain
    {type: http, behavior: domain, format: mrs, interval: 86400}

rule-providers:
  自定义出站:
    <<: *Local
    path: ./etc/自定义规则.list

  WebRTC_端/域:
    <<: *Classical
    path: ./rules/WebRTC.list
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/rules/WebRTC.list"

  CN_IP:
    <<: *IPCIDR
    path: ./rules/CN_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.mrs"
  CN_域:
    <<: *Domain
    path: ./rules/CN_域.mrs
    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/cn.mrs"

  No-ads-all_域:
    <<: *Domain
    path: ./rules/No-ads-all.mrs
    url: "https://anti-ad.net/mihomo.mrs"

  XiaoHongShu_域:
    <<: *Domain
    path: ./rules/XiaoHongShu.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/XiaoHongShu/XiaoHongShu_OCD_Domain.mrs"

  DouYin_域:
    <<: *Domain
    path: ./rules/DouYin.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/DouYin/DouYin_OCD_Domain.mrs"

  BiliBili_域:
    <<: *Domain
    path: ./rules/BiliBili.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/BiliBili/BiliBili_OCD_Domain.mrs"
  BiliBili_IP:
    <<: *IPCIDR
    path: ./rules/BiliBili_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/BiliBili/BiliBili_OCD_IP.mrs"

  Steam_域:
    <<: *Domain
    path: ./rules/Steam.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Steam/Steam_OCD_Domain.mrs"

  TikTok_域:
    <<: *Domain
    path: ./rules/TikTok.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/TikTok/TikTok_OCD_Domain.mrs"

  Spotify_域:
    <<: *Domain
    path: ./rules/Spotify.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Spotify/Spotify_OCD_Domain.mrs"
  Spotify_IP:
    <<: *IPCIDR
    path: ./rules/Spotify_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Spotify/Spotify_OCD_IP.mrs"

  Facebook_域:
    <<: *Domain
    path: ./rules/Facebook.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Facebook/Facebook_OCD_Domain.mrs"
  Facebook_IP:
    <<: *IPCIDR
    path: ./rules/Facebook_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Facebook/Facebook_OCD_IP.mrs"

  Telegram_域:
    <<: *Domain
    path: ./rules/Telegram.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Telegram/Telegram_OCD_Domain.mrs"
  Telegram_IP:
    <<: *IPCIDR
    path: ./rules/Telegram_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Telegram/Telegram_OCD_IP.mrs"

  YouTube_域:
    <<: *Domain
    path: ./rules/YouTube.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/YouTube/YouTube_OCD_Domain.mrs"
  YouTube_IP:
    <<: *IPCIDR
    path: ./rules/YouTube_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/YouTube/YouTube_OCD_IP.mrs"

  Google_域:
    <<: *Domain
    path: ./rules/Google.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Google/Google_OCD_Domain.mrs"
  Google_IP:
    <<: *IPCIDR
    path: ./rules/Google_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Google/Google_OCD_IP.mrs"

  GoogleFCM_域:
    <<: *Domain
    path: ./rules/GoogleFCM.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/GoogleFCM/GoogleFCM_OCD_Domain.mrs"
  GoogleFCM_IP:
    <<: *IPCIDR
    path: ./rules/GoogleFCM_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/GoogleFCM/GoogleFCM_OCD_IP.mrs"

  Microsoft_域:
    <<: *Domain
    path: ./rules/Microsoft.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Microsoft/Microsoft_OCD_Domain.mrs"

  Apple_域:
    <<: *Domain
    path: ./rules/Apple.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Apple/Apple_OCD_Domain.mrs"
  Apple_IP:
    <<: *IPCIDR
    path: ./rules/Apple_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Apple/Apple_OCD_IP.mrs"

  OpenAI_域:
    <<: *Domain
    path: ./rules/OpenAI.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/OpenAI/OpenAI_OCD_Domain.mrs"
  OpenAI_IP:
    <<: *IPCIDR
    path: ./rules/OpenAI_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/OpenAI/OpenAI_OCD_IP.mrs"

  Netflix_域:
    <<: *Domain
    path: ./rules/Netflix.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Netflix/Netflix_OCD_Domain.mrs"
  Netflix_IP:
    <<: *IPCIDR
    path: ./rules/Netflix_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Netflix/Netflix_OCD_IP.mrs"

  Discord_域:
    <<: *Domain
    path: ./rules/Discord.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Discord/Discord_OCD_Domain.mrs"

  GitHub_域:
    <<: *Domain
    path: ./rules/GitHub.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/GitHub/GitHub_OCD_Domain.mrs"

  Twitter_域:
    <<: *Domain
    path: ./rules/Twitter.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Twitter/Twitter_OCD_Domain.mrs"
  Twitter_IP:
    <<: *IPCIDR
    path: ./rules/Twitter_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Twitter/Twitter_OCD_IP.mrs"

  Private_域:
    <<: *Domain
    path: ./rules/LAN.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Lan/Lan_OCD_Domain.mrs"
  Private_IP:
    <<: *IPCIDR
    path: ./rules/Private_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Lan/Lan_OCD_IP.mrs"

rules:
  - DST-PORT,53,🌐 DNS_Hijack
  - DST-PORT,853,DNS连接

  - RULE-SET,自定义出站,白名单出站

  - RULE-SET,WebRTC_端/域,WebRTC
  - RULE-SET,No-ads-all_域,广告拦截

  - PROCESS-PATH,com.ss.android.ugc.aweme,抖音
  - RULE-SET,DouYin_域,抖音

  - PROCESS-PATH,com.xingin.xhs,小红书
  - RULE-SET,XiaoHongShu_域,小红书

  - PROCESS-PATH,tv.danmaku.bili,BiliBili
  - RULE-SET,BiliBili_域,BiliBili
  - RULE-SET,BiliBili_IP,BiliBili

  - RULE-SET,Steam_域,Steam

  - RULE-SET,GitHub_域,GitHub

  - RULE-SET,Discord_域,Discord

  - RULE-SET,TikTok_域,TikTok

  - RULE-SET,Twitter_域,Twitter
  - RULE-SET,Twitter_IP,Twitter

  - RULE-SET,YouTube_域,YouTube
  - RULE-SET,YouTube_IP,YouTube

  - DOMAIN-KEYWORD,mtalk.google,GoogleFCM

  - RULE-SET,Google_域,Google
  - RULE-SET,Google_IP,Google

  - RULE-SET,Netflix_域,Netflix
  - RULE-SET,Netflix_IP,Netflix

  - RULE-SET,Spotify_域,Spotify
  - RULE-SET,Spotify_IP,Spotify

  - RULE-SET,Facebook_域,Facebook
  - RULE-SET,Facebook_IP,Facebook

  - RULE-SET,OpenAI_域,OpenAI
  - RULE-SET,OpenAI_IP,OpenAI

  - RULE-SET,Apple_域,Apple
  - RULE-SET,Apple_IP,Apple

  - RULE-SET,Microsoft_域,Microsoft

  - RULE-SET,Telegram_域,Telegram
  - RULE-SET,Telegram_IP,Telegram

  - DOMAIN,browserleaks.com,漏网之鱼

  - RULE-SET,CN_域,🇨🇳 大陆
  - RULE-SET,CN_IP,🇨🇳 大陆
  - RULE-SET,Private_域,🇨🇳 大陆
  - RULE-SET,Private_IP,🇨🇳 大陆

  - MATCH,漏网之鱼
