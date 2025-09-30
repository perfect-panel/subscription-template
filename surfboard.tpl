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

{{- $supportSet := dict "shadowsocks" true "vmess" true "trojan" true "http" true "https" true "socks5" true -}}
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

{{- /* 直接在需要的位置后置 ', {{ $proxyNames }}'，proxyNames 为空时不会输出额外内容 */ -}}


# {{ .SiteName }}-{{ .SubscribeName }}
# Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $ExpiredAt }}
# Subscribe URL: {{ .UserInfo.SubscribeURL }}
# Generated at: {{ now | date "2006-01-02 15:04:05" }}

#!MANAGED-CONFIG {{ .UserInfo.SubscribeURL }} interval=86400 strict=true


[General]
# DNS服务器配置
dns-server = 114.114.114.114, 223.5.5.5, 8.8.8.8, 8.8.4.4, 9.9.9.9:9953, system

# DoH服务器配置
doh-server = https://doh.pub/dns-query, https://dns.alidns.com/dns-query, https://9.9.9.9/dns-query

# 跳过代理的地址范围
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 17.0.0.0/8, localhost, *.crashlytics.com, *.local, captive.apple.com, www.baidu.com

# 代理测试URL
proxy-test-url = http://www.gstatic.com/generate_204

# 直连测试URL
internet-test-url = http://www.gstatic.com/generate_204

# 连接测试超时
test-timeout = 30

# 真实IP域名
always-real-ip = *.lan, *.localdomain, *.example, *.invalid, *.localhost, *.test, *.local, *.home.arpa, time.*.com, time.*.gov, time.*.edu.cn, time.*.apple.com, time1.*.com, time2.*.com, time3.*.com, time4.*.com, time5.*.com, time6.*.com, time7.*.com, ntp.*.com, ntp1.*.com, ntp2.*.com, ntp3.*.com, ntp4.*.com, ntp5.*.com, ntp6.*.com, ntp7.*.com, *.time.edu.cn, *.ntp.org.cn, +.pool.ntp.org, time1.cloud.tencent.com, music.163.com, *.music.163.com, *.126.net, musicapi.taihe.com, music.taihe.com, songsearch.kugou.com, trackercdn.kugou.com, *.kuwo.cn, api-jooxtt.sanook.com, api.joox.com, joox.com, y.qq.com, *.y.qq.com, streamoc.music.tc.qq.com, mobileoc.music.tc.qq.com, isure.stream.qqmusic.qq.com, dl.stream.qqmusic.qq.com, aqqmusic.tc.qq.com, amobile.music.tc.qq.com, *.xiami.com, *.music.migu.cn, music.migu.cn, *.msftconnecttest.com, *.msftncsi.com, msftconnecttest.com, msftncsi.com, localhost.ptlogin2.qq.com, localhost.sec.qq.com, +.srv.nintendo.net, +.stun.playstation.net, xbox.*.microsoft.com, *.*.xboxlive.com, +.battlenet.com.cn, +.wotgame.cn, +.wggames.cn, +.wowsgame.cn, +.wargaming.net, proxy.golang.org, stun.*.*, stun.*.*.*, +.stun.*.*, +.stun.*.*.*, +.stun.*.*.*.*, heartbeat.belkin.com, *.linksys.com, *.linksyssmartwifi.com, *.router.asus.com, mesu.apple.com, swscan.apple.com, swquery.apple.com, swdownload.apple.com, swcdn.apple.com, swdist.apple.com, lens.l.google.com, stun.l.google.com, +.nflxvideo.net, *.square-enix.com, *.finalfantasyxiv.com, *.ffxiv.com, *.mcdn.bilivideo.cn

# HTTP代理监听端口
http-listen = 0.0.0.0:1234

# SOCKS5代理监听端口
socks5-listen = 127.0.0.1:1235

# UDP策略
udp-policy-not-supported-behaviour = DIRECT

[Host]
localhost = 127.0.0.1

[Proxy]
# 内置策略
DIRECT = direct
REJECT = reject

{{- range $proxy := $supportedProxies }}
  {{- $common := "udp: true, tfo: true" -}}

  {{- $server := $proxy.Server -}}
  {{- if and (contains $server ":") (not (hasPrefix "[" $server)) -}}
    {{- $server = printf "[%s]" $server -}}
  {{- end -}}

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
    {{- $method := default "aes-128-gcm" $proxy.Method -}}
    {{- if ne (default "" $proxy.Obfs) "" -}}
      {{ $proxy.Name | quote }} = ss, {{ $server }}, {{ $proxy.Port }}, encrypt-method={{ $method }}, password={{ $password }}, obfs={{ $proxy.Obfs }}{{- if ne (default "" $proxy.ObfsHost) "" }}, obfs-host={{ $proxy.ObfsHost }}{{- end }}{{- if ne (default "" $proxy.ObfsPath) "" }}, obfs-uri={{ $proxy.ObfsPath }}{{- end }}, udp-relay=true
    {{- else -}}
      {{ $proxy.Name | quote }} = ss, {{ $server }}, {{ $proxy.Port }}, encrypt-method={{ $method }}, password={{ $password }}, udp-relay=true
    {{- end -}}

  {{- else if eq $proxy.Type "vmess" }}
    {{- $wsPath := default "/" $proxy.Path -}}
    {{- $wsHeaders := "" -}}
    {{- if ne (default "" $proxy.Host) "" -}}
      {{- $wsHeaders = printf ", ws-headers=Host:%s" $proxy.Host -}}
    {{- end -}}
    {{- $tlsOpts := "" -}}
    {{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") $proxy.TLS -}}
      {{- $tlsOpts = ", tls=true" -}}
      {{- if $SkipVerify -}}
        {{- $tlsOpts = printf "%s, skip-cert-verify=true" $tlsOpts -}}
      {{- end -}}
      {{- if ne (default "" $proxy.SNI) "" -}}
        {{- $tlsOpts = printf "%s, sni=%s" $tlsOpts $proxy.SNI -}}
      {{- end -}}
    {{- end -}}
  {{ $proxy.Name | quote }} = vmess, {{ $server }}, {{ $proxy.Port }}, username={{ $password }}, udp-relay=true, ws=true, ws-path={{ $wsPath }}{{ $wsHeaders }}{{ $tlsOpts }}, vmess-aead=true

  {{- else if eq $proxy.Type "trojan" }}
    {{- $wsOpts := "" -}}
    {{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") -}}
      {{- $wsPath := default "/" $proxy.Path -}}
      {{- $wsOpts = printf ", ws=true, ws-path=%s" $wsPath -}}
      {{- if ne (default "" $proxy.Host) "" -}}
        {{- $wsOpts = printf "%s, ws-headers=Host:%s" $wsOpts $proxy.Host -}}
      {{- end -}}
    {{- end -}}
    {{- $tlsOpts := "" -}}
    {{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") $proxy.TLS -}}
      {{- $tlsOpts = ", tls=true" -}}
      {{- if $SkipVerify -}}
        {{- $tlsOpts = printf "%s, skip-cert-verify=true" $tlsOpts -}}
      {{- end -}}
      {{- if ne (default "" $proxy.SNI) "" -}}
        {{- $tlsOpts = printf "%s, sni=%s" $tlsOpts $proxy.SNI -}}
      {{- end -}}
    {{- end -}}
  {{ $proxy.Name | quote }} = trojan, {{ $server }}, {{ $proxy.Port }}, password={{ $password }}, udp-relay=true{{ $wsOpts }}{{ $tlsOpts }}

  {{- else if eq $proxy.Type "http" }}
  {{ $proxy.Name | quote }} = http, {{ $server }}, {{ $proxy.Port }}, {{ $password }}, {{ $password }}

  {{- else if eq $proxy.Type "https" }}
    {{- $tlsOpts := "" -}}
    {{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") $proxy.TLS -}}
      {{- $tlsOpts = ", tls=true" -}}
      {{- if $SkipVerify -}}
        {{- $tlsOpts = printf "%s, skip-cert-verify=true" $tlsOpts -}}
      {{- end -}}
      {{- if ne (default "" $proxy.SNI) "" -}}
        {{- $tlsOpts = printf "%s, sni=%s" $tlsOpts $proxy.SNI -}}
      {{- end -}}
    {{- end -}}
  {{ $proxy.Name | quote }} = https, {{ $server }}, {{ $proxy.Port }}, {{ $password }}, {{ $password }}{{ $tlsOpts }}

  {{- else if eq $proxy.Type "socks5" }}
  {{ $proxy.Name | quote }} = socks5, {{ $server }}, {{ $proxy.Port }}, {{ $password }}, {{ $password }}, udp-relay=true

  {{- end }}
{{- end }}

[Proxy Group]
# 主要策略组
🔰节点选择 = select, {{ $proxyNames }}, DIRECT
⚓️其他流量 = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}

# 应用分组
✈️Telegram = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🎙Discord = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
📘Facebook = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
📕Reddit = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🤖OpenAI = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🤖Claude = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🤖Gemini = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
Youtube = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🎬TikTok = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🎬Netflix = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🎬DisneyPlus = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🎬哔哩哔哩 = select, 🚀直接连接, 🔰节点选择, {{ $proxyNames }}
🎬国外媒体 = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🎧Spotify = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🎮Steam = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
💻Microsoft = select, 🚀直接连接, 🔰节点选择, {{ $proxyNames }}
☁OneDrive = select, 🚀直接连接, 🔰节点选择, {{ $proxyNames }}
📧OutLook = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🤖Copilot = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🧧Paypal = select, 🔰节点选择, 🚀直接连接, {{ $proxyNames }}
🚚Amazon = select, 🚀直接连接, 🔰节点选择, {{ $proxyNames }}
📡Speedtest = select, 🚀直接连接, 🔰节点选择, {{ $proxyNames }}
🍎苹果服务 = select, 🚀直接连接, 🔰节点选择, {{ $proxyNames }}
🚀直接连接 = select, DIRECT



[Rule]
# 本地网络直连
DOMAIN-SUFFIX,smtp,DIRECT
DOMAIN-KEYWORD,aria2,DIRECT
DOMAIN,clash.razord.top,DIRECT
DOMAIN-SUFFIX,lancache.steamcontent.com,DIRECT

# 管理面板
DOMAIN,yacd.haishan.me,🔰节点选择
DOMAIN-SUFFIX,appinn.com,🔰节点选择

# AI服务规则
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/OpenAI.list,🤖OpenAI,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Claude.list,🤖Claude,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Gemini.list,🤖Gemini,enhanced-mode

# 下载工具直连
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/DownLoadClient.list,DIRECT
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/ProxyClient.list,DIRECT

# 广告拦截
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/AdBlock.list,REJECT

# 苹果服务
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Apple.list,🍎苹果服务,enhanced-mode

# 各大平台规则
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Amazon.list,🚚Amazon,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Bilibili.list,🎬哔哩哔哩,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/GitHub.list,🔰节点选择,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Google.list,🔰节点选择,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Copilot.list,🤖Copilot,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/OneDrive.list,☁OneDrive,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/OutLook.list,📧OutLook,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Microsoft.list,💻Microsoft,enhanced-mode

# 流媒体规则
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Netflix.list,🎬Netflix,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/DisneyPlus.list,🎬DisneyPlus,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/TikTok.list,🎬TikTok,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/YouTube.list,🎬Youtube,enhanced-mode

# 社交媒体规则
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Telegram.list,✈️Telegram,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Discord.list,🎙Discord,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Facebook.list,📘Facebook,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Reddit.list,📕Reddit,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Twitter.list,🔰节点选择,enhanced-mode

# 其他服务规则
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Speedtest.list,📡Speedtest,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Steam.list,🎮Steam,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Spotify.list,🎧Spotify,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/PayPal.list,🧧Paypal,enhanced-mode

# 腾讯服务直连
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Tencent.list,🚀直接连接

# 代理和直连规则
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Proxy.list,🔰节点选择,enhanced-mode
RULE-SET,https://cdn.jsdmirror.com/gh/Ember-Moth/Surfboard-Template-Config@master/Filter/Direct.list,DIRECT

# 本地域名直连
DOMAIN-SUFFIX,live.cn,🚀直接连接

# 地理位置规则
GEOIP,CN,DIRECT

# 最终规则
FINAL,⚓️其他流量

[Panel]
PanelA = title="订阅信息", content="流量用量: {{ $used }}GB / {{ $total }}GB\n到期时间: {{ $ExpiredAt }}\n更新时间: {{ now | date "2006-01-02 15:04:05" }}", style=info
