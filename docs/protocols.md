# 协议能力与验证边界

本版本生成 Mihomo 配置和 Base64 原始链接，目标核心版本见根目录 `versions.json`。URI 解析、配置校验、实际连接成功是三个不同的验证层级；`sb capabilities` 的 `end_to_end_verified` 不会因为格式测试通过就自动变为 `true`。

| 协议 | URI 导入及两种订阅导出 | 新建本地节点 | 明确限制 |
| --- | --- | --- | --- |
| VLESS | TCP、WS、H2、HTTPUpgrade、gRPC | TCP、WS、H2、HTTPUpgrade | REALITY 只接受 TCP/H2/gRPC；Vision 只接受 TCP；新建 gRPC 暂未提供 |
| Hysteria2 / HY2 | QUIC、密码、SNI、ALPN、证书 pin、salamander | QUIC，默认 UDP 443 | 不支持端口跳跃、realm、gecko、ECH 参数导入；未知参数直接拒绝 |
| Shadowsocks | AEAD 与 2022 方法；SIP002 及旧 Base64 链接 | TCP/UDP 同端口 | 不支持插件；2022 密钥长度必须匹配方法 |
| Trojan | TLS TCP、WS、H2、HTTPUpgrade、gRPC | TLS TCP、WS、H2、HTTPUpgrade | 不支持无 TLS；新建 gRPC 暂未提供 |
| TUIC | v5 UUID/密码、QUIC、拥塞控制、UDP 转发模式 | QUIC | v4 token 不转换为 v5；禁止暗中关闭证书验证 |
| AnyTLS | TLS TCP | TLS TCP | REALITY、HTTP 传输选项不能无损表示时拒绝 |
| VMess | AEAD TCP、HTTP/1 头、WS、H2、HTTPUpgrade | TCP、HTTP/1 头、WS、H2、HTTPUpgrade | HTTP/1 仅接受 `--security none`；`alterId=0`；不接受 QUIC、gRPC 或未知传输的自动 TCP 替代 |
| SOCKS5 | TCP、可选认证、UDP 开关 | TCP/UDP 同端口 | 不支持 SOCKS4 或 TLS 包装；协议本身不加密 |
| Direct | 不属于客户端节点 | 由旧配置迁移处理 | 转发功能不能伪装成可订阅的代理协议 |

默认本地节点优先提供 VLESS REALITY TCP/Vision 与可信证书 HY2。TCP 443 留给 Nginx SNI 入口与 REALITY；其他新建 TCP 节点必须选择独立端口。H2 服务端必须保留 TLS；sing-box HTTP 传输关闭 TLS 不等于 h2c。导入远程 URI 只添加订阅节点，不会在本机创建对应监听端口。

URI 中的未知参数、重复参数、冲突的 TLS 开关，以及放在错误传输类型上的 `host`、`path`、`serviceName` 均会拒绝。HTTPUpgrade 明确生成 Mihomo 的 `v2ray-http-upgrade`，不会退化为普通 WebSocket。错误输出不会复制原 URI 或密码。

连接去重根据规范化后的协议、服务器、端口、认证及连接参数计算，名称不参与。节点在登记后保留独立的稳定 ID；修改名称不改变身份。名称必须唯一，不能覆盖 `节点选择`、`DIRECT` 等保留名。所有可用节点进入唯一的 `节点选择` 手动选择分组。

证书 SHA-256 pin 与浏览器 TLS 指纹是不同字段：前者导出为 Mihomo `fingerprint`，后者为 `client-fingerprint`。新建本机 HY2 使用网站域名的受信证书。导入 URI 的显式不安全设置会原样保留；迁移的旧自签名节点保留原证书与 pin，不能冒充“已经使用可信证书”。TUIC 的 `disable_sni=1` 在目标 Mihomo 中会关闭普通证书验证，因此必须同时提供证书 pin，或明确给出 `insecure=1`。

旧 VMess QUIC 等不能由此适配器导出的节点标记为 `exportable=false`，原监听服务继续保留。能够保留的原链接进入 `/raw`；Mihomo YAML 不含这些节点，诊断结果必须说明遗漏原因及原链接是否保留。一般 URI 导入不允许用这一标记绕过能力检查。

官方依据：

- [Mihomo 传输配置](https://wiki.metacubex.one/en/config/proxies/transport/)
- [Mihomo TLS 配置](https://wiki.metacubex.one/en/config/proxies/tls/)
- [sing-box HTTP 传输：无 TLS 时为 HTTP/1.1](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/#http)
- [Mihomo v1.19.32 TUIC 实现](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/adapter/outbound/tuic.go)
- [Hysteria 2 URI 规范](https://v2.hysteria.network/docs/developers/URI-Scheme/)

这些文档描述上游能力；本项目支持范围以上表和实际校验为准，不能据此推断未实现参数也可导入。
