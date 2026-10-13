# 私有订阅与规则快照

每台服务器独立维护一个 profile，通过 SSH 下的 `sb` 命令管理。订阅服务没有公开管理 API，也不接受网络订阅地址抓取。导入使用 URI 文件或 stdin，避免分享链接进入 shell 历史记录。

先设置客户端导入时显示的订阅名称，再获取订阅地址：

```sh
sb sub name "最伟大的派送员"
sb sub name
sb sub url
sb help sub
```

`sb sub name "自定义名称"` 修改订阅名称；不带名称时显示当前值。名称支持中文，含空格时应保留引号。改名不改变订阅链接、随机密钥或节点名称。已经导入的客户端可能保留本地名称，可在客户端改名或重新导入一次。`sub` 是 `subscription` 的简写，长命令继续兼容。

名称限 1–80 个字符，不含首尾空白、控制字符、斜杠或连续两个英文单引号；旧配置未设置时显示“我的订阅”。HTTP 响应同时发送 RFC 5987 编码的 `Content-Disposition: filename*` 与 UTF-8/Base64 编码的 `Profile-Title`，YAML 和 raw、GET 和 HEAD 均生效。名称独立于访问令牌。

导入或修改订阅内的节点：

```sh
sb node import --file nodes.txt --name '备用节点'
sb node list
sb node rename <节点ID> '新的名称'
```

`--name` 仅适用于单条 URI；批量文件使用各行 URI 的名称。同一个连接不会因换名而被重复添加；冲突名称必须修改。主动运行 `sb node show <节点ID> --uri` 或 `sb subscription url` 才输出含认证信息的地址。

当前入口为 `https://<订阅域名>/<路径>/<令牌>`，返回 YAML；在其后添加 `/raw` 返回 Base64 编码的原始链接列表。令牌由 32 个随机字节生成，是持有即能读取节点凭证的访问密钥。不要把完整订阅链接写进公开问题、截图或公开日志。

```sh
sb subscription path profiles/personal
sb domain subscription new-sub.example.com
sb subscription aliases
sb subscription retire old-sub.example.com old/path
sb subscription rotate
```

修改域名或路径会保留原路由直到明确退役；旧独立订阅服务的 `/clash.yaml` 地址也可作为兼容别名。旧域名继续使用的前提是 DNS 与证书续期仍有效。轮换令牌后所有域名、路径别名统一使用新令牌，旧令牌全部作废。退役某个历史路径与轮换整个 profile 的令牌是两种独立操作。

只保留一个 `节点选择` 分组。客户端可调字段通过模板覆盖设置，节点、代理组、规则与 rule-providers 由生成器管理：

```sh
sb subscription template
sb subscription template --file client-template.yaml
sb subscription metadata
sb subscription metadata --file metadata.json
```

模板示例：

```yaml
tun:
  enable: true
dns:
  ipv6: false
```

有效模板须保留独立的代理服务器 bootstrap DNS；启用规则快照时 Fake-IP 网段与快照契约一致。递归 YAML 别名和超出限制的模板会被拒绝。更改先经完整配置校验，再发布整个订阅版本。

流量信息为管理员手工填报的 profile 信息，不是 sing-box 实时计数，也不会把同一台机器的不同协议套餐重复相加。`upload`、`download`、`total` 必须一起提供，单位是字节；`expire` 是 Unix 到期时间戳。重置日期不会被误作到期日期，也不触发伪造的自动清零：

```json
{"upload": 0, "download": 0, "total": 107374182400, "reset_day": 1, "note": "手工记录；每月一日重置"}
```

只有流量与到期字段出现在 `Subscription-Userinfo` 响应头。`reset_day`、`reset_at`、`note` 供管理查询使用。响应给出 `Profile-Update-Interval: 12`，表示建议客户端每 12 小时刷新；客户端是否遵守由其实现和设置决定。

规则由 systemd 定时器每 15 分钟检查 [Forlooong/clash-rules-mrs](https://github.com/Forlooong/clash-rules-mrs) 的候选构建指针。源项目每日构建与服务器每 15 分钟检查是不同周期。服务器只拉取新构建，不在订阅请求内下载、编译或激活规则。

```sh
sb rules status
sb rules update
sb check
```

每个构建存放在 `/var/lib/sb/rules/<build_id>/`。候选 manifest 必须记录四个来源，文件路径、尺寸及 SHA-256 校验通过后才能暂存；同一 tag 内容变化会被拒绝。随后使用实际 Mihomo 核心验证完整生成配置，事务共同切换订阅与 active 指针。网络失败、哈希不符、异常膨胀或配置失败均保留上一份可用配置。缓存保留当前/待激活构建、最新五份，以及不足 30 天的构建。

客户端 MRS 地址仍直接指向 GitHub 的具体构建 tag；服务器不作为公开规则镜像。SHA-256 检查保证下载结果与 manifest 一致，但 manifest 与文件同源，不能替代独立供应链签名。

运行时仅监听 `127.0.0.1`，以 `sb-subscription` 账户读取一个原子发布的 bundle。请求只返回预生成内容：GET/HEAD、精确域名与路径匹配；查询字符串、重复路由头以及路径归一化绕行被拒绝。服务无访问日志、不抓取远程 URL、无管理写接口；SIGHUP 无法加载完整新 bundle 时保留旧内存版本。Nginx 提供公网 TLS 与请求限制。运行时上限为 200 个节点、100 个入口别名、8 MiB bundle、32 个并发连接及 10 秒连接超时。

`/var/lib/sb/subscription/diagnostics.json` 记录导出节点数、明确遗漏的旧节点和规则版本。这个文件不包含密码或订阅令牌；其他同目录的运行时文件包含客户端凭证，必须保持受限权限。
