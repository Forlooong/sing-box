# 运维与恢复

所有变更以 root 在本机运行 `sb`。不开放管理网页。默认网站文件在
`/var/www/sb-site/index.html`；订阅服务只监听本机，配置、令牌和备份包含访问凭证，不能放入公开仓库。

## 常用操作

```sh
sb help
sb help sub
sb sub name "最伟大的派送员"
sb sub name
sb status
sb check
sb capabilities
sb node list
sb subscription url
sb subscription path private/new-prefix
sb domain subscription sub2.example.com
sb domain site site2.example.com
sb subscription aliases
sb subscription retire old-sub.example.com old-prefix
sb domain retire old-site.example.com
```

修改域名之前，把该域名所有 A/AAAA 记录解析到本机并关闭 CDN 代理。NAT 环境可用
`--public-address` 明确公网地址。脚本不会替你开放云安全组或主机防火墙。
证书需要公网 TCP80；对外服务需要 TCP443 和相应 UDP 端口。
旧域名、路径和网站 SNI 默认继续可用，DNS 和证书续期仍须维持。旧节点仍引用旧网站
SNI，新增节点采用新网站域名；修改后可用 `node set` 明确切换单个节点。

`sub` 是 `subscription` 的简写。`sb` 或 `sb help` 显示中文指南，`sb help node` 等命令按操作分类说明。
`sb sub name "自定义名称"` 修改客户端导入时的名称；已导入的本地名称可在客户端修改或重新导入。

需要作废旧链接时使用 `sb sub rotate`，它会立即替换所有别名使用的令牌。已成功提交的令牌撤销记录独立保存，
回滚其他配置也不会重新启用旧令牌。`subscription url` 和 `node show --uri` 明确输出密钥，
不要复制到公开工单、日志或截图。
迁移后若已撤销原令牌，脚本拒绝回滚到仍保存原令牌的旧独立订阅服务，防止旧地址复活。

```sh
sb node add --name '备用 HY2' --protocol hysteria2 --port 24443
sb node import --file /root/links.txt --name '外部节点' --metadata-file /root/traffic.json
sb node show NODE_ID --uri
sb node rename NODE_ID '新名称'
sb node set NODE_ID --file /root/public-node-settings.json
sb node set NODE_ID --file /root/new-public-key.json --credentials-file /root/new-credentials.json
sb node credentials NODE_ID --file /root/node-credentials.json
sb node disable NODE_ID
sb node enable NODE_ID
sb node remove NODE_ID
sb node retire LEGACY_NODE_ID
sb site show
sb site set --file /root/index.html
sb subscription template
sb subscription template --file /root/client-overrides.yaml
sb subscription metadata --file /root/traffic.json
sb rules status
sb rules update
sb cert status
sb cert renew
sb cert sync
```

凭证更新读取 JSON 文件或 `--file -` 的标准输入，避免把密码放到命令行进程列表。
公共节点设置允许 server、port、transport、security、sni、flow、public_key、short_id、
fingerprint、obfs、alpn、method、path、host、listen_port、listen、congestion_control。
凭证 UUID/password/private_key 等必须用独立 credentials 命令。服务器变更影响客户端配置，
客户端取到下一次订阅之前仍使用旧配置。

流量信息是单个订阅的手工元数据。例如：

```json
{"upload": 0, "download": 1073741824, "total": 107374182400, "reset_day": 1, "note": "按服务器总流量填写"}
```

计量单位为字节，`expire`/`reset_at` 为 Unix 秒；到期时间不会由重置日推算，脚本也不会
自动清零手工计量。多个协议共用一台服务器时不要重复相加总额度。

## 事务、更新与故障

当前分支为四项[审查缺陷](grilling-review-2026-10-13.md)加入了修复和故障回归。
`sb transaction recover` 使用独立于正在更新代码的恢复程序，详见[恢复入口](recovery.md)。
发布验收会等待订阅服务实际提供候选 generation；旧内容返回 HTTP 200 不会通过验收。
已安装版本是否具备这些行为，应以部署版本和验收记录为准。

```sh
sb transaction list
sb transaction recover
sb transaction rollback TRANSACTION_ID
sb update v2.0.0-rc1
```

更新版本必须是本项目已经发布、包含 `code.tar.gz` 和 `SHA256SUMS` 的明确版本。
不会下载可变的 latest，也不会切回 233boy 仓库。包内候选代码先生成配置，再用核心验证，
最后一起切换。下载校验依赖 GitHub HTTPS 与仓库发行权限；同一来源的 SHA256 防止损坏，
不是独立的软件签名。

网络与节点变更流程：全局锁 → 候选完整配置 → 核心和 Nginx 校验 → 备份与持久日志 → 文件切换 →
服务启动/重载 → 候选订阅版本、HTTPS 及本机 REALITY/HY2 数据通路检查 → 提交。失败恢复文件及之前服务状态。
订阅名称、模板、元数据、已有域名下的路径/别名及令牌变更，只生成订阅和管理状态，
用 Mihomo 验证客户端配置，只重载/验收订阅服务与其 HTTPS 入口；代理故障不会阻止这些操作，
失败回滚也只恢复订阅服务。规则已启用时的快照更新同样使用这个范围。
域名、端口、节点凭证、证书、启用规则定时器和程序升级仍走相应完整流程，不通过这个范围绕过校验。
网络栈、证书、节点或核心版本变更可能引起短暂重连。
本机数据通路检查不能代替从实际客户端网络验证公网 UDP 可达性。

管理程序能启动时，普通命令会先恢复未完成文件事务；更新中断导致程序无法导入时，运行
`sb transaction recover`，或直接运行 `/usr/local/bin/sb-recover`。独立入口也恢复准备阶段和 ACME 临时监听；
没有新增开机自动恢复服务。首次安装失败可能保留已安装的系统依赖包与无登录权限的服务用户；脚本
不会使用 `autoremove` 删除可能被其他程序使用的依赖。持久日志和备份留在
`/var/backups/sb/transactions`，目录权限 0700。不要手工删除最近事务的备份。
规则快照至少保留最新五个版本以及最近30天的构建，当前与待激活版本也受保护。
回滚前会检查所需规则快照仍完整；已被清理的更老构建不能直接回滚，避免恢复一个无法继续维护的状态。

证书同步定时任务每15分钟比较已签发lineage与服务使用的证书副本，补偿续期hook与管理锁冲突等失败。
规则更新和证书同步以 `--scheduled` 运行时，若管理锁正被其他操作占用，会记录脱敏的跳过结果并在下一定时周期重试；交互命令遇到锁冲突仍报错，其他故障也仍记为失败。
`cert sync` 按域名暂存通过验证的证书，健康证书副本和激活重试队列先共同提交，再按服务依赖激活。
副本提交前会设置 `root:sb-core`、文件 0640 和目录 0750；即使坏历史证书使服务暂缓激活，
健康副本仍保有服务读取权限。权限设置失败会恢复本次副本及队列，不会重启服务。
输出中的 `applied` 表示文件已提交，`activated` 表示服务已验收，`deferred` 表示待重试，`failed` 表示源证书失败。
有源失败或未完成激活时命令返回非零，已验证的健康副本会保留。
有效旧副本不会阻断其他域名更新；过期但可加载副本允许 Nginx 更新其他站点，
缺失/损坏副本会阻止依赖它的服务重载，代理核心的全部依赖证书有效后才允许重启。
Nginx 重载后会核对实际握手返回的叶证书指纹。
队列位于 `/var/lib/sb/certificate-sync/pending.json`，服务激活失败或同步进程中断后，下次同步会继续重试。
已退役的服务、域名会从队列移除；系统服务短名与 `.service` 名称会统一，未知服务仍拒绝处理。
`certificate copies` 类型的已提交事务不能通过 `transaction rollback` 手工回退；应修复受管
Certbot lineage 后运行 `sb cert sync`。普通配置回滚可以越过与其文件没有重叠的较新证书副本事务，
但有重叠时会明确拒绝，避免覆盖已续期证书；较新的普通事务仍须先按逆序回滚。
中断且尚未提交的证书副本事务仍由 `transaction recover` 恢复旧文件及原队列，详见[恢复说明](recovery.md)。
没有证书变化且没有待激活项时不会重启服务；未知的其他应用 lineage 不会被接管。
证书申请依赖真实公网 DNS、HTTP80、ACME 配额。规则更新依赖 GitHub；失败保留最后成功的
订阅和规则快照，并由 systemd 将本次定时任务记为失败，可用 `systemctl status sb-rules`
查看。未接入邮件、Slack 等外部通知服务。

首次安装从已审查源码目录恢复准备阶段时可运行：

```sh
python3 -m sbmanager.cli transaction recover
```

## 权限边界

`sb-core` 只能读取核心配置及托管证书，`sb-subscription` 只能读取已生成的订阅材料；
它们不能读取管理密钥目录。订阅 daemon 不联网拉规则，不执行 shell，没有管理接口。
Nginx 订阅虚拟主机不记访问日志、不缓存私有路径，也不在 HTTP 上重定向私有订阅路径。
本版本的 Nginx stream 不传递 PROXY protocol，因此后端看见本机来源；依赖真实来源 IP
的旧配置必须另行设计，自动迁移会拒绝。
