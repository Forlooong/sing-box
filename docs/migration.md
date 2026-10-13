# 旧部署迁移与退役

迁移保留旧客户端的连接参数，同时建立新的 Nginx、REALITY、HY2 和订阅服务。它会短暂重启服务，不承诺零断连。迁移检测和本地夹具测试不等同于真实服务器验收。

## 自动迁移范围

支持两个已知布局，可单独或同时存在：

- 233boy/Forlooong 脚本布局：`/etc/sing-box/config.json`、`conf/*.json`、`bin/sing-box`，以及已知 systemd 启动命令。已安装的旧 sing-box 二进制原样保留，迁移不会顺便升级旧核心。
- 本项目旧 `subscription-deploy/install.sh` 生成的独立订阅服务：`/opt/subscription-generator/.managed-install`，已知 Nginx 配置和启用链接，以及已知 Python 服务启动命令。

自建 Nginx stream、Xray、未知 Caddy 网站或全局配置、非标准 Caddy 80/443、systemd 自定义命令/环境/命名空间、全局路由和来源 IP 依赖会阻止整次自动迁移。内核内置 ACME（包括旧 AnyTLS 的 `acme` / `certificate_provider`）须先单独审查证书生命周期，不直接转移。OpenRC 不在本版本范围内。

检测采用已知配置语法，不能识别的行为不会被静默删除。`eligible: true` 仅表示布局可识别；准备阶段仍会校验 SNI、端口、证书、导出能力和迁移前后的文件指纹。

## 执行顺序

1. 运行 `sb migrate inspect`。结果只包含部署类型、端口、文件 SHA-256、权限与符号链接目标，不输出 UUID、密码、订阅令牌或密钥。检查 `blockers`，先处理全部阻断项。
2. 准备新的站点域名和独立订阅域名。它们的 A/AAAA 应仅指向当前服务器，关闭 CDN 代理，并保持公网 TCP 80 可用于 ACME。新的站点 SNI 不能复用仍由旧 TCP 443 节点或旧 Caddy 路由占用的 SNI。
3. 执行：

   ```sh
   sb migrate apply --site new-site.example.com \
     --subscription-domain sub.example.com --email admin@example.com \
     --public-server 203.0.113.10
   ```

   `--public-server` 是旧客户端实际连接的原 IP/域名，不是新站点域名。NAT 主机可另传 `--public-address`。如果各旧节点的公开连接地址不同，应手动核对导出的 URI；当前适配器只有一个旧公开地址参数。`--without-rules` 明确生成仅含 `MATCH` 的规则，不能用于假装完成规则快照校验。
4. 迁移先准备候选状态和保护备份，再申请所需域名证书、校验候选配置、切换服务并检查 HTTP/TLS。证书申请或配置校验失败不得宣称迁移成功。Caddy 暂停用于 ACME 时应恢复原活动状态，正式切换失败则由事务恢复文件和服务状态。
5. 使用原有客户端配置测试旧 REALITY/HY2 等节点，再导入新订阅测试新节点。服务器本机检查不能代替从客户端所在地的网络测试。

## 保留的内容

- 旧 REALITY UUID、私钥、公钥、short ID、SNI 和 handshake 目标保留。旧 TCP 443 listener 改到独立 loopback 端口，Nginx 根据原 SNI 转发，并保留其原默认入口行为。
- 旧专用端口保留。旧 HY2/TUIC/VMess QUIC 占用 UDP 443 时，新 HY2 使用另外的空闲候选端口，旧端口不被抢占。
- 旧自签名证书和私钥复制原始字节；证书指纹按叶证书 DER 计算。旧 `insecure` 兼容行为仅保留于这些旧节点，新节点使用受信任证书。
- 旧 Caddy WS/HTTPUpgrade 路径迁移到 Nginx。H2 使用保留的 HTTP/2 TLS 后端，Nginx 验证后端域名与证书；不把 H2 偷换为明文 HTTP/1 或 h2c。
- VMess QUIC 等无法由 Mihomo 无损表示的旧 listener 保留运行，明确列出不导出的原因；已知 VMess QUIC 分享格式保留于 raw。Direct 是转发 listener，不伪装成可订阅节点。
- 旧独立订阅令牌、`/sub/<token>/clash.yaml` 和 `/sub/<token>/raw` 路径保留为别名，用户模板非托管字段保留。同一连接同时出现在旧订阅和旧核心时合并，保留原订阅名称。规则与分组由新系统统一生成。
- 新域名证书准备成功后，最终事务停用已知旧 `subscription-generator` Certbot 续期条目，避免同一域名重复续期。原证书和私钥 archive/live 目录保留，回滚恢复原续期配置；含自定义 hook 或未知续期参数时阻止自动迁移。
- 原文件的内容、权限和链接目标清单保存在 `/var/lib/sb/migration/<id>/backup`，仅管理员可读。旧核心副本位于 `/opt/sb/legacy/<id>/sing-box`。

旧域名的 DNS 和 ACME 可达性需要持续维护。改站点或订阅域名后旧域名不会自动退役。订阅令牌轮换会使所有旧路径上的旧令牌立即失效；这是一项显式撤销操作，回滚也不应重新启用旧令牌。

## 显式退役

`sb node disable <id>` 只把旧节点从订阅隐藏，保留旧 listener，让已有客户端继续工作。

确认客户端迁移完成后，使用 `sb node retire <id>` 删除对应旧用户。一个 listener 有多个用户时只删除指定用户；最后一个用户退出才移除该 listener、对应 SNI 路由和专用证书副本。全部旧 listener 退役后停止并禁用旧核心服务。保护备份和旧二进制不自动删除。

退役校验旧运行配置的 SHA-256；如果配置被外部修改，操作拒绝继续，以免错误删除另一位用户。站点别名仍须另用 `sb domain retire <name>` 明确删除；仅隐藏旧节点不能解除域名依赖。

## 恢复与限制

用 `sb transaction list` 查看事务，`sb transaction recover` 恢复中断的应用，`sb transaction rollback <id>` 回滚最近可回滚事务。迁移备份包含凭证，不能上传到公开仓库或工单。

如果旧独立订阅的原令牌已被撤销，系统拒绝回滚到会重新启动该旧订阅服务的初次迁移状态；继续使用受管服务和有效新令牌。旧规则快照已经按保留策略清理时，也不能直接回滚到引用它的状态，须先恢复并校验对应快照。

候选检查应同时使用新核心和保留的旧核心验证各自配置。单元测试覆盖拓扑、文件保留、原始证书指纹、别名、拒绝未知结构、TOCTOU、去重和单用户/整 listener 退役；仍须在目标 Linux 发行版验证 Nginx 模块、systemd 权限、ACME、HTTP/2 后端和真实协议握手。
