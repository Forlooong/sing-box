# Debian 12 测试服务器验收

2026-10-13，经用户授权，在 `70.39.195.239` 完成全新安装与公网验收。服务器为 Debian 12、amd64、Python 3.11、systemd 252。首次验收代码为 `3269188`；后续订阅名称与帮助更新为 `aefe5ef`，详见本文末尾。运行时文件均逐项与对应版本源码比对一致。服务保留运行，未修改 SSH 或防火墙。

- 网站：<https://yunyoo.ser321761201019.040323.xyz/>
- 订阅域名：`subnode1.040323.xyz`，路径恢复为 `private`。
- 当前私有订阅地址在服务器执行 `sb subscription url` 获取。验收已经轮换令牌，安装时的旧地址永久失效。
- 代码与测试记录目录：`/root/sb-test-3269188`；首次安装、隔离流量及运维测试记录：`/root/sb-test-a41af98`，均为 root 私有目录。

## 已通过

| 检查 | 实测结果 |
| --- | --- |
| 最终单元回归 | 120 项通过 |
| 真实核心配置 | sing-box 1.14.3 检查 20 种协议/传输配置；Mihomo 1.19.32 完整配置和 URI 往返通过 |
| 规则 | 真实四来源构建 `rules-38341249423-1` 的 manifest、文件哈希、MRS 解码及客户端配置通过；未变更构建不重新发布 |
| 原生 Nginx | 使用签名验证的 Debian bookworm 官方 Nginx 1.30.5 包；实际安装及完整配置验证通过 |
| 证书 | 两个域名均成功签发受信证书；指定各自 lineage 的 Certbot `--dry-run` 续期演练通过 |
| 公网 TLS | 外部客户端验证证书链与域名、TLS 1.3、X25519、HTTP/2；未关闭证书验证 |
| 公网数据通路 | 从用户本机 WSL 通过 REALITY 和 HY2 访问测试网站；错误 UUID/证书 pin 被拒绝，随后正确配置再次成功 |
| 订阅 | 外部 HTTPS 返回单一 `节点选择` 分组、默认两种节点及 12 小时更新头 |
| 热更新 | 修改订阅路径后新旧地址都有效，核心与订阅 daemon PID 不变；回滚恢复原路径 |
| 撤销与回滚 | 轮换令牌后旧 URL 返回 404；回滚该事务后旧令牌仍被拒绝，当前订阅可用 |
| 证书同步 | 连续两次未变更同步不创建事务、不重启核心 |
| 权限 | 核心和订阅服务均为非 root；能读取各自运行材料，不能读取管理密钥；管理密钥为 0600；Nginx worker 为 nginx 用户 |
| 定时任务 | 真实 systemd 服务在管理锁占用时正常跳过，释放后成功执行；交互命令仍拒绝锁冲突 |
| 收尾 | `sb check` 通过，三个服务与三个定时器均 active；无未完成事务或 ACME 准备日志；临时客户端凭证已删除 |

网站通过 TCP443 的 SNI 入口进入 REALITY，再回落到 loopback HTTPS；订阅使用独立 SNI。HY2 使用 UDP443。2443、8443、8444、8767 仅监听 loopback。

## 本轮修复

1. 隔离测试原先依赖已存在的 nginx 用户，且固定使用 Ubuntu 包；改为使用调用账户运行临时单进程实例，并按实际发行版验证对应官方包。
2. 手动证书续期限制为受管 `--cert-name`，避免影响其他应用的 lineage。
3. 准备阶段记录既有目录的权限与所有者，失败时恢复。
4. 安装期间管理锁竞争曾使首次定时任务失败；现在仅对定时模式下的真实锁竞争返回跳过，其他错误仍失败。已在目标机复现竞争并确认修复。

脱敏机器记录：[服务器证据](evidence/server-2026-10-13.json)、[外部客户端证据](evidence/public-client-2026-10-13.json)。测试工具为 `tests/integration_core.py`、`tests/acceptance_client.py`、`tests/acceptance_server.py`。运维测试会永久撤销原订阅令牌，只应在明确指定的测试部署运行。

## 验证边界

这是一台全新 Debian 12 amd64 服务器的结果。尚未覆盖 Debian 13、Ubuntu 24.04、ARM64、真实旧 Caddy/订阅部署迁移、客户端 GUI、长时间稳定性、吞吐与实际流量计量。续期使用 ACME 演练，并非等待生产证书自然到期后观察更换。

公网测试从用户本机 WSL 发起，证明该客户端环境在测试时可达；不能据此保证任意地区、运营商或无代理网络的长期质量。服务器原有 `systemd-networkd-wait-online.service` 失败状态在安装前已存在，未将其归因于或作为本项目初始化任务处理。

## 订阅名称与帮助更新（同日）

提交 `aefe5ef` 修复了订阅缺少名称响应头的问题。修改前，真实 HTTP HEAD 返回的 `Content-Disposition` 和 `Profile-Title` 均为空；[Clash Verge Rev 2.5.8 的导入逻辑](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.8/src-tauri/src/config/prfitem.rs) 因而回退到 URL 最后一段。现在分别使用 RFC 5987 与 UTF-8/Base64 编码中文名称，并通过 `sb sub name "名称"` 修改。

- WSL 和目标 Debian 12 均通过 128 项回归，包括实际 HTTP GET/HEAD 命名、旧状态兼容、无权限帮助入口和全部帮助示例解析。
- 运行时代码通过事务部署，再实际执行改名命令，将名称设为“最伟大的派送员”。原订阅 URL、节点、凭证和代理核心 PID 均保持不变；单独改名时订阅服务 PID 也不变，热加载成功。
- 从本机 WSL 通过公网 HTTPS 验证 YAML/raw 两类订阅的 GET/HEAD 共四次请求，均返回 HTTP 200，两个名称头均解码为所设名称，更新间隔仍为 12 小时。结果见[脱敏记录](evidence/subscription-name-2026-10-13.json)。未操作客户端 GUI；已有客户端本地名称可能需要手动修改或重新导入。
- 已在服务器验证 `sb`、`sb help`、`sb --help`、主题帮助和改名查询；普通 `nobody` 用户也能读取主题帮助。`sb check` 通过，三个服务与三个定时器均 active，无未完成事务。临时订阅 URL 和凭证基线文件已删除。
