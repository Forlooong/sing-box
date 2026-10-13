# 质询审查：已确认的待修问题

2026-10-13，对 `f3deceb`（运行时 `aefe5ef`）进行子代理质询、主代理答辩及隔离故障注入。下文保留当时四项缺陷的复现证据，不代表测试服务器已经发生相应故障。当前稳定性工作分支已加入对应修复和回归；实机部署与持续运行验收另行记录，不能将本地修复等同于已部署。

## 当前分支修复对应关系

| 原问题 | 实现与回归 |
| --- | --- |
| 更新中断后入口无法启动 | 独立恢复 ZIP 入口先于运行时代码更新安装；真实子进程骤停、恢复再次骤停、令牌撤销回归见 `tests/test_recovery.py` 和 [恢复说明](recovery.md) |
| 旧订阅 HTTP 200 误判 | 发布携带候选 generation，等待 `/healthz` 返回同一版本；真实 HTTP 旧 bundle 拒绝并回滚见 `tests/test_subscription_publish.py` |
| 坏历史域名阻断证书同步 | 按域名暂存、按服务依赖激活及持久重试队列；真实证书/TLS/骤停回归见 `tests/test_cert_sync_isolation.py` |
| 第二个默认 REALITY 节点冲突 | 同 SNI 复用监听身份，不同 SNI 分配内部监听；CLI、导出、多用户真实流量及退役回归见 `tests/test_reality_listeners.py`、`tests/integration_core.py` |

订阅内容与令牌变更已限定为订阅发布范围。无关代理停止时可改名、撤销订阅令牌，回滚仍不复活旧 URL；域名/端口/节点凭证等变更仍使用完整校验。

## 1. P1：更新中断可能使已安装的恢复入口无法启动

`transaction.py` 逐文件替换运行时代码，而 `cli.py` 在进入事务恢复前就导入其他管理模块。使用真实旧提交 `adf158b` 的运行目录，更新为当前代码，在新 `cli.py` 写入后、新增 `helptext.py` 写入前对子进程执行 `os._exit(99)`，随后从受损目录运行 `transaction recover`，会因缺失模块退出。事务备份仍在，独立完整源码能够恢复。

隔离结果：`installed_recover_exit=1`、`recovery_reached=false`、事务仍为 `applying`；从完整源码恢复后为 `rolled-back`，旧 CLI 可以正常启动。主代理独立复跑通过。

相关代码：[逐文件发布](../sbmanager/transaction.py)、[CLI 启动与恢复](../sbmanager/cli.py)、[运行时文件清单](../sbmanager/bootstrap.py)。

修复方向：提供不依赖正在更新的代码的恢复入口，或采用完整版本目录切换；覆盖更新进程骤停后的重新启动验证。单纯增加 Python 异常捕获不能处理断电或强制终止。

## 2. P1：订阅保留旧配置时，发布可能误报成功

`server.py` 在重载异常时保留旧 bundle；`system.health` 只判断 HTTP 200，没有核对 `/healthz` 返回的 generation 是否属于本次候选。相同 URL 下修改名称、模板、规则或导出内容时，旧服务仍可满足健康检查。

对真实 loopback HTTP 服务注入一次重载读取失败后，实际调用健康检查并读取服务版本，结果为：

```text
generation_matches_candidate=false
health_returned_success=true
old_profile_still_served=true
```

主代理独立复跑。复现中 HTTP 服务真实运行；系统服务管理、TLS 和代理核心依赖被隔离替代，并非生产服务器端到端故障测试。

相关代码：[健康检查](../sbmanager/system.py)、[订阅重载](../sbmanager/server.py)、[事务发布](../sbmanager/cli.py)。修复方向：把候选 generation 纳入验收，等待服务提供本次版本后再提交；超时进入回滚。

## 3. P2：异常历史域名阻断其他域名证书同步

`cert sync` 顺序处理所有受管域名，任意 `stage_lineage` 异常都会中止整个操作。隔离 CLI 中让 `old.example.com` 的证书验证失败，健康主网站和订阅域名均未继续处理，`publish_called=false`。如果健康域名的续期 hook 先因管理锁冲突失败，定时补偿也会被这个旧域名持续阻断。

主代理已独立复跑上述控制流故障注入；它不等价于对真实过期证书执行 ACME 测试。

相关代码：[证书同步循环](../sbmanager/cli.py)、[lineage 校验](../sbmanager/certificates.py)。修复不能无条件跳过错误：旧 lineage 异常而托管证书副本仍有效时，可以隔离处理；副本缺失或损坏会阻断 Nginx 校验；仍被启用的 HY2 使用的过期证书会阻断代理健康检查。必须分别处理依赖和故障状态。

## 4. P2：默认新增第二个 REALITY 节点失败

在已安装默认节点后运行 `sb node add --name SECOND`，新节点产生不同的 REALITY 密钥，但仍使用内部 `2443` 监听。监听合并要求除用户外的配置一致，因而报 `incompatible local nodes share a listener`。更换网站域名后的默认新增同样失败；显式指定另一个外部端口的对照成功。

相关代码：[节点生成](../sbmanager/cli.py)、[监听合并与 SNI 路由](../sbmanager/render.py)。该校验会在发布前拒绝变更，不会把冲突配置上线。修复方向：同 SNI 明确复用监听身份，不同 SNI 分配独立内部监听并建立对应路由。

## 设计边界与后续决定

- 轮换订阅 token 只撤销下载 URL，不撤销客户端已下载的节点凭证。应急处置还需考虑节点凭证轮换；本分支已将仅订阅 token 的变更限定为订阅校验和激活，无关代理故障不再阻止撤销，节点凭证变更仍执行完整校验。
- 固定 GitHub tag、VPS 不镜像 MRS 是已批准取舍。服务器保留 last-good 不保证新客户端在 GitHub 不可达时冷启动成功。
- 最后一个启用且可导出的节点无法停用，是当前生成器的工程限制。允许空订阅或提供维护模式仍需单独决定。
- 128 项单元回归及既有实机验收没有覆盖上述所有故障，也不能代替客户端 GUI、真实旧部署迁移、全部系统架构或整机灾备验收。令牌不因回滚复活的保证只适用于本项目的同机管理事务。

本分支仍须完成整合审查、指定 Debian 12 测试机部署与真实客户端持续运行验收，再据相应证据决定发布范围。
