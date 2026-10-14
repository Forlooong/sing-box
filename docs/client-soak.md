# 完整订阅的有限持续客户端验证

`tests/soak_client.py` 使用两份持续运行的真实 Mihomo 进程，对已部署测试服务器的
REALITY 和 HY2 分别进行循环 HTTPS 流量检查。默认运行 3600 秒，每 30 秒请求一次，
每 300 秒重新下载并在同一进程中加载完整订阅。一次请求或刷新失败就会让最终结果失败；
一般网络请求失败后继续观察，核心进程退出则立即结束并清理。

这是一小时的有限运行验证，不代表长期稳定性、GUI 导入体验、真实证书续期或不同运营商网络验收。

## 执行

在另一台 Linux 客户端上准备 Python、PyYAML 和 curl，使用已有的私有 acceptance bundle：

```sh
chmod 600 /private/acceptance.json
python3 tests/soak_client.py \
  --bundle /private/acceptance.json \
  --output /private/soak-result.jsonl
```

bundle 复用 `tests/acceptance_client.py` 的格式及读取校验：`site_url`、
`subscription_url`、`expected_site_sha256`，以及两个部署节点完整 Mihomo 字典组成的
`proxies`。它必须是当前用户拥有的普通文件，权限 0600 或更严格；不得是符号链接。
输入文件由调用者管理，脚本不会删除它。不要把这个文件上传到仓库或公开工单。

`--output` 必须是尚不存在的新文件，创建权限为 0600，按 JSONL 逐条写入并 fsync。
标准输出也提供同样的脱敏事件。自定义示例：

```sh
python3 tests/soak_client.py --bundle /private/acceptance.json \
  --duration 3600 --interval 30 --refresh-interval 300 \
  --output /private/soak-result-2.jsonl
```

时间参数允许 1–86400 秒，采样间隔不能超过总时长。启动和核心校验发生在计时窗口之前；
最后一轮有界网络请求或刷新可能使实际结束时间略晚于指定时长。退出码 0 表示本次窗口全部
采样与刷新通过；退出码 1 表示失败或中断。SIGTERM/Ctrl+C 也会清理子进程及临时配置。

## 验证内容和隔离方式

1. 通过真实 HTTPS 下载完整 YAML，使用系统信任库、禁止重定向；校验更新头、单选择组、
   节点身份与 bundle 完全一致。允许节点改名，但不会把已更改 UUID、密码或证书设置的节点
   误当成原测试节点。规则 provider 的缓存路径必须留在私有目录内。
2. 复用实核验收下载器，验证 `versions.json` 固定的 Mihomo 发布包 SHA-256。核心、运行配置、
   curl 响应和诊断日志都位于 0700 临时目录，退出后删除；公开发布包缓存可保留。
3. 保留下载配置中的全部 `proxies`、`proxy-groups`、`rules`、`rule-providers` 及 DNS 内容。
   为隔离测试，仅将 DNS 监听改为 loopback 随机端口。关闭 TUN、自动路由、iptables、LAN、
   自定义入口、额外控制器/UI 和系统时间写入；SOCKS 与 API 仅监听 loopback 随机端口，API
   使用随机 secret。不会修改宿主路由、系统服务、防火墙或 CA。
4. 使用 `global` 模式固定本次测量的代理通路，控制器中将 `GLOBAL` 指向原“节点选择”组，
   再为两个进程分别选择 REALITY/HY2。每次请求前后都读回模式及两层选择，避免网站恰好
   命中 DIRECT 规则而形成假阳性。**规则仍完整加载并检查 provider 数据，但本工具不验证
   规则的分流决策。**
5. 每次流量请求都验证网站响应 SHA-256。刷新通过控制器 `PUT /configs?force=true` 在同一
   主进程加载重新下载的完整配置，重新选择并核对节点；核心 PID 不因正常刷新改变。
   首次 HTTP 规则下载失败时，在 120 秒总就绪预算内，通过核心自身的 provider 更新 API
   对未就绪项最多重试两次，保留原配置的下载代理；仍要求全部规则数据实际加载，不能用
   空计数或本地替代数据冒充成功。重试次数和失败次数也写入脱敏事件。
6. 每次记录协议类别、成功/失败、固定错误分类、耗时、主进程 PID/退出码及 RSS。
   不输出站点/订阅 URL、节点名、密码、token、控制器 secret 或原始错误日志。
   最后一个采样间隔结束后再次检查进程和实际选择，避免最后一次请求成功后核心退出仍被误报成功。

控制器协议依据 [Mihomo 官方 API 文档](https://wiki.metacubex.one/api/)，
入口隔离字段见 [官方全局配置说明](https://wiki.metacubex.one/config/general/)。

## 开发验证证据

```sh
python3 -m unittest tests.test_soak_client -v
python3 tests/integration_soak_client.py
```

2026-10-13，WSL/Python 3.10：13 项单元用例通过，覆盖完整配置保留、凭证匹配、隔离端口与
入口、provider 路径边界、首次下载超时有界重试及持续失败拒绝、时间参数、持续采样/刷新失败、
最后间隔进程退出、脱敏报告、失败清理及拒绝覆盖现有报告。

独立实核 fixture 同样通过：固定哈希 Mihomo/sing-box，loopback HTTPS 完整订阅下载 2 次，
REALITY/HY2 各 3 次网站摘要验证成功，同一 PID 刷新 1 次，RSS 可观察；主动杀死一个核心后
记录退出码 -9 并判定失败。fixture 仅在测试进程环境信任临时 CA，没有修改系统信任库。
脱敏结果见 [本地实核工具验收](evidence/soak-harness-local-2026-10-13.json)。

该次是 **5 秒本地 fixture**，不等价于公网一小时运行。后续指定 Debian 12 部署已完成
独立公网运行：3600.05 秒、两协议各 120 次成功请求、10 次同进程刷新和最终存活检查通过。
完整记录与验收边界见[稳定性记录](stability-2026-10-13.md)。
