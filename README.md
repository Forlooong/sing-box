# sing-box 管理脚本

用 `sb` 命令管理代理节点、网站、证书和私有订阅。基于 [233boy/sing-box](https://github.com/233boy/sing-box) 改造，使用 Nginx 管理 HTTPS、反向代理与 SNI 分流，内置订阅生成器。

## 功能

- 安装时创建 VLESS REALITY（TCP/Vision）和 Hysteria2（HY2）节点。
- 自动部署网站、申请 TLS 证书并配置自动续期；REALITY 使用本机网站作为目标。
- 生成 Mihomo YAML 和 Base64 原始链接订阅，所有可用节点归入一个“节点选择”分组。
- 自定义订阅名称、域名、路径和随机访问密钥。
- 添加本机节点，或从分享链接文件导入外部节点，支持改名、修改、启用和停用。
- 自动检查规则更新，支持修改客户端配置模板和手工填写流量信息。

支持 VLESS、HY2、VMess、Trojan、TUIC、AnyTLS、Shadowsocks 和 SOCKS5；具体传输方式与限制见[协议说明](docs/protocols.md)，也可运行 `sb capabilities` 查看。

**快速导航：** [安装](#安装) · [订阅管理](#订阅管理) · [节点管理](#节点管理) · [网站和域名](#网站和域名) · [故障排查](#故障排查) · [更多文档](#更多文档)

## 安装

### 1. 准备服务器和域名

使用 **root** 登录服务器，准备以下条件：

| 项目 | 要求 |
| --- | --- |
| 系统 | Debian 12 / 13 或 Ubuntu 24.04，使用 systemd |
| 架构 | amd64 或 arm64 |
| 网站域名 | 例如 `site.example.com`，用于网站、默认 REALITY 目标和 HY2 证书 |
| 订阅域名 | 例如 `sub.example.com`，须与网站域名不同 |
| DNS | 两个域名的全部 A / AAAA 记录均指向本机；关闭 CDN 代理 |
| 端口 | 新安装要求 TCP 80、TCP 443、UDP 443 空闲，并在云安全组与服务器防火墙中放行 |
| 联系邮箱 | 普通邮箱地址，用于 Let's Encrypt 证书账户；不需要邮箱密码或 Cloudflare API 令牌 |

TCP 80 用于证书申请和续期；TCP 443 由网站、订阅与 REALITY 共用；UDP 443 用于 HY2。脚本不会替你调整防火墙或 SSH。

已有代理、Caddy 或 Nginx 部署时，先阅读[旧部署迁移](#旧部署迁移)，不要直接执行新安装。

### 2. 下载源码并安装

```sh
apt-get update
apt-get install -y git ca-certificates python3 python3-yaml
git clone https://github.com/Forlooong/sing-box.git
cd sing-box
```

阅读源码后，将下面的两个域名和邮箱替换为自己的信息，再执行：

```sh
sh install.sh \
  --site site.example.com \
  --subscription-domain sub.example.com \
  --email admin@example.com
```

安装器需要完整源码目录，不能只下载 `install.sh` 后通过 `curl | bash` 执行。查看安装参数用 `sh install.sh --help`。

默认启用分流规则。若明确不需要分流规则，可在安装命令末尾加 `--without-rules`；之后运行 `sb rules update` 即可启用。

### 3. 获取订阅并导入客户端

```sh
sb check
sb sub name "最伟大的派送员"
sb sub url
```

1. `sb check` 检查配置、证书和服务。
2. `sb sub name "名称"` 设置客户端显示的订阅名称；未设置时默认为“我的订阅”。
3. `sb sub url` 输出 YAML 和 raw 两个地址。将 **YAML 地址**添加到支持 Mihomo 的客户端订阅中，更新后从“节点选择”分组选择节点。需要原始链接订阅的客户端使用 raw 地址，并确认其支持对应协议。

订阅地址格式：

```text
YAML：https://<订阅域名>/<路径>/<随机访问密钥>
raw ：https://<订阅域名>/<路径>/<随机访问密钥>/raw
```

默认路径前缀为 `private`。完整链接包含读取节点凭证的密钥，请勿公开。客户端会收到每 **12 小时**刷新的建议，实际更新周期以客户端设置为准。

## 查看帮助

安装后输入 `sb` 或 `sb help`，即可查看中文操作指南：

```sh
sb help
sb help sub
sb help node
sb help domain
sb node add -h
```

`sb help 主题` 按操作说明用法，具体子命令的 `-h` 显示全部参数。`sub` 是 `subscription` 的简写。帮助无需 root，管理命令请以 root 执行。

本项目的命令以这里和 `sb help` 为准，上游脚本的快捷参数不能直接照搬。

## 订阅管理

| 操作 | 命令 |
| --- | --- |
| 查看订阅名称 | `sb sub name` |
| 修改订阅名称 | `sb sub name "我的订阅"` |
| 查看订阅地址 | `sb sub url` |
| 修改路径前缀 | `sb sub path profiles/personal` |
| 更换订阅域名 | `sb domain subscription sub2.example.com` |
| 查看历史地址 | `sb sub aliases` |
| 停用某个历史地址 | `sb sub retire old-sub.example.com old/path` |
| 重新生成随机访问密钥 | `sb sub rotate` |

修改名称不会改变链接或节点名称。已经导入的客户端可能保留本地名称，可在客户端改名或重新导入。

修改域名或路径会保留旧地址；更换域名前须配置好 DNS，继续使用的旧域名也须维持 DNS 与证书有效。如需单独停用某个历史地址，使用 `sb sub retire`。

**`sb sub rotate` 会立即作废所有旧订阅链接。** 执行后用 `sb sub url` 获取新地址，并在客户端替换。它只撤销订阅下载入口，不撤销客户端已下载的节点凭证；凭证泄露时还需按[运维说明](docs/operations.md)更换节点凭证。

## 节点管理

先运行 `sb node list` 获取节点 ID，下面命令中的 `NODE_ID` 都要替换为实际 ID。

| 操作 | 命令 |
| --- | --- |
| 查看节点列表 | `sb node list` |
| 查看节点配置 | `sb node show NODE_ID` |
| 修改节点名称 | `sb node rename NODE_ID "新的节点名"` |
| 查看单节点分享链接 | `sb node show NODE_ID --uri` |
| 停用 / 启用节点 | `sb node disable NODE_ID` / `sb node enable NODE_ID` |
| 删除普通节点 | `sb node remove NODE_ID` |
| 修改节点配置 | `sb node set NODE_ID --file /root/node-settings.json` |
| 修改节点凭证 | `sb node credentials NODE_ID --file /root/node-credentials.json` |

分享链接含有凭证，请勿公开。配置与凭证 JSON 的字段说明见[运维说明](docs/operations.md)。

### 添加本机节点

例如，在独立端口创建一个备用 HY2 节点：

```sh
sb node add --name "备用 HY2" --protocol hysteria2 --port 24443
```

同时在云安全组与防火墙放行 **UDP 24443**，然后刷新客户端订阅。其他协议参数用 `sb node add -h` 查看。

### 导入外部节点

把分享链接保存到服务器上的 `/root/links.txt`，每行一条。单条链接可以指定名称：

```sh
sb node import --file /root/links.txt --name "外部节点"
```

多条链接使用各自链接内的名称，省略 `--name`：

```sh
sb node import --file /root/links.txt
```

导入只向订阅添加节点，不会在本机创建相应服务，也不抓取远程订阅 URL。同一连接重复导入会去重，改名不会生成重复节点。导入后刷新客户端订阅即可看到变化。

停用本机普通节点会停止其监听；停用导入节点只会停止导出。迁移保留的旧节点需要 `sb node retire NODE_ID` 才会停止旧监听，详见[迁移说明](docs/migration.md)。

## 网站和域名

默认首页提供时钟、时区和秒表。先把自己的 UTF-8 HTML 文件上传到服务器，再替换首页：

```sh
sb site show
sb site set --file /root/index.html
```

`sb site show` 输出当前首页 HTML；替换文件上限为 1 MiB。更换首页不会更换域名。

更换网站域名时，先把新域名解析到服务器并关闭 CDN 代理，再执行：

```sh
sb domain site site2.example.com
```

脚本检查解析并申请证书，保留旧域名入口。现有节点继续使用原来的 SNI，新节点使用新网站域名。需要切换现有节点时，使用 `sb node set`；仍被节点依赖的旧域名不能直接退役。

## 客户端配置和流量信息

### 修改客户端配置

```sh
sb sub template
sb sub template --file /root/client.yaml
```

第一条查看当前模板，第二条应用 YAML 覆盖文件。模板用于调整客户端设置；节点、分组和分流规则由生成器管理。文件示例和可调范围见[订阅说明](docs/subscription.md)。

### 填写流量信息

将以下内容保存为 `/root/traffic.json`，再按自己的套餐修改数值：

```json
{
  "upload": 0,
  "download": 0,
  "total": 107374182400,
  "reset_day": 1,
  "note": "100 GiB，每月一日重置；手工记录"
}
```

```sh
sb sub metadata --file /root/traffic.json
sb sub metadata
```

`upload`、`download`、`total` 必须一起填写，单位为字节。以上是订阅整体的**手工信息**，不会自动统计或清零；`reset_day` 仅作管理记录。客户端是否展示流量取决于其支持情况。

## 规则与证书

| 操作 | 命令 |
| --- | --- |
| 查看规则版本 | `sb rules status` |
| 立即检查规则更新 | `sb rules update` |
| 查看证书状态 | `sb cert status` |
| 手动检查证书续期 | `sb cert renew` |
| 同步已签发的新证书 | `sb cert sync` |

规则来自 [Forlooong/clash-rules-mrs](https://github.com/Forlooong/clash-rules-mrs) 的已构建快照。服务器每 **15 分钟**检查一次新构建，下载或校验失败时保留上一份可用规则。

证书会自动检查续期，日常无需手动操作。请保持域名解析有效、公网 TCP 80 可达。查看定时任务状态：

```sh
systemctl status sb-rules.timer sb-cert-sync.timer certbot.timer
```

## 旧部署迁移

自动迁移支持可识别的 233boy sing-box/Caddy 部署和本项目原独立订阅服务。先下载本项目完整源码，在源码目录中检查：

```sh
python3 -m sbmanager.cli migrate inspect
```

确认检查结果并阅读[迁移说明](docs/migration.md)后再执行：

```sh
sh install.sh migrate \
  --site new-site.example.com \
  --subscription-domain sub.example.com \
  --email admin@example.com \
  --public-server OLD_SERVER
```

`OLD_SERVER` 替换为旧客户端原本连接的 IP 或域名。迁移会保留可识别的旧端口、凭证、SNI 和证书 pin，可能引起短暂重连；未知或不能安全保留的配置会阻止迁移。

## 更新管理脚本

```sh
sb update VERSION
```

将 `VERSION` 替换为本项目[发行页面](https://github.com/Forlooong/sing-box/releases)上实际发布的版本号，且该版本须提供 `code.tar.gz` 和 `SHA256SUMS`。没有符合条件的发行版时不能使用此命令。规则更新使用 `sb rules update`。

更新前保留一份独立的完整源码目录。当前版本仍有更新中断恢复、订阅重载确认、历史域名证书同步和默认新增第二个 REALITY 节点的[已知限制](docs/grilling-review-2026-10-13.md)，恢复操作见[运维说明](docs/operations.md)。

## 故障排查

先查看状态和检查结果，再读取相关服务日志：

```sh
sb status
sb check
journalctl -u sb-sing-box -u sb-subscription -u nginx -n 100 --no-pager
```

| 现象 | 优先检查 |
| --- | --- |
| 安装提示端口已占用 | 新安装需要空闲的 TCP 80/443 与 UDP 443；已有部署先运行迁移检查 |
| 证书申请或续期失败 | 两个域名的 A / AAAA、CDN 代理状态、公网 TCP 80，以及 `sb cert status` |
| 客户端仍显示旧订阅名 | 在客户端改名或重新导入；服务器用 `sb sub name` 确认当前名称 |
| 修改节点后客户端没有变化 | 手动刷新订阅；轮换访问密钥后须替换订阅地址 |
| REALITY 可用但 HY2 不通 | 检查 HY2 对应的 UDP 端口是否放行，以及客户端网络是否允许 UDP |
| 规则更新失败 | 运行 `sb rules status`，查看 `systemctl status sb-rules`，检查 GitHub 可达性 |

本机检查通过后，仍需从实际客户端网络测试连接。提交问题时请附脱敏后的错误和相关操作，不要公开完整订阅地址、节点分享链接或凭证文件。

## 更多文档

| 文档 | 内容 |
| --- | --- |
| [运维与恢复](docs/operations.md) | 完整命令、配置字段、更新、事务恢复与回滚 |
| [私有订阅](docs/subscription.md) | 模板、流量信息、历史地址与规则快照 |
| [协议说明](docs/protocols.md) | 各协议的导入、导出、传输方式与限制 |
| [迁移说明](docs/migration.md) | 可迁移范围、保留内容与阻断条件 |
| [已知限制](docs/grilling-review-2026-10-13.md) | 当前尚待修复的问题与使用边界 |
| [开发与验证记录](docs/validation.md) | 测试方法、验证范围与实机记录 |

## 致谢与许可证

基于 [233boy/sing-box](https://github.com/233boy/sing-box)；上游使用文档见 [233boy 安装与管理教程](https://233boy.com/sing-box/sing-box-script/)。本项目使用 [GPL-3.0 许可证](LICENSE)，保留原作者归属。
