"""Single-administrator CLI; every published configuration uses one transaction."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets as random
import sys
import uuid

from . import state as registry
from . import protocols, subscription, render, system, certificates, helptext
from .transaction import ManagementBusy, Transaction, atomic, lock


class HelpParser(argparse.ArgumentParser):
    def format_help(self):
        return helptext.render() if self.prog == "sb" else super().format_help()


def parser():
    p = HelpParser(prog="sb", description="Nginx / sing-box / 私有订阅统一管理")
    p.add_argument("--root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    p.add_argument("--offline", action="store_true", help=argparse.SUPPRESS)
    commands = p.add_subparsers(dest="command")
    p.set_defaults(command="help", topic=None)
    commands.add_parser("help", help="中文操作指南，例如 sb help sub").add_argument("topic", nargs="?", help="主题，例如 sub、node、domain")
    install = commands.add_parser("install", help="新安装；需要已解析到本机的两个域名")
    _install_arguments(install)
    commands.add_parser("status", help="显示脱敏配置与服务状态")
    commands.add_parser("check", help="检查完整配置、证书与服务")
    commands.add_parser("capabilities", help="协议与导出能力矩阵")
    node = commands.add_parser("node", help="管理本地节点和导入节点").add_subparsers(dest="action", required=True)
    node.add_parser("list", help="列出节点，不显示凭证")
    add = node.add_parser("add", help="生成本地节点；默认 REALITY TCP/Vision")
    add.add_argument("--protocol", choices=["vless", "hysteria2", "shadowsocks", "trojan", "tuic", "anytls", "vmess", "socks"], default="vless")
    add.add_argument("--name", required=True)
    add.add_argument("--server")
    add.add_argument("--port", type=int)
    add.add_argument("--transport", choices=["tcp", "http", "ws", "h2", "httpupgrade"], default="tcp")
    add.add_argument("--security", choices=["none", "tls", "reality"])
    add.add_argument("--sni")
    add.add_argument("--path", default="/")
    add.add_argument("--method", default="2022-blake3-aes-128-gcm")
    add.add_argument("--metadata-file", type=Path)
    imp = node.add_parser("import", help="从文件或 stdin 导入 URI；不远程抓取")
    imp.add_argument("--file", default="-")
    imp.add_argument("--name", help="单条 URI 的节点名称")
    imp.add_argument("--metadata-file", type=Path, help="可选手工订阅总量/用量/重置信息 JSON")
    for action in ("rename", "remove", "retire", "enable", "disable", "credentials", "set", "show"):
        sub = node.add_parser(action)
        sub.add_argument("id")
        if action == "rename":
            sub.add_argument("name")
        if action in {"credentials", "set"}:
            sub.add_argument("--file", required=True, help="JSON 凭证文件或 - 读取 stdin")
        if action == "set":
            sub.add_argument("--credentials-file", help="同一事务更新配套凭证，适用于 REALITY 公私钥变更")
        if action == "show":
            sub.add_argument("--uri", action="store_true", help="明确输出含凭证的分享链接")
    domain = commands.add_parser("domain", help="修改域名并保留兼容别名").add_subparsers(dest="action", required=True)
    for action in ("site", "subscription"):
        sub = domain.add_parser(action)
        sub.add_argument("name")
        sub.add_argument("--public-address", action="append", default=[])
    retire = domain.add_parser("retire", help="明确停用域名别名；依赖它的节点须先停用")
    retire.add_argument("name")
    sub_parser = commands.add_parser("subscription", aliases=["sub"], help="订阅名称、地址、模板与流量信息（简写 sub）")
    sub_parser.set_defaults(command="subscription")
    sub = sub_parser.add_subparsers(dest="action", required=True)
    name = sub.add_parser("name", help="查看或修改客户端显示的订阅名称，地址不变")
    name.add_argument("name", nargs="?", metavar="名称", help="例如 \"最伟大的派送员\"；不填则查看当前名称")
    sub.add_parser("url", help="输出含密钥的 YAML 和 raw 地址")
    path = sub.add_parser("path")
    path.add_argument("prefix")
    sub.add_parser("rotate", help="立即作废全部旧订阅令牌；回滚也不会恢复")
    sub.add_parser("aliases")
    retire = sub.add_parser("retire", help="明确移除单个历史路径")
    retire.add_argument("domain")
    retire.add_argument("prefix")
    template = sub.add_parser("template")
    template.add_argument("--file", help="YAML 覆盖文件或 -；不带参数查看有效模板")
    metadata = sub.add_parser("metadata")
    metadata.add_argument("--file", help="JSON 文件或 -；不带参数查看手工信息")
    rules = commands.add_parser("rules").add_subparsers(dest="action", required=True)
    rules.add_parser("status")
    update = rules.add_parser("update", help="检查、校验并激活新规则快照")
    update.add_argument("--scheduled", action="store_true")
    update.add_argument("--channel", choices=("v1", "v2"),
                        help="显式迁移规则通道；省略时沿用当前通道，旧安装默认 v1")
    cert = commands.add_parser("cert").add_subparsers(dest="action", required=True)
    cert.add_parser("status")
    cert.add_parser("renew")
    sync = cert.add_parser("sync", help="补偿续期hook失败，仅发布已签发证书的变化")
    sync.add_argument("--scheduled", action="store_true")
    deploy = cert.add_parser("deploy")
    deploy.add_argument("--lineage", required=True)
    tx = commands.add_parser("transaction").add_subparsers(dest="action", required=True)
    tx.add_parser("list")
    tx.add_parser("recover")
    rollback = tx.add_parser("rollback")
    rollback.add_argument("id")
    migrate = commands.add_parser("migrate", help="审查并保留兼容性的旧部署迁移").add_subparsers(dest="action", required=True)
    migrate.add_parser("inspect")
    apply = migrate.add_parser("apply")
    _install_arguments(apply)
    apply.add_argument("--public-server", required=True, help="旧节点客户端使用的原IP或域名")
    update = commands.add_parser("update", help="安装明确指定的本项目发布版本，失败回滚")
    update.add_argument("version")
    site = commands.add_parser("site", help="查看或替换默认静态网站").add_subparsers(dest="action", required=True)
    site.add_parser("show")
    site_set = site.add_parser("set")
    site_set.add_argument("--file", required=True)
    return p


def _install_arguments(p):
    p.add_argument("--site", required=True)
    p.add_argument("--subscription-domain", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--prefix", default="private")
    p.add_argument("--public-address", action="append", default=[])
    p.add_argument("--without-rules", action="store_true", help="明确仅生成 MATCH 规则，之后可 rules update")


def output(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def read_input(name, limit=2 * 1024 * 1024):
    if str(name) == "-":
        value = sys.stdin.buffer.read(limit + 1)
    else:
        path = Path(name)
        if not path.is_file() or path.stat().st_size > limit:
            raise ValueError("Input must be a bounded regular file")
        value = path.read_bytes()
    if len(value) > limit:
        raise ValueError("Input exceeds size limit")
    return value


def find_node(state, identity):
    matches = [n for n in state["nodes"] if n["id"] == identity]
    if len(matches) != 1:
        raise ValueError("Unknown node ID; use sb node list")
    return matches[0]


def reality_keys(offline=False):
    if offline:
        # Valid X25519 keys for fixture rendering, without installing a Linux core.
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
        import base64
        key = X25519PrivateKey.generate()
        encode = lambda x: base64.urlsafe_b64encode(x).decode().rstrip("=")
        return encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())), encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    data = system.run(["/opt/sb/bin/sing-box", "generate", "reality-keypair"])
    values = dict(line.split(":", 1) for line in data.splitlines() if ":" in line)
    return values["PrivateKey"].strip(), values["PublicKey"].strip()


def add_local(state, secret, *, protocol="vless", name, server=None, port=None,
              transport="tcp", security=None, sni=None, path="/", method="2022-blake3-aes-128-gcm", offline=False):
    import base64
    if protocol in {"hysteria2", "tuic"}:
        transport = "quic"
    security = security or ("reality" if protocol == "vless" else "none" if protocol in {"shadowsocks", "socks"} else "tls")
    identifier = uuid.uuid4().hex
    node = {"id": identifier, "name": registry.node_name(name), "protocol": protocol,
            "source": "local", "enabled": True, "server": protocols.hostname(server or state["domains"]["site"]),
            "port": port or (state["ports"]["hy2"] if protocol == "hysteria2" else 443),
            "transport": transport, "security": security}
    credentials = {}
    if protocol in {"vless", "vmess", "tuic"}:
        credentials["uuid"] = str(uuid.uuid4())
    if protocol in {"hysteria2", "shadowsocks", "trojan", "tuic", "anytls", "socks"}:
        credentials["password"] = random.token_urlsafe(32)
    if protocol == "shadowsocks":
        node["method"] = method
        if method.startswith("2022-"):
            credentials["password"] = base64.b64encode(random.token_bytes(16 if "128" in method else 32)).decode()
    if protocol == "socks":
        credentials["username"] = "sb-" + random.token_hex(4)
    if security != "none":
        node["sni"] = registry.domain(sni or state["domains"]["site"])
    if transport not in {"tcp", "quic"}:
        node.update(path=path, host=node.get("sni", state["domains"]["site"]))
    if security == "reality":
        prior = None
        if protocol == "vless" and node["port"] == 443:
            prior, listener_port = render.plan_reality_listener(state, node)
            if prior is None and not offline:
                prior, listener_port = render.plan_reality_listener(state, node, system.occupied_ports())
            node.update(listen="127.0.0.1", listen_port=listener_port)
        if prior is None:
            private, public = reality_keys(offline)
            credentials["private_key"] = private
            node.update(public_key=public, short_id=random.token_hex(8), fingerprint="chrome")
        else:
            credentials["private_key"] = secret["nodes"][prior["id"]]["private_key"]
            for field in ("public_key", "short_id", "fingerprint", "alpn"):
                if field in prior:
                    node[field] = copy.deepcopy(prior[field])
        if transport == "tcp":
            node["flow"] = "xtls-rprx-vision"
    protocols.to_mihomo(node, credentials)
    state["nodes"].append(node)
    secret["nodes"][identifier] = credentials
    return identifier


def import_nodes(state, secret, text, name=None):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if name and len(lines) != 1:
        raise ValueError("--name requires exactly one URI")
    known = {protocols.connection_id(n, secret["nodes"][n["id"]]): n for n in state["nodes"] if n.get("exportable", True)}
    imported, duplicates = [], []
    for line in lines:
        node, credentials = protocols.parse_uri(line)
        if name:
            node["name"] = registry.node_name(name)
        identity = protocols.connection_id(node, credentials)
        if identity in known:
            duplicates.append(known[identity]["id"])
            continue
        node.update(id=uuid.uuid4().hex, source="uri", enabled=True)
        if node["name"] in {n["name"] for n in state["nodes"]}:
            raise ValueError("Imported node name already exists; use --name for a unique name")
        state["nodes"].append(node)
        secret["nodes"][node["id"]] = credentials
        known[identity] = node
        imported.append(node["id"])
    if not lines:
        raise ValueError("No URI supplied")
    return {"imported": imported, "duplicates": duplicates}


def compile_files(root, state, secret, snapshot=None, extra=None):
    registry.validate(state, secret)
    files = render.render(state, secret)
    site_index = state["site"]["root"] + "/index.html"
    if registry.logical_path(root, site_index).exists():
        files.pop(site_index, None)
    files.update(subscription.render(state, secret, snapshot))
    nginx = registry.logical_path(root, "/etc/nginx/nginx.conf")
    base = nginx.read_text() if nginx.exists() else "events {}\nhttp {}\n"
    files["/etc/nginx/nginx.conf"] = system.patch_nginx(base).encode()
    files.update(extra or {})
    files[registry.STATE], files[registry.SECRETS] = registry.encode(state), registry.encode(secret)
    return files


def snapshot_for(root, state):
    if not state["rules"].get("enabled"):
        return None
    from . import rules
    return rules.load(registry.logical_path(root, "/var/lib/sb/rules"), state["rules"].get("active_build"),
                      channel=state["rules"].get("channel", "v1"))


def publish(args, state, secret, *, extra=None, snapshot=None, label="change", commit=lambda: None):
    from . import publication
    if snapshot is None:
        snapshot = snapshot_for(args.root, state)
    sub_only = publication.subscription_only(args, state, secret, extra)
    files = (publication.compile_subscription(state, secret, snapshot) if sub_only else
             compile_files(args.root, state, secret, snapshot, extra))
    switches = state.get("legacy", {}).get("switch", {})
    services = ({"sb-subscription"} if sub_only else
                set(system.SERVICES) | set(switches.get("stop_services", [])) | set(switches.get("start_services", [])))
    snapshot_dir = None
    if snapshot:
        snapshot_dir = registry.logical_path(args.root, "/var/lib/sb/rules/" + snapshot[0]["build_id"])
        if not args.offline:
            from . import rules
            cache = registry.logical_path(args.root, "/var/lib/sb/rules")
            config = files["/var/lib/sb/subscription/clash.yaml"]
            receipt = rules.validate(cache, snapshot[0]["build_id"], config, Path("/opt/sb/bin/mihomo"),
                                     override=state["subscription"].get("template", {}))
            files.update(rules.activation_artifacts(cache, snapshot[0]["build_id"], receipt, config))
    generation = json.loads(files[subscription.DIRECTORY + "/runtime.json"])["generation"]
    def validate(stage):
        if sub_only:
            system.validate_subscription_candidate(stage, root=args.root, snapshot_dir=snapshot_dir)
        else:
            system.validate_candidate(stage, root=args.root, snapshot_dir=snapshot_dir, remove_symlinks=switches.get("remove_symlinks"))
    identifier = Transaction(args.root).apply(files,
        validate=(lambda _: None) if args.offline else validate,
        activate=(lambda _: None) if args.offline else lambda record: (system.activate_subscription if sub_only else system.activate)(state, record),
        health=(lambda: None) if args.offline else lambda: system.health(state, secret, expected_generation=generation, subscription_only=sub_only, root=args.root),
        restore_services=(lambda _: None) if args.offline else system.restore_services,
        service_state={} if args.offline else system.service_state(services),
        remove_symlinks={} if sub_only else switches.get("remove_symlinks", {}), label=label, commit=commit)
    return identifier


def change_domain(state, role, name):
    name = registry.domain(name)
    old = state["domains"][role]
    if old == name:
        return
    opposite = "subscription" if role == "site" else "site"
    if name in [state["domains"][opposite], *state["domains"][opposite + "_aliases"]]:
        raise ValueError("Domain is already assigned to the other role")
    if role == "subscription":
        registry.remember_alias(state)
    aliases = state["domains"][role + "_aliases"]
    aliases[:] = [x for x in aliases if x != name]
    if old not in aliases:
        aliases.append(old)
    state["domains"][role] = name
    # Existing node identities/SNI remain stable; new nodes use the new site.


def _metadata(state, filename):
    data = json.loads(read_input(filename))
    subscription.metadata_headers(data)
    state["subscription"]["metadata"] = data


def install(args, migrate=False):
    if args.offline:
        return _install(args, migrate)
    from . import bootstrap
    try:
        _install(args, migrate)
    except BaseException:
        bootstrap.rollback_preparation()
        raise
    else:
        bootstrap.finish_preparation()


def _install(args, migrate=False):
    root = args.root
    if registry.logical_path(root, registry.STATE).exists():
        raise ValueError("Managed installation already exists")
    state, secret = registry.create(args.site, args.subscription_domain, args.email, args.prefix)
    state["rules"]["enabled"] = not args.without_rules
    extra = {}
    report = None
    if migrate:
        from . import migration
        report = migration.inspect(root)
        if report.get("blockers"):
            output(report)
            raise ValueError("Migration has blockers; no service was modified")
        state["migration"] = {"public_server": protocols.hostname(args.public_server)}
        if not args.offline:
            state["migration"]["occupied_ports"] = sorted(system.occupied_ports())
    # Plan and verify migration before preparation changes any inventoried file.
    if migrate:
        state, secret, legacy_files = migration.prepare(report, state, secret)
        extra.update(legacy_files)
    if not args.offline:
        from . import bootstrap
        source = Path(__file__).resolve().parent.parent
        extra.update(bootstrap.prepare_host(source, state, public_addresses=args.public_address, migration=migrate) or {})
        system.allocate_ports(state)
    add_local(state, secret, name="本机 REALITY", offline=args.offline)
    add_local(state, secret, protocol="hysteria2", name="本机 HY2", offline=args.offline)
    snapshot = None
    if state["rules"]["enabled"]:
        from . import rules
        cache = registry.logical_path(root, "/var/lib/sb/rules")
        build = rules.stage(cache)
        snapshot = rules.load(cache, build)
        state["rules"]["active_build"] = build
    if not args.offline:
        extra.update(bootstrap.ensure_certificates(state, new_install=not migrate))
    identifier = publish(args, state, secret, extra=extra, snapshot=snapshot, label="migrate" if migrate else "install")
    if not args.offline:
        bootstrap.finish_preparation()
    output({"transaction": identifier, "message": "安装完成；sb subscription url 查看私有地址", "node_ids": [n["id"] for n in state["nodes"]]})


def execute(args):
    if args.command == "help":
        print(helptext.render(args.topic), end="")
        return
    if args.command == "capabilities":
        output(protocols.capabilities())
        return
    if args.command == "migrate" and args.action == "inspect":
        from . import migration
        output(migration.inspect(args.root))
        return
    if args.command == "transaction":
        tx = Transaction(args.root)
        restore = (lambda _: None) if args.offline else system.restore_services
        if args.action == "list":
            output([{k: value[k] for k in ("id", "label", "status", "created")} for value in
                    (json.loads(p.read_bytes()) for p in sorted(tx.base.glob("*/journal.json")))])
        elif args.action == "recover":
            tx.recover(restore_services=restore)
            if not args.offline:
                from . import bootstrap
                bootstrap.rollback_preparation()
            output({"recovered": True})
        else:
            tx.rollback(args.id, restore_services=restore)
            output({"rolled_back": args.id})
        return
    # Resolve unfinished transactions before reading a possibly partial state.
    Transaction(args.root).recover(restore_services=(lambda _: None) if args.offline else system.restore_services)
    if args.command == "install" or args.command == "migrate":
        install(args, args.command == "migrate")
        return
    state, secret = registry.load(args.root)
    extra, result, commit = {}, {}, lambda: None
    if args.command == "status":
        diagnostics = registry.logical_path(args.root, "/var/lib/sb/subscription/diagnostics.json")
        output({"state": registry.public_view(state), "services": {} if args.offline else system.service_state(),
                "subscription": json.loads(diagnostics.read_bytes()) if diagnostics.exists() else {}})
        return
    if args.command == "check":
        registry.validate(state, secret)
        files = compile_files(args.root, state, secret, snapshot_for(args.root, state))
        if not args.offline:
            import tempfile
            with tempfile.TemporaryDirectory(prefix="sb-check-") as directory:
                os.chmod(directory, 0o700)
                for name, body in files.items():
                    atomic(registry.logical_path(Path(directory), name), body)
                build = state["rules"].get("active_build")
                cache = Path("/var/lib/sb/rules") / build if build else None
                system.validate_candidate(Path(directory), snapshot_dir=cache)
            system.health(state, secret)
        output({"valid": True, "offline": args.offline})
        return
    if args.command == "node":
        if args.action == "list":
            output(state["nodes"])
            return
        if args.action == "add":
            fields = {k: getattr(args, k) for k in ("protocol", "name", "server", "port", "transport", "security", "sni", "path", "method")}
            result["node_id"] = add_local(state, secret, offline=args.offline, **fields)
        elif args.action == "import":
            text = read_input(args.file).decode("utf-8-sig")
            name = args.name
            if name is None and len(text.splitlines()) == 1 and sys.stdin.isatty():
                name = input("节点名称（留空使用链接中的名称）: ").strip() or None
            result.update(import_nodes(state, secret, text, name))
        else:
            node = find_node(state, args.id)
            if args.action == "show":
                if args.uri:
                    compatible = dict(node)
                    if compatible.get("legacy_insecure"):
                        compatible["insecure"] = True
                    if compatible.get("exportable") is False:
                        raw = secret.get("legacy_uris", {}).get(node["id"])
                        if raw is None:
                            raise ValueError("This legacy protocol has no lossless share link")
                        print(raw)
                    else:
                        print(protocols.to_uri(compatible, secret["nodes"][node["id"]]))
                else:
                    output(node)
                return
            if node["source"] == "legacy" and args.action in {"credentials", "remove", "set"}:
                raise ValueError("Legacy listener retirement requires explicit migration plan; disable export without deleting its retained runtime")
            if args.action == "rename":
                node["name"] = registry.node_name(args.name)
            elif args.action == "remove":
                state["nodes"].remove(node)
                secret["nodes"].pop(node["id"])
            elif args.action in {"enable", "disable"}:
                node["enabled"] = args.action == "enable"
            elif args.action == "credentials":
                secret["nodes"][node["id"]] = json.loads(read_input(args.file))
            elif args.action == "set":
                value = json.loads(read_input(args.file))
                allowed = {"server", "port", "transport", "security", "sni", "flow", "public_key", "short_id", "fingerprint", "obfs", "alpn", "method", "path", "host", "listen_port", "listen", "congestion_control"}
                if not isinstance(value, dict) or set(value) - allowed:
                    raise ValueError("Unsupported node setting; credentials must use the separate credentials command")
                node.update(value)
                if args.credentials_file:
                    if args.credentials_file == "-" and args.file == "-":
                        raise ValueError("Only one input can use stdin")
                    secret["nodes"][node["id"]] = json.loads(read_input(args.credentials_file))
            elif args.action == "retire":
                from . import migration
                state, secret, extra = migration.retire(args.root, state, secret, args.id)
        if getattr(args, "metadata_file", None):
            _metadata(state, args.metadata_file)
    elif args.command == "domain":
        if args.action == "retire":
            name = registry.domain(args.name)
            if name in (state["domains"]["site"], state["domains"]["subscription"]):
                raise ValueError("Cannot retire a current primary domain")
            if any((n.get("enabled", True) or n.get("source") == "legacy") and name in (n.get("sni"), n.get("server")) for n in state["nodes"]) or any(e.get("sni") == name for e in state["legacy"].get("entries", [])):
                raise ValueError("An enabled node still depends on this domain")
            for key in ("site_aliases", "subscription_aliases"):
                state["domains"][key] = [x for x in state["domains"][key] if x != name]
            state["subscription"]["aliases"] = [a for a in state["subscription"]["aliases"] if a["domain"] != name]
        else:
            change_domain(state, args.action, args.name)
            if not args.offline:
                system.network_preflight(state, public_addresses=args.public_address, new_install=False)
                from . import bootstrap
                extra.update(bootstrap.ensure_certificates(state))
    elif args.command == "subscription":
        if args.action == "name":
            if args.name is None:
                output({"name": state["subscription"].get("name", registry.DEFAULT_SUBSCRIPTION_NAME)})
                return
            state["subscription"]["name"] = registry.subscription_name(args.name)
            result.update(name=state["subscription"]["name"], message="订阅名称已更新，地址保持不变；已导入的客户端如仍显示旧名，请在客户端改名或重新导入")
        if args.action == "url":
            output(subscription.urls(state, secret))
            return
        if args.action == "aliases":
            output(state["subscription"]["aliases"])
            return
        if args.action == "path":
            registry.remember_alias(state)
            state["subscription"]["prefix"] = registry.prefix(args.prefix)
        elif args.action == "rotate":
            digest = hashlib.sha256(secret["subscription_token"].encode()).hexdigest()
            secret["subscription_token"] = random.token_urlsafe(32)
            def commit():
                path = registry.logical_path(args.root, registry.REVOKED)
                revoked = set(json.loads(path.read_bytes())) if path.exists() else set()
                revoked.add(digest)
                atomic(path, registry.encode(sorted(revoked)))
            result["message"] = "全部历史 URL 已失效；请重新获取订阅地址"
        elif args.action == "retire":
            domain, prefix = registry.domain(args.domain), registry.prefix(args.prefix)
            if domain == state["domains"]["subscription"] and prefix == state["subscription"]["prefix"]:
                raise ValueError("Cannot retire the current subscription route")
            state["subscription"]["aliases"] = [a for a in state["subscription"]["aliases"] if (a["domain"], a["prefix"]) != (domain, prefix)]
        elif args.action in {"template", "metadata"}:
            if not args.file:
                output(subscription.template_config(state["subscription"]["template"]) if args.action == "template" else state["subscription"]["metadata"])
                return
            if args.action == "metadata":
                _metadata(state, args.file)
            else:
                import yaml
                value = yaml.safe_load(read_input(args.file))
                subscription.template_config(value)
                state["subscription"]["template"] = value
    elif args.command == "cert":
        if args.action == "status":
            output(certificates.certificate_status(state, args.root))
            return
        if args.action == "sync":
            from .certsync import synchronize
            result = synchronize(state, secret, args.root, offline=args.offline)
            if not args.scheduled or not result.get("unchanged") or result["failed"] or result["deferred"]:
                output(result)
            if result["failed"] or (result["deferred"] and not args.offline):
                names = ", ".join(row["domain"] for row in result["failed"])
                raise certificates.CertificateError("Certificate synchronization incomplete"
                                                    + (": " + names if names else "")
                                                    + "; validated copies and pending activations are reported above")
            return
        elif args.action == "renew":
            if args.offline:
                raise ValueError("Renewal requires a live host")
            # The CLI holds the global lock: suppress nested deploy hooks only
            # for our lineages, then stage their copies in one transaction.
            names = certificates.managed_domains(state)
            for name in names:
                system.run(certificates.certbot_renew_command(name) + ["--no-directory-hooks"], timeout=600)
            for name in names:
                extra.update(certificates.stage_lineage("/etc/letsencrypt/live/" + name, state, args.root))
        else:
            from pathlib import PurePosixPath
            lineage = PurePosixPath(args.lineage)
            if not lineage.is_absolute() or lineage.parent != PurePosixPath("/etc/letsencrypt/live"):
                raise ValueError("Unexpected Certbot lineage path")
            if lineage.name not in certificates.managed_domains(state):
                output({"ignored": "Certificate is not owned by this installation"})
                return
            extra.update(certificates.stage_lineage(args.lineage, state, args.root))
    elif args.command == "rules":
        from . import rules
        cache = registry.logical_path(args.root, "/var/lib/sb/rules")
        if args.action == "status":
            output(dict(state["rules"], channel=state["rules"].get("channel", "v1")))
            return
        channel = args.channel or state["rules"].get("channel", "v1")
        build = rules.stage(cache, channel=channel)
        if (build == state["rules"].get("active_build") and state["rules"].get("enabled")
                and channel == state["rules"].get("channel", "v1")):
            if not args.scheduled:
                output({"unchanged": build})
            return
        snapshot = rules.load(cache, build, channel=channel)
        state["rules"].update(enabled=True, active_build=build, channel=channel)
        if args.offline:
            raise ValueError("Rule activation requires actual Mihomo validation")
        result["rules_build"] = build
        result["rules_channel"] = channel
        result["transaction"] = publish(args, state, secret, extra=extra, snapshot=snapshot, label="rules update")
        output(result)
        return
    elif args.command == "update":
        from . import updates
        if args.offline:
            raise ValueError("Release update requires Linux validation")
        files = updates.prepare(args.version, args.root)
        updated_state = json.loads(files[registry.STATE])
        updated_secret = json.loads(files[registry.SECRETS])
        registry.validate(updated_state, updated_secret)
        build = updated_state["rules"].get("active_build")
        snapshot_dir = Path("/var/lib/sb/rules") / build if build else None
        services = set(system.SERVICES) | set(state.get("legacy", {}).get("services", []))
        identifier = Transaction(args.root).apply(files,
            validate=lambda stage: system.validate_candidate(stage, snapshot_dir=snapshot_dir),
            activate=lambda record: system.activate(updated_state, record),
            health=lambda: system.health(updated_state, updated_secret,
                expected_generation=json.loads(files[subscription.DIRECTORY + "/runtime.json"])["generation"]),
            restore_services=system.restore_services, service_state=system.service_state(services),
            label="update " + args.version)
        output({"transaction": identifier, "version": args.version})
        return
    elif args.command == "site":
        index = state["site"]["root"] + "/index.html"
        if args.action == "show":
            print(registry.logical_path(args.root, index).read_text(encoding="utf-8"))
            return
        content = read_input(args.file, 1024 * 1024)
        content.decode("utf-8")
        extra[index] = content
    result["transaction"] = publish(args, state, secret, extra=extra, label=args.command + " " + getattr(args, "action", ""), commit=commit)
    output(result)


def main(argv=None):
    args = parser().parse_args(argv)
    args.root = args.root.resolve()
    if args.offline and args.root == Path("/").resolve():
        raise SystemExit("--offline requires a separate --root fixture directory")
    try:
        if not args.offline and args.command not in {"help", "capabilities"}:
            system.require_linux_root()
            os.umask(0o077)
        if args.command in {"help", "capabilities"}:
            execute(args)
        else:
            with lock(args.root):
                if not args.offline:
                    from . import bootstrap
                    bootstrap.recover_acme()
                execute(args)
    except ManagementBusy as exc:
        if getattr(args, "scheduled", False) and (args.command, args.action) in {
                ("rules", "update"), ("cert", "sync")}:
            output({"skipped": "management_busy", "retry": "next_timer"})
            return 0
        print("sb: " + str(exc), file=sys.stderr)
        return 1
    except (ValueError, RuntimeError, OSError, KeyError) as exc:
        print("sb: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
