# PC 智能代理网关

`smart_proxy_gateway.py` 是运行在华为内网 PC 上的 HTTP/HTTPS 正向代理。它不解密 HTTPS，而是在收到 `CONNECT host:port` 后选择出口：

- `direct_domains` 和 `direct_cidrs` 命中的目标由 PC 直接连接。
- `proxy_domains` 命中的目标转发给现有外网 HTTP 代理。
- 示例默认 `default_route=upstream`：除明确内网规则外，其他目标都走现有外网代理。
- 如需自动探测，可改为 `default_route=auto`；未知目标会先尝试直连，失败后改走外网代理，并缓存成功路线。
- `host_overrides` 可为内网域名指定 IP，避免集群或 PC 的 DNS 差异。

## Windows 启动

复制示例配置并修改上游代理、集群节点白名单和密码：

```powershell
Copy-Item config.example.json .\smart-proxy.json
$env:SMART_PROXY_PASSWORD = '<生成一个长随机密码>'
python smart_proxy_gateway.py --config .\smart-proxy.json
```

默认监听 `0.0.0.0:18081`。Windows 防火墙只应允许 Kubernetes 节点访问该端口，不要将它暴露到公网。

健康检查：

```powershell
curl.exe -x http://ouroboros:$env:SMART_PROXY_PASSWORD@127.0.0.1:18081 http://proxy.local/healthz
```

华为登录接口直连测试：

```powershell
curl.exe -vk -x http://ouroboros:$env:SMART_PROXY_PASSWORD@127.0.0.1:18081 `
  https://rnd-idea-api.huawei.com/ideaclientservice/login/v4/secureLogin
```

日志中的 `route=direct` 表示 PC 直连，`route=upstream` 表示经现有外网代理。

## 接入 Ouroboros

在平台代理配置中，将 HTTP/HTTPS 代理改成 PC 网关地址：

```text
http://ouroboros:<密码>@<PC可被集群访问的IP>:18081
```

DSH Pod 仍只连接自己的 `auth-proxy` sidecar；sidecar 再连接 PC 智能网关。PC 网关负责最后一层内外网分流。

## 路由建议

生产环境建议把已知内网域名放入 `direct_domains`，把已知外网域名放入 `proxy_domains`。`auto` 适合作为未知目标兜底，但外网第一次访问可能增加一次 `connect_timeout_seconds` 的探测延迟。

当 `direct_domains` 命中时，直连失败不会回退到外网代理，避免把内部域名泄露给外部代理。只有默认 `auto` 路由会尝试两条路径。

## 安全边界

- 网关只做 TCP 隧道和普通 HTTP 转发，不执行 HTTPS MITM。
- 必须配置 `allowed_clients`。
- 推荐使用 `auth.password_env`，不要把密码写进配置或提交到 Git。
- Windows 防火墙应进一步限制来源 IP。
- 上游代理 URL 可以带认证，例如 `http://user:password@127.0.0.1:7890`。
