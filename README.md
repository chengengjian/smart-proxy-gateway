# PC 智能代理网关

`smart_proxy_gateway.py` 是运行在华为内网 PC 上的 HTTP/HTTPS 正向代理。它不解密 HTTPS，而是在收到 `CONNECT host:port` 后选择出口：

- `direct_domains` 和 `direct_cidrs` 命中的目标由 PC 直接连接。
- `proxy_domains` 命中的目标转发给现有外网 HTTP 代理。
- 示例默认 `default_route=upstream`：除明确内网规则外，其他目标都走现有外网代理。
- 如需自动探测，可改为 `default_route=auto`；未知目标会先尝试直连，失败后改走外网代理，并缓存成功路线。
- `host_overrides` 可为内网域名指定 IP，避免集群或 PC 的 DNS 差异。

## 获取代码

```powershell
git clone https://github.com/chengengjian/smart-proxy-gateway.git
Set-Location smart-proxy-gateway
```

## Windows 启动

复制示例配置并修改上游代理和集群节点白名单：

```powershell
Copy-Item config.example.json .\smart-proxy.json
python smart_proxy_gateway.py --config .\smart-proxy.json
```

默认监听 `0.0.0.0:18081`。Windows 防火墙只应允许 Kubernetes 节点访问该端口，不要将它暴露到公网。

健康检查：

```powershell
curl.exe -x http://127.0.0.1:18081 http://proxy.local/healthz
```

华为登录接口直连测试：

```powershell
curl.exe -vk -x http://127.0.0.1:18081 `
  https://rnd-idea-api.huawei.com/ideaclientservice/login/v4/secureLogin
```

日志中的 `route=direct` 表示 PC 直连，`route=upstream` 表示经现有外网代理。

## 接入 Ouroboros

在平台代理配置中，将 HTTP/HTTPS 代理改成 PC 网关地址：

```text
http://<PC可被集群访问的IP>:18081
```

DSH Pod 仍只连接自己的 `auth-proxy` sidecar；sidecar 再连接 PC 智能网关。PC 网关负责最后一层内外网分流。

## 路由建议

生产环境建议把已知内网域名放入 `direct_domains`，把已知外网域名放入 `proxy_domains`。`auto` 适合作为未知目标兜底，但外网第一次访问可能增加一次 `connect_timeout_seconds` 的探测延迟。

当 `direct_domains` 命中时，直连失败不会回退到外网代理，避免把内部域名泄露给外部代理。只有默认 `auto` 路由会尝试两条路径。

## 大文件下载与故障排查

转发按 64 KiB 分块并等待下游可写，不会把整个包读入内存。客户端结束发送（TCP 半关闭）后，网关仍会继续下载；两侧正常结束才关闭隧道。连接重置或任务取消时会清理两侧连接。

- `connect_timeout_seconds`：到目标或上游代理的 TCP 建连超时。
- `header_timeout_seconds`：等待客户端请求头或上游 CONNECT 响应头的超时。
- 两项都不是文件下载总时长限制。把它们调到 100 秒不会修复已经建立的隧道被重置或上游传输中断。

启动日志会输出实际加载的超时值。修改配置后需要重启网关。使用 `--log-level DEBUG` 可以查看每个传输方向的 EOF；正常结束会记录 `upload_bytes`、`download_bytes` 和 `duration_seconds`，异常会额外记录 `direction`、目标、路由和异常类型。这些字节数是网关已交给传输层的数据量，不是包大小校验结果。

如果出现 `upstream TCP connect ... failed`，检查运行网关的 PC 上对应上游端口是否在监听；如果出现 `upstream CONNECT response ... timed out`，表示已连接上游，但未及时拿到隧道响应。`stage=client request headers` 则表示还没收到完整客户端请求头。`relay failed direction=download operation=read` 表示读取上游失败，`operation=write` 表示写入客户端失败，需结合异常与两端日志判断。

网关不解密 HTTPS，无法在传输中断后自行重放包下载或切换出口；重试和完整性校验由 pnpm 等客户端处理。

回归测试（包含直连/上游、HTTP/CONNECT、慢速接收、四路并发 4 MiB 下载的长度和 SHA-256 校验，以及半关闭、连接重置、取消与超时）：

```powershell
python -m pip install -e ".[test]"
python -m pytest
```

## 安全边界

- 网关只做 TCP 隧道和普通 HTTP 转发，不执行 HTTPS MITM。
- 必须配置 `allowed_clients`，且只加入实际需要使用网关的主机或网段。
- 网关不提供用户名密码认证；来源 IP 白名单和 Windows 防火墙是访问控制边界。
- Windows 防火墙应进一步限制来源 IP。
- 上游代理 URL 可以带认证，例如 `http://user:password@127.0.0.1:7890`。
