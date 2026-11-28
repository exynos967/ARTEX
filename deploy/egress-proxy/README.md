# ARTEX 透明 SOCKS5 出口网关（含动态 Runner）

通过独立的 `sing-box` TUN 透明网关 Sidecar，在容器网络命名空间层面把 **所有外网 TCP 与 DNS 流量**强制送入上游 SOCKS5 代理，解决静态 Go/C 工具（`nuclei`、`httpx`、`katana`、`naabu`、`ffuf`、`dnsx`、`nmap`、`nc`、自定义二进制、原始 socket 等）不读取 `HTTP_PROXY`/`ALL_PROXY` 或直接发 UDP DNS 导致宿主机真实 IP 暴露的问题。

## 架构与隔离

本方案使用**两个相互隔离的透明网关**，既不给业务容器增加权限，也不破坏 Runner 与数据库的隔离：

1. **`artex-egress-gw`（主服务网关）**
   - 挂载 `default` 与 `runners` 网络（注册别名 `artex`），对外映射 `8787` / `127.0.0.1:8788`。
   - `artex` 容器改为 `network_mode: "service:artex-egress-gw"`，继续保持 `cap_drop: [ALL]`。
   - `artex -> postgres:5432` 和内网网桥流量自动排除在 `tun0` 之外。
2. **`runner-egress-gw`（动态 Runner 专用网关，`--profile runners`）**
   - **仅挂载 `runners` 网络，绝不加入 `postgres` 所在的 `default` 网络**，因此 Runner 沙箱仍无法访问数据库。
   - `runner-manager` 通过 `ARTEX_RUNNER_DOCKER_NETWORK=container:artex-runner-egress-gw` 让每个按任务创建的临时 Runner 容器共享 `runner-egress-gw` 的网络命名空间，同时保持 `--read-only --cap-drop=ALL --security-opt=no-new-privileges`。
3. **DNS 防泄漏与 Fail-Closed Kill Switch**
   - Docker 自定义网络默认把容器 `/etc/resolv.conf` 指向 `127.0.0.11`，而 `dockerd` 会把外部域名通过宿主机命名空间解析（尤其是启用 `systemd-resolved` 的 `127.0.0.53` 宿主机）。
   - 网关自动识别宿主机 `iptables-nft` / `iptables-legacy`，将 `127.0.0.11:53`（UDP/TCP）劫持到 `sing-box` 本地 DNS 入口：
     - 仅内部服务名（`postgres`、`artex`、`host.docker.internal`）转发给 Docker 内置 DNS；
     - 所有外部域名（含 `subfinder`/`dnsx`/`nuclei` 直连 53 端口的查询）默认全部通过 **TCP over SOCKS5** 发往 `EGRESS_DNS_SERVER`（无需 SOCKS5 开启 UDP Associate）。
   - 默认启用 `iptables` / `ip6tables` OUTPUT Kill Switch（`EGRESS_KILL_SWITCH=1`），只有 `lo`、`tun0`、Docker 网桥和由网关 `sing-box` 打标（`SO_MARK`）的上游 SOCKS5 流量允许出网；无 `CAP_NET_ADMIN` 的 `artex` 与 Runner 进程无法伪造标记或绕过。

## 快速启动

需要 Docker Compose `v2.20+`（支持 `!reset` 覆盖语义）及 Linux 宿主机 `/dev/net/tun`。

1. 从根目录 [.env.example](../../.env.example) 复制（或更新）根目录 `.env`，填写 `EGRESS_SOCKS5_URL`（其余网关参数均已内置在 `.env.example` 中）：

   ```bash
   # 上游在远程节点
   EGRESS_SOCKS5_URL=socks5://user:pass@203.0.113.10:1080

   # 若 SOCKS5 代理跑在 Docker 宿主机（如 Clash/sing-box/ssh -D 0.0.0.0:1080）：
   # EGRESS_SOCKS5_URL=socks5://host.docker.internal:1080
   ```

2. 在项目根目录启动：

   ```bash
   # 仅启动主服务（postgres + artex-egress-gw + artex）
   docker compose -f docker-compose.yml -f deploy/egress-proxy/docker-compose.socks5.yml up -d --build

   # 同时启动动态 Runner 池（含独立 runner-egress-gw）
   docker compose -f docker-compose.yml -f deploy/egress-proxy/docker-compose.socks5.yml --profile runners up -d --build
   ```

## 与 ARTEX Web UI 及 Runner 环境的配合

- **系统设置 -> 全局代理**：启用本透明网关后，**保持留空**即可。所有工具（含内建流量录制代理 `:8788`、`WebFetch`、Playwright 浏览器、CLI 扫描器）都会透明经由 `tun0` -> SOCKS5 出网，避免重复代理。
- **LLM API 直连（可选）**：若不希望 LLM 调用也走扫描出口代理，可在 `.env` 配置：
  ```bash
  ARTEX_EGRESS_BYPASS_DOMAINS=api.openai.com,api.anthropic.com
  ```
  仅对主服务生效，Runner 沙箱仍然强制全走 SOCKS5。
- **Runner 执行环境网络模式**：
  - **无需控制端录制 HTTP**：在执行环境里开启 `direct_network=true`（不填 `proxy_url`），Runner 内所有 HTTP/非 HTTP 工具均通过 `runner-egress-gw` 走 SOCKS5。
  - **需要控制端录制 HTTP**：将执行环境 `proxy_url` 配为 `http://artex:8788`。HTTP 工具经 `runners` 网桥进 `artex:8788` 录制后再从 `artex-egress-gw` 走 SOCKS5；非 HTTP/原始 socket 工具直接从 `runner-egress-gw` 走 SOCKS5。

## 生效与防泄漏验证

```bash
# 1. 确认主服务出口 IP 为 SOCKS5 节点 IP（而非宿主机 IP）
docker compose -f docker-compose.yml -f deploy/egress-proxy/docker-compose.socks5.yml \
  exec artex curl -sS https://ifconfig.me

# 2. 确认无 ENV 代理变量时（模拟忽略代理的静态工具）同样走 SOCKS5
docker compose -f docker-compose.yml -f deploy/egress-proxy/docker-compose.socks5.yml \
  exec artex env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY curl -sS https://ifconfig.me

# 3. 确认 nmap TCP Connect 扫描与直接 DNS 查询均可用
docker compose -f docker-compose.yml -f deploy/egress-proxy/docker-compose.socks5.yml \
  exec artex sh -c 'dig +short example.com && nmap -Pn -sT -p 80,443 example.com'

# 4. 确认 Runner 网络隔离（无法解析/连接 postgres）且出口 IP 为 SOCKS5 节点 IP
docker run --rm --network container:artex-runner-egress-gw --cap-drop=ALL \
  curlimages/curl:8.12.1 -sS https://ifconfig.me
```

> **Kill Switch 自检**：临时停止上游 SOCKS5 服务后，上述 `curl` 与 `dig` 必须失败或超时，绝不会回退为宿主机 IP。

## 注意事项

- **TCP Connect vs SYN 扫描**：SOCKS5 是四层连接代理，`nmap` 应使用 `-sT`（`-sS` 需要 `CAP_NET_RAW`，且无法经 SOCKS5 转发）；ICMP（`ping`）被网关显式拒绝以避免 `tun0` 伪造本地回包。
- **UDP / QUIC**：默认 `EGRESS_SOCKS5_UDP=0`，会拒绝非 DNS 的 UDP（如 UDP 443 QUIC 与 STUN/WebRTC），促使浏览器和 `curl` 自动回落到 TCP 走 SOCKS5。如果上游 SOCKS5 支持 RFC 1928 UDP Associate 且需要 UDP 扫描，可设为 `EGRESS_SOCKS5_UDP=1`（如需直连特定权威 DNS 服务器可同时设 `EGRESS_HIJACK_TUN_DNS=0`）。
- **上游代理域名 IP 变动**：启动时会预先解析 `EGRESS_SOCKS5_URL` 的域名并写入 `route_exclude_address` 与 Kill Switch 白名单（防止 DNS 循环死锁）。若代理使用 DDNS 且 IP 发生变化，重启网关容器即可刷新。
- **多并发 Runner 共享网络命名空间**：开启 `--profile runners` 时，并发中的临时 Runner 容器共享 `artex-runner-egress-gw` 的网络命名空间（仍与宿主机网络和 `postgres` 完全隔离，且文件系统/PID/UID 仍各自隔离）。同宿主机部署多套 ARTEX 时，请为每套设置不同的 `ARTEX_RUNNER_NETWORK` 与 `ARTEX_RUNNER_EGRESS_CONTAINER`。
