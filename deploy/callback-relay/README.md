# ARTEX SSH 反向隧道反连中转（含私有 OOB 配合指南）

本目录提供一个**可选、无特权、零宿主机入站端口**的 SSH 反向隧道 Sidecar（`deploy/callback-relay/docker-compose.ssh.yml`），把独立边缘跳板机（Edge VPS）的公网反连端口通过加密 SSH 隧道安全转发到 `artex`（以及可选的 Runner 网关）内部端口，避免在任何反连/带外测试中暴露 ARTEX 主 VPS 的 IP。

## 架构与隔离

- **零额外服务端软件**：边缘机只需系统自带 `sshd`（开启 `GatewayPorts clientspecified`），不需要部署 `frps` 或其他代理守护进程。
- **私钥与主容器彻底隔离**：SSH 私钥只以只读方式挂进独立 Sidecar（`read_only: true`、`cap_drop: [ALL]`），`artex` 主容器和动态 Runner 沙箱均无法接触私钥；边缘机隧道账号可设为 `/usr/sbin/nologin` 彻底禁 Shell，防止靶场 Prompt Injection 危及边缘机。
- **与全局透明 SOCKS5 网关天然兼容**：Sidecar 通过 Docker 内网桥转发到 `artex:<port>`（已在 `egress-proxy` 的内网白名单内），不需要放宽 `EGRESS_KILLSWITCH`。
- **Runner 网络隔离**：可选的 `runner-callback-relay`（`--profile runner-callback`）仅挂载 `runners` 网络，绝不接触 `postgres` 所在的 `default` 网络。

---

## 第一步：准备独立边缘机（约 2 分钟）

### 1. 生成专用 SSH 密钥（在 ARTEX 主 VPS 仓库根目录执行）

```bash
mkdir -p deploy/private
ssh-keygen -t ed25519 -N "" -C "artex-callback-relay" -f deploy/private/callback_id_ed25519
cat deploy/private/callback_id_ed25519.pub
```

> `deploy/private/` 已被 `.gitignore` 忽略，私钥不会被 Git 提交。

### 2. 在边缘机创建禁 Shell 最小权限账号

在**边缘机**上以 root 执行（按实际需要调整允许转发的端口）：

```bash
# 创建无登录 Shell 的专用隧道用户
useradd -m -s /usr/sbin/nologin artex-relay
install -d -m 700 -o artex-relay -g artex-relay /home/artex-relay/.ssh

# 写入公钥，并强制只允许反向端口转发且限制端口白名单（把 <PUBKEY> 换成上一步输出）
cat <<'EOF' > /home/artex-relay/.ssh/authorized_keys
restrict,port-forwarding,permitlisten="0.0.0.0:20001",permitlisten="0.0.0.0:20002",permitlisten="0.0.0.0:20003",permitlisten="0.0.0.0:20004",permitlisten="0.0.0.0:20005" <PUBKEY>
EOF
chown artex-relay:artex-relay /home/artex-relay/.ssh/authorized_keys
chmod 600 /home/artex-relay/.ssh/authorized_keys

# 仅对 artex-relay 放开远端反向监听与保活，严禁 TTY / Shell
cat <<'EOF' > /etc/ssh/sshd_config.d/artex-relay.conf
Match User artex-relay
    AllowTcpForwarding remote
    GatewayPorts clientspecified
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
    ClientAliveInterval 15
    ClientAliveCountMax 3
EOF

sshd -t && systemctl reload sshd
```

> 别忘了在边缘机的防火墙 / 云安全组放行对应端口（例如 `20001-20005/tcp`）。

### 3. （可选）在同一台边缘机顺手跑私有 `interactsh-server` 接 DNS/HTTP OOB

如果你要让 ARTEX 里的 `nuclei` 盲打模板（SSRF / Blind RCE / XXE / DNSLog）走你自己的私有 OOB 而非公共 `oast.*`，先将一个专用域名的 `NS` 记录指向边缘机，然后在边缘机启动：

```bash
docker run -d --name interactsh-server --restart unless-stopped \
  -p 53:53/udp -p 53:53/tcp -p 80:80 -p 443:443 \
  projectdiscovery/interactsh-server:latest \
  -domain oob.example.com -token "replace-with-strong-random-token"
```

然后在主 VPS 的 `.env` 填入 `ARTEX_OOB_SERVER=https://oob.example.com` 与 `ARTEX_OOB_TOKEN=...`，`artex` 主容器与所有动态 Runner 沙箱运行 `nuclei` 时都会**自动注入** `-iserver` / `-itoken`（审计日志中自动对 token 脱敏）。

---

## 第二步：在 ARTEX 主 VPS 配置 `.env` 并启动

在项目根目录 `.env` 中按需填写（完整注释见根目录 [.env.example](../../.env.example)）：

```dotenv
# 可选：私有 OOB（仅需填这几项，无需额外 compose 文件；主容器与 Runner 自动生效）
ARTEX_OOB_SERVER=https://oob.example.com
ARTEX_OOB_TOKEN=replace-with-strong-random-token
# 如未配自建 OOB 且希望彻底禁用 nuclei 访问公共 oast.*，可设为 1：
ARTEX_OOB_DISABLE_PUBLIC=0

# 可选：SSH 反向隧道反连中转（配合 -f deploy/callback-relay/docker-compose.ssh.yml）
CALLBACK_SSH_HOST=203.0.113.20
CALLBACK_SSH_PORT=22
CALLBACK_SSH_USER=artex-relay
CALLBACK_SSH_KEY_FILE=./deploy/private/callback_id_ed25519
# 推荐：用 ssh-keyscan -t ed25519 203.0.113.20 获取一行填入以严格锁定主机指纹（留空则首次 accept-new）
CALLBACK_SSH_KNOWN_HOSTS=
# 边缘机对外公网地址与映射端口（支持范围 20001-20005、逗号分隔或 8080:18080 异端口映射）
ARTEX_CALLBACK_PUBLIC_HOST=203.0.113.20
ARTEX_CALLBACK_PORTS=20001-20005
```

在项目根目录按需组合启动：

```bash
# 组合 A：仅主服务 + SSH 反连中转
docker compose -f docker-compose.yml \
  -f deploy/callback-relay/docker-compose.ssh.yml up -d --build

# 组合 B（推荐）：全局 SOCKS5 透明网关 + SSH 反连中转 + 动态 Runner
docker compose -f docker-compose.yml \
  -f deploy/egress-proxy/docker-compose.socks5.yml \
  -f deploy/callback-relay/docker-compose.ssh.yml \
  --profile runners up -d --build

# 组合 C：如还需把独立端口段直接反连到 Runner 网关（需在 .env 填 ARTEX_RUNNER_CALLBACK_PORTS=20011-20015）
docker compose -f docker-compose.yml \
  -f deploy/egress-proxy/docker-compose.socks5.yml \
  -f deploy/callback-relay/docker-compose.ssh.yml \
  --profile runners --profile runner-callback up -d --build
```

---

## 第三步：验证反连与 OOB 是否生效

```bash
# 1. 检查反向隧道 Sidecar 健康状态（应为 healthy）
docker compose -f docker-compose.yml -f deploy/callback-relay/docker-compose.ssh.yml \
  ps artex-callback-relay

# 2. 在 artex 容器内监听 20001，同时从任意外网机器访问边缘机 20001 测试端到端连通
docker compose -f docker-compose.yml -f deploy/callback-relay/docker-compose.ssh.yml \
  exec artex sh -c 'nc -l -p 20001 -w 15'
# 另开终端测试：printf 'hello-callback\n' | nc 203.0.113.20 20001

# 3. 验证 nuclei 是否自动注入私有 OOB（无须真实发包）
docker compose exec artex env ARTEX_TOOL_GUARD_DEBUG=1 nuclei -u https://example.com
```

> **HTTP 回调小技巧**：如需把 `artex-kit callback`（本地假设监听 `18080`）经边缘机 `8080` 暴露给外部测试目标，直接把 `ARTEX_CALLBACK_PORTS` 设为 `20001-20005,8080:18080`（并在边缘机 `authorized_keys` 放行 `0.0.0.0:8080`）即可。
