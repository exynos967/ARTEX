# 工具网络与资源护栏（tool-guard）

## 背景

高并发渗透扫描工具在 AI Agent 自主调用时容易突破并发/速率/内存边界：

- `katana -jsluice -d 3 -c 10 -kf all` 曾在 31 GB 宿主上单进程占用 **25.8 GB RSS**，引发整机 OOM 失联；启用 `-headless` / `-system-chrome` 还会拉起失控浏览器进程。
- `httpx`、`ffuf`、`naabu`、`sqlmap`、`nuclei` 在缺少速率/并发/超时上限时，可能打爆内置 MITM 录制代理连接池或触发目标封禁。

## 两层防护

| 层 | 手段 | 作用 |
| --- | --- | --- |
| L1 | 容器 `mem_limit` / `pids_limit` | 真正的强隔离边界：任何工具失控或绕过包装器时只在容器 cgroup 内受限/被杀，宿主不受影响 |
| L2 | 默认路径软护栏（`/usr/local/bin/<tool>` + `/usr/lib/artex-bins/<tool>`） | 覆盖默认命令调用（`katana` 或 `/usr/local/bin/katana`），在进程启动前自动夹逼并发/速率/深度/超时/重试并禁用危险模式；需配合 L1 cgroup 兜底，而非对抗任意 Bash 的安全边界 |

## 镜像内置部署布局

`Dockerfile` 在 `security-tools` 阶段完成护栏安装：

- 真实二进制迁移至 `/usr/lib/artex-bins/{katana,httpx,ffuf,naabu,sqlmap}`（`nuclei` 真实二进制位于 `/usr/local/libexec/artex/nuclei`）。
- 公共护栏库安装到 `/usr/local/lib/artex-guard/guard-common.sh`（POSIX `/bin/sh`，LF 换行）。
- `/usr/local/bin/{katana,httpx,ffuf,naabu,sqlmap}` 安装为本目录对应的护栏包装器；`/usr/local/bin/nuclei` 由 `deploy/container-tools/nuclei.py` 提供同等护栏与内置模板初始化（本目录同时提供 `deploy/tool-guard/nuclei` 用于非容器或 PATH 覆盖场景）。
- 所有包装器完整保留 `/usr/local/bin/<tool>` 可执行路径，兼容 `toolenv/inventory.go` 及 `-version` / `-h` / `-help` 版本与帮助检测。

## 6 个受护栏保护的工具与参数上限

参数改写原则：
- **缺省注入**：调用方未传对应参数时，自动前置注入安全默认值（位于任何位置参数与 `--` 之前）。
- **超限夹逼**：同时兼容 `-flag val`、`-flag=val`、`--flag val`、`--flag=val`；合法且低于上限的值原样保留，超过上限的值夹逼到上限，非法值或绕过用的 `0`（如 `ffuf -rate 0`）回退到默认值（`retries` 允许 `0`）。
- **帮助/版本透传**：包含帮助或版本参数时直接透传给真实二进制，不注入额外参数。

| 工具 | 参数（别名） | 默认上限 | 缺省注入 | 环境变量覆盖 | 透传参数 / 特殊规则 |
| --- | --- | --- | --- | --- | --- |
| **katana** | `-c` / `-concurrency` | `4` | `-c 3` | `ARTEX_KATANA_MAX_CONCURRENCY` | 透传：`-version`, `--version`, `-h`, `-help`, `--help`<br>禁止：`-headless`, `-hl`, `-system-chrome`（除非 `ARTEX_ALLOW_KATANA_HEADLESS=1`），默认显式注入 `-headless=false` 防 `-config` YAML 重开<br>剥离：`-jsluice`（除非 `ARTEX_ALLOW_KATANA_JSLUICE=1`），默认显式注入 `-jsluice=false` |
| | `-p` / `-parallelism` | `4` | `-p 3` | `ARTEX_KATANA_MAX_PARALLELISM` | |
| | `-d` / `-depth` | `2` | `-d 2` | `ARTEX_KATANA_MAX_DEPTH` | |
| | `-rl` / `-rate-limit` | `20` | `-rl 15` | `ARTEX_KATANA_MAX_RL` | |
| | `-timeout` | `10` | `-timeout 10` | `ARTEX_KATANA_MAX_TIMEOUT` | |
| **httpx** | `-rl` / `-rate-limit` | `50` | `-rl 40` | `ARTEX_HTTPX_MAX_RL` | 透传：`-version`, `--version`, `-h`, `-help`, `--help` |
| | `-t` / `-threads` | `20` | `-t 15` | `ARTEX_HTTPX_MAX_THREADS` | |
| | `-timeout` | `10` | `-timeout 10` | `ARTEX_HTTPX_MAX_TIMEOUT` | |
| | `-retries` | `1` | `-retries 1` | `ARTEX_HTTPX_MAX_RETRIES` | 允许 `0` |
| **ffuf** | `-t` | `16` | `-t 10` | `ARTEX_FFUF_MAX_THREADS` | 透传：`-V`, `-version`, `--version`, `-h`, `-help`, `--help` |
| | `-rate` | `40` | `-rate 30` | `ARTEX_FFUF_MAX_RATE` | `-rate 0` 会被夹逼回默认值 `30` |
| | `-timeout` | `10` | `-timeout 10` | `ARTEX_FFUF_MAX_TIMEOUT` | |
| **naabu** | `-rate` | `300` | `-rate 200` | `ARTEX_NAABU_MAX_RATE` | 透传：`-version`, `--version`, `-h`, `-help`, `--help`<br>UID 0 且缺少 `CAP_NET_RAW`（`cap_drop: [ALL]`）且未传 `-s`/`-scan-type` 时自动注入 `-s c`（TCP connect 扫描，避免 `EPERM`；单测可用 `ARTEX_NAABU_NO_NET_RAW=1` 模拟） |
| | `-c` / `-concurrency` | `15` | `-c 10` | `ARTEX_NAABU_MAX_CONCURRENCY` | |
| | `-timeout` | `5000ms` (`5s`) | `-timeout 5000ms` | `ARTEX_NAABU_MAX_TIMEOUT` | `naabu v2.6.1` 按 Go `time.Duration` 解析且**裸整数为秒**；护栏解析 `ms`/`s`/`m`/`h` 与裸秒数并始终输出显式 `ms` 单位。环境变量推荐使用 `5s` 或 `5000ms`（纯数字 `<=60` 按秒、`>60` 按毫秒） |
| | `-retries` | `1` | `-retries 1` | `ARTEX_NAABU_MAX_RETRIES` | 允许 `0` |
| **sqlmap** | `--threads` | `4` | `--threads=3` | `ARTEX_SQLMAP_MAX_THREADS` | 透传：`--version`, `-version`, `-h`, `-hh`, `--help`, `-help` |
| | `--timeout` | `15` | `--timeout=15` | `ARTEX_SQLMAP_MAX_TIMEOUT` | 支持正小数（如 `5.5`） |
| | `--retries` | `1` | `--retries=1` | `ARTEX_SQLMAP_MAX_RETRIES` | 允许 `0` |
| **nuclei** | `-rl` / `-rate-limit` | `30` | `-rl 25` | `ARTEX_NUCLEI_MAX_RL` | 透传：`-version`, `--version`, `-h`, `-help`, `--help`<br>禁止：`-headless`, `--headless`, `-hl`, `--hl`（exit 2，除非 `ARTEX_ALLOW_NUCLEI_HEADLESS=1`）<br>容器内 `nuclei.py` 同时负责模板配置与 `-disable-update-check` |
| | `-c` / `-concurrency` | `10` | `-c 10` | `ARTEX_NUCLEI_MAX_CONCURRENCY` | |
| | `-bs` / `-bulk-size` | `10` | `-bs 10` | `ARTEX_NUCLEI_MAX_BULK_SIZE` | |
| | `-timeout` | `10` | `-timeout 10` | `ARTEX_NUCLEI_MAX_TIMEOUT` | |
| | `-retries` | `1` | `-retries 1` | `ARTEX_NUCLEI_MAX_RETRIES` | 允许 `0` |

## 通用环境变量

| 变量 | 说明 |
| --- | --- |
| `ARTEX_TOOL_REAL_BIN` | 显式指定真实二进制路径（测试或自定义安装位置优先使用） |
| `ARTEX_TOOL_GUARD_COMMON` | 显式指定 `guard-common.sh` 路径 |
| `ARTEX_TOOL_GUARD_LOG` | 审计日志路径（每次真实执行前追加时间戳与改写后参数；`katana` 兼容旧变量 `KATANA_SHIM_LOG`） |
| `ARTEX_TOOL_GUARD_DEBUG` | 设为非空（如 `1`）时仅打印改写后的参数并退出 `0`，不执行真实工具（`katana` 兼容旧变量 `KATANA_SHIM_DEBUG`） |

若管理员通过 `ARTEX_*_MAX_*` 将上限调低至低于缺省注入值，缺省注入值会自动下调至不超过生效上限。

## 验证与测试

```bash
# 本地单测（验证 6 个工具包装器、nuclei.py、LF 换行、headless 拦截、环境变量覆盖等）
python deploy/tool-guard/test_guards.py

# 容器内调试参数改写（不执行真实扫描）
docker exec -e ARTEX_TOOL_GUARD_DEBUG=1 artex-artex-1 katana -u https://example.com -d 5 -c 20 -rl 100 -jsluice

# 容器内验证 headless 拦截
docker exec artex-artex-1 katana -u https://example.com -headless
# => stderr: katana headless mode is disabled by resource guard; use Browser MCP (exit 2)
```

## 非容器 / Compose 外挂覆盖（可选）

如果需要在旧镜像或宿主机环境挂载本目录，可将整个 `deploy/tool-guard` 挂载到 `/opt/artex-shim` 并把 `/opt/artex-shim` 置于 `PATH` 最前（所有包装器均会自动同目录查找 `guard-common.sh` 并沿 `PATH` 跳过自身定位真实二进制）。配合 L1 容器资源限制见同目录 `compose.override.example.yml`。
