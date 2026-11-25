# 默认 Compose 的宿主资源预算

默认安装启动应用和 PostgreSQL。下表列出每个常驻容器的硬上限。PID 配额计入进程和线程，内存额度包含该容器内的子进程。每个服务的内存加交换空间上限都设为与内存上限相同，在支持该限制的宿主上，该容器可用的额外交换空间为零。[默认部署清单](../docker-compose.yml)

| 服务 | 内存 | CPU | PID 数 | 额外隔离与配额 | Docker 标准输出及错误日志 |
| --- | ---: | ---: | ---: | --- | --- |
| artex | 2 GiB | 4.0 | 512 | `init: true`、`shm_size: 256m`、`cap_drop: [ALL]`、`cap_add: [DAC_OVERRIDE, FOWNER]`、`no-new-privileges:true`、`nofile: 16384`、`stop_grace_period: 45s` | 每个文件 8 MiB，最多 3 个 |
| postgres | 1 GiB | 未限 | 128 | `max_connections=40`、`shared_buffers=128MB`、`work_mem=4MB`、`maintenance_work_mem=48MB`、`max_parallel_workers=2`、`max_parallel_workers_per_gather=1` | 同上 |
| runner-manager（可选） | 512 MiB | 未限 | 192 | `init: true`、`read_only: true`、`cap_drop: [ALL]`、`cap_add: [DAC_OVERRIDE, FOWNER]`、`no-new-privileges:true`、`TMPDIR=/var/lib/artex-runner/tmp`、`stop_grace_period: 45s` | 同上 |

默认两个容器合计 **3 GiB、640 个 PID**，容器日志的名义轮转预算约为 48 MiB。计入可选管理器后，三者合计 **3.5 GiB、832 个 PID**，日志预算约为 72 MiB。该预算按每个服务一个容器计算。PostgreSQL 预算调整为 1 GiB 并配合连接数与内存参数限制，防止 40 连接叠加 GIN 索引维护/autovacuum 触发 OOM；`runner-manager` 提升至 `512 MiB / 192 PIDs`，确保 4 个并发 Docker runner 槽位同时拉起/同步快照时不会触及 `EAGAIN` 或 OOM。`artex` 仅通过容器级 cgroup `pids_limit: 512` 约束进程数，刻意不设置 `ulimits.nproc`（`RLIMIT_NPROC` 按宿主 UID 跨容器累计，UID 0 下会与其他容器互相误杀）。数值用作保护宿主的初始策略，部署前应为操作系统、Docker 和其他工作负载另留余量。可用资源不足时应暂停部署。

## 进程回收、临时目录与挂载权限

- **PID 1 僵尸进程回收**：镜像入口使用 `ENTRYPOINT ["/usr/bin/tini", "--", "/app/start.sh"]`，确保无论通过 Docker Compose（同时开启 `init: true`）、裸 `docker run` 还是 Kubernetes 部署，容器内都有真正的 PID 1 回收工具子进程树（如 Bash、Playwright/Chromium）产生的孤儿与僵尸进程，并正确转发 `SIGTERM`（`artex` 与 `runner-manager` 均配 `stop_grace_period: 45s` 留足优雅关闭时间）。
- **绑定挂载 `./data` / `./skills` / `ARTEX_RUNNER_DATA_DIR` 兼容性**：为同时兼容宿主机 root 属主与非 root（如 `1000:1000`、`0755`）绑定挂载，`artex` 与 `runner-manager` 保持 UID 0 运行，先通过 `cap_drop: [ALL]` 和 `no-new-privileges:true` 剥离全部默认 Linux capabilities，仅按最小权限加回 `cap_add: [DAC_OVERRIDE, FOWNER]`，明确保持 `CAP_NET_RAW`、`CAP_SYS_ADMIN`、`CAP_SYS_RESOURCE`、`CAP_SYS_PTRACE`、`CAP_SETUID`、`CAP_SETGID` 处于剥离状态。
- **`runner-manager` 快照临时目录**：`runner-manager` 保持只读根文件系统和 64 MiB `/tmp` tmpfs，同时将 `TMPDIR` 指向持久数据卷内的 `/var/lib/artex-runner/tmp` 并在启动时自动建目录，避免最大 1 GiB 的文件同步快照打爆 64 MiB `/tmp`。

## 触及上限时

- 内核可能拒绝分配内存，或在容器内终止进程。PID 耗尽时，创建进程或线程会失败。两种情况都可能只让当前操作失败，主进程仍可运行。如果主进程退出，现有的 `restart: unless-stopped` 策略可能重启容器。反复触限时应停止对应服务，检查资源事件。
- Docker 的 `json-file` 驱动轮转标准输出和标准错误，达到保留份数时淘汰最旧文件。单条大日志和文件系统开销会使实际占用偏离预算。数据库内的日志、数据、WAL 及应用数据目录都消耗各自所在文件系统的空间，需在宿主或存储后端分别配额。
- 由管理器通过 Docker 创建的独立子容器各有自己的资源控制组，管理器的限制对它们无效。使用宿主二进制或外部数据库时，也需单独核算资源。

## 验证

在仓库根目录、已安装 PyYAML 的 Python 环境中运行下列离线检查。它读取默认清单并检查三个服务的声明。

```sh
python -B - <<'PY'
from pathlib import Path
import yaml
services = yaml.safe_load(Path('docker-compose.yml').read_text(encoding='utf-8'))['services']
budgets = {'artex': ('2g', 512), 'postgres': ('1g', 128), 'runner-manager': ('512m', 192)}
assert set(services) == set(budgets), 'service inventory changed'
logging = {'driver': 'json-file', 'options': {'max-size': '8m', 'max-file': '3'}}
errors = []
for name, (memory, pids) in budgets.items():
    expected = {'mem_limit': memory, 'memswap_limit': memory, 'pids_limit': pids, 'logging': logging}
    for key, value in expected.items():
        if services[name].get(key) != value:
            errors.append(f'{name}.{key}')
artex_expected = {
    'init': True,
    'cpus': '4.0',
    'shm_size': '256m',
    'cap_drop': ['ALL'],
    'cap_add': ['DAC_OVERRIDE', 'FOWNER'],
    'security_opt': ['no-new-privileges:true'],
    'ulimits': {'nofile': {'soft': 16384, 'hard': 16384}},
    'stop_grace_period': '45s',
}
for key, value in artex_expected.items():
    if services['artex'].get(key) != value:
        errors.append(f'artex.{key}')
runner_expected = {
    'init': True,
    'read_only': True,
    'cap_drop': ['ALL'],
    'cap_add': ['DAC_OVERRIDE', 'FOWNER'],
    'security_opt': ['no-new-privileges:true'],
    'stop_grace_period': '45s',
}
for key, value in runner_expected.items():
    if services['runner-manager'].get(key) != value:
        errors.append(f'runner-manager.{key}')
if services['runner-manager'].get('environment', {}).get('TMPDIR') != '/var/lib/artex-runner/tmp':
    errors.append('runner-manager.environment.TMPDIR')
if services['postgres'].get('command') != [
    'postgres',
    '-c', 'max_connections=40',
    '-c', 'shared_buffers=128MB',
    '-c', 'work_mem=4MB',
    '-c', 'maintenance_work_mem=48MB',
    '-c', 'max_parallel_workers=2',
    '-c', 'max_parallel_workers_per_gather=1',
]:
    errors.append('postgres.command')
if errors:
    raise SystemExit('Missing or incorrect: ' + ', '.join(errors))
print('PASS: memory, swap, PID, log and containment limits for 3 services')
PY
```

部署时还应检查最终合并的 Compose 配置。已运行容器在重建后才会采用新的限制和日志选项。运维可用 Docker inspect 核对实际容器的内存、交换、PID 和日志配置，并在采用 cgroup v2 的主机上核对容器资源控制组的 `memory.max`、`memory.swap.max` 和 `pids.max`。保留轮转后的磁盘用量和触限事件可用于现场验收。
