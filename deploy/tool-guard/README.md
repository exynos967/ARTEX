# 工具资源护栏（tool-guard）

## 背景

katana 在以 -jsluice -d 3 -c 10 -kf all 爬取大型 SPA（如 openrouter.ai）时，
单进程 RSS 一度涨到 **25.8 GB**，占满 31 GB 宿主的 83%，
随后系统进入内存回收抖动，连 127.0.0.1 的健康检查都停止响应，
最终只能硬断电恢复。

现场证据（1Panel 监控采样）：

    2026-11-18 18:04:03   cpu=99.8%   mem=88.4%
    top CPU: katana  cpu=610.7%
    top MEM: katana  mem=26457.9 MB  (83.2%)
      katana -u https://openrouter.ai -d 3 -jc -jsluice -kf all -rl 20 -c 10 -silent

## 两层防护

| 层 | 手段 | 作用 |
| --- | --- | --- |
| L1 | 容器 mem_limit / pids_limit | 任何工具失控都只在容器 cgroup 内被 OOM 杀掉，宿主不受影响 |
| L2 | 本目录的 katana shim | 在进程启动前强制压低并发/深度并剥离 -jsluice，从源头减少内存占用 |

## 安装

1. 把 katana 放到容器内可读的路径，并让它在 PATH 中**先于** /usr/local/bin：

    services:
      artex:
        mem_limit: 10g
        memswap_limit: 10g      # 与 mem_limit 相等 = 容器内禁用 swap，避免内存抖动
        pids_limit: 4096
        environment:
          PATH: /opt/artex-shim:/opt/artex-tools/node_modules/.bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
          KATANA_SHIM_LOG: /opt/artex-shim/logs/katana.log
        volumes:
          - ./deploy/tool-guard/katana:/opt/artex-shim/katana:ro
          - ./shim-logs:/opt/artex-shim/logs

完整片段见同目录 compose.override.example.yml。

2. 重建容器：

    docker compose -p artex up -d

## 验证

    # 1) 确认 PATH 命中的是 shim
    docker exec artex-artex-1 sh -c 'command -v katana'
    # => /opt/artex-shim/katana

    # 2) 确认参数被改写（不真正执行）
    docker exec -e KATANA_SHIM_DEBUG=1 artex-artex-1 katana -u https://example.com -d 3 -jc -jsluice -c 10 -silent
    # => katana.shim argv: -u https://example.com -d 2 -jc -c 3 -silent

    # 3) 确认 cgroup 内存上限生效（容器内申请超额内存应被就地杀掉）
    docker inspect -f '{{.HostConfig.Memory}}' artex-artex-1          # => 10737418240
    timeout 60 docker exec artex-artex-1 python3 -c 'a=[]; [a.append(bytearray(268435456)) for _ in range(80)]'
    echo exit=$?                                                       # => 137
    journalctl -k | grep -E 'constraint=CONSTRAINT_MEMCG' | tail -1

## 每次真实调用的参数审计

shim 会在委托给真实二进制之前追加一行日志：

    2026-11-18T19:06:45Z  -u https://openrouter.ai -d 2 -jc -kf all -rl 20 -c 3 -silent

路径由 KATANA_SHIM_LOG 指定，默认 /opt/artex-shim/logs/katana.log。
若日志显示 -jc（JS 爬取）仍会把内存顶到上限，可再剥离该参数。

## 范围与限制

- shim 只拦 katana；nuclei / naabu / ffuf 等需要时按同样模板复制一份即可。
- 参数改写是**静默**的：调用方不会收到“参数被降级”的提示，只会看到日志。
- 如果上游镜像更换了 katana 的安装路径，需同步修改 shim 中的 REAL 变量。
- L1 的 mem_limit 是硬约束：任务可能因 OOM 失败，但宿主不会被拖死，这是有意的取舍。

## 回滚

移除 PATH 前置、KATANA_SHIM_LOG 与 mem_limit 后重建容器即可；shim 本身不在镜像内，删除即失效。
