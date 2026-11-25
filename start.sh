#!/bin/sh
# ARTEX 守护启动脚本（Linux / macOS / Docker ENTRYPOINT）
#
# 用法：
#   ./start.sh                       前台运行（Ctrl-C 停止）
#   nohup ./start.sh >artex.log 2>&1 &   后台常驻
#   ./start.sh -addr :9000           额外参数原样透传给 artex
#
# 它只做一件事：把 artex 跑起来，进程退出后按退出码决定要不要再拉起。
#
#   0      用户正常停止        → 退出循环
#   75     程序请求重启        → 立刻重跑（页面点了"一键更新"或"回滚"）
#   其他   崩溃                → 退避后重跑（1→2→4…最多 60 秒）
#
# 刻意不在这里做下载、SHA256 校验或换装：那些逻辑在 sh 和 bat 上要写两套，
# 而它们恰恰是最不能出错的一环——一旦换上跑不起来的二进制，本脚本会忠实地
# 反复拉起它，用户只能上机器手工救。所以校验/换装全部留在 Go 里（selfupdate 包），
# 由 artex 自己在启动时完成，脚本保持傻瓜化。
set -u

cd "$(dirname "$0")" || exit 1

BIN=./artex
[ -x "$BIN" ] || { echo "[artex] 找不到可执行文件 $BIN" >&2; exit 1; }

RESTART_CODE=75
MAX_DELAY=60

child=0
sleep_pid=0
stopping=0

# 转发停止信号给 artex 本体。
#
# Docker 下由 tini 担任 PID 1 回收僵尸进程并将 SIGTERM 转发给本脚本；本脚本再转发给
# artex（以及退避等待中的 sleep），避免 artex 收不到信号而在 10 秒后被 SIGKILL 硬杀。
forward() {
	stopping=1
	if [ "$child" -ne 0 ]; then
		kill -TERM "$child" 2>/dev/null || true
	fi
	if [ "$sleep_pid" -ne 0 ]; then
		kill -TERM "$sleep_pid" 2>/dev/null || true
	fi
}
trap forward INT TERM

delay=1
while :; do
	"$BIN" "$@" &
	child=$!

	# 收到 INT/TERM 时 trap 会打断 wait，此时子进程可能仍在优雅关闭，需继续 wait 到退出；
	# 若子进程本身被外部信号/OOM 杀死（stopping=0），不得二次 wait，保留真实退出码（如 137）。
	wait "$child"
	code=$?
	while [ "$stopping" -eq 1 ] && kill -0 "$child" 2>/dev/null; do
		wait "$child"
		code=$?
	done
	child=0

	if [ "$stopping" -eq 1 ]; then
		echo "[artex] 已停止"
		exit 0
	fi

	case "$code" in
		0)
			echo "[artex] 正常退出"
			exit 0
			;;
		"$RESTART_CODE")
			# 更新/回滚已就绪：重跑后 artex 会在启动时完成换装（见 selfupdate.Bootstrap）。
			echo "[artex] 请求重启（应用新版本）…"
			delay=1
			;;
		*)
			echo "[artex] 异常退出 (code=$code)，${delay}s 后重启" >&2
			sleep "$delay" &
			sleep_pid=$!
			wait "$sleep_pid" 2>/dev/null || true
			sleep_pid=0
			if [ "$stopping" -eq 1 ]; then
				echo "[artex] 已停止"
				exit 0
			fi
			delay=$((delay * 2))
			[ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
			;;
	esac
done
