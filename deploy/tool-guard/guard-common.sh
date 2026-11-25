#!/bin/sh
# ARTEX 扫描工具公共护栏库（POSIX /bin/sh 兼容，LF 换行）
#
# 提供真实二进制定位、数值参数夹逼、环境变量覆盖解析、审计日志与调试输出。
# 由 /usr/local/bin/<tool> 或同目录工具包装器 source 加载。

# guard_canon_path <path>: 规范化路径（解析符号链接），防止 PATH 查找自调用死循环。
guard_canon_path() {
  _gcp_p="$1"
  if command -v readlink >/dev/null 2>&1; then
    _gcp_rl=$(readlink -f "$_gcp_p" 2>/dev/null || true)
    if [ -n "$_gcp_rl" ]; then
      printf '%s\n' "$_gcp_rl"
      return 0
    fi
  fi
  _gcp_dir=$(dirname -- "$_gcp_p" 2>/dev/null || printf '.')
  _gcp_base=$(basename -- "$_gcp_p" 2>/dev/null || printf '%s' "$_gcp_p")
  _gcp_abs=$(CDPATH= cd -- "$_gcp_dir" 2>/dev/null && pwd -P)
  if [ -n "$_gcp_abs" ]; then
    printf '%s/%s\n' "$_gcp_abs" "$_gcp_base"
  else
    printf '%s\n' "$_gcp_p"
  fi
}

# guard_find_real_bin <tool> <self_path> [extra_fallback]
# 查找顺序：
#   1. $ARTEX_TOOL_REAL_BIN（测试或管理员显式覆盖）
#   2. /usr/lib/artex-bins/<tool>（容器镜像内标准真实二进制目录）
#   3. 可选 extra_fallback（如 /usr/local/libexec/artex/nuclei）
#   4. 遍历 PATH，跳过与自身相同的路径
guard_find_real_bin() {
  _gfb_tool="$1"
  _gfb_self="$2"
  _gfb_extra="${3:-}"

  if [ -n "${ARTEX_TOOL_REAL_BIN:-}" ]; then
    if [ -x "$ARTEX_TOOL_REAL_BIN" ] && [ ! -d "$ARTEX_TOOL_REAL_BIN" ]; then
      printf '%s\n' "$ARTEX_TOOL_REAL_BIN"
      return 0
    fi
    printf 'tool-guard(%s): ARTEX_TOOL_REAL_BIN is not executable: %s\n' "$_gfb_tool" "$ARTEX_TOOL_REAL_BIN" >&2
    return 127
  fi

  if [ -x "/usr/lib/artex-bins/$_gfb_tool" ] && [ ! -d "/usr/lib/artex-bins/$_gfb_tool" ]; then
    printf '%s\n' "/usr/lib/artex-bins/$_gfb_tool"
    return 0
  fi

  if [ -n "$_gfb_extra" ] && [ -x "$_gfb_extra" ] && [ ! -d "$_gfb_extra" ]; then
    printf '%s\n' "$_gfb_extra"
    return 0
  fi

  _gfb_self_canon=$(guard_canon_path "$_gfb_self")
  _gfb_path="${PATH:-}"
  while [ -n "$_gfb_path" ]; do
    case "$_gfb_path" in
      *:*)
        _gfb_dir="${_gfb_path%%:*}"
        _gfb_path="${_gfb_path#*:}"
        ;;
      *)
        _gfb_dir="$_gfb_path"
        _gfb_path=""
        ;;
    esac
    [ -z "$_gfb_dir" ] && _gfb_dir="."
    _gfb_cand="$_gfb_dir/$_gfb_tool"
    if [ -x "$_gfb_cand" ] && [ ! -d "$_gfb_cand" ]; then
      if [ "$_gfb_cand" = "$_gfb_self" ]; then
        continue
      fi
      _gfb_cand_canon=$(guard_canon_path "$_gfb_cand")
      if [ "$_gfb_cand_canon" != "$_gfb_self_canon" ]; then
        printf '%s\n' "$_gfb_cand"
        return 0
      fi
    fi
  done

  printf 'tool-guard(%s): real binary not found (checked /usr/lib/artex-bins/%s and PATH)\n' "$_gfb_tool" "$_gfb_tool" >&2
  return 127
}

# guard_strip_leading_zeros <digits>: 去掉前导 0，避免 POSIX 算术误解析为八进制。
guard_strip_leading_zeros() {
  _gsz="$1"
  while [ "${#_gsz}" -gt 1 ]; do
    case "$_gsz" in
      0*) _gsz="${_gsz#0}" ;;
      *) break ;;
    esac
  done
  printf '%s\n' "$_gsz"
}

# guard_env_max <env_value> <default_max> [min_val]
# 解析管理员通过环境变量配置的上限覆盖；非法值回退为 default_max。
guard_env_max() {
  _gem_raw="$1"
  _gem_def="$2"
  _gem_min="${3:-1}"
  case "$_gem_raw" in
    ''|*[!0-9]*)
      printf '%s\n' "$_gem_def"
      return 0
      ;;
  esac
  _gem_num=$(guard_strip_leading_zeros "$_gem_raw")
  if [ "${#_gem_num}" -gt 9 ]; then
    printf '%s\n' "$_gem_def"
    return 0
  fi
  if [ "$_gem_num" -lt "$_gem_min" ]; then
    printf '%s\n' "$_gem_def"
    return 0
  fi
  printf '%s\n' "$_gem_num"
}

# guard_effective_default <default_val> <effective_max>
# 确保默认注入值不会高于管理员下调后的上限。
guard_effective_default() {
  _ged_def="$1"
  _ged_max="$2"
  if [ "$_ged_def" -gt "$_ged_max" ]; then
    printf '%s\n' "$_ged_max"
  else
    printf '%s\n' "$_ged_def"
  fi
}

# guard_clamp_int <raw_val> <max_val> <default_val> [min_val]
# 将整数参数夹逼到 [min_val, max_val]：
#   - 非数字或 < min_val（如 -rate 0、负数等绕过尝试）-> 回退 default_val
#   - 超过 max_val（含超长数字防 64 位溢出）-> 夹逼为 max_val
#   - 合法范围内 -> 保留原值（去除前导 0）
guard_clamp_int() {
  _gci_raw="$1"
  _gci_max="$2"
  _gci_def="$3"
  _gci_min="${4:-1}"
  case "$_gci_raw" in
    ''|*[!0-9]*)
      printf '%s\n' "$_gci_def"
      return 0
      ;;
  esac
  _gci_num=$(guard_strip_leading_zeros "$_gci_raw")
  if [ "${#_gci_num}" -gt 9 ]; then
    printf '%s\n' "$_gci_max"
    return 0
  fi
  if [ "$_gci_num" -lt "$_gci_min" ]; then
    printf '%s\n' "$_gci_def"
  elif [ "$_gci_num" -gt "$_gci_max" ]; then
    printf '%s\n' "$_gci_max"
  else
    printf '%s\n' "$_gci_num"
  fi
}

# guard_clamp_decimal <raw_val> <max_int> <default_val>
# 支持正小数（如 sqlmap --timeout=5.5）；超过 max_int 夹逼为 max_int，0 或非法回退 default_val。
guard_clamp_decimal() {
  _gcd_raw="$1"
  _gcd_max="$2"
  _gcd_def="$3"
  case "$_gcd_raw" in
    *.*)
      _gcd_int="${_gcd_raw%%.*}"
      _gcd_frac="${_gcd_raw#*.}"
      case "$_gcd_int" in
        ''|*[!0-9]*)
          printf '%s\n' "$_gcd_def"
          return 0
          ;;
      esac
      case "$_gcd_frac" in
        ''|*[!0-9]*)
          printf '%s\n' "$_gcd_def"
          return 0
          ;;
      esac
      _gcd_int=$(guard_strip_leading_zeros "$_gcd_int")
      if [ "${#_gcd_int}" -gt 9 ]; then
        printf '%s\n' "$_gcd_max"
        return 0
      fi
      _gcd_frac_nonzero=0
      case "$_gcd_frac" in
        *[1-9]*) _gcd_frac_nonzero=1 ;;
      esac
      if [ "$_gcd_int" -eq 0 ] && [ "$_gcd_frac_nonzero" -eq 0 ]; then
        printf '%s\n' "$_gcd_def"
      elif [ "$_gcd_int" -gt "$_gcd_max" ]; then
        printf '%s\n' "$_gcd_max"
      elif [ "$_gcd_int" -eq "$_gcd_max" ] && [ "$_gcd_frac_nonzero" -eq 1 ]; then
        printf '%s\n' "$_gcd_max"
      else
        printf '%s.%s\n' "$_gcd_int" "$_gcd_frac"
      fi
      ;;
    *)
      guard_clamp_int "$_gcd_raw" "$_gcd_max" "$_gcd_def" 1
      ;;
  esac
}

# guard_parse_duration_ms <raw_val> [bare_mode]
# 解析 Go/naabu 风格时长并返回毫秒整数（非法值返回非 0 且无输出）：
#   - <N>ms -> N ms
#   - <N>s 或 <A>.<B>s -> 毫秒（小数部分截取至毫秒精度）
#   - <N>m -> N * 60000 ms
#   - <N>h -> N * 3600000 ms
#   - 纯整数 <N>：
#       bare_mode=s（默认，匹配 naabu v2.6.1 的 CLI 行为）-> 视为秒（N * 1000 ms）
#       bare_mode=env（用于环境变量覆盖）-> <=60 视为秒，>60 视为毫秒
#   - 超大数值饱和为 999999999，防止 POSIX 算术溢出。
guard_parse_duration_ms() {
  _gpd_raw="$1"
  _gpd_mode="${2:-s}"
  [ -z "$_gpd_raw" ] && return 1
  case "$_gpd_raw" in
    *ms)
      _gpd_n="${_gpd_raw%ms}"
      case "$_gpd_n" in ''|*[!0-9]*) return 1 ;; esac
      _gpd_n=$(guard_strip_leading_zeros "$_gpd_n")
      if [ "${#_gpd_n}" -gt 9 ]; then
        printf '999999999\n'
      else
        printf '%s\n' "$_gpd_n"
      fi
      return 0
      ;;
    *s)
      _gpd_n="${_gpd_raw%s}"
      case "$_gpd_n" in
        *.*)
          _gpd_int="${_gpd_n%%.*}"
          _gpd_frac="${_gpd_n#*.}"
          case "$_gpd_int" in ''|*[!0-9]*) return 1 ;; esac
          case "$_gpd_frac" in ''|*[!0-9]*) return 1 ;; esac
          _gpd_int=$(guard_strip_leading_zeros "$_gpd_int")
          if [ "${#_gpd_int}" -gt 6 ]; then
            printf '999999999\n'
            return 0
          fi
          case "${#_gpd_frac}" in
            1) _gpd_fms="${_gpd_frac}00" ;;
            2) _gpd_fms="${_gpd_frac}0" ;;
            *)
              _gpd_rest="${_gpd_frac#???}"
              _gpd_fms="${_gpd_frac%"$_gpd_rest"}"
              ;;
          esac
          _gpd_fms=$(guard_strip_leading_zeros "$_gpd_fms")
          printf '%s\n' $((_gpd_int * 1000 + _gpd_fms))
          return 0
          ;;
        ''|*[!0-9]*)
          return 1
          ;;
        *)
          _gpd_n=$(guard_strip_leading_zeros "$_gpd_n")
          if [ "${#_gpd_n}" -gt 6 ]; then
            printf '999999999\n'
          else
            printf '%s\n' $((_gpd_n * 1000))
          fi
          return 0
          ;;
      esac
      ;;
    *m)
      _gpd_n="${_gpd_raw%m}"
      case "$_gpd_n" in ''|*[!0-9]*) return 1 ;; esac
      _gpd_n=$(guard_strip_leading_zeros "$_gpd_n")
      if [ "${#_gpd_n}" -gt 4 ]; then
        printf '999999999\n'
      else
        printf '%s\n' $((_gpd_n * 60000))
      fi
      return 0
      ;;
    *h)
      _gpd_n="${_gpd_raw%h}"
      case "$_gpd_n" in ''|*[!0-9]*) return 1 ;; esac
      _gpd_n=$(guard_strip_leading_zeros "$_gpd_n")
      if [ "${#_gpd_n}" -gt 2 ]; then
        printf '999999999\n'
      else
        printf '%s\n' $((_gpd_n * 3600000))
      fi
      return 0
      ;;
    *[!0-9]*)
      return 1
      ;;
    *)
      _gpd_n=$(guard_strip_leading_zeros "$_gpd_raw")
      if [ "$_gpd_mode" = "env" ]; then
        if [ "${#_gpd_n}" -gt 9 ]; then
          printf '999999999\n'
        elif [ "$_gpd_n" -le 60 ]; then
          printf '%s\n' $((_gpd_n * 1000))
        else
          printf '%s\n' "$_gpd_n"
        fi
      else
        if [ "${#_gpd_n}" -gt 6 ]; then
          printf '999999999\n'
        else
          printf '%s\n' $((_gpd_n * 1000))
        fi
      fi
      return 0
      ;;
  esac
}

# guard_env_max_duration_ms <env_val> <default_max_ms> [min_ms]
# 解析环境变量中的时长上限（支持 5s / 5000ms / 纯数字），非法值回退 default_max_ms。
guard_env_max_duration_ms() {
  _gemd_raw="$1"
  _gemd_def="$2"
  _gemd_min="${3:-1}"
  if [ -z "$_gemd_raw" ]; then
    printf '%s\n' "$_gemd_def"
    return 0
  fi
  _gemd_ms=$(guard_parse_duration_ms "$_gemd_raw" env) || {
    printf '%s\n' "$_gemd_def"
    return 0
  }
  if [ "$_gemd_ms" -lt "$_gemd_min" ] || [ "$_gemd_ms" -ge 999999999 ]; then
    printf '%s\n' "$_gemd_def"
    return 0
  fi
  printf '%s\n' "$_gemd_ms"
}

# guard_clamp_duration_ms <raw_val> <max_ms> <default_ms>
# 将 naabu CLI 时长夹逼到 [1ms, max_ms] 并始终输出显式 ms 单位（如 500ms / 5000ms）。
guard_clamp_duration_ms() {
  _gcdm_raw="$1"
  _gcdm_max="$2"
  _gcdm_def="$3"
  _gcdm_ms=$(guard_parse_duration_ms "$_gcdm_raw" s) || {
    printf '%sms\n' "$_gcdm_def"
    return 0
  }
  if [ "$_gcdm_ms" -lt 1 ]; then
    printf '%sms\n' "$_gcdm_def"
  elif [ "$_gcdm_ms" -gt "$_gcdm_max" ]; then
    printf '%sms\n' "$_gcdm_max"
  else
    printf '%sms\n' "$_gcdm_ms"
  fi
}

# guard_audit_log <tool> <log_path> "$@"
guard_audit_log() {
  _gal_tool="$1"
  _gal_log="$2"
  shift 2
  [ -z "$_gal_log" ] && return 0
  {
    _gal_ts=$(date -u +%FT%TZ 2>/dev/null || printf 'unknown-time')
    printf '%s  [%s]' "$_gal_ts" "$_gal_tool"
    for _gal_a in "$@"; do
      printf ' %s' "$_gal_a"
    done
    printf '\n'
  } >> "$_gal_log" 2>/dev/null || true
}

# guard_exec <tool> <real_bin> <log_path> <debug_flag> "$@"
guard_exec() {
  _ge_tool="$1"
  _ge_real="$2"
  _ge_log="$3"
  _ge_debug="$4"
  shift 4
  if [ -n "$_ge_debug" ]; then
    printf '%s.shim argv:' "$_ge_tool"
    for _ge_a in "$@"; do
      printf ' %s' "$_ge_a"
    done
    printf '\n'
    exit 0
  fi
  guard_audit_log "$_ge_tool" "$_ge_log" "$@"
  exec "$_ge_real" "$@"
}
