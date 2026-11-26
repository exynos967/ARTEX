# ARTEX transparent SOCKS5 egress gateway image (sing-box TUN + iptables Kill Switch).
#
# 构建方式（通常由 docker compose -f docker-compose.yml -f deploy/egress-proxy/docker-compose.socks5.yml up -d --build 自动触发）：
#   docker build -t artex-egress-gw:local deploy/egress-proxy
# 国内镜像源可覆盖：
#   --build-arg ALPINE_MIRROR=mirrors.tuna.tsinghua.edu.cn

ARG SING_BOX_IMAGE=ghcr.io/sagernet/sing-box:v1.14.4
FROM ${SING_BOX_IMAGE}

ARG ALPINE_MIRROR=
RUN if [ -n "$ALPINE_MIRROR" ]; then \
      sed -i "s|dl-cdn.alpinelinux.org|${ALPINE_MIRROR}|g" /etc/apk/repositories; \
    fi \
    && apk add --no-cache iptables iptables-legacy iproute2 python3

COPY render_config.py /usr/local/lib/artex-egress/render_config.py
COPY entrypoint.sh /usr/local/bin/egress-entrypoint.sh
RUN chmod 0755 /usr/local/lib/artex-egress/render_config.py /usr/local/bin/egress-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/egress-entrypoint.sh"]
