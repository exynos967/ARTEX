# ARTEX optional SSH reverse-tunnel callback relay Sidecar (openssh-client, unprivileged).
#
# 构建方式（通常由 docker compose -f docker-compose.yml -f deploy/callback-relay/docker-compose.ssh.yml up -d --build 自动触发）：
#   docker build -t artex-callback-relay:local deploy/callback-relay
# 国内镜像源可覆盖：
#   --build-arg ALPINE_MIRROR=mirrors.tuna.tsinghua.edu.cn

ARG ALPINE_IMAGE=alpine:3.21
FROM ${ALPINE_IMAGE}

ARG ALPINE_MIRROR=
RUN if [ -n "$ALPINE_MIRROR" ]; then \
      sed -i "s|dl-cdn.alpinelinux.org|${ALPINE_MIRROR}|g" /etc/apk/repositories; \
    fi \
    && apk add --no-cache openssh-client python3

COPY render_relay.py /usr/local/lib/artex-callback/render_relay.py
COPY entrypoint.sh /usr/local/bin/callback-relay-entrypoint.sh
RUN chmod 0755 /usr/local/lib/artex-callback/render_relay.py /usr/local/bin/callback-relay-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/callback-relay-entrypoint.sh"]
